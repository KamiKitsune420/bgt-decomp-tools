"""Reader for AngelScript's serialized module bytecode (asCReader port).

Implements the exact on-disk format written by asCWriter / consumed by
asCReader (sdk/angelscript/source/as_restore.cpp) at the pinned commit
NVGT builds against (anjo76/angelscript 3fc00a6).

The reader is deliberately forgiving: everything is kept as plain data so
the disassembler and decompiler can inspect the module without a live
engine. Names, types, variable declarations and line numbers all survive
serialization (the last two when the bytecode was saved with debug info).

Public entry point:  read_module(data: bytes) -> Module
"""
from __future__ import annotations

import struct
import hashlib
from dataclasses import dataclass, field
from typing import Optional

try:                      # installed as a package
    from .opcodes import OPCODES
    from .signatures import function_signature, funcdef_declaration
except ImportError:       # run directly from a checkout
    from opcodes import OPCODES
    from signatures import function_signature, funcdef_declaration

# ---------------------------------------------------------------------------
# eTokenType values (as_tokendef.h) used by the datatype encoding.
# ---------------------------------------------------------------------------
TT_UNRECOGNIZED = 0
TT_IDENTIFIER = 5
TT_INT_CONSTANT = 6
TT_FLOAT_CONSTANT = 7
TT_DOUBLE_CONSTANT = 8
TT_STRING_CONSTANT = 9
TT_BITS_CONSTANT = 13
TT_INT = 70
TT_INT8 = 71
TT_INT16 = 72
TT_INT64 = 73
TT_UINT = 77
TT_UINT8 = 78
TT_UINT16 = 79
TT_UINT64 = 80
TT_FLOAT = 81
TT_VOID = 82
TT_DOUBLE = 94
TT_BOOL = 67

# Complete eTokenType table from as_tokendef.h (values auto-extracted from the
# pinned AngelScript source; used for datatype rendering and enum underlying
# types). Comment shows the source token text.
TOKEN_NAMES = {
    0: 'unrecognized_token', 1: 'end', 2: 'whitespace', 3: 'oneline_comment',
    4: 'multiline_comment', 5: 'identifier', 6: 'int_constant',
    7: 'float_constant', 8: 'double_constant', 9: 'string_constant',
    10: 'multiline_string_constant', 11: 'heredoc_string_constant',
    12: 'nonterminated_string_constant', 13: 'bits_constant',
    14: 'plus', 15: 'minus', 16: 'star', 17: 'slash', 18: 'percent',
    19: 'star_star', 20: 'handle', 21: 'add_assign', 22: 'sub_assign',
    23: 'mul_assign', 24: 'div_assign', 25: 'mod_assign', 26: 'pow_assign',
    27: 'or_assign', 28: 'and_assign', 29: 'xor_assign',
    30: 'shift_left_assign', 31: 'shift_right_l_assign',
    32: 'shift_right_a_assign', 33: 'inc', 34: 'dec', 35: 'dot',
    36: 'variadic', 37: 'scope', 38: 'assignment', 39: 'end_statement',
    40: 'list_separator', 41: 'start_statement_block',
    42: 'end_statement_block', 43: 'open_parenthesis',
    44: 'close_parenthesis', 45: 'open_bracket', 46: 'close_bracket',
    47: 'amp', 48: 'bit_or', 49: 'bit_not', 50: 'bit_xor',
    51: 'bit_shift_left', 52: 'bit_shift_right', 53: 'bit_shift_right_arith',
    54: 'equal', 55: 'not_equal', 56: 'less_than', 57: 'greater_than',
    58: 'less_than_or_equal', 59: 'greater_than_or_equal', 60: 'question',
    61: 'colon', 62: 'if', 63: 'else', 64: 'for', 65: 'foreach',
    66: 'while', 67: 'bool', 68: 'funcdef', 69: 'import', 70: 'int',
    71: 'int8', 72: 'int16', 73: 'int64', 74: 'interface', 75: 'is',
    76: 'not_is', 77: 'uint', 78: 'uint8', 79: 'uint16', 80: 'uint64',
    81: 'float', 82: 'void', 83: 'true', 84: 'false', 85: 'return',
    86: 'not', 87: 'and', 88: 'or', 89: 'xor', 90: 'break', 91: 'continue',
    92: 'const', 93: 'do', 94: 'double', 95: 'switch', 96: 'case',
    97: 'default', 98: 'in', 99: 'out', 100: 'inout', 101: 'null',
    102: 'class', 103: 'typedef', 104: 'enum', 105: 'cast', 106: 'private',
    107: 'protected', 108: 'namespace', 109: 'mixin', 110: 'auto',
    111: 'try', 112: 'catch', 113: 'using',
}

# Token id -> printable primitive type name (subset seen in datatype streams).
PRIMITIVE_NAMES = {
    TT_VOID: "void", TT_BOOL: "bool", TT_INT: "int", TT_INT8: "int8",
    TT_INT16: "int16", TT_INT64: "int64", TT_UINT: "uint", TT_UINT8: "uint8",
    TT_UINT16: "uint16", TT_UINT64: "uint64", TT_FLOAT: "float",
    TT_DOUBLE: "double",
}

# asEFuncType (angelscript.h)
FUNC_TYPES = {
    -1: "dummy", 0: "system", 1: "script", 2: "interface", 3: "virtual",
    4: "funcdef", 5: "imported", 6: "delegate", 7: "template",
}


class ReaderError(ValueError):
    pass


@dataclass
class DataType:
    """A decoded asCDataType. token_type identifies primitives; obj_type
    names script/registered object types. Flags mirror asCDataType bits."""
    token_type: int = TT_UNRECOGNIZED
    obj_type: Optional["TypeInfo"] = None
    is_object_handle: bool = False
    is_handle_to_const: bool = False
    is_reference: bool = False
    is_readonly: bool = False
    template_subtypes: list = field(default_factory=list)  # for 'a' entries

    def format(self, default_ns: str = "") -> str:
        if self.obj_type is not None:
            name = self.obj_type.format_name(default_ns)
        else:
            name = PRIMITIVE_NAMES.get(self.token_type, f"tok{self.token_type}")
        if self.obj_type is not None and self.template_subtypes:
            name += "<" + ", ".join(s.format(default_ns) for s in self.template_subtypes) + ">"
        if self.is_handle_to_const:
            name = "const " + name
        if self.is_object_handle:
            name += "@"
            if self.is_readonly:
                name += "const"
        elif self.is_readonly:
            name = "const " + name
        if self.is_reference:
            name += "&"
        return name


@dataclass
class TypeInfo:
    """A type referenced by the module (script class, enum, funcdef,
    registered app type, template instance...)."""
    kind: str = "class"          # class | enum | funcdef | typedef | app | template | list | subtype
    name: str = ""
    namespace_: str = ""
    flags: int = 0
    size: int = 0
    derived_from: Optional["TypeInfo"] = None
    interfaces: list = field(default_factory=list)
    parent_class: Optional["TypeInfo"] = None  # scoped child funcdef
    child_funcdefs: list = field(default_factory=list)
    enum_values: list = field(default_factory=list)      # [(name, value)]
    properties: list = field(default_factory=list)       # [(name, DataType, flags)]
    methods: list = field(default_factory=list)          # [Function]
    constructors: list = field(default_factory=list)     # [Function]
    factories: list = field(default_factory=list)        # [Function]
    destructor: Optional["Function"] = None
    vft: list = field(default_factory=list)               # virtual function table entries (full copies of methods)
    typedef_target: Optional[DataType] = None
    enum_underlying: str = "int"
    template_typename: str = ""
    is_shared: bool = False
    is_external: bool = False
    is_interface: bool = False
    return_via_object_register: bool = False  # inferred registered REF type
    return_via_value_register: bool = False   # inferred registered enum

    def format_name(self, default_ns: str = "") -> str:
        if self.parent_class is not None:
            return self.parent_class.format_name(default_ns) + "::" + self.name
        if self.namespace_ and self.namespace_ != default_ns:
            return f"{self.namespace_}::{self.name}"
        return self.name


@dataclass
class ScriptVariable:
    declared_at: int = 0
    name: str = ""
    stack_offset: int = 0
    on_heap: bool = False
    type: DataType = field(default_factory=DataType)


@dataclass
class Function:
    """One asCScriptFunction. Script functions carry bytecode; signatures
    for app (registered) functions carry just the declaration."""
    name: str = ""
    return_type: DataType = field(default_factory=DataType)
    param_types: list = field(default_factory=list)      # [DataType]
    in_out_flags: list = field(default_factory=list)     # [int]
    func_type: int = 0
    is_template_func: bool = False
    template_subtypes: list = field(default_factory=list)
    default_args: list = field(default_factory=list)     # [str|None] aligned to params
    object_type: Optional[TypeInfo] = None
    flags_byte: int = 0          # readonly/private/protected/final/override/explicit/property/variadic
    namespace_: str = ""
    parent_class: Optional[TypeInfo] = None

    # script-function payload
    is_shared: bool = False
    dont_clean_up_on_exception: bool = False
    is_external: bool = False
    bytecode: list = field(default_factory=list)         # [Instr]
    variable_space: int = 0
    obj_variable_info: list = field(default_factory=list)
    try_catch_info: list = field(default_factory=list)
    has_debug_info: bool = False
    line_numbers: list = field(default_factory=list)     # flat [pos, line, ...]
    sections: list = field(default_factory=list)         # flat [pos, name, ...]
    variables: list = field(default_factory=list)        # [ScriptVariable]
    script_section: str = ""
    declared_at: int = 0
    param_names: list = field(default_factory=list)      # [str]
    vf_table_idx: int = 0

    # filled by the module after reading (resolution of usedFunctions etc.)
    index: int = -1

    def signature(self, with_param_names: bool = True) -> str:
        return function_signature(self, with_param_names=with_param_names,
                                  include_defaults=False, include_modifiers=False,
                                  qualify_owner=True, qualify_namespace=True)

    def declaration(self) -> str:
        """Best-effort source-level declaration for this function."""
        if self.func_type == 4:  # funcdef
            return funcdef_declaration(self)
        return function_signature(self, qualify_owner=True, qualify_namespace=True)


@dataclass
class Instr:
    """One decoded bytecode instruction."""
    pos: int                    # dword offset inside the function's bytecode
    op: int
    name: str
    bc_type: str
    size: int                   # size in dwords
    w_arg: int = 0              # first 16-bit arg (stack/register index)
    w_arg2: int = 0             # second 16-bit arg
    dw_arg: int = 0             # 32-bit arg (raw)
    qw_arg: int = 0             # 64-bit arg (raw)

    # semantic fields filled by the reader's post-processing:
    type_ref: Optional[TypeInfo] = None       # ALLOC/FREE/REFCPY/OBJTYPE/TYPEID/Cast...
    type_id: int = 0
    data_type: Optional[DataType] = None       # TYPEID / SetListType / Cast
    func_ref: Optional[Function] = None       # CALL/CALLSYS/CALLBND/CallPtr targets
    func_name: str = ""                       # resolved name for calls
    prop_name: Optional[str] = None           # object property access name
    prop_offset: int = 0
    global_name: Optional[str] = None         # global variable access name
    string_const: Optional[str] = None        # STR / SetV string constant
    jump_arg: int = 0                         # saved instruction-number delta (jumps)
    jump_target: Optional[int] = None         # restored dword offset of the target


@dataclass
class GlobalProperty:
    name: str = ""
    namespace_: str = ""
    type: DataType = field(default_factory=DataType)
    init_func: Optional[Function] = None
    from_module: bool = True


@dataclass
class ImportedFunction:
    signature: Function = None
    module: str = ""


@dataclass
class Module:
    """Everything recovered from one serialized script module."""
    debug_info: bool = True
    enums: list = field(default_factory=list)            # [TypeInfo]
    classes: list = field(default_factory=list)          # [TypeInfo]
    funcdefs: list = field(default_factory=list)         # [Function]
    typedefs: list = field(default_factory=list)         # [TypeInfo]
    globals: list = field(default_factory=list)          # [GlobalProperty]
    script_functions: list = field(default_factory=list) # [Function]
    global_functions: list = field(default_factory=list) # [Function]
    imported_functions: list = field(default_factory=list)  # [ImportedFunction]
    used_types: list = field(default_factory=list)       # [TypeInfo]
    used_type_ids: list = field(default_factory=list)    # [DataType]
    used_functions: list = field(default_factory=list)   # [Function|None]
    used_globals: list = field(default_factory=list)     # [GlobalProperty]
    used_strings: list = field(default_factory=list)     # [str]

    # cross-reference helpers (filled post-read)
    saved_data_types: list = field(default_factory=list, repr=False)
    saved_strings: list = field(default_factory=list, repr=False)
    saved_functions: list = field(default_factory=list, repr=False)
    _by_name: dict = field(default_factory=dict, repr=False)

    def function_by_name(self, name: str) -> Optional[Function]:
        return self._by_name.get(name)

    def entry_point(self) -> Optional[Function]:
        for f in self.global_functions:
            if f.name == "main":
                return f
        for f in self.script_functions:
            if f.name == "main" and not f.param_types:
                return f
        return None


# ---------------------------------------------------------------------------
# Stream primitives
# ---------------------------------------------------------------------------

class _Stream:
    __slots__ = ("data", "pos", "bytes_read")

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.bytes_read = 0

    def read(self, size: int) -> bytes:
        if size < 0 or self.pos + size > len(self.data):
            raise ReaderError(
                f"unexpected end of stream at byte {self.pos} (wanted {size}, "
                f"have {len(self.data) - self.pos})")
        chunk = self.data[self.pos:self.pos + size]
        self.pos += size
        self.bytes_read += size
        return chunk

    def u8(self) -> int:
        return self.read(1)[0]

    def i8(self) -> int:
        return struct.unpack("<b", self.read(1))[0]

    def u16(self) -> int:
        return struct.unpack("<H", self.read(2))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.read(4))[0]

    def u64(self) -> int:
        # asCWriter::WriteData emits multi-byte values big-endian on
        # little-endian hosts (it writes most-significant byte first).
        return struct.unpack(">Q", self.read(8))[0]

    def read_encoded_uint64(self) -> int:
        """Variable-length encoding used everywhere (asCReader::ReadEncodedUInt64)."""
        b = self.u8()
        negative = bool(b & 0x80)
        b &= 0x7F
        if b == 0x7F:
            i = int.from_bytes(self.read(8), "big")
        elif (b & 0x7E) == 0x7E:
            i = (b & 0x01) << 48 | self.u8() << 40 | self.u8() << 32 | \
                self.u8() << 24 | self.u8() << 16 | self.u8() << 8 | self.u8()
        elif (b & 0x7C) == 0x7C:
            i = (b & 0x03) << 40 | self.u8() << 32 | self.u8() << 24 | \
                self.u8() << 16 | self.u8() << 8 | self.u8()
        elif (b & 0x78) == 0x78:
            i = (b & 0x07) << 32 | self.u8() << 24 | self.u8() << 16 | self.u8() << 8 | self.u8()
        elif (b & 0x70) == 0x70:
            i = (b & 0x0F) << 24 | self.u8() << 16 | self.u8() << 8 | self.u8()
        elif (b & 0x60) == 0x60:
            i = (b & 0x1F) << 16 | self.u8() << 8 | self.u8()
        elif (b & 0x40) == 0x40:
            i = (b & 0x3F) << 8 | self.u8()
        else:
            i = b
        if negative:
            i = (-i) & 0xFFFFFFFFFFFFFFFF
        return i

    def encoded_uint(self) -> int:
        v = self.read_encoded_uint64()
        hi = v >> 32
        if hi != 0 and hi != 0xFFFFFFFF:
            raise ReaderError(f"encoded uint out of range: {v:#x}")
        return v & 0xFFFFFFFF

    def encoded_int(self) -> int:
        v = self.encoded_uint()
        return v - (1 << 32) if v >= (1 << 31) else v

    def encoded_uint16(self) -> int:
        v = self.encoded_uint()
        hi = v >> 16
        if hi != 0 and hi != 0xFFFF:
            raise ReaderError(f"encoded uint16 out of range: {v:#x}")
        return v & 0xFFFF

    def sanity(self, val: int, max_val: int) -> int:
        if val > max_val:
            raise ReaderError(f"sanity check failed: {val} > {max_val}")
        return val


# ---------------------------------------------------------------------------
# Reader
# ---------------------------------------------------------------------------

class _Reader:
    def __init__(self, data: bytes, legacy=False):
        self.s = _Stream(data)
        self.legacy = legacy
        self.module = Module()
        self.error: Optional[str] = None

    # -- generic helpers ----------------------------------------------------

    def read_token(self):
        token = self.s.encoded_uint()
        return token + int(token >= 36) + int(token >= 64) if self.legacy else token

    def read_string(self) -> str:
        """asCReader::ReadString: even length = literal, odd = back-reference.
        Empty strings are stored literally and NOT added to the back-reference
        table (matches both asCReader and asCWriter)."""
        enc = self.s.sanity(self.s.encoded_uint(), 1_000_000)
        if enc & 1:
            idx = enc // 2
            if idx >= len(self.module.saved_strings):
                raise ReaderError(f"string back-reference {idx} out of range")
            return self.module.saved_strings[idx]
        length = enc // 2
        if length == 0:
            return ""
        text = self.s.read(length).decode("utf-8", errors="surrogateescape")
        self.module.saved_strings.append(text)
        return text

    def read_data_type(self) -> DataType:
        """asCReader::ReadDataType."""
        idx = self.s.encoded_uint()
        if idx != 0:
            if idx - 1 >= len(self.module.saved_data_types):
                raise ReaderError(f"datatype back-reference {idx} out of range")
            return self.module.saved_data_types[idx - 1]
        token_type = self.read_token()
        save_slot = len(self.module.saved_data_types)
        self.module.saved_data_types.append(DataType())  # reserve slot (may recurse)
        ti = None
        template_subtypes: list = []
        if token_type == TT_IDENTIFIER:
            ti = self.read_type_info()
        b = self.s.u8()
        is_object_handle = bool(b & 1)
        is_handle_to_const = bool(b & 2)
        is_reference = bool(b & 4)
        is_readonly = bool(b & 8)
        # Template arguments are serialized as part of the type-info record,
        # but they describe this data type.  Keep them on DataType so format()
        # can render declarations such as array<string> instead of bare array.
        template_subtypes = list(getattr(ti, "template_subtypes", [])) if ti else []
        dt = DataType(token_type=token_type, obj_type=ti,
                      is_object_handle=is_object_handle,
                      is_handle_to_const=is_handle_to_const,
                      is_reference=is_reference, is_readonly=is_readonly)
        dt.template_subtypes = template_subtypes
        if token_type == TT_UNRECOGNIZED and is_object_handle and ti is None:
            dt = DataType(token_type=TT_UNRECOGNIZED, obj_type=None,
                          is_object_handle=True)  # null handle
        self.module.saved_data_types[save_slot] = dt
        return dt

    def read_type_info(self) -> Optional[TypeInfo]:
        """asCReader::ReadTypeInfo."""
        ch = self.s.read(1)
        if ch == b"\x00":
            return None
        if ch == b"a":  # template instance
            type_name = self.read_string()
            ns = self.read_string()
            num_sub = self.s.sanity(self.s.encoded_uint(), 100)
            subs: list = []
            for _ in range(num_sub):
                c = self.s.u8()
                if c == ord("s"):
                    subs.append(self.read_data_type())
                else:
                    subs.append(DataType(token_type=self.read_token()))
            ti = TypeInfo(kind="template", name=type_name, namespace_=ns)
            ti.template_subtypes = subs  # type: ignore[attr-defined]
            return ti
        if ch == b"l":  # list pattern type
            inner = self.read_type_info()
            ti = TypeInfo(kind="list", name=(inner.name if inner else "") + "[]")
            return ti
        if ch == b"s":  # registered template subtype (e.g. a typename T)
            type_name = self.read_string()
            ti = TypeInfo(kind="subtype", name=type_name)
            return ti
        if ch == b"o":  # named object type
            type_name = self.read_string()
            ns = self.read_string()
            if type_name == "$obj":
                ti = TypeInfo(kind="class", name="$obj", namespace_=ns)
            elif type_name == "$func":
                ti = TypeInfo(kind="class", name="$func", namespace_=ns)
            else:
                ti = self._find_or_register_type(type_name, ns)
            return ti
        if ch == b"c":  # child funcdef of a class
            type_name = self.read_string()
            parent = self.read_type_info()
            ti = TypeInfo(kind="funcdef", name=type_name, parent_class=parent)
            if parent is not None:
                existing = next((f for f in parent.child_funcdefs if f.name == type_name), None)
                if existing is not None:
                    return existing
                parent.child_funcdefs.append(ti)
            return ti
        raise ReaderError(f"ReadTypeInfo: unknown kind byte {ch!r}")

    def _find_or_register_type(self, name: str, ns: str) -> TypeInfo:
        key = f"{ns}::{name}" if ns else name
        existing = self.module._by_name.get(key)
        if existing is not None:
            return existing
        ti = TypeInfo(kind="app", name=name, namespace_=ns)
        self.module._by_name[key] = ti
        return ti

    # -- module structure ---------------------------------------------------

    def read(self) -> Module:
        m = self.module
        # The stored flag is *stripDebugInfo*: 0 means debug info IS present
        # (variable names, line numbers, script sections).
        m.debug_info = self.s.encoded_uint() == 0

        # enums
        count = self.s.sanity(self.s.encoded_uint(), 1_000_000)
        for _ in range(count):
            ti = TypeInfo(kind="enum")
            self._read_type_declaration(ti, 1)
            if ti.is_shared:
                pass  # shared dedup handled leniently
            m.enums.append(ti)
            self._read_type_declaration(ti, 2)

        # classes (names first)
        count = self.s.sanity(self.s.encoded_uint(), 1_000_000)
        class_list: list = []
        for _ in range(count):
            ti = TypeInfo(kind="class")
            self._read_type_declaration(ti, 1)
            class_list.append(ti)
        m.classes.extend(class_list)

        # funcdefs
        count = self.s.sanity(self.s.encoded_uint(), 1_000_000)
        for _ in range(count):
            f = self._read_function(allow_null=False)
            if f is not None:
                m.funcdefs.append(f)

        # interface methods, then class methods/behaviours, then properties
        for ti in class_list:
            if ti.is_interface:
                self._read_type_declaration(ti, 2)
        for ti in class_list:
            if not ti.is_interface:
                self._read_type_declaration(ti, 2)
        for ti in class_list:
            if not ti.is_interface:
                self._read_type_declaration(ti, 3)

        # typedefs
        count = self.s.sanity(self.s.encoded_uint(), 1_000_000)
        for _ in range(count):
            ti = TypeInfo(kind="typedef")
            self._read_type_declaration(ti, 1)
            m.typedefs.append(ti)
            self._read_type_declaration(ti, 2)

        # global variables
        count = self.s.sanity(self.s.encoded_uint(), 1_000_000)
        for _ in range(count):
            gp = GlobalProperty()
            gp.name = self.read_string()
            gp.namespace_ = self.read_string()
            gp.type = self.read_data_type()
            gp.from_module = True
            f = self._read_function(allow_null=True)
            gp.init_func = f
            m.globals.append(gp)

        # script functions (includes methods, constructors, init funcs)
        count = self.s.sanity(self.s.encoded_uint(), 1_000_000)
        for _ in range(count):
            f = self._read_function(allow_null=False)
            if f is not None:
                f.index = len(m.script_functions)
                m.script_functions.append(f)
                m._by_name.setdefault(f.name, f)

        # global functions (references into script_functions)
        count = self.s.sanity(self.s.encoded_uint(), 1_000_000)
        for _ in range(count):
            f = self._read_function(allow_null=False)
            if f is not None:
                m.global_functions.append(f)

        # imported functions
        count = self.s.sanity(self.s.encoded_uint(), 1_000_000)
        for _ in range(count):
            f = self._read_function(allow_null=False)
            mod = self.read_string()
            if f is not None:
                m.imported_functions.append(ImportedFunction(f, mod))

        # usedTypes
        count = self.s.sanity(self.s.encoded_uint(), 1_000_000)
        for _ in range(count):
            ti = self.read_type_info()
            if ti is not None:
                m.used_types.append(ti)

        # usedTypeIds (datatype per entry)
        count = self.s.sanity(self.s.encoded_uint(), 1_000_000)
        for _ in range(count):
            m.used_type_ids.append(self.read_data_type())

        # usedFunctions
        count = self.s.sanity(self.s.encoded_uint(), 1_000_000)
        used_funcs: list = []
        for _ in range(count):
            f = self._read_used_function()
            used_funcs.append(f)
        m.used_functions = used_funcs

        # usedGlobalProperties
        count = self.s.sanity(self.s.encoded_uint(), 1_000_000)
        for _ in range(count):
            gp = GlobalProperty()
            gp.name = self.read_string()
            gp.namespace_ = self.read_string()
            gp.type = self.read_data_type()
            gp.from_module = self.s.u8() != 0
            m.used_globals.append(gp)

        # usedStringConstants
        count = self.s.sanity(self.s.encoded_uint(), 1_000_000)
        for _ in range(count):
            m.used_strings.append(self.read_string())

        # usedObjectProperties: (type, name) pairs
        count = self.s.sanity(self.s.encoded_uint(), 1_000_000)
        used_obj_props: list = []
        for _ in range(count):
            ti = self.read_type_info()
            name = self.read_string()
            used_obj_props.append((ti, name))
        m._by_name["__used_obj_props__"] = used_obj_props  # type: ignore[assignment]

        self._post_process()
        return m

    # -- type declarations --------------------------------------------------

    def _read_type_declaration(self, ti: TypeInfo, phase: int) -> None:
        if phase == 1:
            ti.name = self.read_string()
            ti.flags = int.from_bytes(self.s.read(4), "big") if self.legacy else self.s.u64()
            ti.size = self.s.sanity(self.s.encoded_uint(), 1_000_000)
            ti.namespace_ = self.read_string()
            ti.is_shared = bool(ti.flags & (1 << 22))   # asOBJ_SHARED
            ti.is_interface = bool(ti.flags & (1 << 21)) and ti.size == 0
            if ti.is_shared:
                c = self.s.u8()
                if c == ord("e"):
                    ti.is_external = True
                elif c != ord(" "):
                    raise ReaderError(f"type {ti.name}: bad external flag {c:#x}")
            key = f"{ti.namespace_}::{ti.name}" if ti.namespace_ else ti.name
            self.module._by_name.setdefault(key, ti)
        elif phase == 2:
            if ti.is_external:
                return
            if ti.kind == "enum":
                tok = TT_INT if self.legacy else self.s.encoded_uint()
                ti.enum_underlying = PRIMITIVE_NAMES.get(tok, f"tok{tok}")
                count = self.s.sanity(self.s.encoded_uint(), 1_000_000)
                size = {  # bytes per value by underlying type
                    "int": 4, "int8": 1, "int16": 2, "int64": 8,
                    "uint": 4, "uint8": 1, "uint16": 2, "uint64": 8,
                }.get(ti.enum_underlying, 4)
                for _ in range(count):
                    name = self.read_string()
                    raw = self.s.read(size)
                    value = int.from_bytes(raw, "big", signed=ti.enum_underlying.startswith("int"))
                    ti.enum_values.append((name, value))
            elif ti.kind == "typedef":
                tok = self.read_token()
                ti.typedef_target = DataType(token_type=tok)
            else:
                ti.derived_from = self.read_type_info()
                count = self.s.sanity(self.s.encoded_uint(), 1_000_000)
                for _ in range(count):
                    intf = self.read_type_info()
                    ti.interfaces.append(intf)
                    if not ti.is_interface:
                        self.s.encoded_uint()  # vft offset
                if not ti.is_interface:
                    # destructor
                    f = self._read_function(allow_null=True)
                    ti.destructor = f
                    # constructor/factory pairs
                    count = self.s.sanity(self.s.encoded_uint(), 1_000_000)
                    for _ in range(count):
                        c = self._read_function(allow_null=False)
                        if c is not None:
                            ti.constructors.append(c)
                        f2 = self._read_function(allow_null=False)
                        if f2 is not None:
                            ti.factories.append(f2)
                # Interfaces also serialize methods and a virtual function table.
                count = self.s.sanity(self.s.encoded_uint(), 1_000_000)
                for _ in range(count):
                    f = self._read_function(allow_null=False)
                    if f is not None:
                        ti.methods.append(f)
                count = self.s.sanity(self.s.encoded_uint(), 1_000_000)
                for _ in range(count):
                    vf = self._read_function(allow_null=False)
                    if vf is not None:
                        ti.vft.append(vf)
        elif phase == 3:
            if ti.is_external:
                return
            count = self.s.sanity(self.s.encoded_uint(), 1_000_000)
            for _ in range(count):
                name = self.read_string()
                dt = self.read_data_type()
                flags = self.s.encoded_uint()
                ti.properties.append((name, dt, flags))

    # -- functions ----------------------------------------------------------

    def _read_function(self, allow_null: bool) -> Optional[Function]:
        """asCReader::ReadFunction. Returns None for null refs; references to
        previously saved functions return the same Function object."""
        ch = self.s.u8()
        if ch == 0:
            if not allow_null:
                raise ReaderError("unexpected null function reference")
            return None
        if ch == ord("r"):
            idx = self.s.encoded_uint()
            saved = self.module.saved_functions
            if idx >= len(saved):
                raise ReaderError(f"function back-reference {idx} out of range")
            return saved[idx]
        f = Function()
        self.module.saved_functions.append(f)
        self._read_function_signature(f)

        if f.func_type == 1:  # asFUNC_SCRIPT
            bits = self.s.u8()
            f.is_shared = bool(bits & 1)
            f.dont_clean_up_on_exception = bool(bits & 2)
            f.is_external = bool(bits & 4)
            if not f.is_external:
                f.has_debug_info = self.module.debug_info
                self._read_bytecode(f)
                f.variable_space = self.s.sanity(self.s.encoded_uint(), 1_000_000)
                if bits & 8:  # objVariableInfo
                    length = self.s.sanity(self.s.encoded_uint(), 1_000_000)
                    for _ in range(length):
                        pos = self.s.sanity(self.s.encoded_uint(), 1_000_000)
                        off = self.s.sanity(self.s.encoded_int(), 10_000)
                        option = self.s.encoded_uint()
                        f.obj_variable_info.append((pos, off, option))
                if bits & 16:  # try/catch info
                    length = self.s.sanity(self.s.encoded_uint(), 1_000_000)
                    for _ in range(length):
                        try_pos = self.s.sanity(self.s.encoded_uint(), 1_000_000)
                        catch_pos = self.s.sanity(self.s.encoded_uint(), 1_000_000)
                        stack = 0 if self.legacy else self.s.sanity(self.s.encoded_uint(), 100_000)
                        f.try_catch_info.append((try_pos, catch_pos, stack))
                if self.module.debug_info:
                    length = self.s.sanity(self.s.encoded_uint(), 1_000_000)
                    f.line_numbers = [self.s.encoded_uint() for _ in range(length)]
                    length = self.s.sanity(self.s.encoded_uint(), 1_000_000)
                    for i in range(length):
                        if i % 2 == 0:
                            f.sections.append(self.s.encoded_uint())
                        else:
                            f.sections.append(self.read_string())
                # variable declarations (always present; names only with debug)
                length = self.s.sanity(self.s.encoded_uint(), 1_000_000)
                for _ in range(length):
                    v = ScriptVariable()
                    if self.module.debug_info:
                        v.declared_at = self.s.encoded_uint()
                        v.name = self.read_string()
                    raw_off = self.s.sanity(self.s.encoded_int(), 10_000)
                    v.on_heap = bool(raw_off & 1)
                    v.stack_offset = raw_off >> 1
                    v.type = self.read_data_type()
                    f.variables.append(v)
                if self.module.debug_info:
                    f.script_section = self.read_string()
                    f.declared_at = self.s.encoded_uint()
                    count_params = self.s.read_encoded_uint64()
                    if count_params > len(f.param_types):
                        raise ReaderError("parameter name count exceeds parameter count")
                    f.param_names = [self.read_string() for _ in range(count_params)]
        elif f.func_type in (3, 2):  # virtual / interface
            f.vf_table_idx = self.s.encoded_uint()
        elif f.func_type == 4:  # funcdef
            bits = self.s.u8()
            f.is_shared = bool(bits & 1)
            f.is_external = bool(bits & 2)
        return f

    def _read_function_signature(self, f: Function) -> None:
        f.name = self.read_string()
        if f.name == "$dlgte":
            # delegate factory: signature fully known, nothing more stored
            f.func_type = 6
            return
        f.return_type = self.read_data_type()
        count = self.s.sanity(self.s.encoded_uint(), 256)
        f.param_types = [self.read_data_type() for _ in range(count)]
        f.in_out_flags = [0] * len(f.param_types)
        if f.param_types:
            count = self.s.encoded_uint()
            if count > len(f.param_types):
                raise ReaderError("inOutFlags count exceeds parameter count")
            for i in range(count):
                f.in_out_flags[i] = self.s.encoded_uint()
        val = self.s.encoded_uint()
        f.is_template_func = bool(val & 128)
        f.func_type = val & ~128
        if f.param_types:
            count = self.s.encoded_uint()
            if count > len(f.param_types):
                raise ReaderError("defaultArgs count exceeds parameter count")
            f.default_args = [None] * len(f.param_types)
            for i in range(count):
                f.default_args[len(f.param_types) - 1 - i] = self.read_string()
        f.object_type = self.read_type_info()
        flags = self.s.u8() if not self.legacy or f.object_type or f.name.startswith(("get_", "set_")) else 0
        f.flags_byte = flags
        if f.object_type is None:
            if f.func_type == 4:
                b = self.s.u8()
                if b == ord("n"):
                    f.namespace_ = self.read_string()
                elif b == ord("o"):
                    f.parent_class = self.read_type_info()
                else:
                    raise ReaderError(f"funcdef namespace kind {b:#x}")
            else:
                f.namespace_ = self.read_string()
        if f.is_template_func:
            count = self.s.encoded_uint()
            f.template_subtypes = [self.read_data_type() for _ in range(count)]

    def _read_used_function(self) -> Optional[Function]:
        """asCReader::ReadUsedFunctions entry: identifies an app-registered or
        module function by signature. We keep the signature itself, which is
        exactly what the decompiler needs for calls into the engine."""
        c = self.s.u8()
        if c == ord("n"):
            return None
        f = Function()
        self._read_function_signature(f)
        f.func_type = 6 if c in (ord("a"), ord("s")) else f.func_type
        f.index = -1
        # 'm' entries reference module functions already read; keep signature
        # so the decompiler can still render calls by name.
        return f

    # -- bytecode -----------------------------------------------------------

    def _read_bytecode(self, f: Function) -> None:
        count = self.s.sanity(self.s.encoded_uint(), 1_000_000)
        pos = 0
        for _ in range(count):
            op = self.s.u8()
            if op not in OPCODES:
                raise ReaderError(f"unknown opcode {op} at dword {pos}")
            name, bc_type, size, _stack = OPCODES[op]
            if self.legacy and name == "ALLOC":
                bc_type, size = "asBCTYPE_QW_DW_ARG", 4
            elif self.legacy and name == "CALLSYS":
                bc_type, size = "asBCTYPE_DW_ARG", 2
            elif self.legacy and name == "CallPtr":
                bc_type, size = "asBCTYPE_rW_ARG", 1
            ins = Instr(pos=pos, op=op, name=name, bc_type=bc_type, size=size)
            t = bc_type
            if t == "asBCTYPE_NO_ARG":
                pass
            elif t in ("asBCTYPE_W_ARG", "asBCTYPE_wW_ARG", "asBCTYPE_rW_ARG"):
                ins.w_arg = self.s.encoded_uint16()
            elif t in ("asBCTYPE_rW_DW_ARG", "asBCTYPE_wW_DW_ARG", "asBCTYPE_W_DW_ARG"):
                ins.w_arg = self.s.encoded_uint16()
                ins.dw_arg = self.s.encoded_uint()
            elif t == "asBCTYPE_DW_ARG":
                ins.dw_arg = self.s.encoded_uint()
            elif t == "asBCTYPE_DW_DW_ARG":
                ins.dw_arg = self.s.encoded_uint()
                ins.qw_arg = self.s.encoded_uint()  # second dword kept in qw_arg low bits
            elif t == "asBCTYPE_wW_rW_rW_ARG":
                ins.w_arg = self.s.encoded_uint16()
                ins.w_arg2 = self.s.encoded_uint16()
                ins.qw_arg = self.s.encoded_uint16()  # third word
            elif t in ("asBCTYPE_wW_rW_ARG", "asBCTYPE_rW_rW_ARG",
                       "asBCTYPE_wW_W_ARG", "asBCTYPE_W_rW_ARG"):
                ins.w_arg = self.s.encoded_uint16()
                ins.w_arg2 = self.s.encoded_uint16()
            elif t in ("asBCTYPE_wW_rW_DW_ARG", "asBCTYPE_rW_W_DW_ARG"):
                ins.w_arg = self.s.encoded_uint16()
                ins.w_arg2 = self.s.encoded_uint16()
                ins.dw_arg = self.s.encoded_uint()
            elif t == "asBCTYPE_QW_ARG":
                ins.qw_arg = self.s.read_encoded_uint64()
            elif t == "asBCTYPE_QW_DW_ARG":
                ins.qw_arg = self.s.read_encoded_uint64()
                ins.dw_arg = self.s.encoded_uint()
            elif t == "asBCTYPE_W_QW_DW_ARG":
                ins.w_arg = self.s.encoded_uint16()
                ins.qw_arg = self.s.read_encoded_uint64()
                ins.dw_arg = self.s.encoded_uint()
            elif t in ("asBCTYPE_rW_QW_ARG", "asBCTYPE_wW_QW_ARG"):
                ins.w_arg = self.s.encoded_uint16()
                ins.qw_arg = self.s.read_encoded_uint64()
            elif t in ("asBCTYPE_rW_DW_DW_ARG", "asBCTYPE_W_DW_DW_ARG"):
                ins.w_arg = self.s.encoded_uint16()
                ins.dw_arg = self.s.encoded_uint()
                ins.qw_arg = self.s.encoded_uint()  # third dword in low bits
            else:
                raise ReaderError(f"unhandled bc type {t} for opcode {name}")
            f.bytecode.append(ins)
            if self.legacy and name == "CallPtr":
                ins.w_arg2, ins.w_arg = ins.w_arg, 0
            pos += size

    # -- post processing ----------------------------------------------------

    def _post_process(self) -> None:
        """Resolve semantic info on instructions: type refs, call targets,
        string constants, global/property names, jump targets.

        Mirrors asCReader::TranslateFunction, applied to every function that
        carries bytecode (module functions, class methods, behaviours,
        global-variable init functions)."""
        m = self.module
        # Anonymous functions use compiler-only names containing punctuation.
        # The same symbol can also occur in the used-function signature table.
        lambda_names = {}
        occupied = {f.name for f in m.saved_functions + m.used_functions if f}
        for function in m.saved_functions + m.used_functions:
            if function and function.name.startswith("$") and function.name.rsplit("$", 1)[-1].isdigit():
                original = function.name
                if original not in lambda_names:
                    stem = "__nvgt_lambda_" + hashlib.sha256(original.encode()).hexdigest()[:12]
                    candidate = stem
                    while candidate in occupied:
                        candidate += "_"
                    occupied.add(candidate)
                    lambda_names[original] = candidate
                function.original_name = original
                function.name = lambda_names[original]
        used_obj_props = m._by_name.get("__used_obj_props__", [])  # type: ignore[arg-type]

        def find_used_function(idx: int) -> Optional[Function]:
            if 0 <= idx < len(m.used_functions):
                return m.used_functions[idx]
            return None

        # Collect every distinct Function object that has bytecode. Back
        # references return the same object, so identity dedup is correct.
        all_funcs: list = []
        seen_ids: set = set()

        def collect(f: Optional[Function]) -> None:
            if f is not None and id(f) not in seen_ids:
                seen_ids.add(id(f))
                all_funcs.append(f)

        for ti in m.classes:
            collect(ti.destructor)
            for c in ti.constructors:
                collect(c)
            for fc in ti.factories:
                collect(fc)
            for me in ti.methods:
                collect(me)
            for vf in ti.vft:            # VFT copies carry the real bodies
                collect(vf)
        for gp in m.globals:
            collect(gp.init_func)
        for f in m.script_functions:
            collect(f)
        for f in m.global_functions:
            collect(f)
        for imp in m.imported_functions:
            collect(imp.signature)

        for f in all_funcs:
            self._translate_function(f, used_obj_props, find_used_function)

        # Registered type flags are not included in SaveByteCode. Infer REF
        # returns from the actual calling protocol: STOREOBJ receives them,
        # while value objects such as string use a hidden output pointer.
        reference_keys = set()
        scalar_keys = set()
        def mark(dt):
            if dt.obj_type and not dt.is_reference:
                reference_keys.add((dt.obj_type.namespace_, dt.obj_type.name))
        for f in all_funcs:
            if any(i.name == "LOADOBJ" for i in f.bytecode):
                mark(f.return_type)
            for index, ins in enumerate(f.bytecode[:-1]):
                if ins.func_ref and f.bytecode[index + 1].name == "STOREOBJ":
                    mark(ins.func_ref.return_type)
                if ins.func_ref and f.bytecode[index + 1].name in ("CpyRtoV4", "CpyRtoV8"):
                    dt = ins.func_ref.return_type
                    if dt.obj_type and not dt.is_reference and not dt.is_object_handle:
                        scalar_keys.add((dt.obj_type.namespace_, dt.obj_type.name))
        def apply(dt):
            if dt.obj_type:
                key = (dt.obj_type.namespace_, dt.obj_type.name)
                if key in reference_keys:
                    dt.obj_type.return_via_object_register = True
                if key in scalar_keys:
                    dt.obj_type.return_via_value_register = True
            for subtype in dt.template_subtypes:
                apply(subtype)
        for f in all_funcs + [f for f in m.used_functions if f]:
            apply(f.return_type)
            for dt in f.param_types:
                apply(dt)

    def _translate_function(self, f: Function, used_obj_props, find_used_function) -> None:
        """Resolve instruction operands for one function (TranslateFunction)."""
        m = self.module
        # Instruction sizes, indexed by instruction number (bcNum).
        bc_sizes = [i.size for i in f.bytecode]
        for bc_num, ins in enumerate(f.bytecode):
            n = ins.name
            if n in ("ALLOC", "FREE", "REFCPY", "RefCpyV", "OBJTYPE"):
                # All carry a usedTypes index in their pointer-sized arg
                # (asBCTYPE_*_QW on x64). RefCpyV is PSF+REFCPY fused and
                # carries the same handle type -- module-relative, so it too
                # made a matching handle copy read differently across builds.
                idx = ins.qw_arg
                if 0 <= idx < len(m.used_types):
                    ins.type_ref = m.used_types[idx]
            if n == "ALLOC":
                # dw_arg = usedFunctions index + 1 (0 means "no constructor",
                # i.e. default allocation).
                if ins.dw_arg > 0:
                    ins.func_ref = find_used_function(ins.dw_arg - 1)
                    if ins.func_ref is not None:
                        ins.func_name = ins.func_ref.signature()
            elif n in ("CALL", "CALLSYS", "CALLBND", "CALLINTF",
                       "Thiscall1"):
                # Call families index usedFunctions (asCWriter always calls
                # FindFunctionIndex for them).
                ins.func_ref = find_used_function(ins.dw_arg)
                if ins.func_ref is not None:
                    ins.func_name = ins.func_ref.signature()
            elif n == "FuncPtr":
                # FuncPtr is asBCTYPE_QW_ARG, unlike the call opcodes above.
                ins.func_ref = find_used_function(ins.qw_arg)
                if ins.func_ref is not None:
                    ins.func_name = ins.func_ref.signature()
            elif n in ("ADDProp", "LoadRObjR", "LoadVObjR", "ADDSi",
                       "LoadThisR"):
                # object property access via usedObjectProperties index
                idx = ins.w_arg2 if n in ("LoadRObjR", "LoadVObjR") else ins.w_arg
                if idx < len(used_obj_props):
                    ti, pname = used_obj_props[idx]
                    ins.prop_name = f"{ti.name}.{pname}" if ti else pname
                # LoadThisR/LoadRObjR/LoadVObjR also carry the property's type as
                # a usedTypeIds index in dw_arg -- module-relative, so a raw
                # index makes the same property read differently across two
                # builds. Resolve it (the decompiler reads only prop_name;
                # library_recovery's bytecode comparison reads this).
                if n in ("LoadThisR", "LoadRObjR", "LoadVObjR", "ADDSi", "ADDProp") \
                        and 0 <= ins.dw_arg < len(m.used_type_ids):
                    ins.type_id = ins.dw_arg
                    ins.data_type = m.used_type_ids[ins.dw_arg]
            elif n in ("TYPEID", "Cast", "ADDi", "ADDIf"):
                ins.type_id = ins.dw_arg
                if n in ("TYPEID", "Cast") and 0 <= ins.dw_arg < len(m.used_type_ids):
                    ins.data_type = m.used_type_ids[ins.dw_arg]
                    ins.type_ref = ins.data_type.obj_type
            elif n == "SetListType" and 0 <= ins.qw_arg < len(m.used_type_ids):
                ins.data_type = m.used_type_ids[ins.qw_arg]
            elif n in ("PGA", "PshGPtr", "LDG", "PshG4", "LdGRdR4",
                       "CpyGtoV4", "CpyVtoG4", "SetG4"):
                # Pointer-sized arg encodes either a global property ptr
                # (bit0 set) or a string constant (bit0 clear; only PGA and
                # PshGPtr can legally hold strings).
                if ins.qw_arg & 1:
                    idx = ins.qw_arg >> 1
                    if 0 <= idx < len(m.used_globals):
                        glob = m.used_globals[idx]
                        ins.global_name = (glob.namespace_ + "::" if glob.namespace_ else "") + glob.name
                elif n in ("PGA", "PshGPtr"):
                    idx = ins.qw_arg >> 1
                    if 0 <= idx < len(m.used_strings):
                        ins.string_const = m.used_strings[idx]
            elif n == "STR":
                idx = ins.dw_arg
                if 0 <= idx < len(m.used_strings):
                    ins.string_const = m.used_strings[idx]
            elif n in ("JMP", "JZ", "JNZ", "JLowZ", "JLowNZ",
                       "JS", "JNS", "JP", "JNP"):
                # Saved arg is an instruction-number delta relative to the
                # NEXT instruction (asCWriter::WriteData). Restore the dword
                # offset exactly as asCReader::TranslateFunction does:
                #   d >= 0: size = sum(sizes[bcNum+1 .. targetNbr])
                #   d <  0: size = -sum(sizes[targetNbr .. bcNum])
                # target pos = ins.pos + 2 + size
                d = ins.dw_arg if ins.dw_arg < 0x80000000 else ins.dw_arg - 0x100000000
                if d > 0:
                    # forward: sizes of the d instructions AFTER this one
                    # (the target instruction itself is excluded)
                    size = sum(bc_sizes[bc_num + 1: bc_num + 1 + d])
                elif d == 0:
                    size = 0
                else:
                    target_nbr = bc_num + 1 + d
                    size = -sum(bc_sizes[target_nbr: bc_num + 1])
                target_nbr = bc_num + 1 + d
                ins.jump_arg = d
                ins.jump_target = ins.pos + 2 + size if 0 <= target_nbr < len(f.bytecode) else None
        # Convert instruction-number-based positions back to dword offsets
        # (asCReader::TranslateFunction does this via instructionNbrToPos).
        nbr_to_pos = [i.pos for i in f.bytecode]
        nbr_to_pos.append(f.bytecode[-1].pos + f.bytecode[-1].size if f.bytecode else 0)
        if f.has_debug_info:
            for variable in f.variables:
                if not 0 <= variable.declared_at < len(nbr_to_pos):
                    raise ReaderError("variable declaration outside function bytecode")
                variable.declared_at = nbr_to_pos[variable.declared_at]
        f.obj_variable_info = [
            (nbr_to_pos[p], off, opt) if 0 <= p < len(nbr_to_pos) else (p, off, opt)
            for (p, off, opt) in f.obj_variable_info
        ]
        f.try_catch_info = [
            (nbr_to_pos[tp], nbr_to_pos[cp], st)
            if 0 <= tp < len(nbr_to_pos) and 0 <= cp < len(nbr_to_pos)
            else (tp, cp, st)
            for (tp, cp, st) in f.try_catch_info
        ]
        f.line_numbers = [
            nbr_to_pos[v] if (k % 2 == 0 and 0 <= v < len(nbr_to_pos)) else v
            for k, v in enumerate(f.line_numbers)
        ]
        f.sections = [
            nbr_to_pos[v] if (k % 2 == 0 and isinstance(v, int) and 0 <= v < len(nbr_to_pos)) else v
            for k, v in enumerate(f.sections)
        ]
        # line number list is flat pairs -> dict-like access helper
        f.line_numbers_pairs = list(zip(f.line_numbers[0::2], f.line_numbers[1::2]))  # type: ignore[attr-defined]


def unwrap_bytecode(data: bytes) -> bytes:
    """Validate the owned ASBC container; leave raw engine streams unchanged."""
    if data[:4] != b"ASBC":
        return data
    if len(data) < 12:
        raise ReaderError("truncated ASBC header")
    version, size = struct.unpack_from("<II", data, 4)
    if version != 1:
        raise ReaderError(f"unsupported ASBC version {version}")
    if size != len(data) - 12:
        raise ReaderError("ASBC bytecode length mismatch")
    return data[12:]


def read_module(data: bytes) -> Module:
    """Parse a raw (decompressed, decrypted) AngelScript module stream."""
    errors = []
    for legacy in (False, True):
        reader = _Reader(data, legacy=legacy)
        try:
            module = reader.read()
            if reader.s.pos != len(data):
                raise ReaderError(f"Unconsumed bytecode at {reader.s.pos} of {len(data)}")
            module.bytecode_profile = "legacy_32bit_flags" if legacy else "current_64bit_flags"
            return module
        except (ReaderError, IndexError, struct.error) as error:
            errors.append(str(error))
    raise ReaderError("Unsupported bytecode format: " + "; ".join(errors))
