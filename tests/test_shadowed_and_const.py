"""Known-answer tests for four things that stopped a recovery compiling.

Build to Survive is three stock BGT 1.3 **debug** builds, so its recovered
source carries the author's own names -- and every one of these is a rule
that reads a declaration, asked in several places with only one of them
right. The client and the server both passed every free check and neither
compiled:

  * `string local_2("");` is a declaration, and only `_body` knew it. The
    hoist put `string local_2;` above it (`'local_2' is already declared`)
    and `_fold_to_construction` refused the whole body, emitting a generated
    initialiser that declares a class with no default constructor.
  * `const string[] dirs = array<string>(); dirs = local_4;` -- the author
    wrote `const string[] dirs = find_files(...)`, which is legal because
    the value is in the declaration. Split in two, the `const` is a lie
    about the statement that follows: "Reference is read-only".
  * `player@ handel;` then `handel = get_player(id);` -- a handle is
    reassigned with `@`, and the rule looked the name up in a map that
    keeps one name per slot, so every name that reached it through the
    debug variables missed.
  * `sound_pool p(5000)` globally and a `uint p` the author scoped to an
    inner block: hoisted, the local shadows the pool for the whole function
    and sixteen calls on it are "Illegal operation on 'uint'".

Synthetic inputs only.
"""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, os.path.join(ROOT, "tools", "nvgt"))

import bgt_asir                                                 # noqa: E402
from nvgt import decompile                                      # noqa: E402
from nvgt.asreader import (DataType, Function, GlobalProperty,   # noqa: E402
                           Module, ScriptVariable, TypeInfo)


def dt(name, handle=False, readonly=False, obj=False):
    out = DataType()
    if obj:
        out.obj_type = TypeInfo(name=name)
    else:
        out.primitive_name = name
    out.is_object_handle = handle
    out.is_readonly = readonly
    return out


class TheConstructorFormIsADeclaration(unittest.TestCase):
    """One question -- "is this a plain local declaration?" -- one answer."""

    def test_both_initialiser_forms_bind(self):
        self.assertEqual(decompile._local_binding('    string s = "a";'),
                         ("s", '"a"'))
        self.assertEqual(decompile._local_binding('    string s("a");'),
                         ("s", 'string("a")'))
        self.assertEqual(decompile._local_binding("    string s;"),
                         ("s", None))

    def test_a_statement_keyword_is_not_a_type(self):
        """`return f(x);` matches the constructor form exactly.

        Taken for a declaration of `f` it would both refuse a fold and skip
        a declaration that is needed, so the words that can stand where a
        type does are excluded by name.
        """
        self.assertIsNone(decompile._local_binding("    return f(x);"))
        self.assertIsNone(decompile._local_binding("    if (x) foo(y);"))
        self.assertIsNone(decompile._local_binding("    p = local_4;"))
        self.assertIsNone(decompile._local_binding('    f.open(d[i], "rb");'))

    def test_the_fold_accepts_a_constructed_local(self):
        """`prowl p("9f0d...", string(""))` rather than a helper function.

        A class whose only constructor takes arguments has no default one,
        so the helper cannot compile at all: it declares `prowl p;`, assigns
        with an opAssign the class does not have, and returns by value.
        """
        stmts = ['    string local_2("");',
                 '    string local_3 = "9f0d";',
                 "    prowl@ local_4 = prowl(local_3, local_2);",
                 "    p = local_4;"]
        got = decompile._fold_to_construction(dt("prowl", obj=True), stmts, "p")
        self.assertEqual(got, '"9f0d", (string(""))')

    def test_the_hoist_skips_a_name_the_constructor_form_declares(self):
        fd = _FakeFd({2: dt("string", obj=True)}, {2: "local_2"})
        stmts = ['    string local_2("");', "    local_2 = local_2;"]
        self.assertEqual(
            decompile._initialiser_declarations(fd, stmts, "p"), [],
            "the constructor form already declares it")

    def test_a_hoisted_declaration_is_never_const(self):
        fd = _FakeFd({2: dt("string", obj=True, readonly=True)}, {2: "s"})
        fd.var_types[2].format = lambda: "const string"
        self.assertEqual(
            decompile._initialiser_declarations(fd, ["    s = x;"], "p"),
            ["string s;"], "without its initialiser it will be assigned")


class AConstLocalThatIsAssignedLater(unittest.TestCase):
    """The module records what the author wrote, and it was legal.

    `const string[] dirs = find_files(...)` puts the value in the
    declaration. This decompiler splits that into an empty construction plus
    an assignment, so the `const` becomes a lie about the statement that
    follows -- "Reference is read-only", five times in the server and three
    in the client.

    Conditional, because four of the corpus's twelve `const` locals are
    complete (`const string[] d2 = __nvgt_list_5_241;`) and keeping those
    faithful costs nothing.
    """

    def _fd(self):
        array = dt("array", obj=True)
        array.format = lambda: "const string[]"
        fd = object.__new__(decompile.FuncDecompiler)
        fd.var_types = {2: array}
        fd.var_names = {2: "dirs"}
        fd.temps, fd.consumed_temps = {}, set()
        fd.mixed_boolean_slots, fd.declared = set(), set()
        fd.const_declarations, fd.slot_values = {}, {}
        fd.events, fd.stmt_texts, fd.stmt_count = [], [], 0
        fd.pushed_values = []
        fd.instrs = [_Pos(0), _Pos(1)]
        fd.k = 0
        fd._snapshot_pushed = lambda off: None
        fd._order_out_arguments = lambda text: None
        fd._normalize_arg = lambda a, d: a
        fd.fn = Function()
        fd.fn.object_type = None
        return fd

    def test_a_second_assignment_removes_the_const(self):
        fd = self._fd()
        fd._emit_assign(2, decompile.Atom("call", "array<string>()"))
        self.assertEqual(fd.events[0].data[0], "const string[]",
                         "the declaration carries it until proven wrong")
        fd.k = 1
        fd._emit_assign(2, decompile.Atom("raw", "local_4"))
        self.assertEqual(fd.events[0].data[0], "string[]",
                         "the value arrives by assignment, so not const")

    def test_a_declaration_nothing_reassigns_keeps_it(self):
        fd = self._fd()
        fd._emit_assign(2, decompile.Atom("raw", "__nvgt_list_5_241"))
        self.assertEqual(fd.events[0].data[0], "const string[]",
                         "complete in the declaration, as the author wrote")


class _Pos:
    def __init__(self, pos):
        self.pos = pos


class _FakeFd:
    """Just what `_initialiser_declarations` reads."""

    def __init__(self, var_types, var_names):
        self.var_types = var_types
        self.var_names = var_names

    def is_named(self, off):
        return off in self.var_names

    def name_of(self, off):
        return self.var_names.get(off, "tmp%d" % off)


class AHandleIsReassignedWithAt(unittest.TestCase):
    def test_the_typename_is_what_says_so(self):
        """And it cannot disagree with the declaration built from it.

        Looked up by NAME in `var_names` instead, this missed every name
        that reached the hoist through the debug variables: that map keeps
        one name per slot and a reused slot carries several, so
        `player@ handel;` was declared and `handel = get_player(id);`
        emitted without the `@` -- a value copy into whatever the handle
        points at.
        """
        path = os.path.join(ROOT, "tools", "nvgt", "decompile.py")
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        self.assertIn('is_handle = typename.rstrip().endswith("@")', source)
        self.assertNotIn("is_handle = off is not None", source,
                         "the name lookup must not come back")


class AHoistedLocalMustNotShadowAGlobal(unittest.TestCase):

    def _module(self, local_name, reads_global):
        m = Module(debug_info=True)
        m.globals = [GlobalProperty(name="p", namespace_="",
                                    type=dt("sound_pool", obj=True))]
        f = Function()
        f.name = "netloop"
        f.has_debug_info = True
        f.param_names = []
        f.variables = [ScriptVariable(declared_at=0, name=local_name,
                                      stack_offset=4, type=dt("uint"))]

        class _Ins:
            global_name = "p" if reads_global else None
        f.bytecode = [_Ins()]
        m.saved_functions = [f]
        return m, f

    def test_a_local_the_body_also_reads_as_a_global_is_renamed(self):
        m, f = self._module("p", reads_global=True)
        bgt_asir.Builder.rename_shadowed_locals(None, m)
        self.assertEqual([v.name for v in f.variables], ["p_2"])

    def test_a_local_the_body_never_reads_as_a_global_keeps_its_name(self):
        """Shadowing is legal, and the original compiled.

        Renaming those loses the author's names for nothing: measured at six
        of the client's files -- `seconds`, `m`, `w`, `s`, `r`, `bla`.
        """
        m, f = self._module("p", reads_global=False)
        bgt_asir.Builder.rename_shadowed_locals(None, m)
        self.assertEqual([v.name for v in f.variables], ["p"])

    def test_a_parameter_is_left_alone(self):
        """It is in scope for the whole function in the original too, so a
        body using that name means the parameter."""
        m, f = self._module("p", reads_global=True)
        f.variables = [ScriptVariable(declared_at=0, name="p",
                                      stack_offset=-1, type=dt("uint"))]
        f.param_names = ["p"]
        bgt_asir.Builder.rename_shadowed_locals(None, m)
        self.assertEqual([v.name for v in f.variables], ["p"])


if __name__ == "__main__":
    unittest.main()


class DestinationPsfTests(unittest.TestCase):
    """A destination `PSF` is not a READ of the slot.

    1.3 fuses `PSF v ; REFCPY` into `RefCpyV`, whose own operand nothing
    counts as a read; the 2010-2012 generations emit the pair, and counting
    its `PSF` as a read meant the stronger half of `_borrowed_handle` --
    *"nothing in the body reads the slot, and a `FREE` releases it"* -- could
    never fire for them at all: the bind's own `PSF` was the read.

    It is the same reading `FREE` already gets in that function, whose
    docstring says it outright -- *"releasing a slot is not a use of its
    value"* -- and where the value GOES is not a use of it either.
    """

    @staticmethod
    def _ins(name, **kw):
        """One instruction, with its bc_type taken from the ENGINE's own
        table rather than written down -- `PSF` is `asBCTYPE_rW_ARG`, and a
        test that hardcoded `W_ARG` would be asking about an instruction this
        reader does not have."""
        from nvgt.asreader import Instr, OPCODES
        bc = next(b for _n, b, _s, _st in OPCODES.values()
                  if _n == name) if any(
            n == name for n, _b, _s, _st in OPCODES.values()) else "asBCTYPE_NO_ARG"
        i = Instr.__new__(Instr)
        i.name = name
        for field in ("w_arg", "w_arg2", "dw_arg", "qw_arg", "pos", "op",
                      "size"):
            setattr(i, field, kw.get(field, 0))
        i.bc_type = kw.get("bc_type", bc)
        return i

    def test_a_destination_psf_is_not_a_read(self):
        body = [self._ins("PSF", w_arg=4), self._ins("REFCPY"),
                self._ins("FREE", w_arg=4)]
        self.assertNotIn(4, decompile._read_slots(body))

    def test_a_psf_that_is_not_a_destination_still_reads(self):
        body = [self._ins("PSF", w_arg=4), self._ins("CALLSYS")]
        self.assertIn(4, decompile._read_slots(body))

    def test_with_two_the_destination_is_the_one_pushed_last(self):
        """The earlier is a SOURCE and really is read. `PSF a ; PSF b ;
        REFCPY` does not occur in the one title with this shape -- 0 of 227 --
        so nothing rests on it, and the rule is right either way."""
        body = [self._ins("PSF", w_arg=3), self._ins("PSF", w_arg=4),
                self._ins("REFCPY")]
        reads = decompile._read_slots(body)
        self.assertIn(3, reads)
        self.assertNotIn(4, reads)

    def test_one_instruction_on_its_own_is_unchanged(self):
        """`_read_slots` is also called with a single instruction, where there
        is no next one to look at -- that keeps the conservative answer."""
        self.assertIn(4, decompile._read_slots([self._ins("PSF", w_arg=4)]))

    def test_the_unfused_borrow_asks_the_same_question_as_the_fused_one(self):
        """A test about the SOURCE, because the behaviour needs a module: the
        fused branch asks `_borrowed_handle` and the unfused one went straight
        to `_emit_assign`, which is the whole bug. Perilous Hearts indexed
        `map[uint(path[path_step].x)]` BEFORE the `&&` that guards it, which
        is the shape that made entering any map throw in Paladin."""
        import inspect
        source = inspect.getsource(decompile.FuncDecompiler._refcpy)
        unfused = source.partition("else:  # REFCPY")[2]
        self.assertTrue(unfused, "the unfused branch was not found")
        self.assertIn("_borrowed_handle(", unfused)


class ReturnAddressConstructionTests(unittest.TestCase):
    """Constructing into the hidden RETURN ADDRESS is a `return`.

    A value type returned by value is built in the caller's storage, whose
    address the frame holds at the return slot -- so the receiver arrives as
    `PshV4 -1`, the VALUE of that slot, where every other construction's
    receiver is a slot ADDRESS. `dst.is_ptr` is therefore False and the
    handler fell through to the value register, which nothing then read:

        STR "Dragon" ; PSF 15 ; CALLSYS $str
        PSF 15 ; PshV4 -1 ; CALLSYS $beh0      <- the return
        PSF 15 ; CALLSYS $beh1                 <- the temp goes
        JMP -> exit

    `player::look_for_character` is twelve of those, and every arm came out
    as a bare `break;` -- so the function returned nothing at all and twelve
    creature names were lost. `bgt audit` found it on the first run it could
    read that generation, and NVGT had been counting it all along as "Not
    all paths return a value".
    """

    def test_the_return_slot_is_named_apart_from_every_positive_slot(self):
        """Which is what makes the receiver identifiable without giving a
        value atom an offset it has never carried: `name_of` renders a
        negative slot `tmp_N` and a positive one `tmpN`, so slot -1 and slot
        1 cannot be confused."""
        fd = decompile.FuncDecompiler.__new__(decompile.FuncDecompiler)
        fd.var_names = {}
        fd.fn = type("F", (), {"object_type": None})()
        self.assertEqual(fd.name_of(-1), "tmp_1")
        self.assertEqual(fd.name_of(1), "tmp1")
        self.assertNotEqual(fd.name_of(-1), fd.name_of(1))

    def test_the_branch_asks_for_a_VALUE_of_the_return_slot(self):
        """A test about the SOURCE, because the behaviour needs a module: the
        whole point is that this receiver is not a pointer, so a branch that
        required `is_ptr` -- as every sibling does -- could never fire."""
        import inspect
        source = inspect.getsource(decompile.FuncDecompiler._call)
        marker = "self.name_of(self.return_slot)"
        self.assertIn(marker, source)
        window = source[source.index(marker) - 400:source.index(marker) + 200]
        self.assertIn("not dst.is_ptr", window,
                      "the receiver is a value, not an address")
        self.assertIn("self.return_slot < 0", window,
                      "slot 0 is `this`, never the return address")
        self.assertIn("_needs_out_ref", window,
                      "only a type returned IN the caller's storage")
