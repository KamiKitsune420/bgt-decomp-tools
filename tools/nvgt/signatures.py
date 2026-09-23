"""Render AngelScript declarations from the metadata retained in bytecode.

The direction values and attribute bits follow asETypeModifiers and
asCWriter::WriteFunctionSignature in the pinned AngelScript source.  This
module deliberately avoids importing asreader, so its dataclasses can use
the same formatting helpers as the source renderer.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:
    from asreader import DataType, Function, TypeInfo


REFERENCE_DIRECTIONS = {1: "in", 2: "out", 3: "inout"}


def format_parameter(dtype: DataType, direction: int = 0, name: str = "",
                     default: str | None = None, default_ns: str = "") -> str:
    text = dtype.format(default_ns)
    if dtype.is_reference:
        # asTM_CONST is independent of the two direction bits.  The actual
        # const qualifier is already encoded in the data type.
        text += REFERENCE_DIRECTIONS.get(direction & 3, "")
    if name:
        text += " " + name
    if default is not None:
        text += " = " + default
    return text


def format_parameters(f: Function, param_names: Iterable[str] | None = None,
                      *, with_param_names: bool = True,
                      include_defaults: bool = True,
                      default_ns: str | None = None) -> str:
    names = list(f.param_names if param_names is None else param_names)
    if default_ns is None:
        owner = f.object_type or f.parent_class
        default_ns = owner.namespace_ if owner else f.namespace_
    params = []
    for i, dtype in enumerate(f.param_types):
        direction = f.in_out_flags[i] if i < len(f.in_out_flags) else 0
        name = names[i] if with_param_names and i < len(names) else ""
        default = (f.default_args[i] if include_defaults and
                   i < len(f.default_args) else None)
        params.append(format_parameter(dtype, direction, name, default, default_ns))
    text = ", ".join(params)
    if f.flags_byte & 128:
        # AngelScript's variadic marker follows the final parameter directly.
        text += "..."
    return text


def function_signature(f: Function, param_names: Iterable[str] | None = None,
                       *, with_param_names: bool = True,
                       include_defaults: bool = True,
                       include_modifiers: bool = True,
                       qualify_owner: bool = False,
                       qualify_namespace: bool = False,
                       name: str | None = None) -> str:
    owner = f.object_type or f.parent_class
    namespace = owner.namespace_ if owner else f.namespace_
    name = f.name if name is None else name
    constructor = bool(f.object_type and f.return_type.token_type == 82 and
                       (name in (f.object_type.name, "$beh0", "$beh2") or
                        name.startswith("~")))
    if f.object_type and name == "$beh0":
        name = f.object_type.name
    elif f.object_type and name == "$beh2":
        name = "~" + f.object_type.name
    if qualify_owner and owner:
        name = owner.format_name("" if qualify_namespace else namespace) + "::" + name
    elif qualify_namespace and namespace and owner is None:
        name = namespace + "::" + name
    params = format_parameters(f, param_names, with_param_names=with_param_names,
                               include_defaults=include_defaults,
                               default_ns=namespace)
    result = f"{name}({params})"
    if not constructor:
        result = f.return_type.format(namespace) + " " + result
    prefix = ""
    if include_modifiers:
        if owner is None:
            if f.is_external:
                prefix += "external "
            if f.is_shared:
                prefix += "shared "
        if f.flags_byte & 2:
            prefix += "private "
        elif f.flags_byte & 4:
            prefix += "protected "
    # Const is part of overload identity even when source-only modifiers are
    # omitted.  Dropping it can select the wrong virtual-function body.
    if f.flags_byte & 1:
        result += " const"
    if include_modifiers:
        for bit, keyword in ((8, "final"), (16, "override"),
                             (32, "explicit"), (64, "property")):
            if f.flags_byte & bit:
                result += " " + keyword
    return prefix + result


def funcdef_declaration(f: Function, param_names: Iterable[str] | None = None) -> str:
    # Scoped callbacks inherit sharing from their class; these modifiers are
    # accepted only for top-level funcdefs in source.
    prefix = "" if f.parent_class else (("external " if f.is_external else "") +
                                       ("shared " if f.is_shared else ""))
    return prefix + "funcdef " + function_signature(
        f, param_names, include_modifiers=False) + ";"


def class_header(c: TypeInfo) -> str:
    modifiers = []
    if c.is_external:
        modifiers.append("external")
    if c.is_shared:
        modifiers.append("shared")
    if not c.is_interface:
        if c.flags & (1 << 29):
            modifiers.append("abstract")
        if c.flags & (1 << 23):
            modifiers.append("final")
    modifiers += ["interface" if c.is_interface else "class", c.name]
    parents = ([c.derived_from] if c.derived_from else []) + list(c.interfaces)
    # Old parser output mixed child funcdefs into interfaces.  They are scoped
    # callback declarations, never inherited interfaces.
    bases = list(dict.fromkeys(p.format_name(c.namespace_) for p in parents
                               if p is not None and p.kind != "funcdef"))
    header = " ".join(modifiers)
    return header + (" : " + ", ".join(bases) if bases else "")


def namespace_block(source: str, namespace: str) -> str:
    """Wrap declarations in their saved namespace; qualified definitions are
    not a substitute for a namespace block in AngelScript source.
    """
    if not namespace:
        return source
    body = "\n".join("    " + line if line else "" for line in source.splitlines())
    return f"namespace {namespace} {{\n{body}\n}}"
