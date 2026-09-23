"""Conservative, optional reuse of installed NVGT include sources.

Compile a fresh debug reference containing only the requested includes and an
empty main, then compare every declaration against the target module. A name
match is never sufficient. Reuse is all-or-nothing: a changed library function,
class layout, global initializer, enum or callback signature rejects the plan.
Unmatched target declarations are retained for ordinary decompilation.

This does not recover original application source or stripped identifiers.
"""
from __future__ import annotations

import argparse
import bisect
import copy
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import subprocess
import zipfile

try:                      # installed as a package
    from .asreader import Function, Module
    from .decompile import decompile_module, load_any
except ImportError:       # run directly from a checkout
    from asreader import Function, Module
    from decompile import decompile_module, load_any


def type_key(t):
    if t is None:
        return None
    return (t.namespace_, t.name, t.kind, t.template_typename)


def datatype_key(t):
    return (t.token_type, type_key(t.obj_type), t.is_object_handle,
            t.is_handle_to_const, t.is_reference, t.is_readonly,
            tuple(datatype_key(s) for s in t.template_subtypes))


def function_key(f):
    return (f.namespace_, type_key(f.object_type), f.name,
            datatype_key(f.return_type), tuple(map(datatype_key, f.param_types)),
            tuple(f.in_out_flags), f.flags_byte, type_key(f.parent_class))


def normalized_function(f: Function):
    """Exclude debug metadata and table indices, preserving executable data.

    Debug compilation adds SUSPEND instructions. Jump and exception positions
    are mapped to the next executable instruction before comparison. Unknown
    operands stay raw, deliberately preferring false negatives to false matches.
    """
    code = [i for i in f.bytecode if i.name != "SUSPEND"]
    positions = [i.pos for i in code]
    pos_key = lambda p: bisect.bisect_left(positions, p)
    instructions = []
    for i in code:
        w, w2, dw, qw = i.w_arg, i.w_arg2, i.dw_arg, i.qw_arg
        if i.jump_target is not None:
            dw = ("jump", pos_key(i.jump_target))
        if i.func_ref is not None:
            target = ("function", function_key(i.func_ref))
            if i.name == "FuncPtr":
                qw = target
            else:
                dw = target
        if i.type_ref is not None:
            target = ("type", type_key(i.type_ref))
            if i.name in ("ALLOC", "FREE", "REFCPY", "RefCpyV", "OBJTYPE"):
                qw = target
            elif i.name == "TYPEID":
                dw = target
        if i.data_type is not None:
            target = ("datatype", datatype_key(i.data_type))
            if i.name in ("TYPEID", "Cast", "LoadThisR", "LoadRObjR", "LoadVObjR",
                          "ADDSi", "ADDProp"):
                # These carry the property's type as a usedTypeIds index in
                # dw_arg. Raw, it differs between two builds of the same source
                # (different type tables) and rejected every class with a
                # this-property load or member access -- almost all of them.
                dw = target
            elif i.name == "SetListType":
                qw = target
        if i.prop_name is not None:
            if i.name in ("LoadRObjR", "LoadVObjR"):
                w2 = ("property", i.prop_name)
            else:
                w = ("property", i.prop_name)
        if i.global_name is not None:
            qw = ("global", i.global_name)
        if i.string_const is not None:
            if i.name == "STR":
                dw = ("string", i.string_const)
            else:
                qw = ("string", i.string_const)
        instructions.append((i.name, w, w2, dw, qw))
    return (function_key(f), f.variable_space,
            tuple((v.stack_offset, v.on_heap, datatype_key(v.type))
                  for v in f.variables), tuple(instructions),
            tuple((pos_key(p), off, opt) for p, off, opt in f.obj_variable_info),
            tuple((pos_key(p), pos_key(c), st) for p, c, st in f.try_catch_info))


def _class_key(c):
    return type_key(c)


def _class_value(c):
    # Virtual stubs and full VFT functions both matter; sort by repr because
    # tuple fields may contain optional values.
    functions = c.methods + c.constructors + c.factories + c.vft
    if c.destructor:
        functions += [c.destructor]
    return (c.flags, c.size, c.is_interface, c.is_shared, c.is_external,
            type_key(c.derived_from), tuple(map(type_key, c.interfaces)),
            tuple((n, datatype_key(t), flags) for n, t, flags in c.properties),
            tuple(sorted((normalized_function(f) for f in functions), key=repr)))


def _global_key(g):
    return (g.namespace_, g.name)


def _global_value(g):
    return (datatype_key(g.type),
            normalized_function(g.init_func) if g.init_func else None)


def _type_value(t):
    return (t.flags, tuple(t.enum_values), t.enum_underlying,
            datatype_key(t.typedef_target) if t.typedef_target else None)


_ENTITY_FIELDS = {
    "classes": (_class_key, _class_value),
    "globals": (_global_key, _global_value),
    "enums": (type_key, _type_value),
    "typedefs": (type_key, _type_value),
    "funcdefs": (function_key, function_key),
    "script_functions": (function_key, normalized_function),
    "global_functions": (function_key, normalized_function),
}


@dataclass
class ReusePlan:
    includes: list[str]
    include_root: str
    matched: dict[str, set] = field(default_factory=dict)
    conflicts: list[str] = field(default_factory=list)
    source_hashes: dict[str, str] = field(default_factory=dict)

    @property
    def safe_to_reuse(self):
        return bool(self.source_hashes) and not self.conflicts

    def report(self):
        return {"safe_to_reuse": self.safe_to_reuse,
                "includes": self.includes, "include_root": self.include_root,
                "matched_counts": {k: len(v) for k, v in self.matched.items()},
                "conflicts": self.conflicts, "source_sha256": self.source_hashes}


def plan_reuse(target: Module, reference: Module, includes, include_root,
               source_hashes=None, reference_root_sections=()):
    """Compare a library-only reference, ignoring its empty harness main.

    source_hashes must come from compile_reference() or an equivalent source
    snapshot made around compilation. Passing an old debug module and hashes
    collected later does not establish source provenance.
    """
    root_sections = {str(Path(p).resolve()).casefold()
                     for p in reference_root_sections}
    plan = ReusePlan(list(includes), str(Path(include_root).resolve()),
                     source_hashes=dict(source_hashes or {}))
    if not reference.debug_info:
        plan.conflicts.append("Reference must retain debug section metadata")
    for field, (key, value) in _ENTITY_FIELDS.items():
        original = {}
        for entity in getattr(target, field):
            original.setdefault(key(entity), []).append(entity)
        matched = plan.matched[field] = set()
        for entity in getattr(reference, field):
            if isinstance(entity, Function):
                section = str(Path(entity.script_section).resolve()).casefold()
                if section in root_sections:
                    continue
            candidates = original.get(key(entity), [])
            if not candidates:
                plan.conflicts.append(f"{field}: missing {getattr(entity, 'name', key(entity))}")
            elif any(value(c) != value(entity) for c in candidates):
                plan.conflicts.append(f"{field}: changed {getattr(entity, 'name', key(entity))}")
            else:
                matched.add(key(entity))
    return plan


def render_reused(target: Module, plan: ReusePlan, comments=False):
    """Use verified includes, retaining every unmatched original declaration."""
    if not plan.safe_to_reuse:
        raise ValueError("Library reuse rejected: " + "; ".join(plan.conflicts or
                         ["source provenance was not verified"]))
    for path, expected in plan.source_hashes.items():
        if hashlib.sha256(Path(path).read_bytes()).hexdigest() != expected:
            raise ValueError(f"Include changed since reference compilation: {path}")
    module = copy.copy(target)
    for field, (key, _) in _ENTITY_FIELDS.items():
        setattr(module, field, [e for e in getattr(target, field)
                               if key(e) not in plan.matched[field]])
    # Keep the full module's call/type tables; only declaration lists are filtered.
    prefix = "// Standard library sources verified against target bytecode.\n"
    prefix += "\n".join(f'#include "{Path(plan.include_root, inc).as_posix()}"'
                         for inc in plan.includes) + "\n\n"
    source = decompile_module(module, comments)
    # Plugin words must be defined before preprocessing include files.
    lines = source.splitlines(keepends=True)
    split = 0
    while split < len(lines) and (lines[split].startswith("#pragma ") or not lines[split].strip()):
        split += 1
    return "".join(lines[:split]) + prefix + "".join(lines[split:])


def detect_includes(target: Module, include_root) -> list[str]:
    """The shipped library files this module was built with, by name.

    Reuses script_files' attribution -- a declaration match, not just a name --
    so a game's own class that happens to share a library name is not offered
    for reuse. Only the top-level includes are returned; each pulls its own
    sub-includes when the reference is compiled, and plan_reuse confirms every
    declaration by bytecode regardless of nesting. The names are what a game's
    own code would `#include`, so a game that shipped an edited copy still
    surfaces here and is then rejected by the exact-bytecode check, not hidden.
    """
    try:                      # installed as a package
        from .. import script_files
    except ImportError:       # run directly from a checkout
        try:
            import script_files
        except ImportError:   # only tools/nvgt on the path (nvgt test context)
            import sys as _sys
            _sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
            import script_files
    library = script_files.library_index([str(include_root)], ("*.nvgt",))
    entities = script_files.nvgt_entities(target)
    attribution = script_files.attribute(entities, library)
    return script_files.top_level_includes(attribution, library)


def compile_reference(compiler, includes, include_root, build_dir, nvgt_info=None,
                      reference_mode="packaged"):
    """Compile a fresh, isolated include-only probe and capture source hashes."""
    include_root = Path(include_root).resolve()
    build_dir = Path(build_dir).resolve()
    build_dir.mkdir(parents=True, exist_ok=True)
    for include in includes:
        path = (include_root / include).resolve()
        if not path.is_relative_to(include_root) or not path.is_file():
            raise ValueError(f"Include must exist inside include root: {include}")
    # Snapshot all include sources because conditional/transitive includes are
    # resolved by NVGT, not by a partial preprocessor in this recovery tool.
    before = {str(p.resolve()): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in include_root.rglob("*.nvgt")}
    source = build_dir / "library_probe.nvgt"
    bytecode = source.with_suffix(".bin")
    if reference_mode not in ("runtime", "packaged"):
        raise ValueError("Unknown reference mode")
    # Never accept artifacts left by an earlier compiler invocation.
    for suffix in (".bin", ".exe", ".zip"):
        source.with_suffix(suffix).unlink(missing_ok=True)
    body = "void main() {}\n"
    if reference_mode == "runtime":
        body = ("void main() {\n    file_put_contents(" + json.dumps(bytecode.as_posix())
                + ', script_get_module("nvgt_game", 0).get_bytecode(false));\n}\n')
        bytecode.unlink(missing_ok=True)
    pragmas = []
    if nvgt_info is not None:
        pragmas += [f"#pragma plugin {name}" for name in nvgt_info.plugins]
        pragmas += [f"#pragma namespace {system} {ns}" for system, ns in nvgt_info.namespaces]
    source.write_text("\n".join(pragmas) + "\n" + "\n".join(
        f'#include "{(include_root / inc).as_posix()}"' for inc in includes
    ) + "\n" + body, encoding="utf-8")
    temp_dir = build_dir / "temp"
    temp_dir.mkdir(exist_ok=True)
    env = dict(os.environ, TEMP=str(temp_dir), TMP=str(temp_dir))
    command = [str(compiler), str(source)] if reference_mode == "runtime" else [str(compiler), "--compile-debug", str(source)]
    result = subprocess.run(command,
                            cwd=build_dir, capture_output=True, text=True,
                            timeout=90, env=env)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    if reference_mode == "runtime":
        if not bytecode.exists() or not bytecode.stat().st_size:
            raise RuntimeError("Reference execution produced no bytecode: " + result.stdout + result.stderr)
        reference = load_any(str(bytecode))
        after = {str(p.resolve()): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in include_root.rglob("*.nvgt")}
        if before != after:
            raise RuntimeError("Include sources changed during reference compilation")
        return reference, before, source
    executable = source.with_suffix(".exe")
    archive = source.with_suffix(".zip")
    if archive.exists():
        # Extract only the specifically expected executable into our own path.
        with zipfile.ZipFile(archive) as package:
            executable.write_bytes(package.read(executable.name))
    if not executable.exists():
        raise RuntimeError("Compiler did not produce the expected probe executable")
    reference = load_any(str(executable))
    after = {str(p.resolve()): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in include_root.rglob("*.nvgt")}
    if before != after:
        raise RuntimeError("Include sources changed during reference compilation")
    hashes = {}
    # Hash all source files, including files providing only enums or typedefs.
    for path, digest in before.items():
        if hashlib.sha256(Path(path).read_bytes()).hexdigest() != digest:
            raise RuntimeError(f"Include changed during reference compilation: {path}")
        hashes[path] = digest
    return reference, hashes, source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target")
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--include-root", required=True)
    parser.add_argument("--include", action="append",
                        help="a library file to try reusing; repeatable. Omit "
                             "to auto-detect from the target (see --auto)")
    parser.add_argument("--auto", action="store_true",
                        help="detect the includes from the target with bgt files "
                             "(the default when no --include is given)")
    parser.add_argument("--build-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--bundle", action="store_true",
                        help="Copy verified include sources beside the output")
    parser.add_argument("--reference-mode", choices=("packaged", "runtime"), default="packaged",
                        help="runtime exports bytecode from an owned include-only harness; works with randomized CI encryption")
    args = parser.parse_args()
    target = load_any(args.target)
    includes = args.include
    if not includes or args.auto:
        detected = detect_includes(target, args.include_root)
        includes = sorted(set((includes or []) + detected))
        print("auto-detected includes: %s" % (", ".join(includes) or "(none)"))
        if not includes:
            raise SystemExit("No shipped library file was detected in the target; "
                             "pass --include explicitly if you know one")
    reference, hashes, harness = compile_reference(
        args.compiler, includes, args.include_root, args.build_dir,
        getattr(target, "nvgt_info", None), args.reference_mode)
    plan = plan_reuse(target, reference, includes, args.include_root,
                      hashes, [harness])
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.with_suffix(".reuse.json").write_text(
        json.dumps(plan.report(), indent=2), encoding="utf-8")
    if not plan.safe_to_reuse:
        raise SystemExit("Library reuse rejected; inspect the .reuse.json report")
    source = render_reused(target, plan)
    if args.bundle:
        root = Path(plan.include_root).resolve()
        bundled_hashes = {}
        for path, digest in plan.source_hashes.items():
            original = Path(path).resolve()
            relative = original.relative_to(root)
            data = original.read_bytes()
            if hashlib.sha256(data).hexdigest() != digest:
                raise RuntimeError(f"Include changed before bundling: {path}")
            destination = output.parent / "include" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            bundled_hashes[(Path("include") / relative).as_posix()] = digest
        for inc in plan.includes:
            source = source.replace((root / inc).as_posix(),
                                    (Path("include") / inc).as_posix())
        report = plan.report()
        report["bundled_source_sha256"] = bundled_hashes
        report["target_sha256"] = hashlib.sha256(Path(args.target).read_bytes()).hexdigest()
        output.with_suffix(".reuse.json").write_text(
            json.dumps(report, indent=2), encoding="utf-8")
    output.write_text(source, encoding="utf-8")
    print(json.dumps(plan.report()["matched_counts"], indent=2))


if __name__ == "__main__":
    main()
