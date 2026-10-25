"""
bgt_project -- recover a BGT game as a browsable, compilable project.

    bgt recover game.exe -o recovered/

One command from a shipped executable to a tree of `.bgt` files with an entry
script that `#include`s them, a report of what was recovered, and -- where the
engine is installed -- the compiler's own verdict on the result.

## What the layout can and cannot claim

The original file *names* are not recoverable for a game's own code: they live
only in AngelScript's debug information and BGT always strips it (`bgt files`
explains what does survive). So the layout here is generated, and says so:

    recovered/
      game.bgt                  the entry script: plugin includes, then
                                #include for every file below, in order
      includes/
        types.bgt               enums, typedefs and funcdefs
        globals.bgt             every global, in declaration order
        dynamic_menu.bgt        a *library* file, named exactly: a run that
                                declares what a shipped include declares IS
                                that file
        classes/menu.bgt        one class per file, for the game's own classes
        functions/part_1.bgt    the game's own global functions, in segments
                                that follow the recovered file boundaries

Library files carry their real names because `script_files` identifies them by
what they declare, both ways, against BGT's shipped `include/*.bgt`. Everything
else is named by what it holds, which is honest and browsable, rather than by a
guessed filename.

## The one invariant that makes splitting safe

`#include` in BGT is textual, so a project is its files concatenated in include
order. This writer therefore partitions the single-file source **without
reordering it**, and then checks that: concatenating the emitted files in
include order reproduces the one-file render byte for byte (`verify`). A split
that reorders declarations can change global initialisation order, which is a
behaviour change that compiles perfectly.

## Plugins

A type the base engine never registered -- Psycho Strike's `elias` -- comes
from a BGT plugin, and the plugin include is part of the source. The DLL is
named in the game's own executable (`elias.dll` beside `elias @f()`), so the
entry script's `#include "elias.dll"` is recovered evidence rather than a
guess. A type that is neither the engine's nor the module's own and has no
matching DLL is reported as unexplained instead of being quietly dropped.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import zipfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:                      # installed as a package
    from . import (as_opcodes, bgt_api, bgt_asir, bgt_compile, bgtlib,
                   script_files)
    from .nvgt import decompile
except ImportError:       # run directly from a checkout
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "nvgt"))
    import as_opcodes
    import bgt_api
    import bgt_asir
    import bgt_compile
    import bgtlib
    import script_files
    import decompile

# DLLs every BGT game links against; a plugin is anything else.
SYSTEM_DLLS = {
    "advapi32.dll", "comdlg32.dll", "dinput8.dll", "dsound.dll", "gdi32.dll",
    "kernel32.dll", "oleaut32.dll", "ole32.dll", "saapi32.dll", "shell32.dll",
    "user32.dll", "winmm.dll", "ws2_32.dll", "nvdacontrollerclient32.dll",
    "msvcrt.dll", "msvcp60.dll", "version.dll", "imm32.dll", "wininet.dll",
}
DLL_RE = re.compile(rb"[A-Za-z0-9_\-]{2,40}\.dll")


@dataclass
class Section:
    """One emitted declaration, with where it came from and where it goes."""
    kind: str                      # types | globals | class | function
    name: str
    text: str
    origin: str = ""               # the library file it belongs to, if known
    path: str = ""                 # its published path in the project


@dataclass
class Project:
    name: str
    out_dir: str
    entry: str
    files: List[str] = field(default_factory=list)
    includes: List[str] = field(default_factory=list)
    plugins: List[str] = field(default_factory=list)
    newer_engine: List[str] = field(default_factory=list)
    sections: List[Section] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)
    problems: List[str] = field(default_factory=list)
    compile_report: Optional[bgt_compile.Report] = None

    def summary(self) -> str:
        s = self.stats
        lines = ["%-22s %s" % ("project", self.out_dir),
                 "%-22s %d" % ("files", len(self.files)),
                 "%-22s %d  (%d named from the library)"
                 % ("classes", s.get("classes", 0), s.get("library_classes", 0)),
                 "%-22s %d" % ("functions", s.get("functions", 0)),
                 "%-22s %d" % ("globals", s.get("globals", 0)),
                 "%-22s %d" % ("enums", s.get("enums", 0)),
                 "%-22s %d" % ("source lines", s.get("lines", 0)),
                 "%-22s %d" % ("unmodelled opcodes", s.get("passthrough", 0)),
                 "%-22s %d" % ("bodies that failed", s.get("body_errors", 0)),
                 "%-22s %d" % ("residual gotos", s.get("gotos", 0)),
                 "%-22s %s" % ("unbalanced files", s.get("unbalanced", 0)),
                 "%-22s %s" % ("dangling else", s.get("dangling_else", 0)),
                 "%-22s %s" % ("split verified", "yes" if s.get("verified") else "NO")]
        if self.plugins:
            lines.append("%-22s %s  (types a stock engine lacks)"
                         % ("plugin needed", ", ".join(self.plugins)))
        if self.newer_engine:
            lines.append("%-22s %s" % ("needs a newer engine",
                                       ", ".join(self.newer_engine[:6])))
        if self.compile_report is not None:
            lines.append("%-22s %s" % ("compiler", self.compile_report.summary()))
        for problem in self.problems:
            lines.append("  ! %s" % problem)
        return "\n".join(lines)


class _Splitter(decompile.ModuleDecompiler):
    """Renders exactly as the one-file decompiler does, keeping the pieces.

    Every declaration is captured where the base class would have emitted it,
    so the sections in order ARE the single-file source. Nothing is reordered
    here; the file each one lands in is decided afterwards.
    """

    def __init__(self, module):
        super().__init__(module)
        self.sections: List[Section] = []

    def _capture(self, kind: str, name: str, render) -> None:
        start = len(self.lines)
        render()
        text = "\n".join(self.lines[start:]).strip("\n")
        del self.lines[start:]
        if text.strip():
            self.sections.append(Section(kind=kind, name=name, text=text + "\n"))

    def _render_class(self, c):
        self._capture("class", c.format_name(),
                      lambda: super(_Splitter, self)._render_class(c))

    def _render_globals(self):
        self._capture("globals", "globals",
                      lambda: super(_Splitter, self)._render_globals())

    def _render_function(self, f):
        self._capture("function", f.name,
                      lambda: super(_Splitter, self)._render_function(f))

    def render(self) -> str:
        super().render()
        # Whatever the base class emitted outside a captured declaration --
        # the header comment, the enums, typedefs and funcdefs -- is the
        # remainder, and it leads, because everything else may use it. The
        # base class's own return value is only that remainder here, since
        # each capture took its lines out, so the source is the sections.
        remainder = "\n".join(self.lines).strip("\n")
        if remainder.strip():
            self.sections.insert(0, Section(kind="types", name="types",
                                            text=remainder + "\n"))
        return "\n".join(section.text for section in self.sections)


def plugin_dlls(exe_path: str, type_names: Sequence[str]) -> List[str]:
    """DLLs the executable names that look like plugins providing a used type.

    BGT links a plugin's registration into the built executable and loads the
    DLL at run time, so a game using Elias carries both `elias.dll` and the
    registered `elias @f()`. Matching the DLL's stem against a type the module
    uses is what makes this evidence rather than a list of every DLL present.
    """
    with open(exe_path, "rb") as fh:
        blob = fh.read()
    wanted = {name.lower() for name in type_names}
    found: List[str] = []
    for match in DLL_RE.finditer(blob):
        dll = match.group().decode("latin1")
        if dll.lower() in SYSTEM_DLLS or dll in found:
            continue
        if os.path.splitext(dll)[0].lower() in wanted:
            found.append(dll)
    return found


def engine_gap(exe_path: str, used: Sequence[str],
               compiler: Optional[str] = None) -> List[Tuple[str, str]]:
    """Types the module uses that the *installed* engine does not have.

    A recovered module is faithful to the build that produced it, and that
    build is not necessarily the one installed here. Psycho Strike's `elias`
    comes from a plugin DLL; Manamon 2 uses `weakref` and `protected`, and
    both appear in its own `rpg.exe` and in neither BGT 1.0 nor 1.3. Those are
    the engine's age, not the recovery's, and saying so is the difference
    between a report and a mystery.

    The test is the one piece of evidence available: the name appears in the
    game's own executable -- so its runtime registered it -- and not in the
    installed compiler.
    """
    exe = bgt_compile.find_compiler(compiler)
    if exe is None:
        return []
    names = [name for name in dict.fromkeys(used)
             if len(name) >= 3 and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name)
             # The engine's own placeholders are not types anyone is missing.
             and not name.startswith("$") and name != "_builtin_function_"]

    # The engine's own documentation is a list of what it has, where searching
    # its binary for a name is a guess. Fall back to the guess only when the
    # help file cannot be read.
    try:
        api = bgt_api.read()
        absent = set(bgt_api.missing(names, api))
    except (RuntimeError, OSError):
        absent = None

    with open(exe_path, "rb") as fh:
        game = fh.read()
    if absent is None:
        with open(exe, "rb") as fh:
            engine = fh.read()
        runtime = os.path.join(os.path.dirname(exe), "exec.bin")
        if os.path.isfile(runtime):
            with open(runtime, "rb") as fh:
                engine += fh.read()
        absent = {name for name in names
                  if name.encode("latin1") not in engine}

    # Either way, it only counts when the game's own executable has it: that
    # is what says the build it came from provided it.
    return [(name, os.path.basename(exe_path)) for name in names
            if name in absent and name.encode("latin1") in game]


def method_gap(exe_path: str, module, compiler: Optional[str] = None
               ) -> List[Tuple[str, str]]:
    """Methods of engine types that the *installed* engine does not have.

    `engine_gap` answers this for types, which is where the difference
    usually shows. It can also be one method of a type the engine does have:
    Psycho Strike calls `tts_voice::speak_to_sound`, which returns the
    generated speech as a `sound@`. BGT 1.3 documents `speak`,
    `speak_interrupt`, `speak_interrupt_wait`, `speak_to_file` and
    `speak_wait`, and not that one -- and `speak_to_sound` appears in the
    game's own `strike.exe` and in neither `bgt.exe` nor `exec.bin`. So that
    build had it and this one does not, which is the same finding as
    `weakref`, one level down.

    Needs the documentation, because a *list* of a type's methods is what
    makes an absence provable; a binary search for a short name is not.
    """
    exe = bgt_compile.find_compiler(compiler)
    if exe is None:
        return []
    try:
        api = bgt_api.read()
    except (RuntimeError, OSError):
        return []
    types = api["types"]                      # type: ignore[index]

    declared = {ti.name for ti in module.classes if ti}
    with open(exe_path, "rb") as fh:
        game = fh.read()
    with open(exe, "rb") as fh:
        engine = fh.read()
    runtime = os.path.join(os.path.dirname(exe), "exec.bin")
    if os.path.isfile(runtime):
        with open(runtime, "rb") as fh:
            engine += fh.read()

    gap: List[Tuple[str, str]] = []
    for f in module.used_functions:
        owner = f.object_type if f is not None else None
        if owner is None or owner.name in declared or owner.name not in types:
            continue
        method = f.name.split("::")[-1]
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", method) or len(method) < 3:
            continue
        documented = types[owner.name]["methods"] + types[owner.name]["properties"]
        if any(re.search(r"%s" % re.escape(method), line) for line in documented):
            continue
        name = "%s::%s" % (owner.name, method)
        if name in [existing for existing, _ in gap]:
            continue
        # The same corroboration as for a type: the build that produced this
        # module registered it, and the installed one does not.
        if (method.encode("latin1") in game
                and method.encode("latin1") not in engine):
            gap.append((name, os.path.basename(exe_path)))
    return gap


def _library(include_dirs: Optional[Sequence[str]]):
    dirs = list(include_dirs) if include_dirs else []
    if not dirs:
        for candidate in (r"C:\Program Files (x86)\BGT\include",
                          r"C:\Program Files\BGT\include"):
            if os.path.isdir(candidate):
                dirs.append(candidate)
    return script_files.library_index(dirs, extensions=("*.bgt",)) if dirs else []


def _origins(module_path: str, exe_path: str,
             include_dirs: Optional[Sequence[str]] = None
             ) -> Tuple[Dict[str, str], List[str]]:
    """Which library file each class and function belongs to, where known."""
    library = _library(include_dirs)
    if not library:
        return {}, ["no BGT include folder found: library files are unnamed"]
    entities, _ = script_files.load_entities(module_path, exe_path, nvgt=False)
    attribution = script_files.attribute(entities, library)
    # The runs carry the declarations; `file_order`'s segments carry the order
    # and the notes, and are consulted only for problems here.
    origins: Dict[str, str] = {}
    for owner, run in attribution.runs():
        if not owner:                       # a run of the game's own code
            continue
        for entity in run:
            origins[entity.name] = owner
    _, problems = script_files.file_order(attribution, library)
    return origins, problems


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", name).strip("_") or "unnamed"


def assign_paths(sections: List[Section], origins: Dict[str, str],
                 functions_per_file: int = 40) -> None:
    """Give every section its file, keeping the emitted order intact.

    A library file keeps its real name and collects everything attributed to
    it. A class of the game's own gets a file to itself -- the original
    grouping is not recoverable, and one class per file is the layout that
    stays readable. The game's own functions are cut into parts along the
    recovered file boundaries, so a part is never a mixture of two files.
    """
    part = 0
    in_part = 0
    previous_origin: Optional[str] = None
    for section in sections:
        origin = origins.get(section.name, "")
        section.origin = origin
        if section.kind == "types":
            section.path = "includes/types.bgt"
        elif section.kind == "globals":
            section.path = "includes/globals.bgt"
        elif origin:
            section.path = "includes/" + origin
        elif section.kind == "class":
            section.path = "includes/classes/%s.bgt" % _safe(section.name)
        else:
            # A change of origin is a real file boundary, so start a new part
            # there as well as every `functions_per_file`.
            if previous_origin != origin or in_part >= functions_per_file:
                part += 1
                in_part = 0
            in_part += 1
            section.path = "includes/functions/part_%d.bgt" % part
        previous_origin = origin


STRING_LITERAL = re.compile(r'"(?:\\.|[^"\\])*"')


def unbalanced(sections: List["Section"]) -> List[Tuple[str, int]]:
    """Emitted files whose braces do not balance, with the running total.

    An unbalanced file cannot parse at all, and the compiler says so somewhere
    else entirely: a `}` too many closes the class, and every declaration
    after it is reported as "Expected method or property" -- which reads
    exactly like the engine missing a keyword. That is how Manamon 2's
    `cure_all_statuses` hid. The structurer gave up on a branch and emitted a
    `goto`, then emitted the arm anyway:

        local_1 = 0;
        goto L003b;
        } else {                      <- no `if` was ever opened

    So the balance is checked rather than assumed. String literals are masked
    first, because a brace inside one is text, not structure.
    """
    out: List[Tuple[str, int]] = []
    totals: Dict[str, int] = {}
    for section in sections:
        masked = STRING_LITERAL.sub('""', section.text)
        totals[section.path] = (totals.get(section.path, 0)
                                + masked.count("{") - masked.count("}"))
    for path, depth in totals.items():
        if depth:
            out.append((path, depth))
    return out


def dangling_else(sections: List["Section"]) -> List[Tuple[str, str]]:
    """`else` arms with no `if` above them.

    `unbalanced` is what *detects* the damage; this says what it is. The
    structurer gives up on a branch, emits a `goto`, and emits the arm
    anyway, so the arm's closing brace has no opener. Manamon 2's
    `cure_all_statuses` reads

        local_1 = 0;
        goto L003b;
        } else {                   <- the `if` became the `goto`

    and the compiler blames a declaration hundreds of lines later with
    "Expected method or property", which is exactly what the engine's own
    missing keywords report too. That is how it stayed hidden -- and why the
    two causes are now told apart by the brace count: Manamon 2's three
    broken files are -2, -10 and -1 deep, while `item.bgt`, which fails only
    on `protected`, balances at zero.

    A block stack per file, keyed on each opener's first word: an `else` is
    sound only when the `}` just above it closed an `if` or an `else`.
    """
    bad: List[Tuple[str, str]] = []
    stacks: Dict[str, List[str]] = {}
    pending: Dict[str, Optional[str]] = {}
    for section in sections:
        stack = stacks.setdefault(section.path, [])
        for raw in STRING_LITERAL.sub('""', section.text).splitlines():
            line = raw.strip()
            if not line or line.startswith("//"):
                continue
            closed = pending.pop(section.path, None)
            rest = line
            while rest.startswith("}"):
                closed = stack.pop() if stack else None
                rest = rest[1:].strip()
            word = re.match(r"[A-Za-z_]\w*", rest)
            word = word.group(0) if word else ""
            if word == "else" and closed not in ("if", "else"):
                bad.append((section.path, line))
            if line.endswith("{"):
                stack.append(word or "block")
            elif closed is not None and not rest:
                # A bare `}` on its own line: remember what it closed, so an
                # `else {` written on the NEXT line still sees it.
                pending[section.path] = closed
    return bad


def verify(sections: List[Section], order: List[str], source: str) -> bool:
    """Do the emitted files, concatenated in include order, say the same thing?

    Compared on non-blank lines: the writer adds a header and blank lines
    between files, and neither changes a declaration. Anything else differing
    means a declaration moved, which can change global initialisation order.
    """
    by_path: Dict[str, List[str]] = {}
    for section in sections:
        by_path.setdefault(section.path, []).append(section.text)
    rebuilt = "\n".join("\n".join(by_path[path]) for path in order if path in by_path)
    strip = lambda text: [l.rstrip() for l in text.splitlines() if l.strip()]
    return strip(rebuilt) == strip(source)


def recover(exe_path: str, out_dir: str, include_dirs: Optional[Sequence[str]] = None,
            make_zip: bool = True, compile_check: bool = False,
            timeout: float = 600.0, progress=lambda message: None) -> Project:
    name = os.path.splitext(os.path.basename(exe_path))[0]
    os.makedirs(out_dir, exist_ok=True)

    progress("unpacking %s" % os.path.basename(exe_path))
    unpacked = bgtlib.unpack_file(exe_path)
    module_path = os.path.join(out_dir, "%s_bytecode.bin" % name)
    with open(module_path, "wb") as fh:
        fh.write(unpacked.bytecode)

    progress("reading the opcode table and the module")
    opcodes = as_opcodes.extract(exe_path)["table"]
    module = bgt_asir.load(module_path, opcodes=opcodes)

    progress("decompiling")
    splitter = _Splitter(module)
    source = splitter.render()
    sections = splitter.sections

    progress("recovering the file structure")
    origins, problems = _origins(module_path, exe_path, include_dirs)
    assign_paths(sections, origins)

    # Types the module uses that neither the engine nor the module declares
    # come from a plugin; the executable names the DLL.
    declared = {ti.name for ti in module.classes} | {ti.name for ti in module.enums}
    used = [ti.name for ti in module.used_types if ti and ti.name not in declared]
    plugins = plugin_dlls(exe_path, used)
    # ...and types the installed engine simply does not have, plugin or not.
    newer = [name for name, _ in engine_gap(exe_path, used)
             if not any(os.path.splitext(dll)[0].lower() == name.lower()
                        for dll in plugins)]
    # ...and one method of a type it does have, which is the same finding one
    # level down.
    newer += [name for name, _ in method_gap(exe_path, module)]

    order: List[str] = []
    for section in sections:
        if section.path not in order:
            order.append(section.path)

    project = Project(name=name, out_dir=out_dir, entry=name + ".bgt",
                      files=[], includes=order, plugins=plugins,
                      newer_engine=newer, sections=sections,
                      problems=list(problems))

    progress("writing %d files" % (len(order) + 1))
    by_path: Dict[str, List[Section]] = {}
    for section in sections:
        by_path.setdefault(section.path, []).append(section)
    for path, group in by_path.items():
        target = os.path.join(out_dir, path.replace("/", os.sep))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        header = ["// %s" % path,
                  "// Recovered from %s. Original file names are not recoverable"
                  % os.path.basename(exe_path),
                  "// for a game's own code (BGT strips debug information);"]
        if group[0].origin:
            header = ["// %s" % path,
                      "// Recovered from %s. This run declares exactly what BGT's"
                      % os.path.basename(exe_path),
                      "// shipped %s declares, so that is its name." % group[0].origin]
        else:
            header.append("// this file is named for what it holds.")
        with open(target, "w", encoding="utf-8") as fh:
            fh.write("\n".join(header) + "\n\n")
            fh.write("\n".join(section.text for section in group))
        project.files.append(path)

    entry_lines = ["// %s -- entry script for the recovered project." % project.entry,
                   "// Generated by `bgt recover` from %s." % os.path.basename(exe_path),
                   "// `#include` is textual in BGT, so these files in this order",
                   "// are the module the game shipped.", ""]
    if newer:
        entry_lines.append("// This module uses %s, which the installed engine"
                           % ", ".join(newer[:6]))
        entry_lines.append("// does not have and %s does: it was built with a"
                           % os.path.basename(exe_path))
        entry_lines.append("// newer BGT than the one here.")
        entry_lines.append("")
    if plugins:
        # NOT an include: this engine's `#include` takes a script or a pack
        # file, and handed a DLL it reports "Expected identifier". The types
        # the DLL registers are simply absent from a stock build -- the
        # executable that shipped had them compiled in -- so the honest thing
        # is to name what is missing and where it came from.
        entry_lines.append("// This module uses types a stock engine does not")
        entry_lines.append("// provide. They are registered by %s,"
                           % ", ".join(plugins))
        entry_lines.append("// which ships beside the game executable and is")
        entry_lines.append("// copied into this project. Compiling here needs")
        entry_lines.append("// the engine build that has it.")
        entry_lines.append("")
    entry_lines += ['#include "%s"' % path for path in order]
    entry_lines.append("")
    entry_path = os.path.join(out_dir, project.entry)
    with open(entry_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(entry_lines))
    project.files.insert(0, project.entry)

    lines = source.splitlines()
    project.stats = {
        "classes": sum(1 for s in sections if s.kind == "class"),
        "library_classes": sum(1 for s in sections if s.kind == "class" and s.origin),
        "functions": sum(1 for s in sections if s.kind == "function"),
        "globals": len(module.globals),
        "enums": len(module.enums),
        "lines": len(lines),
        "passthrough": source.count("/* OPCODE"),
        "body_errors": source.count("decompiler error"),
        "gotos": sum(1 for l in lines if l.strip().startswith("goto ")),
        "bodies": sum(1 for f in module.saved_functions if f.bytecode),
        "verified": verify(sections, order, source),
        "unbalanced": len(unbalanced(sections)),
        "dangling_else": len(dangling_else(sections)),
    }
    for path, line in dangling_else(sections)[:5]:
        project.problems.append(
            "%s has an `else` with no `if`: `%s` -- the structurer gave up on "
            "a branch and emitted the arm anyway, and the file cannot parse"
            % (path, line))
    for path, depth in unbalanced(sections):
        project.problems.append(
            "%s does not balance its braces (%+d): it cannot parse, and the "
            "compiler will blame the next declaration instead" % (path, depth))
    if not project.stats["verified"]:
        project.problems.append(
            "the files do not concatenate back to the one-file source: "
            "a declaration moved, which can change global initialisation order")

    if make_zip:
        archive = os.path.join(out_dir, name + "_project.zip")
        progress("writing %s" % os.path.basename(archive))
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in project.files:
                zf.write(os.path.join(out_dir, path.replace("/", os.sep)), path)
        with zipfile.ZipFile(archive) as zf:
            bad = zf.testzip()
            if bad is not None:
                project.problems.append("the archive is corrupt at %s" % bad)
            elif len(zf.namelist()) != len(project.files):
                project.problems.append("the archive holds %d of %d files"
                                        % (len(zf.namelist()), len(project.files)))
        project.stats["zip"] = archive
        project.stats["zip_entries"] = len(project.files)

    # A plugin include needs the DLL itself to compile. It ships with the game,
    # so it is beside the executable; copying it in is what makes the recovered
    # project build on its own, and a missing one is reported rather than left
    # to show up as "elias is not a data type".
    for dll in plugins:
        source_dll = os.path.join(os.path.dirname(os.path.abspath(exe_path)), dll)
        if os.path.isfile(source_dll):
            with open(source_dll, "rb") as src, \
                    open(os.path.join(out_dir, dll), "wb") as dst:
                dst.write(src.read())
            project.files.append(dll)
        else:
            project.problems.append(
                "%s is included but not beside the executable: copy it in, or "
                "the types it registers have no declaration" % dll)

    if compile_check:
        progress("compiling the project with BGT's own compiler")
        check_dir = os.path.join(out_dir, "_compile_check")
        target = bgt_compile.neutered(entry_path, check_dir)
        # The entry copy still has to reach the real files.
        with open(target, "r", encoding="utf-8") as fh:
            text = fh.read()
        text = text.replace('#include "includes/', '#include "../includes/')
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(text)
        project.compile_report = bgt_compile.check(target, timeout=timeout)

    with open(os.path.join(out_dir, "recovery.json"), "w", encoding="utf-8") as fh:
        json.dump({"executable": exe_path, "entry": project.entry,
                   "files": project.files, "includes": order,
                   "plugins": plugins, "newer_engine": newer,
                   "stats": project.stats,
                   "problems": project.problems,
                   "origins": {s.name: s.origin for s in sections if s.origin},
                   "compile": (None if project.compile_report is None else
                               {"outcome": project.compile_report.outcome,
                                "errors": [d.__dict__ for d in
                                           project.compile_report.errors]})},
                  fh, indent=1)
    return project


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="bgt recover",
                                 description=__doc__.split("\n\n")[1],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("exe", help="the BGT executable to recover")
    ap.add_argument("-o", "--output", required=True, help="the project directory")
    ap.add_argument("--include", action="append",
                    help="a BGT include folder, for naming library files")
    ap.add_argument("--no-zip", action="store_true")
    ap.add_argument("--compile", action="store_true",
                    help="compile the result with BGT's own compiler and report")
    ap.add_argument("--timeout", type=float, default=600.0)
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args(argv)

    project = recover(args.exe, args.output, args.include,
                      make_zip=not args.no_zip, compile_check=args.compile,
                      timeout=args.timeout,
                      progress=(lambda m: None) if args.quiet
                      else (lambda m: print("  %s" % m, flush=True)))
    print(project.summary())
    if project.compile_report is not None and not project.compile_report.ok:
        for diagnostic in project.compile_report.errors[:20]:
            print(diagnostic)
    return 0


if __name__ == "__main__":
    sys.exit(main())
