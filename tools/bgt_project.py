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
import shutil
import sys
import zipfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:                      # installed as a package
    from . import (as_opcodes, bgt_api, bgt_apicheck, bgt_asir,
                   bgt_compile, bgt_crack, bgt_kdf, bgt_libcheck,
                   bgt_pack, bgtlib, script_files)
    from .nvgt import decompile
except ImportError:       # run directly from a checkout
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "nvgt"))
    import as_opcodes
    import bgt_api
    import bgt_apicheck
    import bgt_asir
    import bgt_compile
    import bgt_crack
    import bgt_kdf
    import bgt_libcheck
    import bgt_pack
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
    #: what was done with the asset packs -- an action, not a complaint
    data: List[str] = field(default_factory=list)
    #: which library files came from the engine rather than the module
    stock: List[str] = field(default_factory=list)
    #: the screen-reader client DLLs brought in, and why
    speech: List[str] = field(default_factory=list)
    #: DLLs the script loads itself with `library::load`, and why
    loaded: List[str] = field(default_factory=list)
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
        if s.get("calls_checked") is not None:
            # The one check that needs no BGT at all, and the only one a
            # title the compiler refuses to parse ever gets.
            lines.append("%-22s %d against this build's own declarations"
                         % ("calls read back", s["calls_checked"]))
        if self.plugins:
            lines.append("%-22s %s  (types a stock engine lacks)"
                         % ("plugin needed", ", ".join(self.plugins)))
        if self.newer_engine:
            lines.append("%-22s %s" % ("needs a newer engine",
                                       ", ".join(self.newer_engine[:6])))
        if self.stock:
            lines.append("%-22s %s" % ("stock library", self.stock[0]))
            for note in self.stock[1:]:
                lines.append("%-22s %s" % ("", note))
        if self.data:
            lines.append("%-22s %s" % ("asset packs", self.data[0]))
            for note in self.data[1:]:
                lines.append("%-22s %s" % ("", note))
        if self.speech:
            lines.append("%-22s %s" % ("screen reader", self.speech[0]))
            for note in self.speech[1:]:
                lines.append("%-22s %s" % ("", note))
        if self.loaded:
            lines.append("%-22s %s" % ("script loads", self.loaded[0]))
            for note in self.loaded[1:]:
                lines.append("%-22s %s" % ("", note))
        if self.compile_report is not None:
            used = s.get("compiler_used")
            lines.append("%-22s %s" % ("compiler", self.compile_report.summary()))
            if used:
                lines.append("%-22s %s" % ("", used))
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
        # Qualified, because the namespace is the only thing telling a game's
        # own copy of a library function from the library's. Manamon 2
        # declares both `position_sound_1d` and `rhythm::position_sound_1d`,
        # and keyed on the bare name the namespaced one inherited the
        # library's file -- moving 71 lines fifty thousand lines earlier,
        # which is exactly the kind of reordering `verify` exists to catch,
        # and the only thing it was catching.
        name = ("%s::%s" % (f.namespace_, f.name)) if f.namespace_ else f.name
        self._capture("function", name,
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


def script_loaded_dlls(exe_path: str, module) -> List[str]:
    """DLLs the *script* loads itself, through the engine's `library` type.

    This is a second way a BGT game depends on a DLL, and it leaves none of
    the evidence `plugin_dlls` looks for. `library` is a stock, documented
    engine type -- `bool load(const string& in)`, `bool unload()`,
    `dictionary@ call(const string& in, ?&in param1=null, ... param10=null)`
    -- so a game using it registers no new type and the DLL is named after
    nothing. It arrives as an ordinary **string literal** passed to
    `library::load`.

    Manamon 2 is the case: a `sqlite3_legacy` class whose `load_library`
    calls `library::load("sqlite3.dll")`, with `Unable to locate
    sqlite3.dll.` as its own error text. Recovered without it, the project
    compiles, runs, and loses whatever that database held -- the same shape
    as a missing asset pack, one layer over.

    The evidence is the same pair the pack search uses, and neither half is
    enough alone: the **name** comes from the module's string constants,
    because the call site passes a local; the **filter** is a PE file of
    that name sitting beside the executable. A system DLL is never brought,
    and the module must really call `library::load`, or any `.dll` mentioned
    anywhere would qualify.
    """
    calls_load = any(
        f is not None and f.name.split("::")[-1] in ("load", "call")
        and getattr(f, "object_type", None) is not None
        and f.object_type.name == "library"
        for f in module.used_functions)
    if not calls_load:
        return []
    folder = os.path.dirname(os.path.abspath(exe_path))
    found: List[str] = []
    for raw in module.used_strings:
        text = raw.decode("latin1") if isinstance(raw, bytes) else raw
        if not text.lower().endswith(".dll") or text in found:
            continue
        if text.lower() in SYSTEM_DLLS or not DLL_RE.fullmatch(
                text.encode("latin1", "replace")):
            continue
        beside = os.path.join(folder, text)
        try:
            with open(beside, "rb") as fh:
                if fh.read(2) != b"MZ":
                    continue
        except OSError:
            continue
        found.append(text)
    return found


def engine_gap(exe_path: str, used: Sequence[str],
               compiler: Optional[str] = None) -> List[Tuple[str, str]]:
    """Types the module uses that the *installed* engine does not have.

    A recovered module is faithful to the build that produced it, and that
    build is not necessarily the one installed here. Psycho Strike uses
    `elias`; Manamon 2 uses `weakref`, `ecdh` and `protected`, and none of
    them is in BGT 1.0 or 1.3. Those are the engine's age, not the
    recovery's, and saying so is the difference between a report and a
    mystery.

    **The game's own executable is an engine too**, and that is better
    evidence than it was being asked for. A BGT game is the runtime with the
    module appended, so the runtime's registration strings are right there
    uncompressed -- the whole interface the build that produced this module
    offered. Manamon 2's `rpg.exe` registers 509 names and 52 types against
    stock 1.3's 432 and 32. So the corroboration is now a *registration*
    rather than the name appearing somewhere in the file, which a substring
    match cannot distinguish from a coincidence, and the report can carry
    the signature the build actually had.
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

    # Either way, it only counts when the build that produced this module
    # provided it. Its own runtime's registrations say so outright; the
    # name merely appearing in the file is the fallback for a runtime whose
    # strings cannot be read.
    offered = bgt_api.registered_types(exe_path)
    return [(name, os.path.basename(exe_path)) for name in names
            if name in absent
            and (name in offered if offered
                 else name.encode("latin1") in game)]


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

    Needs a *list* on both sides, because a binary search for a short name
    is not an absence: the installed engine's registrations and its
    documentation on one, and the **game's own runtime's registrations** on
    the other. Strike's `rpg`-era engine declares
    `sound@ speak_to_sound(string)` and Manamon 2's
    `sound@ speak_to_sound(string text, bool normalize=false)`, which is the
    same method two builds apart; stock 1.3 declares neither.
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
    offered = bgt_api.registered(exe_path)
    installed = bgt_api.registered(exe)
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
        if any(re.search(r"\b%s\b" % re.escape(method), line) for line in documented):
            continue
        if method in installed:               # registered, merely undocumented
            continue
        name = "%s::%s" % (owner.name, method)
        if name in [existing for existing, _ in gap]:
            continue
        # The same corroboration as for a type, and from the same place: the
        # build that produced this module registered it, and the installed
        # one does not. The raw search stays as the fallback for a runtime
        # whose strings cannot be read.
        if (method in offered if offered
                else (method.encode("latin1") in game
                      and method.encode("latin1") not in engine)):
            gap.append((name, os.path.basename(exe_path)))
    return gap


#: characters that cannot appear in a path the engine would open, so a
#: string constant carrying one is not a file name.
def _inside(folder: str, candidate: str) -> bool:
    """Is `candidate` within `folder`?

    `commonpath` raises `ValueError` for paths on different drives, and a
    string constant out of a game module can name anything -- a drive letter, a UNC
    share, a bare `/`. A different drive is simply outside, so the exception
    is the answer rather than a crash. Crazy Party's constants hit this.
    """
    try:
        return os.path.commonpath([folder, candidate]) == folder
    except ValueError:
        return False


_UNUSABLE = re.compile(r'["<>|*?]|[\r\n]')

def data_packs(exe_path: str, module, sample: int = 0) -> List[Dict[str, Any]]:
    """The asset packs this module names, as they sit beside the game.

    A recovered script still calls `set_sound_storage("data.dat")`, and if the
    pack is not where it looks, the game does not politely do without sound --
    it can die at startup. So the project has to say what it needs, and be
    able to bring it.

    The names come from the module's string constants, because the calls pass
    locals rather than literals (`set_sound_storage(local_8)`). A name counts
    only when a file of that name sits beside the executable *and* starts with
    `SFPv`: that magic is what separates `data.dat` from `log.txt`, `save.bin`
    and the `.` / `/` that also appear in the constants.
    """
    folder = os.path.dirname(os.path.abspath(exe_path))
    found: List[Dict[str, Any]] = []
    seen = set()
    for text in getattr(module, "used_strings", ()) or ():
        if not text or len(text) > 128 or _UNUSABLE.search(text):
            continue
        candidate = os.path.normpath(os.path.join(folder, text))
        # A string from the module is data: it must not reach outside the
        # game's own folder.
        if not _inside(folder, candidate):
            continue
        if candidate in seen or not os.path.isfile(candidate):
            continue
        with open(candidate, "rb") as fh:
            if fh.read(4) != bgt_pack.PACK_MAGIC:
                continue
        seen.add(candidate)
        try:
            info: Dict[str, Any] = bgt_pack.survey(candidate, sample=sample)
        except bgt_pack.PackError as exc:
            info = {"path": candidate, "error": str(exc)}
        info["name"] = text.replace("\\", "/")
        found.append(info)
    return sorted(found, key=lambda d: d["name"])


def pack_keys(module_path: str, packs: Sequence[Dict[str, Any]],
              progress=lambda message: None) -> Tuple[Dict[bytes, bytes], List[str]]:
    """Recover the AES key for every encrypted pack, from the module itself.

    Extraction without this answers "it needs its key" and stops, which is the
    one thing the module can usually settle on its own: the key is whatever the
    script passed to `set_sound_decryption_key`, and the script is in the file.

    Super Egg Hunt is the case that matters, because it is the normal one. Its
    key is not a literal -- `set_sound_decryption_key(string_decrypt(h_key,
    "af-dc7=rqp+"), true)` -- so a harvest over literals finds nothing, and
    `bgt crack` reported 3,392 candidates and 0 hits while both halves of the
    password sat in the module. `bgt_crack.harvest_encrypted` composes them.

    A candidate costs one AES block against the tag each entry stores, so the
    whole search is cheaper than reading the pack, and a key that verifies is
    not a guess: `tag == AES-ECB(key, 16 zero bytes)` cannot be satisfied by
    the wrong key.

    Returns ({verification tag: key}, notes). Keyed by tag rather than by pack
    because one key usually opens all of them, and the tag is what says so.
    """
    wanted: Dict[bytes, List[str]] = {}
    for pack in packs:
        for tag in pack.get("tags") or ():
            wanted.setdefault(tag, []).append(pack["name"])
    if not wanted:
        return {}, []

    with open(module_path, "rb") as fh:
        data = fh.read()
    candidates, counts = bgt_crack.build_candidates(
        data, ("strings", "runs", "cores", "encrypted"))
    progress("searching %d candidates for %d pack key(s)"
             % (len(candidates), len(wanted)))

    found: Dict[bytes, bytes] = {}
    notes: List[str] = []
    for candidate in candidates:
        key = bgt_kdf.aes_key(candidate)
        tag = bgt_pack.tag_for_key(key)
        if tag in wanted and tag not in found:
            found[tag] = key
            notes.append("key for %s recovered from the module: %r"
                         % (", ".join(sorted(wanted[tag])), candidate))
            if len(found) == len(wanted):
                break
    for tag, names in sorted(wanted.items()):
        if tag not in found:
            notes.append(
                "no key found for %s among %d candidates (%s). The password "
                "is computed rather than stored -- read the caller of "
                "set_sound_decryption_key in the recovered source, which is "
                "where Super Egg Hunt's `string_decrypt(h_key, ...)` was found"
                % (", ".join(sorted(names)), len(candidates),
                   ", ".join("%s=%d" % kv for kv in sorted(counts.items()))))
    return found, notes


def bring_data(packs: Sequence[Dict[str, Any]], out_dir: str,
               extract: bool = False,
               keys: Optional[Dict[bytes, bytes]] = None,
               copy: Optional[bool] = None) -> List[str]:
    """Copy each pack next to the entry script, or extract its entries.

    Copying is what makes the recovered project runnable, because the engine
    looks for the pack by the same relative name the original used -- and the
    script sets its own decryption key, so a copied pack needs nothing from
    here.

    Extracting is for reading the assets, and needs the key: `keys` maps each
    verification tag to the key that satisfies it (`pack_keys`). An entry whose
    key is not known is **skipped and counted**, never written, because a file
    of ciphertext named `music.ogg` is worse than no file.

    **The two are independent, not alternatives.** They answer different
    questions -- "can this project run?" and "what is in the pack?" -- and
    wanting both is the ordinary case. `copy` defaults to "whatever `extract`
    is not", which keeps the old two-way behaviour for existing callers.
    """
    keys = keys or {}
    copy = (not extract) if copy is None else copy
    notes: List[str] = []
    for pack in packs:
        if pack.get("error"):
            notes.append("%s could not be read: %s" % (pack["name"], pack["error"]))
            continue
        if copy:
            target = os.path.join(out_dir, pack["name"].replace("/", os.sep))
            os.makedirs(os.path.dirname(target) or out_dir, exist_ok=True)
            shutil.copy2(pack["path"], target)
            notes.append("%s copied (%.1f MB)" % (pack["name"], pack["size"] / 1e6))
        if not extract:
            continue
        unopened = [tag for tag in (pack.get("tags") or ()) if tag not in keys]
        if unopened and pack["encrypted"]:
            notes.append("%s holds %d encrypted entries and its key was not "
                         "recovered, so nothing was written: bgt crack %s "
                         "--dict <module>.bin"
                         % (pack["name"], pack["encrypted"],
                            os.path.basename(pack["path"])))
            continue
        where = os.path.join(out_dir, "assets",
                             os.path.splitext(os.path.basename(pack["name"]))[0])
        os.makedirs(where, exist_ok=True)
        _, entries = bgt_pack.parse(pack["path"], load_data=True)
        written = 0
        refused = 0
        for entry in entries:
            name = os.path.normpath(entry.name.replace("\\", "/")).lstrip("./\\")
            target = os.path.join(where, name)
            if not _inside(where, os.path.abspath(target)):
                continue                      # a pack cannot write outside itself
            if entry.encrypted:
                plain = entry.decrypt(keys.get(entry.tag, b"\x00" * 32))
                if plain is None:
                    refused += 1
                    continue
            else:
                plain = entry.data or b""
            os.makedirs(os.path.dirname(target) or where, exist_ok=True)
            with open(target, "wb") as fh:
                fh.write(plain)
            written += 1
        notes.append("%s extracted %d entries to assets/%s%s"
                     % (pack["name"], written, os.path.basename(where),
                        "" if not refused
                        else " (%d skipped: no key that verifies)" % refused))
    return notes


ASSET_APIS = ("set_sound_storage", "set_sound_decryption_key")


def asset_gaps(exe_path: str, module, packs: Sequence[Dict[str, Any]],
               keys: Optional[Dict[bytes, bytes]] = None,
               extracted: bool = False, copied: bool = False) -> List[str]:
    """What the script will look for at run time and may not find.

    Finding nothing is the case that matters. `data_packs` only reports a pack
    it can see beside the executable, so recovering from a copy of the exe --
    which is the normal thing to do -- finds none, and silence there is
    exactly the surprise to avoid: the engine does not quietly do without its
    sounds.

    So the module's own calls are the evidence instead. `set_sound_storage`
    means it opens a pack; `set_sound_decryption_key` means the entries are
    encrypted and the key is a separate hunt. The names come from the string
    constants, which is a list of what it may ask for, not proof of which.
    """
    called = {f.name for f in getattr(module, "used_functions", ()) or ()
              if f is not None and f.name}
    uses = [api for api in ASSET_APIS if api in called]
    if not uses:
        return []
    notes: List[str] = []
    if not packs:
        folder = os.path.dirname(os.path.abspath(exe_path))
        asked = sorted({t.replace("\\", "/").lstrip("/") for t in
                        (getattr(module, "used_strings", ()) or ())
                        if t and 4 < len(t) < 64 and t.lower().endswith(".dat")})
        notes.append(
            "this game loads assets through %s and no pack was found beside "
            "%s -- the recovered script will ask the engine for one by name "
            "and can die at startup without it. Run recovery on the "
            "executable in its own folder, or copy the data in by hand.%s"
            % (" and ".join(uses), folder,
               (" It names: " + ", ".join(asked[:8])) if asked else ""))
    if "set_sound_decryption_key" in called:
        # Only extraction needs the key. A copied pack does not: the script
        # sets its own key at run time, from a literal this project carries.
        unopened = [pack["name"] for pack in packs
                    if extracted and any(tag not in (keys or {})
                                         for tag in (pack.get("tags") or ()))]
        if not packs or unopened:
            notes.append(
                "its pack entries are encrypted%s: the key is whatever the "
                "script passed to set_sound_decryption_key, and `bgt crack "
                "<pack> --dict <module>.bin` harvests candidates from this "
                "module and tests each against one AES block"
                % ("" if not packs else " and %s stayed shut"
                   % ", ".join(unopened[:4])))
    if extracted and packs and not copied:
        # Extracted assets are for reading. The script still calls
        # `set_sound_storage("data/bgm.dat")`, so the project does not have
        # what it opens -- which the engine says out loud ("ERROR! could not
        # load pack data/bgm.dat.") and is worth saying before it does.
        notes.append(
            "the assets were extracted for reading, which is not what the "
            "script opens: it still asks the engine for %s by name, and will "
            "report `could not load pack %s`. Drop --no-data to copy the "
            "pack(s) in as well." % (packs[0]["name"], packs[0]["name"]))
    return notes


#: a `#include` directive, with or without space before the name
#: (`#include"form.bgt"` is how BGT's own sources write some of them).
_INCLUDE_LINE = re.compile(r'\s*#\s*include\b')


#: a `funcdef` declaration; `types.bgt` already carries every one of
#: the module's, so a stock file's copy would be a name conflict.
_FUNCDEF_LINE = re.compile(r'\s*funcdef\b')


def stock_library(include_dirs: Optional[Sequence[str]] = None) -> Dict[str, str]:
    """{file name: path} for the library source BGT ships with itself."""
    found: Dict[str, str] = {}
    for folder in (list(include_dirs) if include_dirs else _default_includes()):
        if not os.path.isdir(folder):
            continue
        for name in sorted(os.listdir(folder)):
            if name.lower().endswith(".bgt"):
                found.setdefault(name, os.path.join(folder, name))
    return found


#: a function or method definition's opening line: `bool f(int a, string b)`.
_SIGNATURE = re.compile(
    r"^[ \t]*(?:[A-Za-z_][\w:]*(?:\[\])*@?[ \t]+)+([A-Za-z_]\w*)[ \t]*\(([^)]*)\)",
    re.MULTILINE)


def _param_types(params: str) -> List[str]:
    """The parameter *types* of one parameter list, names and defaults dropped.

    `tts_voice@ handle` and `voice_manager@ arg0` differ in the only part that
    matters, and `bool persistent=false` is the same parameter as
    `bool arg2 = false`. So the default is cut, and the trailing identifier --
    the parameter's own name -- goes with it, leaving `const string&in` intact
    because its type is more than one token.
    """
    out: List[str] = []
    for raw in params.split(","):
        text = raw.split("=")[0].strip()
        if not text:
            continue
        words = text.split()
        out.append(" ".join(words[:-1]) if len(words) > 1 else words[0])
    return out


def _signatures(text: str) -> Dict[str, List[List[str]]]:
    """{name: [parameter type lists]} for every definition in some source."""
    found: Dict[str, List[List[str]]] = {}
    for match in _SIGNATURE.finditer(text):
        found.setdefault(match.group(1), []).append(_param_types(match.group(2)))
    return found


def _bodies_that_differ(stock_text: str, group: Sequence[Section]) -> List[str]:
    """Functions whose recovered call sequence is not the stock one.

    Reused from `bgt_libcheck`, which is the thing that scores recovered code
    against BGT's shipped library in the first place: the sequence of calls in
    evaluation order, and the string literals as a multiset.
    """
    try:
        stock = bgt_libcheck.source_functions(stock_text)
        recovered = bgt_libcheck.source_functions(
            chr(10).join(section.text for section in group))
    except Exception:
        return []
    differing: List[str] = []
    for label, bodies in sorted(stock.items()):
        mine = recovered.get(label)
        if len(bodies) != 1 or not mine or len(mine) != 1:
            continue
        pair = bgt_libcheck.Comparison(label, bodies[0], mine[0])
        if not pair.identical or not pair.literals_equal:
            differing.append(label)
    return differing


def _members(module, class_name: str) -> List[str]:
    """Every member name the module records for this class.

    Methods and properties both, because a game's edit can be either, and the
    one that caught this out was a property: Super Egg Hunt's `dynamic_menu`
    carries an `is_main` that stock BGT's has never heard of.
    """
    names: List[str] = []
    for ti in getattr(module, "classes", ()) or ():
        if ti is None or ti.name != class_name:
            continue
        names += [m.name for m in (ti.methods or ()) if m is not None and m.name]
        names += [n for n, _dt, _flags in (ti.properties or ())]
    return names


def _why_not_stock(name: str, described, text: str, group: Sequence[Section],
                   module) -> str:
    """Why this library file must keep its decompiled version, or "" to take
    the engine's.

    Every one of these came from a title that broke:

    * **It declares types of its own.** `form.bgt` declares four enums, and
      `types.bgt` already carries every enum in the module, so taking the
      stock file too is four "Name conflict" errors. Psycho Strike.
    * **The game added a member.** Super Egg Hunt's `dynamic_menu` has
      `is_main`, `confirm`, `select` and `sound_pack`; substituting dropped
      them and the game's own code then failed against the engine's class.
    * **The game changed a signature.** Paladin's
      `dynamic_menu::set_tts_object` takes its own `voice_manager@` where
      stock takes `tts_voice@`. The names match, which is why comparing names
      was not enough, and the call site is what broke.
    """
    if described.enums or described.globals:
        return ("it declares %d enum(s) and %d global(s) of its own, which "
                "types.bgt and globals.bgt already carry"
                % (len(described.enums), len(described.globals)))

    declared = set(described.classes) | set(described.functions)
    stock_signatures = _signatures(text)
    for section in group:
        if section.name not in declared:
            return "the game declares %s, which the engine's copy does not" % section.name
        if section.kind != "class":
            continue
        for member in _members(module, section.name):
            if not re.search(r"(?<![\w.])" + re.escape(member) + r"\b", text):
                return ("the game's %s has %s, which the engine's does not"
                        % (section.name, member))
    for member, mine in _signatures(
            chr(10).join(section.text for section in group)).items():
        theirs = stock_signatures.get(member)
        if theirs is None or len(mine) != 1 or len(theirs) != 1:
            continue
        if mine[0] != theirs[0]:
            return ("the game's %s takes (%s) where the engine's takes (%s)"
                    % (member, ", ".join(mine[0]), ", ".join(theirs[0])))
    return ""


def substitute_stock(sections: List[Section], out_dir: str, module,
                     include_dirs: Optional[Sequence[str]] = None
                     ) -> Tuple[Dict[str, str], List[str]]:
    """Use the engine's own copy of a library file instead of the decompiled one.

    A stock `include/*.bgt` is not what anyone is trying to recover: it ships
    with BGT, and its real source carries the parameter names, the comments
    and the author's own structure, none of which survive compilation.
    Decompiling it throws all of that away -- `play_stationary(string arg0,
    bool arg1, bool arg2 = false)` where the original reads
    `play_stationary(string filename, bool looping, bool persistent=false)`.

    So where a run was attributed to a shipped file, that file is copied in and
    the decompiled sections for it are dropped -- but **only when nothing says
    the game's copy is different**, and games edit this library constantly.
    `_why_not_stock` holds the three reasons found so far, each from a title
    that broke when the check was weaker than it is now.

    A differing method *body* blocks it too. That cannot distinguish the
    game's edit from this decompiler's own rendering -- but it does not need
    to, because the costs are not symmetric: keeping the decompiled copy loses
    parameter names in a file nobody wanted recovered, while substituting over
    a real edit replaces the game's code with the engine's and says nothing.

    Returns ({library name: source path}, notes).
    """
    stock = stock_library(include_dirs)
    if not stock:
        return {}, ["no BGT include folder found, so library files stay decompiled"]
    index = {f.name: f for f in _library(include_dirs)}

    runs: Dict[str, List[Section]] = {}
    for section in sections:
        if section.origin:
            runs.setdefault(section.origin, []).append(section)

    used: Dict[str, str] = {}
    notes: List[str] = []
    for name, group in sorted(runs.items()):
        source = stock.get(name)
        described = index.get(name)
        if source is None or described is None:
            notes.append("%s is attributed but not shipped here, so it stays "
                         "as decompiled" % name)
            continue
        with open(source, "r", encoding="latin-1") as fh:
            text = fh.read()

        why = _why_not_stock(name, described, text, group, module)
        if why:
            notes.append("%s keeps its decompiled version: %s" % (name, why))
            continue

        # **A differing body blocks the substitution.** This used to be
        # reported and acted on anyway, on the argument that a body difference
        # is either the game's edit or this decompiler's own rendering and the
        # comparison cannot tell them apart. True -- but the costs are not
        # symmetric. Keeping the decompiled copy costs parameter names and
        # comments in a file nobody was trying to recover; substituting over a
        # real edit silently replaces the game's code with the engine's.
        #
        # Paladin settled it. Its `sound_pool` -- the audio engine -- matched
        # on every member and signature and differed in four bodies, so it was
        # replaced; the recovered game then reached its menu and could not
        # speak or play anything. With `--no-stock-includes` the same build
        # compiles cleanly and opens a window titled 'Paladin of the sky'.
        differing = _bodies_that_differ(text, group)
        if differing:
            notes.append(
                "%s keeps its decompiled version: %s differ from the engine's "
                "source, so the engine's copy would replace whatever the game "
                "changed there. `bgt libcheck --decompiler` says which are the "
                "game's edits and which are this decompiler's rendering."
                % (name, ", ".join(differing[:4])))
            continue

        target = os.path.join(out_dir, "includes", name)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        kept = [line for line in text.splitlines()
                if not _INCLUDE_LINE.match(line) and not _FUNCDEF_LINE.match(line)]
        header = (
            "// %s -- BGT's own copy of this file, from\n"
            "// %s\n"
            "//\n"
            "// Decompiling a stock library file loses its parameter names and\n"
            "// comments for nothing, so the engine's source is used instead. Every\n"
            "// member and signature the game's own copy has was checked against\n"
            "// this file first, so it is not hiding an edit the game made.\n"
            "//\n"
            "// Its #include and funcdef lines are stripped: the entry script lists\n"
            "// every file in order, and types.bgt already declares the funcdefs.\n"
            "\n" % (name, source))
        with open(target, "w", encoding="latin-1", newline="\n") as fh:
            fh.write(header)
            fh.write("\n".join(kept).rstrip() + "\n")
        used[name] = source
        notes.append("%s taken from the engine, replacing %d decompiled "
                     "declaration(s) -- every member, signature and body "
                     "matches" % (name, len(group)))
    return used, notes


def _default_includes() -> List[str]:
    """Where BGT keeps the library source it ships with."""
    return [folder for folder in (r"C:\Program Files (x86)\BGT\include",
                                  r"C:\Program Files\BGT\include")
            if os.path.isdir(folder)]


def _bgt_roots() -> List[str]:
    """Where BGT is installed, derived from where its include folder is."""
    return [os.path.dirname(folder) for folder in _default_includes()]


#: BGT's own redistributables for talking to a screen reader, and the API each
#: one serves. BGT ships them under `redist/screen_readers/` precisely because
#: a built game needs them beside it.
SPEECH_CLIENTS = (
    ("nvdaControllerClient32.dll", os.path.join("screen_readers", "nvda"), "NVDA"),
    ("SAAPI32.dll", os.path.join("screen_readers", "system_access"),
     "System Access"),
)

#: the APIs whose presence means the module speaks through a screen reader at
#: all. `screen_reader_speak` and friends fall back to SAPI when no client DLL
#: is found, which is why a missing DLL is not an error -- it is a game that
#: suddenly has the wrong voice.
SPEECH_APIS = ("screen_reader_speak", "screen_reader_speak_interrupt",
               "screen_reader_is_running", "screen_reader_detect",
               "screen_reader_output", "screen_reader_output_braille")


def speech_clients(module, out_dir: str,
                   bgt_roots: Optional[Sequence[str]] = None
                   ) -> Tuple[List[str], List[str]]:
    """Bring BGT's screen-reader client DLLs into the project.

    A recovered game that calls `screen_reader_speak` needs
    `nvdaControllerClient32.dll` beside its script to reach NVDA. Without it
    the engine does not fail -- it falls back to SAPI, so the game talks, in
    the wrong voice, and nothing says why. That is worth copying rather than
    mentioning: the file ships with BGT, under `redist/screen_readers/`, and
    the project is useless to its actual audience without it.

    Only when the module calls one of those APIs, which is what makes this
    evidence rather than scattering DLLs into every project.

    Returns (copied file names, notes).
    """
    called = {f.name for f in getattr(module, "used_functions", ()) or ()
              if f is not None and f.name}
    uses = sorted(called & set(SPEECH_APIS))
    if not uses:
        return [], []

    copied: List[str] = []
    notes: List[str] = []
    for name, where, reader in SPEECH_CLIENTS:
        source = next((os.path.join(root, "redist", where, name)
                       for root in (bgt_roots or _bgt_roots())
                       if os.path.isfile(os.path.join(root, "redist", where, name))),
                      None)
        if source is None:
            notes.append("%s was not found in BGT's redist folder, so this "
                         "project cannot talk to %s and the engine will fall "
                         "back to SAPI" % (name, reader))
            continue
        shutil.copy2(source, os.path.join(out_dir, name))
        copied.append(name)
        notes.append("%s copied in, so speech reaches %s rather than falling "
                     "back to SAPI" % (name, reader))
    if copied:
        notes.append("keep %s beside the script: this game calls %s, and the "
                     "engine looks for the client DLL in the script's own "
                     "folder" % (" and ".join(copied), ", ".join(uses[:3])))
    return copied, notes


def _library(include_dirs: Optional[Sequence[str]]):
    dirs = list(include_dirs) if include_dirs else _default_includes()
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


def declares_anything(text: str) -> bool:
    """Is there anything here but comments, blank lines and `#include`?

    What BGT means by "The script section is empty", and it is not a cosmetic
    warning: measured, the engine shows it in a modal dialog and then **writes
    no executable at all**.

    The scrubber that reads calls back is reused rather than a second one
    written, because a `//` can sit inside a string literal and a quote inside
    a comment -- two passes over one text desynchronise, which is how
    `url_get("http://...")` once turned a one-argument call into a
    thirty-three argument report.
    """
    stripped = bgt_apicheck.scrub(text)
    return bool(re.sub(r'(?m)^\s*#include\b.*$', "", stripped).strip())


def inline_prefix(order: List[str],
                  written_text: Dict[str, List[str]]) -> Tuple[List[str], Optional[str]]:
    """Which sections the entry script carries inline, and any problem with that.

    The entry script holds the text of a **prefix** of the order rather than
    only `#include` lines, and takes as many sections as it needs before one
    declares something.

    A prefix is what keeps the concatenation exactly as the module had it. The
    inlined text is emitted ahead of every `#include`, so inlining anything
    but a prefix moves a declaration -- and `verify` compares the sections
    against the one-file render, so it could not see that happen.

    **Declaring something is the requirement, and naming the types section was
    a proxy for it that failed.** A module with no enums, typedefs or funcdefs
    still gets a `types.bgt` section, holding the decompiler's comment banner
    and nothing else, so the old test inlined a section that declared nothing
    and the entry script stayed empty. `bgt recover --compile` then reported
    `compiled cleanly` while `--build release` produced 901,120 bytes of
    runtime stub with no script attached -- which Windows declines to launch
    at all, as "not a valid application for this OS platform".
    """
    inlined: List[str] = []
    for path in order:
        if path not in written_text:
            # A substituted library file: BGT's own source is already on disk
            # there, so there is nothing of ours to carry, and the prefix stops
            # rather than skipping past it and reordering the rest.
            break
        inlined.append(path)
        if declares_anything("\n".join(written_text[path])):
            return inlined, None
    return [], ("the entry script declares nothing of the module's own, so it "
                "carries a marker global: BGT writes no executable for a script "
                "section it calls empty")


def recover(exe_path: str, out_dir: str, include_dirs: Optional[Sequence[str]] = None,
            make_zip: bool = True, compile_check: bool = False,
            timeout: float = 600.0, with_data: bool = True,
            extract_data: bool = False, stock_includes: bool = True,
            progress=lambda message: None) -> Project:
    name = os.path.splitext(os.path.basename(exe_path))[0]
    os.makedirs(out_dir, exist_ok=True)

    progress("unpacking %s" % os.path.basename(exe_path))
    unpacked = bgtlib.unpack_file(exe_path)
    module_path = os.path.join(out_dir, "%s_bytecode.bin" % name)
    with open(module_path, "wb") as fh:
        fh.write(unpacked.bytecode)

    progress("reading the opcode table and the module")
    opcodes = as_opcodes.extract(exe_path)["table"]
    # The executable goes in as well as the opcode table. It is not needed to
    # *read* the module, but `name_engine_funcdefs` asks it which funcdef the
    # `_builtin_function_` placeholder stands for, and on a machine with no
    # BGT installed the game's own runtime is the only source there is.
    module = bgt_asir.load(module_path, exe_path, opcodes=opcodes)

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
    # ...and the other way a game depends on a DLL: the script loading one
    # itself through the stock `library` type, which registers no new type
    # and so leaves none of a plugin's evidence.
    loaded = script_loaded_dlls(exe_path, module)
    # The asset packs the script will look for at run time. Discovery is
    # always done, because a project that cannot find its sounds can die
    # at startup and the report is the only warning you get.
    packs = data_packs(exe_path, module)
    data_notes: List[str] = []
    keys: Dict[bytes, bytes] = {}
    if packs and extract_data:
        # Extraction needs the key, and the module is where it is. Copying
        # does not: the script sets its own key at run time.
        keys, key_notes = pack_keys(module_path, packs, progress)
        data_notes += key_notes
    if packs and (with_data or extract_data):
        progress("bringing %d asset pack(s)" % len(packs))
        data_notes += bring_data(packs, out_dir, extract=extract_data,
                                 keys=keys, copy=with_data)
    # ...and types the installed engine simply does not have, plugin or not.
    newer = [name for name, _ in engine_gap(exe_path, used)
             if not any(os.path.splitext(dll)[0].lower() == name.lower()
                        for dll in plugins)]
    # ...and one method of a type it does have, which is the same finding one
    # level down.
    newer += [name for name, _ in method_gap(exe_path, module)]

    # The library files BGT ships are taken from BGT, not from the module.
    # The order still comes from the module, so the entry script lists them
    # exactly where the game declared them.
    stock_used: Dict[str, str] = {}
    stock_notes: List[str] = []
    if stock_includes:
        progress("taking the stock library files from the engine")
        stock_used, stock_notes = substitute_stock(sections, out_dir, module,
                                                   include_dirs)

    order: List[str] = []
    for section in sections:
        if section.path not in order:
            order.append(section.path)
    # A substituted file is already written, so its decompiled sections must
    # not be written over it -- but its place in the order is kept.
    written = [s for s in sections if s.origin not in stock_used]
    written_text: Dict[str, List[str]] = {}
    for section in written:
        written_text.setdefault(section.path, []).append(section.text)
    inlined_paths, inline_problem = inline_prefix(order, written_text)
    if inline_problem:
        problems.append(inline_problem)

    project = Project(name=name, out_dir=out_dir, entry=name + ".bgt",
                      files=[], includes=order, plugins=plugins,
                      newer_engine=newer, sections=sections,
                      problems=list(problems))

    # The entry script, plus one file per path in the order -- except the
    # inlined one, whose text the entry script carries instead.
    progress("writing %d files" % (len(order) + 1 - len(inlined_paths)))
    by_path: Dict[str, List[Section]] = {}
    for section in written:
        by_path.setdefault(section.path, []).append(section)
    for path, group in by_path.items():
        if path in inlined_paths:
            # The entry script carries this section's text inline, so writing
            # the file too leaves one in the project that nothing includes --
            # and, if anyone does include it, a duplicate declaration.
            continue
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
    # The entry script carries the first section's own text rather than only
    # `#include` lines. Two reasons, and neither is cosmetic alone:
    #
    #   * BGT warns "The script section is empty" for a file that declares
    #     nothing, and it shows that warning in a modal dialog, so an
    #     unattended compile stops on it.
    #   * A warning nobody can explain invites the conclusion that the
    #     structure is wrong. It is not: `#include` is textual, so the module
    #     is the concatenation, and `main()` inside an include runs -- which
    #     was checked directly rather than assumed.
    #
    # The first section is `types.bgt` (enums, typedefs, funcdefs), and it is
    # first in the order, so moving its text into the entry script leaves that
    # order exactly as the module had it.
    inlined = [section for path in inlined_paths
               for section in written if section.path == path]
    for section in inlined:
        entry_lines.append(section.text.rstrip())
        entry_lines.append("")
    included = [path for path in order if path not in inlined_paths]
    if not inlined_paths:
        entry_lines.append("// BGT writes no executable for a script section it")
        entry_lines.append("// calls empty, and nothing of the module can go first")
        entry_lines.append("// here without moving a declaration. One unused global:")
        entry_lines.append("int __bgt_recovered_entry = 0;")
        entry_lines.append("")
    entry_lines += ['#include "%s"' % path for path in included]
    entry_lines.append("")
    entry_path = os.path.join(out_dir, project.entry)
    with open(entry_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(entry_lines))

    # The file list is built from the include order and from what is actually
    # on disk, not from the sections that were written here. A substituted
    # library file is written by `substitute_stock`, so appending as each
    # decompiled group was written left every one of them out of the list, out
    # of the count, and -- the part that mattered -- out of the ZIP: unzipping
    # Super Egg Hunt gave an entry script that included `number_speaker.bgt`
    # and `sound_positioning.bgt` and two files that were not there. From
    # outside that is indistinguishable from "it does not copy the stock
    # includes", which is how it was reported.
    project.files = [project.entry] + [
        path for path in order
        if os.path.isfile(os.path.join(out_dir, path.replace("/", os.sep)))]

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
        # The tags are bytes, and `recovery.json` is where they would stop the
        # whole run: a key-verification tag is for comparing, not for reading,
        # so it is written as hex rather than carried through.
        "data_packs": [dict(pack, tags=[tag.hex() for tag in pack.get("tags") or ()])
                       for pack in packs],
        "dangling_else": len(dangling_else(sections)),
    }
    for pack in packs:
        if pack.get("error"):
            project.problems.append(
                "the asset pack %s could not be read: %s"
                % (pack["name"], pack["error"]))
        elif not with_data:
            project.problems.append(
                "%s needs %s beside it (%d entries, %.1f MB%s): the script "
                "asks the engine for it by that name, and without it the game "
                "reports `could not load pack %s` and plays no audio. Drop "
                "--no-data to copy it in."
                % (project.entry, pack["name"], pack["entries"],
                   pack["size"] / 1e6,
                   ", %d encrypted" % pack["encrypted"] if pack["encrypted"] else "",
                   pack["name"]))
    for note in asset_gaps(exe_path, module, packs, keys, extract_data,
                           with_data and bool(packs)):
        project.problems.append(note)
    project.data = list(data_notes)
    project.stock = list(stock_notes)
    for path, line in dangling_else(sections)[:5]:
        project.problems.append(
            "%s has an `else` with no `if`: `%s` -- the structurer gave up on "
            "a branch and emitted the arm anyway, and the file cannot parse"
            % (path, line))
    for path, depth in unbalanced(sections):
        project.problems.append(
            "%s does not balance its braces (%+d): it cannot parse, and the "
            "compiler will blame the next declaration instead" % (path, depth))
    if stock_used:
        project.stock.append(
            "the concatenation check covers the decompiled sections; the "
            "%d file(s) above are the engine's own source by choice, not a "
            "reconstruction of it" % len(stock_used))
    if not project.stats["verified"]:
        project.problems.append(
            "the files do not concatenate back to the one-file source: "
            "a declaration moved, which can change global initialisation order")

    # The runtime files the project needs beside its script, before the ZIP is
    # written -- they used to be copied after it, so a plugin DLL was listed in
    # `recovery.json` and absent from the archive. Same mistake as the stock
    # library files, one directory up.
    #
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

    # ...and a DLL the *script* loads itself through the engine's `library`
    # type, which leaves none of a plugin's evidence: `library` is stock, so
    # no new type is registered and the DLL arrives as a string literal.
    # Manamon 2 loads `sqlite3.dll` that way. Nothing needs it to *compile*,
    # which is why it is copied without being named a plugin and a missing
    # one is a note rather than a problem.
    for dll in loaded:
        source_dll = os.path.join(os.path.dirname(os.path.abspath(exe_path)), dll)
        if dll not in project.files and os.path.isfile(source_dll):
            with open(source_dll, "rb") as src, \
                    open(os.path.join(out_dir, dll), "wb") as dst:
                dst.write(src.read())
            project.files.append(dll)
            project.loaded.append(
                "%s copied in: the script loads it itself with "
                "library::load, so nothing in the source names it and "
                "without it that code path simply fails at run time" % dll)

    # ...and the screen-reader client, which is the difference between the
    # game speaking through NVDA and the engine quietly falling back to SAPI.
    spoken, speech_notes = speech_clients(module, out_dir)
    project.speech = list(speech_notes)
    project.files += [dll for dll in spoken if dll not in project.files]

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

    if compile_check:
        progress("compiling the project with BGT's own compiler")
        exe = bgt_compile.find_compiler()
        caps = bgt_compile.capabilities()
        project.stats["compiler_used"] = exe
        if caps.get("default_arguments") is False:
            # The recovered source uses default arguments wherever the
            # original did, and BGT 1.0 cannot parse them at all. Compiling a
            # perfectly good project with it gives a cascade that reads as a
            # broken decompilation, and saying nothing about which compiler
            # ran is what made that look like the recovery's fault.
            project.problems.append(
                "%s has no default arguments, which this source uses: every "
                "`= false` in a signature will be reported as \"Expected ')' "
                "or ','\". That is the compiler's age, not the recovery -- "
                "pass --compiler to use a newer BGT." % exe)
        # ...and the compiler this toolkit chose is not the one a person
        # reaches by double-clicking the script. Installing BGT 1.0 after 1.3
        # leaves `open`, `run` and `compile` pointing at 1.0 while only
        # `compile_debug` and `compile_release` still point at 1.3, so a
        # project that compiles cleanly here reports a hundred
        # `Expected ')' or ','` there -- which is exactly how it was reported.
        for note in bgt_compile.verb_warnings():
            project.problems.append(note)
        # `check_project` stages the entry script inside the project rather
        # than in a subfolder, because BGT resolves an `#include` and a data
        # path alike against the script's own location: a copy one level down
        # reported `could not load pack data/bgm.dat.` for a pack that had
        # just been copied in. It cleans the copy up afterwards.
        project.compile_report = bgt_compile.check_project(entry_path,
                                                           timeout=timeout)

    # Read the calls in what was just written back against what this build
    # declares. The simulation pops a callee's declared arity by
    # construction, so this can only ever find a defect of the *rendering* --
    # and that is the half the compiler cannot reach on a title it refuses to
    # parse. It costs a second and needs no BGT at all.
    progress("reading the calls back against the game's own build")
    try:
        calls = bgt_apicheck.check(out_dir, exe_path, module=module)
    except Exception as exc:                 # never fail a recovery over it
        calls = {"error": str(exc)}
        project.problems.append("the call check could not run: %s" % exc)
    else:
        project.stats["calls_checked"] = calls["checked"]
        for line in calls["problems"]:       # type: ignore[index]
            project.problems.append("call arity: %s" % line)
        for name, n in sorted(calls["undeclared"].items()):   # type: ignore
            project.problems.append(
                "nothing declares `%s`, called %d time%s: neither this build's "
                "registrations nor the script itself"
                % (name, n, "" if n == 1 else "s"))

    with open(os.path.join(out_dir, "recovery.json"), "w", encoding="utf-8") as fh:
        json.dump({"executable": exe_path, "entry": project.entry,
                   "calls": calls,
                   "files": project.files,
                   # What the entry script really includes, and the one
                   # section it carries inline instead. Reporting `order` here
                   # listed `includes/types.bgt` as included when the entry
                   # script had inlined it -- a file list nothing reads is
                   # still a claim about the project.
                   "includes": included,
                   "inlined": list(inlined_paths),
                   "order": order,
                   "plugins": plugins, "newer_engine": newer,
                   "script_loaded_dlls": loaded,
                   "stats": project.stats,
                   "problems": project.problems,
                   "origins": {s.name: s.origin for s in sections if s.origin},
                   "compile": (None if project.compile_report is None else
                               {"outcome": project.compile_report.outcome,
                                # When the check could not run at all, the
                                # reason is the only thing worth having, and
                                # it used to be dropped here: `nodriver` with
                                # no explanation reads like a result.
                                "detail": project.compile_report.raw,
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
    ap.add_argument("--no-stock-includes", action="store_true",
                    help="decompile BGT's own library files too, instead of "
                         "copying the engine's source for them")
    # Copying the packs is the DEFAULT. A recovered project whose script calls
    # `set_sound_storage("data/bgm.dat")` and has no pack beside it reports
    # `ERROR! could not load pack data/bgm.dat.` and plays no audio -- which is
    # not a recovered game, and it was reported twice before this stopped being
    # opt-in. `--with-data` is kept so existing commands still work.
    ap.add_argument("--with-data", action="store_true",
                    help="copy the asset packs in (the default; kept for compatibility)")
    ap.add_argument("--no-data", action="store_true",
                    help="do not bring the asset packs, leaving a project that cannot play audio")
    ap.add_argument("--extract-data", action="store_true",
                    help="also extract the packs' entries, decrypting with the key recovered from the module")
    ap.add_argument("--timeout", type=float, default=600.0)
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args(argv)

    project = recover(args.exe, args.output, args.include,
                      make_zip=not args.no_zip, compile_check=args.compile,
                      timeout=args.timeout, with_data=not args.no_data,
                      extract_data=args.extract_data,
                      stock_includes=not args.no_stock_includes,
                      progress=(lambda m: None) if args.quiet
                      else (lambda m: print("  %s" % m, flush=True)))
    print(project.summary())
    if project.compile_report is not None and not project.compile_report.ok:
        for diagnostic in project.compile_report.errors[:20]:
            print(diagnostic)
    return 0


if __name__ == "__main__":
    sys.exit(main())
