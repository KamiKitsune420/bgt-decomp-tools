"""
bgt_api -- the engine's own documented API, read out of the installed `bgt.chm`.

Every question of the form "does this engine have that?" has an authoritative
answer sitting next to `bgt.exe`: the help file documents one page per
registered function, class, method and property, each carrying its signature
verbatim:

    string[] string_split(string source, string delimiter, bool require_full_delimiter)

That matters for recovery because a recovered module is faithful to the build
that produced it, and that build is not necessarily the one installed here.
Psycho Strike uses `elias`, Manamon 2 uses `weakref` and `protected`, Paladin
declares its own `input_recorder` -- and only the first two are the engine's
absence rather than the recovery's fault. Searching the binaries for a name is
a guess; the documentation is a list.

It also answers the other half: a recovered call whose arity or argument types
cannot match any documented signature is a recovery bug, and that can be said
without running the compiler at all.

## How it is read

`bgt.chm` is a compiled help file, so Windows' own `hh.exe -decompile` does the
unpacking, once, into a cache beside it (or a temporary directory). Nothing
from the help file is ever copied into this repository: it is the engine's
documentation, it belongs to whoever installed it, and the only thing kept here
is the code that reads it.

    bgt api string_split            one name
    bgt api --list sound            everything matching
    bgt api --missing elias weakref types this engine does not document
"""
from __future__ import annotations

import argparse
import html
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from typing import Dict, List, Optional, Sequence

DEFAULT_CHM = (
    r"C:\Program Files (x86)\BGT\bgt.chm",
    r"C:\Program Files\BGT\bgt.chm",
)

# `<return type> <name>(<parameters>)`, as the reference pages write it. The
# return type may be an array (`string[]`) or a handle (`sound@`), and a
# method page may end in `const`.
SIGNATURE = re.compile(
    r"^(?P<ret>[A-Za-z_][\w:]*(?:\[\])*@?)\s+"
    r"(?P<name>[A-Za-z_][\w:]*)\s*\((?P<params>[^()]*)\)\s*(?:const)?$")
# A property page writes `<type> <name>` with no parentheses.
PROPERTY = re.compile(r"^(?P<type>[A-Za-z_][\w:]*(?:\[\])*@?)\s+"
                      r"(?P<name>[A-Za-z_]\w*)$")


def find_chm(explicit: Optional[str] = None) -> Optional[str]:
    for path in ([explicit] if explicit else []) + list(DEFAULT_CHM):
        if path and os.path.isfile(path):
            return path
    return None


def _text(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as fh:
        raw = fh.read()
    raw = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", raw, flags=re.S | re.I)
    return html.unescape(re.sub(r"<[^>]+>", "\n", raw))


def decompile(chm: str, into: Optional[str] = None) -> str:
    """Unpack the help file, and return the directory holding it.

    Windows ships the only thing that reads this format. The result is cached,
    so the cost is paid once per machine rather than once per call.
    """
    target = into or os.path.join(tempfile.gettempdir(), "bgt_chm_cache")
    marker = os.path.join(target, "bgt.hhc")
    if os.path.isfile(marker):
        return target
    os.makedirs(target, exist_ok=True)
    helper = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "hh.exe")
    if not os.path.isfile(helper):
        raise RuntimeError("hh.exe not found: cannot unpack %s" % chm)
    # Launched directly with pipes attached, `hh.exe` returns without doing
    # anything; started the way the shell starts it, and waited for, it
    # unpacks. So the shell starts it.
    command = ("Start-Process -FilePath '%s' -ArgumentList "
               "@('-decompile', '%s', '%s') -Wait"
               % (helper.replace("'", "''"), target.replace("'", "''"),
                  chm.replace("'", "''")))
    subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive",
                    "-ExecutionPolicy", "Bypass", "-Command", command],
                   check=False, capture_output=True,
                   stdin=subprocess.DEVNULL, timeout=180)
    # `hh.exe` hands the work to the help service and returns at once, so the
    # files appear after it has already exited. Wait for them, and for the
    # table of contents to stop growing, rather than for the process.
    size = -1
    for _ in range(120):
        if os.path.isfile(marker):
            current = os.path.getsize(marker)
            if current == size and current > 0:
                break
            size = current
        time.sleep(0.25)
    if not os.path.isfile(marker):
        raise RuntimeError("hh.exe did not unpack %s" % chm)
    return target


def read(chm: Optional[str] = None, cache: Optional[str] = None) -> Dict[str, object]:
    """The documented API: free functions, and each type's methods and properties.

    A page under `object_reference` belongs to a type, and the directory above
    it is that type's name -- which is how a method is told from a free
    function without parsing prose.
    """
    path = find_chm(chm)
    if path is None:
        raise RuntimeError("no bgt.chm found -- pass --chm <path>")
    root = decompile(path, cache)

    functions: Dict[str, List[str]] = {}
    types: Dict[str, Dict[str, List[str]]] = {}
    for folder, _, names in os.walk(root):
        parts = folder.replace("\\", "/").split("/")
        # Only the reference tree: a tutorial page is full of example code,
        # and example code is not an API.
        if "references" not in parts:
            continue
        owner = None
        if "object_reference" in parts:
            index = parts.index("object_reference")
            if len(parts) > index + 1:
                owner = parts[index + 1]
        for name in names:
            if not name.endswith(".htm"):
                continue
            lines = [l.strip() for l in _text(os.path.join(folder, name)).splitlines()]
            page = os.path.splitext(name)[0]
            for line in lines:
                match = SIGNATURE.match(line)
                if match:
                    name = match.group("name").split("::")[-1]
                    # **A reference page is named after the one API it
                    # documents.** Every other signature on it is example
                    # code -- `garbage_collect`'s page defines
                    # `generate_garbage`, `get_call_stack`'s defines
                    # `first_dummy_method`, `serialize`'s defines `save`.
                    # Counted as API, those eleven tutorial names made the
                    # list this module exists to be: a name it wrongly holds
                    # is a gap it will not report. The PROPERTY branch below
                    # has always applied exactly this rule.
                    if name != page:
                        continue
                    if owner:
                        entry = types.setdefault(owner, {"methods": [], "properties": []})
                        if line not in entry["methods"]:
                            entry["methods"].append(line)
                    elif line not in functions.setdefault(name, []):
                        functions[name].append(line)
                    continue
                prop = PROPERTY.match(line)
                if prop and owner and prop.group("name") == page:
                    entry = types.setdefault(owner, {"methods": [], "properties": []})
                    if line not in entry["properties"]:
                        entry["properties"].append(line)
    # A type documented only by its own page still exists.
    for folder, subfolders, _ in os.walk(root):
        if os.path.basename(folder) == "object_reference":
            for sub in subfolders:
                types.setdefault(sub, {"methods": [], "properties": []})
    return {"source": path, "functions": functions, "types": types}


def documented(api: Dict[str, object]) -> set:
    """Every name the engine documents: functions and types alike."""
    return set(api["functions"]) | set(api["types"])        # type: ignore[arg-type]


#: An AngelScript declaration, as the engine hands it to `RegisterX`. The
#: return type may be a template (`array<T>@`), an array (`string[]@`) or a
#: handle, and a method's may end in `const`. The first version of this
#: rejected an array return, so `string[]@ find_files(string& in)` read as
#: four functions the engine did not have -- which is this repository's own
#: lesson about an extractor that answers anyway, in a new costume.
_REG_TYPE = (r"(?:const\s+)?[A-Za-z_]\w*(?:<[^<>()]*>)?(?:\s*\[\s*\])?")
#: The handle or reference marker may sit against either side: the engine
#: writes a factory `network_event @f()` and a getter `network_event@
#: request()`, so a rule that demands whitespace between the type and the
#: name finds the second and silently loses all eighteen of the first.
REGISTRATION = re.compile(r"^(?P<ret>%s)\s*(?P<mark>[@&](?:\s*(?:in|out|inout))?)?"
                          r"\s*(?P<name>[A-Za-z_]\w*)\s*"
                          r"\((?P<params>[^()]*)\)(?:\s*const)?$" % _REG_TYPE)
#: A declaration's parameters are *types*. `All Files (*.*)` and `BGT
#: Scripts (*.bgt)` are file-dialog filters shaped exactly like a
#: declaration, and this is what tells them apart.
_PARAM = re.compile(r"^(?:const\s+)?(?:\?|[A-Za-z_]\w*)")


def registered(exe: Optional[str] = None) -> Dict[str, List[str]]:
    """The engine's **registered** interface, read out of `bgt.exe` itself.

    AngelScript registers everything by handing the engine a declaration
    *string*, so the whole interface is a literal in the binary -- exact
    parameter types, `&in`/`&out`, `const`, and the default arguments the
    engine gives its own functions. That makes the executable a stronger
    oracle than the help file for the one question this module is asked:
    BGT 1.3 registers `string_compress`, `string_decompress`, `crc32`,
    `add_fx`, `delete_fx`, `hex_string_to_number`, `screen_reader_braille`
    and `string_create_from_pointer`, and documents **none** of them --
    while Paladin's save path calls `string_compress`. Asked of the
    documentation alone, "does this engine have that?" answered no.

    It registers two types the help file omits as well, `network_event` and
    `library_structure`, so a game using either would have been reported as
    needing a newer engine than the one installed.

    The two sources answer different questions and neither subsumes the
    other: a signature here has no parameter names, and the five documented
    `position_sound_*`/`convert_to_currency` functions are not registered at
    all because they are *library* code in `include/*.bgt`, which recovers
    like any other script. Returns `{}` when no executable can be found.
    """
    if exe is None:
        try:                                     # imported late on purpose:
            from . import bgt_compile            # only finding the exe needs
        except ImportError:                      # the compiler driver, and
            import bgt_compile                   # nothing else here does
        exe = bgt_compile.find_compiler()
    if not exe or not os.path.isfile(exe):
        return {}
    try:
        with open(exe, "rb") as fh:
            data = fh.read()
    except OSError:
        return {}
    out: Dict[str, List[str]] = {}
    for match in re.finditer(rb"[\x20-\x7e]{5,}", data):
        text = match.group().decode("latin1").strip()
        found = REGISTRATION.match(text)
        if found is None:
            continue
        # **A return type and a name must be separated by something.** The
        # type pattern backtracks, so a bare `send()` splits into a return
        # type `sen` and a function `d` -- which is how four names out of
        # the import table became registered types. Whitespace or the
        # handle marker is that something, and there is always one.
        if found.start("name") == found.end("ret"):
            continue
        if any(not _PARAM.match(p.strip())
               for p in found.group("params").split(",") if p.strip()):
            continue
        out.setdefault(found.group("name"), []).append(text)
    return out


#: A type as it appears inside a declaration: `const network_event &in`,
#: `string[]@`, `array<T>@`. Only the identifier is wanted.
_BARE_TYPE = re.compile(r"[A-Za-z_]\w*")


def registered_types(exe: Optional[str] = None,
                     decls: Optional[Dict[str, List[str]]] = None) -> set:
    """Every type the engine's own registrations name.

    A reference type is registered with a factory, which the engine declares
    as `network_event @f()` -- that is the direct evidence, and it finds all
    eighteen of them. A value type has no factory, so `string`, `vector` and
    `array` are reached the other way: a type named as a return or a
    parameter of a registration is a type the engine has. That also sweeps
    in the primitives and the template placeholder `T`, which costs nothing
    -- this is a set of names the engine *has*, used to stop an absence
    being claimed, and `int` is not a name anyone is missing.
    """
    found: set = set()
    for name, signatures in (decls if decls is not None
                             else registered(exe)).items():
        for text in signatures:
            match = REGISTRATION.match(text)
            if match is None:
                continue
            for part in [match.group("ret")] + match.group("params").split(","):
                head = _BARE_TYPE.search(part.replace("const", "", 1))
                # `&in` / `&out` qualify a reference; they are not types.
                if head is not None and head.group() not in ("in", "out",
                                                             "inout"):
                    found.add(head.group())
    return found


def available(api: Optional[Dict[str, object]] = None,
              exe: Optional[str] = None) -> set:
    """Every name this engine has: documented, registered, or both."""
    names = documented(api) if api else set()
    decls = registered(exe)
    return names | set(decls) | registered_types(decls=decls)


def missing(names: Sequence[str], api: Dict[str, object],
            exe: Optional[str] = None) -> List[str]:
    """Which of these names the installed engine does not have.

    Primitives and the names the module declares itself are the caller's
    business to exclude. The engine's registrations are consulted as well as
    its documentation, because the help file omits some of what it registers
    and a name wrongly called absent is the dangerous direction: it reports
    the installed engine's age for something the installed engine has.
    """
    known = available(api, exe)
    return [name for name in dict.fromkeys(names) if name not in known]


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="bgt api",
                                 description=__doc__.split("\n")[1],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("name", nargs="*", help="names to look up")
    ap.add_argument("--chm", help="path to bgt.chm (default: the usual install paths)")
    ap.add_argument("--cache", help="where to unpack it (default: a temp directory)")
    ap.add_argument("--list", metavar="SUBSTRING",
                    help="every documented name containing this")
    ap.add_argument("--exe", help="path to bgt.exe, whose registrations are "
                                  "consulted as well (default: the installed one)")
    ap.add_argument("--missing", action="store_true",
                    help="report which of the given names this engine lacks")
    ap.add_argument("--json", metavar="FILE", help="write the whole API as JSON")
    args = ap.parse_args(argv)

    try:
        api = read(args.chm, args.cache)
    except RuntimeError as exc:
        print("bgt api: %s" % exc, file=sys.stderr)
        return 2

    functions: Dict[str, List[str]] = api["functions"]        # type: ignore[assignment]
    types: Dict[str, Dict[str, List[str]]] = api["types"]     # type: ignore[assignment]
    reg = registered(args.exe)
    print("%d functions, %d types documented in %s"
          % (len(functions), len(types), api["source"]), file=sys.stderr)
    if reg:
        print("%d names and %d types registered by the engine itself"
              % (len(reg), len(registered_types(decls=reg))), file=sys.stderr)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(api, fh, indent=1, sort_keys=True)
        print("written to %s" % args.json)

    if args.missing:
        absent = missing(args.name, api, args.exe)
        for name in args.name:
            if name in absent:
                verdict = "NOT in this engine"
            elif name in functions or name in types:
                verdict = "documented"
            else:
                verdict = "registered, undocumented"
            print("%-24s %s" % (name, verdict))
        return 0

    if args.list:
        needle = args.list.lower()
        for name in sorted(functions):
            if needle in name.lower():
                print("  %s" % functions[name][0])
        for name in sorted(types):
            if needle in name.lower():
                print("  type %s  (%d methods, %d properties)"
                      % (name, len(types[name]["methods"]), len(types[name]["properties"])))
        return 0

    for name in args.name:
        if name in functions:
            for signature in functions[name]:
                print("  %s" % signature)
        elif name in types:
            entry = types[name]
            print("  type %s" % name)
            for signature in entry["methods"]:
                print("      %s" % signature)
            for signature in entry["properties"]:
                print("      %s" % signature)
        elif name in reg:
            for signature in reg[name]:
                print("  %s        [registered, not documented]" % signature)
        else:
            print("  %s: this engine neither documents nor registers it" % name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
