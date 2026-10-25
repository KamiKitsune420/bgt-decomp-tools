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


def missing(names: Sequence[str], api: Dict[str, object]) -> List[str]:
    """Which of these names the installed engine does not document.

    Primitives and the names the module declares itself are the caller's
    business to exclude; this only answers the documentation question.
    """
    known = documented(api)
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
    ap.add_argument("--missing", action="store_true",
                    help="report which of the given names are NOT documented")
    ap.add_argument("--json", metavar="FILE", help="write the whole API as JSON")
    args = ap.parse_args(argv)

    try:
        api = read(args.chm, args.cache)
    except RuntimeError as exc:
        print("bgt api: %s" % exc, file=sys.stderr)
        return 2

    functions: Dict[str, List[str]] = api["functions"]        # type: ignore[assignment]
    types: Dict[str, Dict[str, List[str]]] = api["types"]     # type: ignore[assignment]
    print("%d functions, %d types documented in %s"
          % (len(functions), len(types), api["source"]), file=sys.stderr)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(api, fh, indent=1, sort_keys=True)
        print("written to %s" % args.json)

    if args.missing:
        absent = missing(args.name, api)
        for name in args.name:
            print("%-24s %s" % (name, "NOT documented" if name in absent else "documented"))
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
        else:
            print("  %s: not documented by this engine" % name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
