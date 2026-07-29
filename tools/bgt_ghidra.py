"""
bgt_ghidra -- find, install and drive Ghidra for BGT reverse engineering.

Ghidra is **not** bundled: it is roughly a gigabyte unpacked and a new release
lands every few months, so a copy vendored here would be both large and stale.
This finds an existing install, offers to fetch one if there is none, and then
runs headless decompiles for you.

    python bgt_ghidra.py status                       what is installed
    python bgt_ghidra.py install                      download Ghidra (asks first)
    python bgt_ghidra.py install-extension <dir|zip>  install a Ghidra extension
    python bgt_ghidra.py decompile game.exe --string _builtin_function_
    python bgt_ghidra.py decompile game.exe --at 0x0041E2A0,0x0041DE20

`decompile` is the one that matters for this toolkit. Extending the reader means
transcribing `asCReader` out of the binary in front of you, and these two modes
cover how you actually find it:

  --string   decompile every function referencing a string. `_builtin_function_`
             lands on ReadDataType and ReadTypeInfo; "LoadByteCode failed" leads
             to ReadInner.
  --at       decompile specific addresses, once you know them.

## What it needs

A JDK 21 or newer -- Ghidra will not launch on anything older, and the JDK on
PATH is often an old one that is there for something else. `status` reports
what it found and where, and every command takes `--jdk` to override.
"""

import argparse
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple

GHIDRA_RELEASES_API = "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest"
MIN_JDK = 21

# Where a Ghidra install is likely to be, relative to this checkout and beyond.
SEARCH_HINTS = (
    "..", "../..", "~", "~/Downloads", "~/tools", "C:/", "C:/tools",
    "/opt", "/usr/local", "/usr/share",
)


# --------------------------------------------------------------------------
# discovery
# --------------------------------------------------------------------------

def _version_key(name: str) -> Tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", name)) or (0,)


def find_ghidra(extra: Optional[str] = None) -> Optional[str]:
    """Return the newest Ghidra install directory found, or None.

    A Ghidra install is identified by `support/analyzeHeadless` -- the launcher
    this module actually uses -- rather than by directory name, so a renamed or
    relocated copy is still found.
    """
    candidates: List[str] = []
    for root in ([extra] if extra else []) + [os.environ.get("GHIDRA_INSTALL_DIR", "")]:
        if root and _is_ghidra(root):
            return os.path.abspath(root)

    for hint in SEARCH_HINTS:
        base = os.path.abspath(os.path.expanduser(hint))
        if not os.path.isdir(base):
            continue
        try:
            entries = os.listdir(base)
        except OSError:
            continue
        for entry in entries:
            if "ghidra" not in entry.lower():
                continue
            path = os.path.join(base, entry)
            if _is_ghidra(path):
                candidates.append(path)

    if not candidates:
        return None
    return sorted(candidates, key=lambda p: _version_key(os.path.basename(p)))[-1]


def _is_ghidra(path: str) -> bool:
    return bool(path) and os.path.isfile(os.path.join(path, "support", _headless_name()))


def _find_under(root: str) -> Optional[str]:
    """A Ghidra install inside `root` only -- no fallback to system locations."""
    if _is_ghidra(root):
        return os.path.abspath(root)
    try:
        entries = sorted(os.listdir(root))
    except OSError:
        return None
    for entry in entries:
        path = os.path.join(root, entry)
        if _is_ghidra(path):
            return os.path.abspath(path)
    return None


def _headless_name() -> str:
    return "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"


def ghidra_version(install: str) -> str:
    """Read the version out of the install, for the extension directory name."""
    props = os.path.join(install, "Ghidra", "application.properties")
    try:
        with open(props, encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("application.version="):
                    return line.split("=", 1)[1].strip()
    except OSError:
        pass
    m = re.search(r"(\d+\.\d+(?:\.\d+)?)", os.path.basename(install))
    return m.group(1) if m else "unknown"


def find_jdk(extra: Optional[str] = None, minimum: int = MIN_JDK) -> Optional[str]:
    """A JDK home of at least `minimum`, or None.

    Checks the explicit override, JAVA_HOME, PATH, and the usual install roots.
    The JDK on PATH is frequently an old one kept for something else, so a
    too-old PATH java is skipped rather than reported as a find.
    """
    tried = []
    for home in filter(None, [extra, os.environ.get("JAVA_HOME")]):
        tried.append(home)
        if _jdk_version(home) >= minimum:
            return os.path.abspath(home)

    exe = shutil.which("java")
    if exe:
        home = os.path.dirname(os.path.dirname(exe))
        if _jdk_version(home) >= minimum:
            return home

    roots = [r"C:\Program Files\Java", r"C:\Program Files (x86)\Java",
             r"C:\Program Files\Eclipse Adoptium", r"C:\Program Files\Microsoft",
             "/usr/lib/jvm", "/Library/Java/JavaVirtualMachines"]
    best, best_v = None, 0
    for root in roots:
        if not os.path.isdir(root):
            continue
        for entry in os.listdir(root):
            home = os.path.join(root, entry)
            if os.name != "nt" and os.path.isdir(os.path.join(home, "Contents", "Home")):
                home = os.path.join(home, "Contents", "Home")
            v = _jdk_version(home)
            if v >= minimum and v > best_v:
                best, best_v = home, v
    return best


def _jdk_version(home: str) -> int:
    """Major version of the JDK at `home`, or 0 if it is not a usable JDK."""
    if not home or not os.path.isdir(home):
        return 0
    java = os.path.join(home, "bin", "java.exe" if os.name == "nt" else "java")
    if not os.path.isfile(java):
        return 0
    try:
        out = subprocess.run([java, "-version"], capture_output=True, text=True,
                             timeout=30)
    except (OSError, subprocess.SubprocessError):
        return 0
    text = (out.stderr or "") + (out.stdout or "")
    m = re.search(r'version "(\d+)(?:\.(\d+))?', text)
    if not m:
        return 0
    major = int(m.group(1))
    # 1.8 style numbering: the major version is the second component
    return int(m.group(2) or 0) if major == 1 else major


# --------------------------------------------------------------------------
# installing
# --------------------------------------------------------------------------

def latest_release() -> Tuple[str, str]:
    """(version, download URL) of the newest public Ghidra release."""
    import json
    import urllib.request
    req = urllib.request.Request(
        GHIDRA_RELEASES_API, headers={"Accept": "application/vnd.github+json",
                                      "User-Agent": "bgt-decomp-toolkit"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.load(resp)
    return pick_release_asset(data)


def pick_release_asset(release: Dict[str, Any]) -> Tuple[str, str]:
    """(version, url) for the public zip in a GitHub release payload.

    Split out from the network call so it can be checked against a recorded
    payload -- the parsing is the part that breaks when the release layout
    changes, and it is the part a live download would not exercise anyway.
    """
    for asset in release.get("assets", []):
        name = asset.get("name", "")
        if name.endswith(".zip") and "PUBLIC" in name:
            return release.get("tag_name", "?"), asset["browser_download_url"]
    raise RuntimeError("no PUBLIC .zip asset in the release payload")


def install_from_archive(archive: str, dest: str) -> str:
    """Unpack a Ghidra zip into `dest` and return the install directory.

    Separate from the download so the half that can actually be wrong -- the
    unpack, locating `analyzeHeadless`, making it executable -- is testable
    without moving a gigabyte.
    """
    import zipfile

    os.makedirs(dest, exist_ok=True)
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(dest)

    # Look ONLY under dest. `find_ghidra` falls back to searching the usual
    # install roots, which would happily return a Ghidra that was already on the
    # machine -- so a truncated or wrong archive reports success and every later
    # command silently uses a different install than the one just unpacked.
    install = _find_under(dest)
    if not install:
        raise RuntimeError(
            "unpacked %s but found no support/%s under %s -- not a Ghidra archive"
            % (os.path.basename(archive), _headless_name(), dest))
    if os.name != "nt":
        os.chmod(os.path.join(install, "support", _headless_name()), 0o755)
    return install


def install_ghidra(dest: str, assume_yes: bool = False) -> str:
    """Download and unpack Ghidra into `dest`. Returns the install directory."""
    version, url = latest_release()
    print("latest Ghidra release: %s" % version)
    print("  %s" % url)
    print("  unpacks to roughly 1 GB in %s" % os.path.abspath(dest))
    if not assume_yes and not _confirm("Download it now?"):
        print("not downloading. Install Ghidra yourself and pass --ghidra <dir>,")
        print("or set GHIDRA_INSTALL_DIR.")
        return ""

    tmp = os.path.join(tempfile.gettempdir(), os.path.basename(url))
    print("downloading to %s ..." % tmp)
    _download(url, tmp)
    print("unpacking ...")
    try:
        install = install_from_archive(tmp, dest)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    print("installed: %s" % install)
    return install


def _download(url: str, dest: str) -> None:
    import urllib.request
    with urllib.request.urlopen(url, timeout=120) as resp:
        total = int(resp.headers.get("Content-Length") or 0)
        done = 0
        with open(dest, "wb") as fh:
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                fh.write(chunk)
                done += len(chunk)
                if total:
                    sys.stderr.write("\r  %5.1f%%  %d/%d MB"
                                     % (100.0 * done / total,
                                        done >> 20, total >> 20))
                    sys.stderr.flush()
    sys.stderr.write("\n")


def _confirm(question: str) -> bool:
    if not sys.stdin or not sys.stdin.isatty():
        print("%s [not a terminal -- assuming no]" % question)
        return False
    try:
        return input("%s [y/N] " % question).strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False


def extensions_dir(install: str) -> str:
    """Where user-installed extensions go, which is NOT under the install.

    Ghidra loads them from the per-user directory:

        Windows   %APPDATA%\\ghidra\\ghidra_<version>_PUBLIC\\Extensions
        Linux     ~/.config/ghidra/ghidra_<version>_PUBLIC/Extensions
        macOS     ~/Library/ghidra/ghidra_<version>_PUBLIC/Extensions

    Dropping an extension into the install's own `Extensions/` looks right and
    does not load.
    """
    version = ghidra_version(install)
    folder = "ghidra_%s_PUBLIC" % version
    if os.name == "nt":
        base = os.environ.get("APPDATA") or os.path.expanduser("~/AppData/Roaming")
    elif platform.system() == "Darwin":
        base = os.path.expanduser("~/Library")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "ghidra", folder, "Extensions")


def install_extension(install: str, source: str) -> str:
    """Install an extension from a directory or a .zip into the user dir."""
    import zipfile

    target = extensions_dir(install)
    os.makedirs(target, exist_ok=True)

    if os.path.isfile(source) and source.lower().endswith(".zip"):
        with zipfile.ZipFile(source) as zf:
            names = zf.namelist()
            top = {n.split("/", 1)[0] for n in names if "/" in n}
            zf.extractall(target)
        name = sorted(top)[0] if len(top) == 1 else os.path.basename(source)[:-4]
    elif os.path.isdir(source):
        name = os.path.basename(os.path.normpath(source))
        dest = os.path.join(target, name)
        if os.path.exists(dest):
            shutil.rmtree(dest)
        shutil.copytree(source, dest)
    else:
        raise SystemExit("extension source must be a directory or a .zip: %s" % source)

    print("installed %s -> %s" % (name, target))
    print("Restart Ghidra, then enable it under File > Configure > Extensions.")
    print("Note: extensions that are GUI plugins (the MCP servers among them) do")
    print("nothing in headless mode -- headless uses -postScript instead, which")
    print("is what `bgt_ghidra.py decompile` does.")
    return os.path.join(target, name)


# --------------------------------------------------------------------------
# driving it
# --------------------------------------------------------------------------

DUMP_AT = r'''
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.io.*;

public class BgtDumpAt extends GhidraScript {
    public void run() throws Exception {
        String addrs = System.getenv("BGT_ADDRS");
        String out = System.getenv("BGT_OUT");
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        PrintWriter pw = new PrintWriter(new FileWriter(out));
        for (String a : addrs.split(",")) {
            a = a.trim();
            if (a.isEmpty()) continue;
            Address ad = currentProgram.getAddressFactory().getAddress(a);
            Function f = getFunctionContaining(ad);
            pw.println("//////// " + a + "  " + (f == null ? "<none>" : f.getName()));
            if (f == null) { pw.println(); continue; }
            DecompileResults r = di.decompileFunction(f, 120, monitor);
            pw.println(r != null && r.decompileCompleted()
                       ? r.getDecompiledFunction().getC() : "// decompile failed");
            pw.println();
        }
        pw.close();
        println("wrote " + out);
    }
}
'''

DUMP_STRING = r'''
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class BgtDumpString extends GhidraScript {
    public void run() throws Exception {
        String needle = System.getenv("BGT_STR");
        String out = System.getenv("BGT_OUT");
        PrintWriter pw = new PrintWriter(new FileWriter(out));
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        Set<Function> targets = new LinkedHashSet<>();
        DataIterator it = currentProgram.getListing().getDefinedData(true);
        while (it.hasNext()) {
            Data dd = it.next();
            Object v = dd.getValue();
            if (!(v instanceof String) || !((String) v).equals(needle)) continue;
            pw.println("// " + needle + " at " + dd.getAddress());
            ReferenceIterator ri = currentProgram.getReferenceManager()
                    .getReferencesTo(dd.getAddress());
            while (ri.hasNext()) {
                Function f = getFunctionContaining(ri.next().getFromAddress());
                if (f != null) targets.add(f);
            }
        }
        pw.println("// " + targets.size() + " referencing function(s)");
        for (Function f : targets) {
            pw.println("//////// " + f.getEntryPoint() + "  " + f.getName());
            DecompileResults r = di.decompileFunction(f, 120, monitor);
            pw.println(r != null && r.decompileCompleted()
                       ? r.getDecompiledFunction().getC() : "// decompile failed");
            pw.println();
        }
        pw.close();
        println("wrote " + out + " (" + targets.size() + " functions)");
    }
}
'''


def decompile(install: str, jdk: str, binary: str, out: str,
              addrs: Optional[str] = None, needle: Optional[str] = None,
              project_dir: Optional[str] = None, max_mem: str = "2G") -> int:
    """Import `binary` headless and decompile the functions asked for."""
    scripts = tempfile.mkdtemp(prefix="bgt_ghidra_")
    if addrs:
        script, body = "BgtDumpAt.java", DUMP_AT
    else:
        script, body = "BgtDumpString.java", DUMP_STRING
    with open(os.path.join(scripts, script), "w", encoding="utf-8") as fh:
        fh.write(body.lstrip())

    # analyzeHeadless rejects any path element starting with '.', so a relative
    # project directory ("../foo") dies with an unhelpful IllegalArgumentException.
    project_dir = os.path.abspath(project_dir or tempfile.mkdtemp(prefix="bgt_gproj_"))
    os.makedirs(project_dir, exist_ok=True)
    name = os.path.splitext(os.path.basename(binary))[0]

    env = dict(os.environ)
    env["JAVA_HOME"] = jdk
    env["GHIDRA_HEADLESS_MAXMEM"] = max_mem
    env["BGT_OUT"] = os.path.abspath(out)
    if addrs:
        env["BGT_ADDRS"] = addrs
    if needle:
        env["BGT_STR"] = needle

    headless = os.path.join(install, "support", _headless_name())
    existing = os.path.join(project_dir, name + ".gpr")
    cmd = [headless, project_dir, name]
    if os.path.exists(existing):
        cmd += ["-process", "-noanalysis"]
    else:
        cmd += ["-import", os.path.abspath(binary),
                "-processor", "x86:LE:32:default"]
    cmd += ["-scriptPath", scripts, "-postScript", script]

    print("running headless (%s, JDK at %s)" % (os.path.basename(install), jdk))
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
    tail = [ln for ln in (proc.stdout or "").splitlines()
            if "wrote" in ln or "ERROR" in ln or "Analysis succeeded" in ln]
    for ln in tail[-6:]:
        print("  " + ln.strip())
    if not os.path.exists(out):
        print("no output produced; last stderr:", file=sys.stderr)
        print((proc.stderr or "")[-800:], file=sys.stderr)
        return 1
    print("decompiled -> %s" % out)
    return 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _resolve(args, need_jdk: bool = True) -> Tuple[str, str]:
    install = find_ghidra(getattr(args, "ghidra", None))
    if not install:
        raise SystemExit(
            "no Ghidra install found. Run `python bgt_ghidra.py install`, "
            "or pass --ghidra <dir> / set GHIDRA_INSTALL_DIR.")
    jdk = ""
    if need_jdk:
        jdk = find_jdk(getattr(args, "jdk", None)) or ""
        if not jdk:
            raise SystemExit(
                "no JDK %d+ found -- Ghidra will not launch without one. "
                "Install a recent JDK (Temurin is fine) and pass --jdk <dir>."
                % MIN_JDK)
    return install, jdk


def cmd_status(args) -> int:
    install = find_ghidra(args.ghidra)
    jdk = find_jdk(args.jdk)
    print("ghidra      %s" % (install or "NOT FOUND"))
    if install:
        print("  version   %s" % ghidra_version(install))
        print("  headless  %s" % os.path.join(install, "support", _headless_name()))
        print("  extensions %s" % extensions_dir(install))
    print("jdk %d+      %s" % (MIN_JDK, jdk or "NOT FOUND"))
    if jdk:
        print("  version   %d" % _jdk_version(jdk))
    ready = bool(install and jdk)
    print()
    print("ready to decompile: %s" % ("yes" if ready else "no"))
    return 0 if ready else 1


def cmd_install(args) -> int:
    if find_ghidra(args.ghidra) and not args.force:
        print("Ghidra is already installed: %s" % find_ghidra(args.ghidra))
        print("pass --force to install another copy anyway")
        return 0
    dest = args.dest or os.path.abspath("ghidra")
    return 0 if install_ghidra(dest, assume_yes=args.yes) else 1


def cmd_install_extension(args) -> int:
    install, _ = _resolve(args, need_jdk=False)
    install_extension(install, args.source)
    return 0


def cmd_decompile(args) -> int:
    install, jdk = _resolve(args)
    if not args.at and not args.string:
        raise SystemExit("pass --at <hex,...> or --string <literal>")
    return decompile(install, jdk, args.binary, args.output,
                     addrs=args.at, needle=args.string,
                     project_dir=args.project, max_mem=args.max_mem)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="bgt_ghidra", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ghidra", help="Ghidra install directory")
    ap.add_argument("--jdk", help="JDK home (needs %d or newer)" % MIN_JDK)
    sub = ap.add_subparsers(dest="command", metavar="<command>")

    p = sub.add_parser("status", help="report what is installed")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("install", help="download the latest Ghidra")
    p.add_argument("--dest", help="where to unpack (default ./ghidra)")
    p.add_argument("-y", "--yes", action="store_true", help="do not ask first")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_install)

    p = sub.add_parser("install-extension", help="install a Ghidra extension")
    p.add_argument("source", help="extension directory or .zip")
    p.set_defaults(func=cmd_install_extension)

    p = sub.add_parser("decompile", help="headless decompile out of a binary")
    p.add_argument("binary")
    p.add_argument("-o", "--output", default="decompiled.c")
    p.add_argument("--at", help="comma-separated addresses, e.g. 0x0041E2A0")
    p.add_argument("--string", help="decompile everything referencing this literal")
    p.add_argument("--project", help="reuse/create a Ghidra project here")
    p.add_argument("--max-mem", default="2G",
                   help="headless heap cap (default 2G; the GUI analyser OOMs "
                        "on small machines)")
    p.set_defaults(func=cmd_decompile)
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    if not getattr(args, "command", None):
        ap.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
