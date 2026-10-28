"""
bgt_compile -- run recovered source through BGT's own compiler and read back
every diagnostic it produces.

This is the check that decides whether recovered source is real. Output that
looks like BGT is not BGT; the compiler that shipped with the engine is the
only authority on the language it accepts and on the exact signature of every
registered function.

## How it has to be driven

`bgt.exe` takes a script path and *runs* it. There is no console mode and no
switches -- it is a GUI program, and it reports compilation through a window of
its own class (`bgtgame`) rather than through stdout or an exit code. The window
carries no child controls: the message is exposed only to the accessibility
tree, which is also how the engine's intended audience reads it.

So the driver launches the compiler, waits for one of two outcomes, and reads
the text out of the window through UI Automation:

    window titled "Compilation Error"   ->  diagnostics, parsed below
    the process exits on its own        ->  it compiled

A timeout is a third outcome and is reported as one rather than guessed at: a
script that compiles *and then runs* holds a window open forever, which is why
a check neuters the entry point instead of hoping the game exits (see
`neutered`).

The text is identical to what the engine shows a developer:

    File: C:\\...\\game.bgt
    On line: 5 (5)
    Line:     ::garbage_collect(int(1000));
    Error: No matching signatures to '::garbage_collect(const int)'
    ...
    Information: Candidates are:
    Information: void garbage_collect()

Candidate lists are kept with the diagnostic they belong to: when a recovered
call does not match, the compiler prints the signature it *does* have, which
says what the recovered code got wrong -- an argument too many, or a type.

## What a clean compile does and does not prove

It proves the source is valid BGT and every call resolves. It does not prove
the program does the same thing as the original: an argument dropped to make a
call match, or a condition inverted, compiles perfectly. Behaviour is checked
by comparing against source nobody here wrote (`bgt libcheck`) and by running
the result -- never by the compiler alone.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

DEFAULT_COMPILERS = (
    r"C:\Program Files (x86)\BGT\bgt.exe",
    r"C:\Program Files\BGT\bgt.exe",
)

# One PowerShell driver, written beside the script it checks. It launches the
# compiler, polls for either outcome, prints a JSON record and always kills the
# process it started -- a GUI left running would hold the next check's window.
DRIVER = r"""
# **Never name a parameter `$Switch`.** Declaring one silently breaks every
# `switch` statement in the script: the statement below matched nothing, so
# `$flag` was always empty, the driver *ran* the script instead of compiling
# it, and a disarmed entry point exiting 0 was read as `compiled cleanly`. So
# `bgt compile --build` reported success and produced no executable, in either
# mode, for as long as it existed -- while `bgt.exe -C"<path>"` by hand built
# one fine. Run mode never passed a flag, so it was correct by accident and
# hid this completely. `-Mode` is the same string by another name.
param([string]$Compiler, [string]$Script, [string]$WorkDir, [int]$TimeoutMs,
      [string]$Mode = "run")
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public class BgtKeys {
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
}
"@
# `-c<file>` / `-C<file>` compile (debug / release) and take NO space before
# the path -- the shell verbs the installer registers are the documentation
# for that. Without a switch the engine runs the script instead.
# The mode is passed by name, never as "-c": PowerShell would read a value
# that starts with a dash as the next parameter's name.
$flag = switch ($Mode) { "debug" { "-c" } "release" { "-C" } default { "" } }
$arguments = if ($flag -eq "") { "`"$Script`"" } else { "$flag`"$Script`"" }
$proc = Start-Process -FilePath $Compiler -ArgumentList $arguments `
                      -WorkingDirectory $WorkDir -PassThru
$root = [System.Windows.Automation.AutomationElement]::RootElement
$cond = New-Object System.Windows.Automation.PropertyCondition(
            [System.Windows.Automation.AutomationElement]::ProcessIdProperty, $proc.Id)
$deadline = (Get-Date).AddMilliseconds($TimeoutMs)
$outcome = "timeout"
$title = ""
$text = ""
# Whether a window that is NOT the compilation report appeared, i.e. the
# script itself got as far as drawing. Running past the report is the whole
# point of run mode, so breaking on the report would answer the wrong
# question.
$ran = $false
# Panes seen on a window that is NOT the compilation report, i.e. whatever the
# script itself put on screen.
$said = @()
while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { $outcome = "exited"; break }
    $window = $null
    try { $window = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $cond) } catch {}
    if ($window -ne $null) {
        $title = $window.Current.Name
        if ($title -ne "") {
            # Any window of its own is an outcome: the report window, or the
            # script's own first window, which means it got past compiling.
            $panes = $window.FindAll([System.Windows.Automation.TreeScope]::Descendants,
                        (New-Object System.Windows.Automation.PropertyCondition(
                            [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
                            [System.Windows.Automation.ControlType]::Pane)))
            $parts = @()
            foreach ($pane in $panes) {
                $name = $pane.Current.Name
                # Buttons are furniture, and their labels read exactly like a
                # one-word message: `-- and said: Continue` is a dialog's own
                # button, not anything the script reported. The diagnostics
                # are the long pane.
                if ($name -ne "" -and
                    @("Exit","OK","Continue","Cancel","Yes","No","Close") -notcontains $name) {
                    $parts += $name
                }
            }
            $isReport = ($title -like "Compilation*")
            if ($isReport -or $text -eq "") { $text = $parts -join "`n" }
            # What the script itself said, kept apart from what the compiler
            # said about the source. A clean compile is silent about whether
            # the project has the files it opens, and the engine is not.
            if (-not $isReport) {
                foreach ($part in $parts) {
                    if ($said -notcontains $part) { $said += $part }
                }
            }
            $outcome = "window"
            if (($Mode -eq "run") -and (-not $isReport)) {
                # The script's own window: it compiled and started.
                $ran = $true
                break
            }
            # The report window is informational -- it appears for warnings as
            # well as errors -- and the compiler waits on it before writing the
            # executable or running the script. Dismiss it and let the process
            # go on; killing it here leaves a truncated file with no trailer,
            # which then starts and exits without running anything.
            $handle = [IntPtr]$window.Current.NativeWindowHandle
            [BgtKeys]::SetForegroundWindow($handle) | Out-Null
            [BgtKeys]::PostMessage($handle, 0x0100, [IntPtr]0x0D, [IntPtr]0) | Out-Null
            [BgtKeys]::PostMessage($handle, 0x0101, [IntPtr]0x0D, [IntPtr]0) | Out-Null
            Start-Sleep -Milliseconds 1200
        }
    }
    Start-Sleep -Milliseconds 150
}
if (-not $proc.HasExited) { try { $proc.Kill() } catch {} }
$exit = -1
if ($proc.HasExited) { $exit = $proc.ExitCode }
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
@{ outcome = $outcome; title = $title; text = $text; exit = $exit; ran = $ran;
   said = ($said -join "`n") } |
    ConvertTo-Json -Compress -Depth 3
"""

# "On line: 5 (5)" -- the line, then the column in parentheses.
LINE_RE = re.compile(r"^On line: (\d+) \((\d+)\)$")


@dataclass
class Diagnostic:
    kind: str                      # Error | Warning | Information
    file: str = ""
    line: int = 0
    column: int = 0
    message: str = ""
    source: str = ""               # the source line the compiler echoed
    candidates: List[str] = field(default_factory=list)

    def __str__(self) -> str:
        where = "%s:%d:%d" % (os.path.basename(self.file) or "?",
                              self.line, self.column)
        out = "%-7s %-28s %s" % (self.kind.lower(), where, self.message)
        for candidate in self.candidates:
            out += "\n%-7s %-28s   candidate: %s" % ("", "", candidate)
        return out


@dataclass
class Report:
    outcome: str                   # compiled | errors | started | timeout | nodriver
    diagnostics: List[Diagnostic] = field(default_factory=list)
    title: str = ""
    raw: str = ""
    exit_code: int = -1

    @property
    def ok(self) -> bool:
        # A report window with warnings but no errors is a successful compile:
        # the engine shows one for either, and only an error stops it.
        return (self.outcome in ("compiled", "started", "errors")
                and not self.errors)

    @property
    def errors(self) -> List[Diagnostic]:
        return [d for d in self.diagnostics if d.kind == "Error"]

    #: What the script itself put on screen, as opposed to what the compiler
    #: said about the source. The driver keeps them apart by which window the
    #: text came from, which is exact; filtering one stream by what the lines
    #: look like is not -- it reported a dialog's `Continue` button as
    #: something Crazy Party had said.
    said: str = ""

    @property
    def runtime_complaints(self) -> List[str]:
        """What the engine said at run time.

        A clean compile says nothing about whether the project has the files it
        opens, and the engine does not fail quietly about that: Super Egg Hunt
        compiled cleanly, ran, and said `could not load pack data/bgm.dat.`
        That line is the difference between "it works" and "it runs with no
        sound", so it is not left in `raw` for someone to find.
        """
        return [line.strip() for line in (self.said or "").splitlines()
                if line.strip()]

    def summary(self) -> str:
        if self.outcome == "compiled":
            return "compiled cleanly"
        if self.outcome == "started":
            warnings = sum(1 for d in self.diagnostics if d.kind == "Warning")
            said = self.runtime_complaints
            return ("compiled%s, and ran: it opened a window of its own%s%s"
                    % (" with %d warning(s)" % warnings if warnings else " cleanly",
                       " titled %r" % self.title if self.title else "",
                       "" if not said else
                       " -- and said: %s" % "; ".join(said[:3])))
        if self.outcome == "crashed":
            return "the compiler itself died: exit 0x%08X%s" % (
                self.exit_code & 0xFFFFFFFF,
                " (access violation)" if self.exit_code == -1073741819 else "")
        counts: Dict[str, int] = {}
        for d in self.diagnostics:
            counts[d.kind] = counts.get(d.kind, 0) + 1
        if self.outcome == "errors":
            if not counts.get("Error"):
                return "compiled with %d warning(s)" % counts.get("Warning", 0)
            return "%d error(s), %d warning(s)" % (counts.get("Error", 0),
                                                   counts.get("Warning", 0))
        if self.outcome == "nodriver":
            # The check did not run. Saying only "nodriver" reads like a
            # result, and a result is exactly what this is not.
            return "the check could not run: %s" % (self.raw or "no reason recorded")
        return self.outcome


_LOCK = os.path.join(tempfile.gettempdir(), "bgt_compile.lock")


def find_compiler(explicit: Optional[str] = None) -> Optional[str]:
    for path in ([explicit] if explicit else []) + list(DEFAULT_COMPILERS):
        if path and os.path.isfile(path):
            return path
    return None


#: the shell verbs BGT's installer registers for a `.bgt` file, and which of
#: them a person actually reaches: `open` is double-clicking it.
SHELL_VERBS = ("open", "run", "compile", "compile_debug", "compile_release")

_VERB_EXE = re.compile(r'^"([^"]+)"')


#: Where the shell resolves a ProgID from, in the order it wins. `HKEY_CLASSES_ROOT`
#: is the merged view and therefore the authoritative answer; the other two are
#: named only so a failure can say which hive it came from. **HKCU outranks HKLM**,
#: which is what makes a per-user override possible without an administrator -- and
#: reading HKLM first, as this once did, reports the overridden value as the live one.
_VERB_HIVES = ("HKEY_CLASSES_ROOT", "HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE")

#: The key a verb's command lives under, per hive. HKCR is already rooted at the
#: class table; the other two reach it through `SOFTWARE\\Classes`.
_VERB_KEYS = {
    "HKEY_CLASSES_ROOT": r"bgtscript\shell\%s\command",
    "HKEY_CURRENT_USER": r"SOFTWARE\Classes\bgtscript\shell\%s\command",
    "HKEY_LOCAL_MACHINE": r"SOFTWARE\Classes\bgtscript\shell\%s\command",
}


def verb_commands(hive: str = "HKEY_CLASSES_ROOT") -> Dict[str, str]:
    """{verb: the whole command string} for a `.bgt` file, out of one hive.

    The command and not just the executable, because repointing a verb has to
    keep its switch: `open` and `run` pass the script bare, `compile` passes
    `-c"%1"` and `compile_release` `-C"%1"`, and the switch is the difference
    between compiling the script and running it.
    """
    if hive not in _VERB_HIVES:
        raise ValueError("unknown hive %r; expected one of %s"
                         % (hive, ", ".join(_VERB_HIVES)))
    try:
        import winreg
    except ImportError:                      # not Windows
        return {}
    root = getattr(winreg, hive)
    found: Dict[str, str] = {}
    for verb in SHELL_VERBS:
        try:
            with winreg.OpenKey(root, _VERB_KEYS[hive] % verb) as handle:
                command, _ = winreg.QueryValueEx(handle, "")
        except OSError:
            continue
        found[verb] = str(command).strip()
    return found


def shell_verbs() -> Dict[str, str]:
    """{verb: bgt.exe} as the shell would run it for a `.bgt` file.

    Worth reading, because **more than one BGT can be installed and the newest
    one does not win**. Installing 1.0 after 1.3 leaves `open`, `run` and
    `compile` pointing at 1.0 while only `compile_debug` and `compile_release`
    still point at 1.3 -- so double-clicking a recovered script compiles it
    with the engine that has no default arguments, and every `bool x = false`
    in a signature comes back as `Expected ')' or ','`.

    That is a hundred errors in a project that compiles cleanly one verb over,
    and nothing in the report could see it, because the report only knew about
    the compiler *this toolkit* chose.

    **Read the merged view, not HKLM.** This looked in HKLM first and stopped
    there, which is the wrong way round: the shell reads `HKEY_CLASSES_ROOT`,
    where a per-user key outranks the machine one. With an override in place
    the old order went on reporting the *overridden* path, so the one check
    that could confirm the fix would have denied it.
    """
    out: Dict[str, str] = {}
    for verb, command in verb_commands().items():
        match = _VERB_EXE.match(command)
        if match and os.path.isfile(match.group(1)):
            out[verb] = match.group(1)
    return out


#: The verbs a person reaches by hand, which are exactly the ones a stale
#: install captures: double-clicking is `open`, "Run Script" is `run`, and
#: "Compile Script" is `compile`. `compile_debug` and `compile_release` are
#: left out because BGT's installer does not take them.
HAND_VERBS = ("open", "run", "compile")


def repoint_verbs(compiler: Optional[str] = None,
                  verbs: Sequence[str] = HAND_VERBS,
                  dry_run: bool = False) -> List[Tuple[str, str, str]]:
    """Point the hand-reached shell verbs at a BGT that can parse a project.

    Returns `(verb, was, now)` for each verb changed.

    Three things decide the shape of this, and each one is why it is safe to
    offer at all:

    - **It writes HKCU, never HKLM.** The machine key needs an administrator
      and would change the association for every account; the per-user key
      needs neither and wins anyway. So this is a change one person can make
      and one person can undo.
    - **The undo is structural.** `restore_verbs()` deletes the override, and
      HKLM's own value applies again *by construction* -- there is no saved
      copy to lose, and no way for the restore to write a path that was never
      there.
    - **Only the executable is substituted.** The rest of the command string
      is kept verbatim, so each verb keeps the switch that decides whether it
      runs the script or compiles it. Rebuilding the command from a table of
      switches would work until BGT's installer used a different one.

    It refuses rather than guesses when the target cannot parse a default
    argument: repointing a verb at a *second* engine with the same gap would
    report success and change nothing that matters.
    """
    try:
        import winreg
    except ImportError:                      # not Windows
        raise RuntimeError("shell verbs are a Windows thing")

    target = find_compiler(compiler)
    if not target:
        raise RuntimeError("no bgt.exe found to point the verbs at")
    if not capabilities(target).get("default_arguments", False):
        raise RuntimeError(
            "%s cannot parse default arguments either, so pointing the shell "
            "at it would fix nothing. Pass --compiler with the path to a "
            "BGT 1.3 install." % target)

    live = verb_commands()
    changed: List[Tuple[str, str, str]] = []
    for verb in verbs:
        command = live.get(verb)
        if not command:
            continue
        match = _VERB_EXE.match(command)
        if not match:
            continue
        was = match.group(1)
        if os.path.normcase(was) == os.path.normcase(target):
            continue
        rebuilt = '"%s"%s' % (target, command[match.end():])
        if not dry_run:
            key = _VERB_KEYS["HKEY_CURRENT_USER"] % verb
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key) as handle:
                winreg.SetValueEx(handle, "", 0, winreg.REG_SZ, rebuilt)
        changed.append((verb, was, target))
    return changed


def restore_verbs() -> List[str]:
    """Delete the per-user verb overrides, so the machine's own values apply.

    Returns the verbs that had an override. Nothing is reconstructed: removing
    the key that shadows HKLM is the whole undo, which is why this cannot put
    back a path that was never registered.
    """
    try:
        import winreg
    except ImportError:                      # not Windows
        return []
    removed: List[str] = []
    for verb in SHELL_VERBS:
        # Deepest first: a key with subkeys cannot be deleted.
        base = r"SOFTWARE\Classes\bgtscript\shell\%s" % verb
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, base + r"\command")
        except OSError:
            continue
        removed.append(verb)
        for dead in (base, r"SOFTWARE\Classes\bgtscript\shell",
                     r"SOFTWARE\Classes\bgtscript"):
            try:                             # only if now empty
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, dead)
            except OSError:
                break
    return removed


def verb_warnings(needs_default_args: bool = True) -> List[str]:
    """Shell verbs whose BGT cannot parse what a recovered project contains.

    Only the verbs a person reaches by hand are worth reporting, and only when
    the answer is actually different from the one the checked compiler gave --
    `capabilities` caches per executable, so asking about a second install
    costs one small compile.
    """
    if not needs_default_args:
        return []
    notes: List[str] = []
    for verb, exe in sorted(shell_verbs().items()):
        if not capabilities(exe).get("default_arguments", True):
            notes.append(
                "the shell's `%s` verb for a .bgt file runs %s, which cannot "
                "parse default arguments -- opening this project that way "
                "reports `Expected ')' or ','` on every signature that has "
                "one. Use \"Compile Script (Debug)\" or pass --compiler."
                % (verb, exe))
    return notes


#: a one-line script whose only unusual feature is a default argument, which
#: is how the compiler is asked whether it has them.
_DEFAULT_ARG_PROBE = chr(10).join([
    "int f(int a, bool b = false) { return a; }",
    "void main() { f(1); }",
    "",
])

_CAPABILITIES: Dict[str, Dict[str, bool]] = {}

#: where the answer is remembered between runs. Probing means launching the
#: compiler, and a compiler that rejects the probe shows a modal error dialog
#: -- which lands on whoever is at the machine. Asking once per install is
#: enough: the answer cannot change unless the executable does, so the key
#: includes its size and mtime.
_CAPS_CACHE = os.path.join(tempfile.gettempdir(), "bgt_capabilities.json")


def _cache_key(exe: str) -> str:
    try:
        info = os.stat(exe)
        return "%s|%d|%d" % (os.path.normcase(exe), info.st_size,
                             int(info.st_mtime))
    except OSError:
        return os.path.normcase(exe)


def _load_caps() -> Dict[str, Dict[str, bool]]:
    try:
        with open(_CAPS_CACHE, "r", encoding="utf-8") as fh:
            stored = json.load(fh)
        return stored if isinstance(stored, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_caps(cache: Dict[str, Dict[str, bool]]) -> None:
    try:
        with open(_CAPS_CACHE, "w", encoding="utf-8") as fh:
            json.dump(cache, fh)
    except OSError:
        pass                              # a cache that cannot be written is
                                          # a slower answer, not a wrong one


def capabilities(compiler: Optional[str] = None) -> Dict[str, bool]:
    """What this BGT can parse, asked rather than assumed.

    There is no version string in `bgt.exe` and no version metadata on the
    file, so the only way to tell two installs apart is to put something to
    them. BGT 1.0 does not support **default arguments at all**, and a
    recovered module uses them wherever the original did, so compiling a
    perfectly good project with 1.0 produces a cascade that reads as a broken
    decompilation: `Expected ')' or ','` at the `=`, then "Expected method or
    property", then "Unexpected token '}'" at the end of the class.

    That happened, and the report said nothing about which compiler it had
    used, which is what made it look like the recovery's fault.
    """
    exe = find_compiler(compiler)
    if exe is None:
        return {}
    if exe in _CAPABILITIES:
        return _CAPABILITIES[exe]
    key = _cache_key(exe)
    stored = _load_caps()
    if key in stored:
        _CAPABILITIES[exe] = stored[key]
        return stored[key]
    folder = tempfile.mkdtemp(prefix="bgtcaps_")
    script = os.path.join(folder, "probe.bgt")
    try:
        with open(script, "w", encoding="utf-8") as fh:
            fh.write(_DEFAULT_ARG_PROBE)
        report = check(script, compiler=exe, timeout=60.0, build="debug")
        # **"No errors" is only an answer when the check ran.** `nodriver`,
        # `timeout` and `crashed` carry no diagnostics, so `not report.errors`
        # reads as "this compiler is fine" -- and that is how BGT 1.0 came to
        # be reported as supporting default arguments while a project
        # compiled against it produced a hundred `Expected ')' or ','`. One
        # busy lock was enough, because two checks cannot run at once.
        if report.outcome not in ("compiled", "errors", "started"):
            return {}                     # unknown, and not cached: ask again
        found = {"default_arguments": not report.errors}
    except Exception:
        return {}
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    _CAPABILITIES[exe] = found
    stored[key] = found
    _save_caps(stored)
    return found


def parse(text: str) -> List[Diagnostic]:
    """Parse the engine's report into one diagnostic per message.

    The format is a blank-line-separated run of records, each naming a file, a
    line and one message. `Information: Candidates are:` introduces the
    signatures the compiler *does* have for the call that just failed, so those
    attach to the preceding error rather than standing as messages of their own
    -- that list is the most useful thing in the report.
    """
    out: List[Diagnostic] = []
    current: Dict[str, object] = {}
    expecting_candidates = False

    def flush() -> None:
        nonlocal current
        kind = current.get("kind")
        if kind:
            out.append(Diagnostic(kind=str(kind), file=str(current.get("file", "")),
                                  line=int(current.get("line", 0) or 0),
                                  column=int(current.get("column", 0) or 0),
                                  message=str(current.get("message", "")),
                                  source=str(current.get("source", ""))))
        current = {}

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line.strip():
            continue
        if line.startswith("File: "):
            flush()
            current["file"] = line[6:]
            continue
        match = LINE_RE.match(line.strip())
        if match:
            current["line"], current["column"] = match.group(1), match.group(2)
            continue
        if line.startswith("Line:"):
            current["source"] = line[5:].strip()
            continue
        for kind in ("Error", "Warning", "Information"):
            prefix = kind + ": "
            if not line.startswith(prefix):
                continue
            message = line[len(prefix):]
            if kind == "Information":
                if message.startswith("Candidates are"):
                    # The list that follows belongs to the error above it.
                    # The marker itself is not a diagnostic.
                    expecting_candidates = bool(out)
                    current = {}
                    break
                if expecting_candidates and out:
                    out[-1].candidates.append(message)
                    current = {}
                    break
            else:
                # Any error or warning ends the candidate list. Without this
                # the first list swallowed every later message in the report:
                # 1,800 diagnostics came back as seven.
                expecting_candidates = False
            current["kind"] = kind
            current["message"] = message
            flush()
            break
        else:
            # A continuation of whatever message is open (messages can wrap).
            if out and not current:
                out[-1].message += " " + line.strip()
    flush()
    return out


def check(script: str, compiler: Optional[str] = None, timeout: float = 60.0,
          keep_driver: bool = False, build: Optional[str] = None,
          workdir: Optional[str] = None) -> Report:
    """Compile one script and return every diagnostic the engine reported.

    `build` asks for a real compile rather than a run: "debug" (`-c`) or
    "release" (`-C`), which writes an executable beside the script. That is
    the better check, because nothing of the program runs -- a game cannot
    open a window and sit there -- and it is what proves the whole module
    reaches the engine.

    `workdir` is where the script *runs*, which is not always where it lives.
    An include resolves against the including script's directory and a data
    file against the working directory, so a staged copy needs the two to be
    different: the copy's includes point back at the project (`stage`), and
    its working directory has to be the project or `set_sound_storage
    ("data/bgm.dat")` cannot find a pack that is sitting right there. It
    defaults to the script's own directory.
    """
    exe = find_compiler(compiler)
    if exe is None:
        return Report(outcome="nodriver",
                      raw="no bgt.exe found -- pass --compiler <path to bgt.exe>")
    with _one_at_a_time(timeout) as held:
        if not held:
            return Report(outcome="nodriver",
                          raw="another compile check still holds %s after %ds"
                              % (_LOCK, int(timeout)))
        return _check(exe, script, timeout, keep_driver, build, workdir)


@contextlib.contextmanager
def _one_at_a_time(timeout: float):
    """Serialise compile checks across processes.

    `bgt.exe` is a GUI program driven through the accessibility tree, and two
    of them at once do not both get read: one run returns `nodriver` with
    nothing to say. Two titles were checked in parallel here and one came back
    blank, which looks like a broken check rather than a busy one -- so they
    queue instead, and a queue that never clears says so.
    """
    deadline = time.time() + max(timeout, 60.0)
    handle = None
    while handle is None and time.time() < deadline:
        try:
            handle = os.open(_LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            # A lock left behind by a killed run would block every later
            # check forever, so an old one is cleared rather than waited on.
            try:
                if time.time() - os.path.getmtime(_LOCK) > max(timeout, 60.0) * 2:
                    os.unlink(_LOCK)
                    continue
            except OSError:
                pass
            time.sleep(0.5)
    try:
        yield handle is not None
    finally:
        if handle is not None:
            os.close(handle)
            try:
                os.unlink(_LOCK)
            except OSError:
                pass


def _check(exe: str, script: str, timeout: float, keep_driver: bool,
           build: Optional[str], workdir: Optional[str] = None) -> "Report":
    script = os.path.abspath(script)
    workdir = os.path.abspath(workdir) if workdir else os.path.dirname(script)
    fd, driver = tempfile.mkstemp(suffix=".ps1", prefix="bgtcheck_")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(DRIVER)
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-File", driver,
             "-Compiler", exe, "-Script", script, "-WorkDir", workdir,
             "-TimeoutMs", str(int(timeout * 1000)),
             "-Mode", build or "run"],
            capture_output=True, stdin=subprocess.DEVNULL, timeout=timeout + 60,
            # The report echoes source lines, which carry whatever bytes the
            # game's string literals do; decoded with the console's own
            # codepage that raises and the whole check is lost.
            encoding="utf-8", errors="replace")
    finally:
        if not keep_driver:
            try:
                os.unlink(driver)
            except OSError:
                pass

    payload = (proc.stdout or "").strip()
    start = payload.find("{")
    if start < 0:
        return Report(outcome="nodriver",
                      raw="driver produced no result: %s%s" % (payload, proc.stderr))
    try:
        result = json.loads(payload[start:])
    except ValueError as exc:
        return Report(outcome="nodriver", raw="unreadable driver result (%s): %s"
                                              % (exc, payload))

    title = result.get("title") or ""
    text = result.get("text") or ""
    said = result.get("said") or ""
    raw_exit = result.get("exit", -1)
    # `or -1` here would turn a clean exit (0, the success case) into -1.
    exit_code = -1 if raw_exit is None else int(raw_exit)
    if result.get("outcome") == "exited":
        # A clean exit is the compile-only success case: nothing was reported
        # and the disarmed entry point returned. Any other status is the
        # compiler itself failing -- 0xC0000005 for an access violation, which
        # it does silently, with no window and no message. Read as success it
        # would make a module that crashes the compiler look perfect.
        #
        # "Nothing was reported" has to be checked, not assumed. The engine
        # reports through a window and then exits, and the driver dismisses
        # that window to let it finish -- so a report and a clean exit arrive
        # together, and taking the exit code alone threw the diagnostics away:
        # Psycho Strike's 33 errors came back as "compiled cleanly".
        reported = parse(text)
        if reported:
            return Report(outcome="errors", diagnostics=reported, raw=text,
                          title=title, exit_code=exit_code, said=said)
        if exit_code == 0:
            return Report(outcome="compiled", raw=text, title=title,
                          exit_code=exit_code, said=said)
        return Report(outcome="crashed", raw=text, title=title,
                      exit_code=exit_code, said=said)
    if result.get("outcome") == "timeout":
        return Report(outcome="timeout", raw=text, title=title,
                      exit_code=exit_code, said=said)

    diagnostics = parse(text)
    # Any window other than the report window means compilation finished and
    # the script itself started drawing. Warnings do not contradict that: the
    # engine reports them and then runs, so the diagnostics are kept.
    if result.get("ran") or ("error" not in title.lower() and not diagnostics):
        return Report(outcome="started", raw=text, title=title,
                      diagnostics=diagnostics, exit_code=exit_code, said=said)
    return Report(outcome="errors", diagnostics=diagnostics, raw=text,
                  title=title, exit_code=exit_code, said=said)


#: a `#include` directive. BGT's own sources write some of them without the
#: space (`#include"form.bgt"`), so neither space is required.
_INCLUDE = re.compile(r'(#\s*include\s*")([^"]+)(")')


def _repoint_includes(source: str, script_dir: str, out_dir: str) -> str:
    """Rewrite each relative `#include` so it still resolves from `out_dir`.

    BGT resolves an include against the *including script's* directory, so a
    staged copy one level down looks for `includes/classes/player.bgt` beside
    itself and reports, truthfully, that there is no such file. Only
    `bgt recover --compile` knew that, with a `../includes/` string replace of
    its own, so `bgt compile` on the very project `bgt recover` had just
    written failed on its first include and blamed the file it could not find.

    `relpath` is used rather than an absolute path because a relative include
    is the form the engine is known to accept, and rather than a fixed `../`
    because the staging directory need not be one level down.
    """
    def fix(match):
        head, name, tail = match.groups()
        if os.path.isabs(name) or ":" in name:
            return match.group(0)
        target = os.path.normpath(os.path.join(script_dir, name))
        return head + os.path.relpath(target, out_dir).replace(os.sep, "/") + tail
    return _INCLUDE.sub(fix, source)


def stage(script: str, out_dir: str, disarm: bool = True,
          as_name: Optional[str] = None) -> str:
    """Copy a script into `out_dir` ready for a compile-only check.

    Two things have to happen to the copy, and leaving either out looks like a
    broken recovery rather than a broken check:

    * **`main` is disarmed** (when `disarm`), so the whole module still
      compiles -- every function, class and global is seen -- while the process
      exits instead of opening the game. Without it a *successful* compile looks
      exactly like a hang.
    * **Relative includes are repointed** at the real files, because the copy
      does not sit in the directory they are written against.

    The copy exists at all so the executable the compiler writes lands beside
    it and not in the project the caller is reading.
    """
    with open(script, "r", encoding="utf-8", errors="replace") as fh:
        source = fh.read()
    if disarm:
        source, count = re.subn(r"(?m)^(\s*)void\s+main\s*\(\s*\)",
                                r"\1void __recovered_main()", source, count=1)
        if count:
            source += "\n\nvoid main()\n{\n}\n"
    os.makedirs(out_dir, exist_ok=True)
    source = _repoint_includes(
        source, os.path.dirname(os.path.abspath(script)),
        os.path.abspath(out_dir))
    target = os.path.join(out_dir, as_name or os.path.basename(script))
    with open(target, "w", encoding="utf-8") as fh:
        fh.write(source)
    return target


def neutered(script: str, out_dir: str) -> str:
    """Kept for callers that predate `stage`; `stage` is the one to use."""
    return stage(script, out_dir, disarm=True)


#: prefix for the staged copy and for the executable the compiler writes beside
#: it. Reserved, so a project file is never overwritten and both are safe to
#: delete afterwards.
STAGED_PREFIX = "_bgtcheck_"


def check_project(script: str, compiler: Optional[str] = None,
                  timeout: float = 60.0, build: str = "debug",
                  keep: bool = False) -> Report:
    """Compile-check a script where it lives, and leave nothing behind.

    The copy goes in the script's **own** directory under a reserved name,
    not in a subfolder, because BGT resolves everything relative against the
    script's location -- an `#include` and a data path alike. A copy one level
    down was given repointed includes and *still* reported `could not load
    pack data/bgm.dat.` for a pack sitting one directory up, because
    `set_sound_storage("data/bgm.dat")` is relative to the script too. Running
    the same project in place said nothing, which is how the difference
    showed. Same directory means nothing to rewrite and nothing to get wrong.

    The copy exists so the executable the compiler writes does not land on the
    project's own name; it lands under the reserved prefix instead, and both
    go away afterwards.
    """
    home = os.path.dirname(os.path.abspath(script))
    staged = os.path.join(home, STAGED_PREFIX + os.path.basename(script))
    produced = os.path.splitext(staged)[0] + ".exe"
    try:
        stage(script, home, disarm=True, as_name=os.path.basename(staged))
        return check(staged, compiler, timeout, build=build, workdir=home)
    finally:
        if not keep:
            for path in (staged, produced):
                try:
                    os.unlink(path)
                except OSError:
                    pass


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("script", help="the .bgt script to compile")
    ap.add_argument("--compiler", help="path to bgt.exe (default: the usual install paths)")
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--run", action="store_true",
                    help="run the script instead of compiling it")
    ap.add_argument("--build", choices=("debug", "release"),
                    help="compile to an executable beside the script (-c / -C)")
    ap.add_argument("--max", type=int, default=40, help="diagnostics to print")
    ap.add_argument("--raw", action="store_true", help="print the engine's own text")
    args = ap.parse_args(argv)

    if not args.run and not args.build:
        # Compiling is the check, and it goes through a staged copy so the
        # executable the compiler writes does not land on the project's own
        # name. `check_project` keeps that copy in the script's own directory,
        # which is what both its includes and its data paths are relative to.
        report = check_project(args.script, args.compiler, args.timeout)
    else:
        report = check(args.script, args.compiler, args.timeout,
                       build=args.build)
    print(report.summary())
    if args.raw:
        print(report.raw)
    shown = [d for d in report.diagnostics if d.kind != "Information"][:args.max]
    for d in shown:
        print(d)
    hidden = len([d for d in report.diagnostics if d.kind != "Information"]) - len(shown)
    if hidden > 0:
        print("... %d more" % hidden)
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
