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
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional

DEFAULT_COMPILERS = (
    r"C:\Program Files (x86)\BGT\bgt.exe",
    r"C:\Program Files\BGT\bgt.exe",
)

# One PowerShell driver, written beside the script it checks. It launches the
# compiler, polls for either outcome, prints a JSON record and always kills the
# process it started -- a GUI left running would hold the next check's window.
DRIVER = r"""
param([string]$Compiler, [string]$Script, [string]$WorkDir, [int]$TimeoutMs,
      [string]$Switch = "run")
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
$flag = switch ($Switch) { "debug" { "-c" } "release" { "-C" } default { "" } }
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
                # The exit button is furniture; the diagnostics are the long one.
                if ($name -ne "" -and $name -ne "Exit") { $parts += $name }
            }
            $isReport = ($title -like "Compilation*")
            if ($isReport -or $text -eq "") { $text = $parts -join "`n" }
            $outcome = "window"
            if (($Switch -eq "run") -and (-not $isReport)) {
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
@{ outcome = $outcome; title = $title; text = $text; exit = $exit; ran = $ran } |
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

    def summary(self) -> str:
        if self.outcome == "compiled":
            return "compiled cleanly"
        if self.outcome == "started":
            warnings = sum(1 for d in self.diagnostics if d.kind == "Warning")
            return ("compiled%s, and ran: it opened a window of its own%s"
                    % (" with %d warning(s)" % warnings if warnings else " cleanly",
                       " titled %r" % self.title if self.title else ""))
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
        return self.outcome


def find_compiler(explicit: Optional[str] = None) -> Optional[str]:
    for path in ([explicit] if explicit else []) + list(DEFAULT_COMPILERS):
        if path and os.path.isfile(path):
            return path
    return None


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
          keep_driver: bool = False, build: Optional[str] = None) -> Report:
    """Compile one script and return every diagnostic the engine reported.

    `build` asks for a real compile rather than a run: "debug" (`-c`) or
    "release" (`-C`), which writes an executable beside the script. That is
    the better check, because nothing of the program runs -- a game cannot
    open a window and sit there -- and it is what proves the whole module
    reaches the engine.
    """
    exe = find_compiler(compiler)
    if exe is None:
        return Report(outcome="nodriver",
                      raw="no bgt.exe found -- pass --compiler <path to bgt.exe>")
    script = os.path.abspath(script)
    workdir = os.path.dirname(script)
    fd, driver = tempfile.mkstemp(suffix=".ps1", prefix="bgtcheck_")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(DRIVER)
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-File", driver,
             "-Compiler", exe, "-Script", script, "-WorkDir", workdir,
             "-TimeoutMs", str(int(timeout * 1000)),
             "-Switch", build or "run"],
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
                          title=title, exit_code=exit_code)
        if exit_code == 0:
            return Report(outcome="compiled", raw=text, title=title,
                          exit_code=exit_code)
        return Report(outcome="crashed", raw=text, title=title,
                      exit_code=exit_code)
    if result.get("outcome") == "timeout":
        return Report(outcome="timeout", raw=text, title=title, exit_code=exit_code)

    diagnostics = parse(text)
    # Any window other than the report window means compilation finished and
    # the script itself started drawing. Warnings do not contradict that: the
    # engine reports them and then runs, so the diagnostics are kept.
    if result.get("ran") or ("error" not in title.lower() and not diagnostics):
        return Report(outcome="started", raw=text, title=title,
                      diagnostics=diagnostics, exit_code=exit_code)
    return Report(outcome="errors", diagnostics=diagnostics, raw=text,
                  title=title, exit_code=exit_code)


def neutered(script: str, out_dir: str) -> str:
    """Copy a script with its entry point disarmed, for a compile-only check.

    The whole module still compiles -- every function, class and global is
    seen by the compiler -- but `main` does nothing, so the process exits
    instead of opening the game. Without this a *successful* compile looks
    exactly like a hang.
    """
    with open(script, "r", encoding="utf-8", errors="replace") as fh:
        source = fh.read()
    patched, count = re.subn(r"(?m)^(\s*)void\s+main\s*\(\s*\)",
                             r"\1void __recovered_main()", source, count=1)
    if count:
        patched += "\n\nvoid main()\n{\n}\n"
    os.makedirs(out_dir, exist_ok=True)
    target = os.path.join(out_dir, os.path.basename(script))
    with open(target, "w", encoding="utf-8") as fh:
        fh.write(patched)
    return target


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

    script = args.script
    build = args.build
    if not args.run and not build:
        # Compiling is the check. It goes through a copy so the executable the
        # compiler writes lands beside that copy and not in the caller's
        # directory.
        build = "debug"
        script = os.path.join(os.path.dirname(os.path.abspath(script)),
                              "_compile_check", os.path.basename(script))
        os.makedirs(os.path.dirname(script), exist_ok=True)
        with open(args.script, "r", encoding="utf-8", errors="replace") as src, \
                open(script, "w", encoding="utf-8") as dst:
            dst.write(src.read())
    report = check(script, args.compiler, args.timeout, build=build)
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
