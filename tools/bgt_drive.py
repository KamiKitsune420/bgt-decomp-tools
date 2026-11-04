"""
bgt_drive -- run a recovered game's own code and watch what it does, silently.

    bgt drive recovered/ --scenario ctrl
    bgt drive recovered/ --watch "k_ctrl(1)" --hold KEY_LCONTROL
    bgt drive recovered/ --watch "player.x" --hold KEY_RIGHT --for 1000 --every 100

Every other check in this toolkit reads the recovery. The compiler says it is
valid BGT, `bgt audit` says no value was lost, `bgt libcheck` says it matches
source nobody here wrote, `bgt roundtrip` says it compiles back to something
close. None of them runs it, and this file is a long record of defects that
compiled cleanly, ran, and did the wrong thing: a menu that could not be
arrowed through, a clock that ran at one minute a scene, a control key that
answered for one hand only.

`bgt oracle` closes that gap for shapes written here. This closes it for a
GAME's own code -- it calls any function of a recovered project with any keys
held down, samples any expressions on a clock, and prints a table.

**It makes no sound and opens no window.** `set_sound_master_volume(-100)`
is the first thing the probe does, which is the engine's own registered master
gain, so a game that loads and plays its whole soundtrack does it into silence.
That matters because these are audio games: a harness that drove them audibly
could not be run while anybody was using the computer, which is the cost this
file records paying three times over for BGT's modal dialogs.

And it calls no `show_game_window`, which is the difference between a driver
that works and one that reports nothing. **A forced key does not go through a
window**: asked directly, a script with no window at all answers `down=1
pressed=1` after `force_key_down(KEY_LCONTROL)`. That matters twice over,
because `bgt_compile.check` treats a window of the script's own as an outcome
and kills the process to get it -- so a probe that opened one was killed
before it could write its table, and the run came back `started` with no
rows.

## What it can and cannot drive

It calls FUNCTIONS, which covers every library class, every helper and every
`bool k_ctrl(int)`-shaped input reader. The control-key defect this file
records would have shown up on the first run of

    bgt drive recovered/ --scenario ctrl

as `false` where it should read `true`, in a title whose only other symptom
was somebody reporting that the weapon would not fire.

It cannot drive a game's own main loop, because that loop does not return:
Field Wars' movement lives inside `game()`, so there is no function to call and
no tick to sample between. Driving those needs the loop broken into steps,
which is a change to the recovery rather than to the harness and is not done
here. A tool that implied otherwise would be worse than one that says so.

## Why the probe lives in the project directory

Because BGT resolves everything relative against the **script's own**
directory -- an `#include` and `set_sound_storage("data/bgm.dat")` alike. This
file already records a staged copy one level down being given repointed
includes and *still* reporting `could not load pack data/bgm.dat.` So the
probe goes in beside the entry script under a reserved prefix, exactly as
`check_project` does, and nothing has to be rewritten or guessed.

The one thing that has to change in the project is the file declaring
`void main()` -- `includes/functions/part_0.bgt` in every recovery here, since
`main` is one of the game's own global functions. It is renamed for the run and
**restored in a `finally`**, from a copy taken before it was touched.

## Why it runs from source rather than building

`check(build=None)` runs the script, and running a script is a DEBUG run where
`get_SCRIPT_COMPILED()` is false -- which this file records as a game taking
its developer path. That is right for a driver: the question is what one
function does with given inputs, and a probe that built an executable would pay
a whole compile per question. Where the answer could depend on the build, pass
`--build release`.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Sequence

try:                      # installed as a package
    from . import bgt_compile
except ImportError:       # run directly from a checkout
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import bgt_compile

#: Reserved, so a project file is never overwritten and everything this leaves
#: behind is safe to delete. The same argument as `STAGED_PREFIX`.
PREFIX = "_bgtdrive_"

#: What the probe writes its samples to. A file rather than stdout because a
#: BGT script has no stdout: the engine is a GUI program, and `file::write` is
#: the only way out of it.
RESULTS = PREFIX + "out.tsv"

#: BGT's master gain in decibels, and its floor. Read off the engine's own
#: registration -- `bool set_sound_master_volume(double volume)` -- rather than
#: assumed.
SILENT = -100.0

#: What `main` is renamed to for the run. Prefixed, because a recovered project
#: declares thousands of names and one collision would be a compiler error
#: blamed on the recovery.
RENAMED_MAIN = PREFIX + "game_main"

MAIN = re.compile(r"(?m)^(\s*)void\s+main\s*\(\s*\)")

TEMPLATE = '''#include "{entry}"

// ---- written by `bgt drive`, and deleted again ------------------------
// The game's own `main` is renamed for this run, so nothing of the game
// starts on its own. This one silences the engine, holds the keys asked
// for, calls what was asked for, and writes a sample per tick.
void main()
{{
\tset_sound_master_volume({silent});
\tfile {p}out;
\t{p}out.open("{results}", "wb");
\t{p}out.write("ms\\t{headers}\\n");
{setup}
{holds}
\ttimer {p}clock;
\tdouble {p}next = 0.0;
\twhile ({p}clock.elapsed < {duration})
\t{{
{calls}
\t\tif ({p}clock.elapsed >= {p}next)
\t\t{{
\t\t\t{p}out.write(string(int({p}clock.elapsed)){samples} + "\\n");
\t\t\t{p}next += {every};
\t\t}}
\t\twait({tick});
\t}}
\treset_all_forced_keys();
\t{p}out.close();
\texit();
}}
'''


def find_entry(project: str) -> str:
    """The project's entry script: the `.bgt` at the top that includes others.

    `bgt recover` writes exactly one, named after the executable, and every
    other file lives under `includes/`. Accepting any top-level `.bgt` with an
    `#include` in it keeps this working on a hand-written project too.
    """
    names = sorted(n for n in os.listdir(project)
                   if n.endswith(".bgt") and not n.startswith(PREFIX))
    for name in names:
        with open(os.path.join(project, name), encoding="utf-8",
                  errors="replace") as fh:
            if "#include" in fh.read():
                return os.path.join(project, name)
    if names:
        return os.path.join(project, names[0])
    raise SystemExit("no .bgt entry script in %s" % project)


def find_main(project: str) -> Optional[str]:
    """The file declaring `void main()`, wherever in the project it is.

    It is **not** the entry script: `main` is one of the game's own global
    functions, so `bgt recover` writes it into
    `includes/functions/part_0.bgt`. `bgt_compile.stage` looks only at the
    script it is handed, which is right for a compile-only check -- with `-c`
    nothing runs, so disarming is cosmetic there -- and not enough to RUN one.
    """
    for root, _dirs, files in os.walk(project):
        for name in sorted(files):
            if not name.endswith(".bgt") or name.startswith(PREFIX):
                continue
            path = os.path.join(root, name)
            with open(path, encoding="utf-8", errors="replace") as fh:
                if MAIN.search(fh.read()):
                    return path
    return None


def _tabs(lines: Sequence[str], depth: int) -> str:
    pad = "\t" * depth
    return "\n".join(pad + line for line in lines)


def column(expr: str) -> str:
    """The table's name for one watch -- used for the header AND the lookup.

    One function, because the two used to differ: the header replaced every
    `"` with `'` so the BGT string literal holding it would close, and the
    summary looked the column up by the expression as typed. So every watch
    containing a quote came back blank -- `get_string_size("hello")`
    reported nothing while the recovered function correctly returns `5 B`,
    which reads as a defect in the recovery rather than in the tool.

    A tab or a newline is the one thing a column name cannot hold, because
    the table is tab-separated, so those become spaces on both sides.
    """
    return expr.replace("\t", " ").replace("\r", " ").replace("\n", " ")


def _literal(text: str) -> str:
    """`text` as the body of a BGT string literal."""
    return text.replace("\\", "\\\\").replace('"', '\\"')


def probe_source(entry: str, watch: Sequence[str], call: Sequence[str] = (),
                 hold: Sequence[str] = (), setup: Sequence[str] = (),
                 duration: int = 1000, every: int = 100,
                 tick: int = 5) -> str:
    """The probe script's text, as it will sit beside `entry`."""
    return TEMPLATE.format(
        entry=os.path.basename(entry), p=PREFIX, silent=SILENT,
        results=RESULTS,
        headers="\\t".join(_literal(column(w)) for w in watch),
        setup=_tabs([s.rstrip(";") + ";" for s in setup], 1),
        holds=_tabs(["force_key_down(%s);" % k for k in hold], 1),
        calls=_tabs([c.rstrip(";") + ";" for c in call], 2),
        #: each watch becomes `+ "\\t" + string(<expr>)`, so one row is one
        #: tick and one column is one expression however it happens to be
        #: typed. All five of `string(bool)`, `string(int)`,
        #: `string(double)`, `"" + bool` and `"x" + int` were put to the
        #: compiler before this picked one -- and the engine was then asked
        #: what they PRODUCE, which is where `string(true)` turned out to be
        #: **`1`** rather than `true`. A scenario expecting the word would
        #: have failed on a correct recovery, which is the shape this file
        #: keeps recording.
        samples="".join(' + "\\t" + string(%s)' % w for w in watch),
        duration=float(duration), every=float(every), tick=int(tick))


def read_results(path: str) -> List[Dict[str, str]]:
    """The probe's table, as a row per tick."""
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = [l.rstrip("\r\n") for l in fh if l.strip()]
    if not lines:
        return []
    head = lines[0].split("\t")
    return [dict(zip(head, line.split("\t"))) for line in lines[1:]]


def _run_built(executable, project, results, timeout):
    """Start the built probe and wait for its table. Returns an outcome.

    The probe writes its rows and exits, so there is nothing to read from the
    process: the file appearing is the signal. It is given the project as its
    working directory, because the script asks the engine for its pack by a
    relative name.

    The process is killed if it outlives the deadline. That is not a failure
    on its own -- a probe whose watched expression opens a window waits on it
    -- so the rows are read either way and the caller reports what it got.
    """
    if not os.path.isfile(executable):
        return "nobuild"
    deadline = time.monotonic() + max(timeout, 5.0)
    try:
        proc = subprocess.Popen([executable], cwd=project,
                                stdin=subprocess.DEVNULL)
    except OSError as exc:
        print("note: could not start %s: %s" % (executable, exc))
        return "nodriver"
    try:
        while time.monotonic() < deadline:
            if os.path.isfile(results):
                # written in one go, but give the write a moment to land
                time.sleep(0.2)
                break
            if proc.poll() is not None:
                break
            time.sleep(0.1)
    finally:
        if proc.poll() is None:
            try:
                proc.kill()
            except OSError:
                pass
            proc.wait()
    return "started" if os.path.isfile(results) else "timeout"


def drive(project: str, watch: Sequence[str], call: Sequence[str] = (),
          hold: Sequence[str] = (), setup: Sequence[str] = (),
          duration: int = 1000, every: int = 100, tick: int = 5,
          compiler: Optional[str] = None, build: Optional[str] = None,
          timeout: float = 240.0, keep: bool = False) -> Dict[str, Any]:
    """Drive the project once and return what the probe observed.

    Everything written into the project is removed again, and the file holding
    `main` is restored from a copy taken before it was touched -- in a
    `finally`, because an interrupted run that left a project with no `main`
    would look exactly like a broken recovery.
    """
    project = os.path.abspath(project)
    entry = find_entry(project)
    source = probe_source(entry, watch, call, hold, setup,
                          duration, every, tick)
    probe = os.path.join(project, PREFIX + "probe.bgt")
    produced = os.path.splitext(probe)[0] + ".exe"
    results = os.path.join(project, RESULTS)
    main_file = find_main(project)
    backup = (main_file + PREFIX + "bak") if main_file else None

    try:
        if main_file is not None and backup is not None:
            shutil.copy2(main_file, backup)
            with open(main_file, encoding="utf-8", errors="replace") as fh:
                body = fh.read()
            with open(main_file, "w", encoding="utf-8") as fh:
                fh.write(MAIN.sub(r"\1void %s()" % RENAMED_MAIN, body,
                                  count=1))
        else:
            #: Not fatal: a project that declares no `main` is drivable, and
            #: saying so beats refusing.
            print("note: no `void main()` in this project -- nothing to "
                  "disarm")

        with open(probe, "w", encoding="utf-8") as fh:
            fh.write(source)
        if os.path.isfile(results):
            #: a previous run's table read as this one's is the staleness trap
            #: `bgt oracle` records; delete rather than trust a timestamp
            os.remove(results)
        report = bgt_compile.check(probe, compiler=compiler, timeout=timeout,
                                   build=build, workdir=project)
        outcome = report.outcome
        if build and report.ok:
            #: **And then run it.** `check(build=...)` compiles and verifies
            #: the executable exists; it does not start it, so every
            #: `--build` run came back `compiled` with no rows -- the one
            #: mode whose whole purpose is a question a script run cannot
            #: answer. Crazy Party is why it matters: `g_test` is
            #: `!get_SCRIPT_COMPILED()` and its sound loading is behind the
            #: same test, so run from source it opens no pack and announces
            #: 223 missing bot sounds, and `--build release` was the only
            #: way to ask it anything and silently asked nothing.
            outcome = _run_built(produced, project, results, timeout) \
                or outcome
        return {"probe": probe, "outcome": outcome,
                "errors": [d.message for d in report.errors],
                "raw": (report.raw or "").strip(),
                "rows": read_results(results),
                "watch": list(watch), "source": source}
    finally:
        if backup and os.path.isfile(backup):
            shutil.move(backup, main_file)
        if not keep:
            for path in (probe, produced, results):
                if os.path.isfile(path):
                    os.remove(path)


#: Ready-made runs for the questions this file keeps asking. Each one is a real
#: defect's shape, so a canned scenario is a regression check rather than a
#: demonstration -- and `expect` says what a correct recovery answers, so the
#: run has a verdict and not just a table to squint at.
SCENARIOS: Dict[str, Dict[str, Any]] = {
    "keys": {
        "watch": ["key_down(KEY_DOWN)", "key_pressed(KEY_DOWN)"],
        "hold": ["KEY_DOWN"], "duration": 300, "every": 50,
        #: `1`, not `true`: `string(bool)` is the engine's own rendering,
        #: asked rather than assumed
        "expect": {"key_down(KEY_DOWN)": "1"},
        "why": "that a forced key reaches the engine at all. This is the "
               "control every other scenario rests on, so run it first on a "
               "title whose answers look wrong.",
    },
    "ctrl": {
        "watch": ["k_ctrl(0)", "k_ctrl(1)", "k_ctrl(2)"],
        "hold": ["KEY_LCONTROL"], "duration": 400, "every": 100,
        "expect": {"k_ctrl(0)": "1"},
        "why": "the control key, held on the LEFT. `k_ctrl(0)` asks whether "
               "it is down, so it must read 1 -- answering only for the "
               "right control is the nested-`||` defect this file records, "
               "whose one symptom was a weapon that would not fire.",
    },
    "shift": {
        "watch": ["k_shift(0)", "k_shift(1)"],
        "hold": ["KEY_LSHIFT"], "duration": 400, "every": 100,
        "expect": {"k_shift(0)": "1"},
        "why": "the same function one key over, which had the same three "
               "declined merges.",
    },
}


def main(argv: Optional[Sequence[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="bgt drive",
        description="run a recovered game's own functions, silently, and "
                    "watch what they answer")
    parser.add_argument("project", help="a directory of recovered .bgt files")
    parser.add_argument("--watch", action="append", default=[], metavar="EXPR",
                        help="an expression to sample each tick (repeatable)")
    parser.add_argument("--call", action="append", default=[], metavar="STMT",
                        help="a statement to run each tick (repeatable)")
    parser.add_argument("--hold", action="append", default=[], metavar="KEY",
                        help="a key to hold down for the whole run")
    parser.add_argument("--setup", action="append", default=[], metavar="STMT",
                        help="a statement to run once before the loop")
    parser.add_argument("--scenario", choices=sorted(SCENARIOS),
                        help="a ready-made run; --watch and --hold add to it")
    parser.add_argument("--for", dest="duration", type=int, default=1000,
                        metavar="MS", help="how long to drive (default 1000)")
    parser.add_argument("--every", type=int, default=100, metavar="MS",
                        help="how often to sample (default 100)")
    parser.add_argument("--tick", type=int, default=5, metavar="MS",
                        help="the loop's own wait (default 5)")
    parser.add_argument("--build", choices=("debug", "release"),
                        help="build and run an executable instead of running "
                             "the script, where the answer could depend on "
                             "`get_SCRIPT_COMPILED()`")
    parser.add_argument("--compiler", metavar="PATH", help="bgt.exe")
    parser.add_argument("--timeout", type=float, default=240.0, metavar="S")
    parser.add_argument("--keep", action="store_true",
                        help="leave the probe and its table in the project")
    parser.add_argument("--show-probe", action="store_true",
                        help="print the probe script instead of running it")
    args = parser.parse_args(argv)

    watch, hold = list(args.watch), list(args.hold)
    duration, every, expect = args.duration, args.every, {}
    if args.scenario:
        canned = SCENARIOS[args.scenario]
        watch = list(canned["watch"]) + watch
        hold = list(canned.get("hold", ())) + hold
        duration = canned.get("duration", duration)
        every = canned.get("every", every)
        expect = dict(canned.get("expect", {}))
        print("%s: %s\n" % (args.scenario, canned["why"]))
    if not watch:
        print("nothing to watch: pass --watch EXPR or --scenario",
              file=sys.stderr)
        return 2

    if args.show_probe:
        print(probe_source(find_entry(os.path.abspath(args.project)), watch,
                           args.call, hold, args.setup, duration, every,
                           args.tick))
        return 0

    out = drive(args.project, watch, args.call, hold, args.setup,
                duration, every, args.tick, args.compiler, args.build,
                args.timeout, args.keep)
    if not out["rows"]:
        print("the probe did not report: %s" % out["outcome"])
        for line in out["errors"][:8]:
            print("    %s" % line)
        if not out["errors"] and out["raw"]:
            print("    %s" % out["raw"].splitlines()[0])
        if out["outcome"] == "started":
            #: the one outcome worth explaining, because it reads as a
            #: failure of the recovery and is a failure of the harness: some
            #: function under test opened a window, which `check` takes as
            #: its answer and kills the process to get.
            print("    a window opened, so the run was cut short. Drive a "
                  "function that does not draw one.")
        return 1
    if out["outcome"] == "started":
        print("note: a window opened during the run, so the table below may "
              "stop early\n")

    cols = ["ms"] + out["watch"]
    widths = [max([len(c)] + [len(r.get(c, "")) for r in out["rows"]])
              for c in cols]
    print("  ".join(c.ljust(w) for c, w in zip(cols, widths)))
    for row in out["rows"]:
        print("  ".join(row.get(c, "").ljust(w) for c, w in zip(cols, widths)))

    #: The summary a reader wants: which watched expressions ever changed, and
    #: which never budged. A column that never moves is the shape every defect
    #: in this file leaves behind -- and where a scenario says what to expect,
    #: this is a verdict.
    print()
    failed = 0
    for col in out["watch"]:
        seen = [r.get(column(col), "") for r in out["rows"]]
        want = expect.get(col)
        if want is not None and want not in seen:
            print("  %-26s WRONG: never %s, only %s"
                  % (col, want, "/".join(sorted(set(seen)))))
            failed += 1
        elif want is not None:
            print("  %-26s ok: reached %s" % (col, want))
        elif len(set(seen)) == 1:
            print("  %-26s never changed: %s" % (col, seen[0]))
        else:
            print("  %-26s took %d values" % (col, len(set(seen))))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
