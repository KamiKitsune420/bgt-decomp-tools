# BGT decompilation toolkit

Recover the source-level structure and the assets from games built with **BGT**
(BlastBay Gaming Toolkit), the 2010 audio-game engine.

Give it a game executable and it gives you back the game's code as readable
pseudo-source, every string in it, and its sounds.

```bash
pip install -e .
bgt unpack game.exe -o work/
bgt lift work/game_bytecode.bin game.exe -o game.as
```

```c
void <global>::main()
{
    v1 = string("Psycho Strike");
    ret = show_game_window(&v1);
    v1 = string("sounds.dat");
    ret = v1.open(retreave);
    ret = reset_game();
    ret = prepare_audio();
    v2 = performance_debug;
    if (v2) {
        ret = start_profiling();
        v1 = string("strikelog_errors.log");
        ret = set_error_output(&v1);
    }
    ...
```

---

## Install

Needs Python 3.8+ and `pycryptodome`.

```bash
pip install -e .
```

That gives you a `bgt` command. You can also run everything straight out of
`tools/` without installing (`python tools/bgt_unpack.py ...`).

---

## The five things you probably want

### 1. Get the code out of a game

```bash
bgt unpack game.exe -o work/
```

Writes `work/game_bytecode.bin` — the game's compiled script, decrypted and
decompressed.

### 2. Read it

```bash
bgt lift work/game_bytecode.bin game.exe -o game.as
```

Pseudo-source: real function names, class names, string literals, `if`/`while`,
resolved call targets. This is the one you want most of the time.

For the raw instruction listing instead:

```bash
bgt disasm work/game_bytecode.bin game.exe -o game.asm
```

Just one function:

```bash
bgt lift work/game_bytecode.bin game.exe -f main
```

### 3. Look inside a sound pack

```bash
bgt pack list sounds.dat
```

```
sounds.dat: v1, 975 entries, 974 encrypted, 1 distinct key
```

If it says **1 distinct key**, one password opens the whole pack. If it says
thousands, the game uses a key per file and you will need the derivation, not a
password.

### 4. Extract the sounds

You need the key. If the game's password is a plain string in its script:

```bash
bgt crack sounds.dat --dict work/game_bytecode.bin --workers 0
```

Then:

```bash
bgt pack extract sounds.dat -o sounds/ --key <the hex key it printed>
```

If `crack` finds nothing, the password is computed rather than stored — that is
common. Read the function that builds it. `set_sound_decryption_key` is part of
the engine and has no body of its own, so ask for whatever **calls** it:

```bash
bgt lift work/game_bytecode.bin game.exe --calls set_sound_decryption_key
```

```c
void <global>::prepare_audio()
{
    ret = get_SCRIPT_COMPILED();
    if (ret) {
        v2 = string("ZGtz9mdqa2F3ZWx0dXdGSkRLTFNKVklDMTA4MzIx...");
        ret = get(&v2);                     // <- this transforms it
        ret = set_sound_decryption_key(v3, &v2);
        v2 = string("sounds.dat");
        ret = set_sound_storage(v3);
    }
}
```

There is the seed and the function that turns it into the key. `--calls` works
on `bgt disasm` too, and is the general way in when the name you have belongs to
the engine rather than the script.

### 5. Change something and rebuild the game

```bash
bgt asm work/game_bytecode.bin game.exe \
        --replace sounds.dat=my_sounds.dat -o work/modified.bin
bgt repack game.exe work/modified.bin -o patched.exe
```

The replacement can be a different length. Both steps verify themselves and
refuse to write if anything is off.

---

## Every command

| command | what it does |
|---|---|
| `bgt unpack game.exe -o work/` | recover the script from an executable |
| `bgt info game.exe` | just the header: overlay, key, sizes |
| `bgt lift module.bin game.exe` | pseudo-source |
| `... -f NAME` / `--calls NAME` | one function, or whatever calls it |
| `bgt disasm module.bin game.exe` | annotated instruction listing |
| `bgt asm module.bin game.exe` | rewrite a module, edit its literals |
| `bgt repack game.exe module.bin -o out.exe` | put a module back into an executable |
| `bgt pack list \| extract sounds.dat` | inspect or extract an asset pack |
| `bgt crack sounds.dat --dict module.bin` | search the script for the pack password |
| `bgt opcodes game.exe` | dump the engine's opcode table |
| `bgt validate a.exe b.exe` | run the whole pipeline over several games |
| `bgt ghidra status \| install \| decompile` | set up and drive Ghidra |

`bgt <command> --help` for the options.

---

## What you get, and what you don't

**You get** every function, class, property and enum **name**, every string
literal, the full call graph, and control flow as `if` / `while` / `break`.

**You don't get** local variable names, parameter names, line numbers or
comments. BGT strips them at compile time and they are genuinely gone — locals
read as `v3`, parameters as `a0`. So you can rebuild a game faithfully; you
cannot recover its original text exactly.

---

## Does it work on my game?

Run:

```bash
bgt validate mygame.exe
```

Every stage prints `ok` or `FAIL`. All three games this was built against pass
every stage:

| | Psycho Strike | Paladin of the Sky | Manamon 2 |
|---|---|---|---|
| classes | 68 | 47 | 1,604 |
| functions | 1,102 | 926 | 9,924 |
| operands named | 100% | 100% | 100% |
| rebuilds byte-for-byte | yes | yes | yes |

BGT games share one engine, so a title that fails is more likely a BGT *version*
this has not seen than a modified engine. `bgt validate` will show you which
stage stops.

---

## If something goes wrong

**"no xproc10 trailer"** — not a BGT executable, or a BGT version that packages
differently.

**`bgt lift` says "no function bodies were recovered"** — the module parsed but
its function records did not. It will tell you the dialect and where it stopped.

**`bgt crack` finds nothing** — that only rules out the candidates it tried, and
it prints how many. The password is probably computed; see step 4 above.

**Ghidra commands fail** — run `bgt ghidra status`. Ghidra needs a JDK 21 or
newer, and the `java` on your PATH is often an older one kept for something else.

---

## Files

```
tools/      the toolkit
tests/      python -m pytest tests/ -q      (124 tests, no game files needed)
docs/       ghidra_workflow.md — how to read the engine's own loader
CLAUDE.md   the format itself, in detail, and why each part is believed
```

`CLAUDE.md` is the reference: how the encryption chain works, how the bytecode
format is laid out, which parts were read out of the binary and which were
inferred, and what is still open. Read it before extending anything.

---

## Contributing

Contributions are welcome — issues, fixes, and support for BGT versions this has
not seen. Two house rules, both from `CLAUDE.md`:

- **Read the reader, don't guess the format.** Format claims should come from the
  engine's own `asCReader` / `pack::create` in the binary, not from byte patterns.
- **Keep the repo free of game files and per-title findings.** Run
  `python tests/test_toolkit.py` before opening a PR — the 124 tests use synthetic
  inputs only and need no game files.

By contributing you agree your contribution is licensed under the same terms as
the rest of the project.

---

## License

[PolyForm Noncommercial License 1.0.0](LICENSE.md) — Copyright KamiKitsune420
(Adel Spence).

In short: **use it, modify it, share it, contribute to it** — for any
noncommercial purpose, including personal use, hobby projects, research and
education. You must keep the license and the copyright notice with any copy you
pass on, so you cannot pass this off as your own work. You may **not sell it** or
use it commercially.

This is a source-available license, not an OSI-approved open-source one; the
noncommercial restriction is the reason.

---

## Disclaimer

**The software is provided as is, with no warranty of any kind. The author is not
responsible for any outcome of using it** — including damaged files, broken game
installs, or any legal consequence of what you do with what it recovers. See
[No Liability](LICENSE.md#no-liability).

Intended for interoperability, preservation and study of games you own. It ships
no game files and no keys — everything it does is derived from an executable you
already have. Whether extracting or redistributing a particular game's code or
assets is lawful where you live is your responsibility to determine, not this
tool's.
