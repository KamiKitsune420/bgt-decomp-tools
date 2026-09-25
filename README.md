# BGT & NVGT decompilation toolkit

Recover the source-level structure and the assets from audio games built with
**BGT** (BlastBay Gaming Toolkit, 2010) and its open-source successor **NVGT**
(NonVisual Gaming Toolkit).

Give it a game executable and it gives you back the game's code, every string
in it, and its sounds.

```bash
pip install -e .
bgt identify game.exe                 # BGT or NVGT?
```

**BGT game:**

```bash
bgt unpack game.exe -o work/
bgt lift work/game_bytecode.bin game.exe -o game.as
```

```c
void <global>::main()
{
    v1 = string("Psycho Strike");
    ret = show_game_window(&v1);
    v1 = string("sounds.dat");
    ret = retreave.open(v1);
    v1 = string(data_directory);
    ret = directory_create(&v1);
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

**NVGT game:**

```bash
bgt nvgt recover game.exe -o game-source.zip
```

That produces a complete source project: `main.nvgt`, `includes/`, an offline
source browser, a manifest and the evidence the bytecode actually retained. It
can optionally check that the result compiles (`--check-with nvgt.exe`).

---

## Install

Needs Python 3.10+ and `pycryptodome`.

```bash
pip install -e .
```

That gives you the `bgt` command (plus `nvgt-recover` and `nvgt-pack`
shortcuts). You can also run everything straight out of `tools/` without
installing (`python tools/bgt_unpack.py ...`, `python tools/nvgt/recover.py ...`).

Optional: `pip install -e .[scan]` for NumPy, used only by `bgt nvgt keyscan`.

---

## Which half do I need?

```bash
bgt identify game.exe
```

```
strike.exe: BGT (overlay 0x10A400, key seed 0x11)
nvgt.exe: not recognised (bgt: no xproc10 trailer -- ...; nvgt: nothing is
          appended after the last PE section -- no compiled payload)
```

A recognised NVGT game reads like `game.exe: NVGT (current_preamble profile,
1756 bytes of bytecode, 1 embedded pack)`.

It only names an engine when that engine's own self-verifying layer agrees: a
BGT container header that decrypts, or an NVGT payload that decrypts, unpads
and inflates completely. It never guesses from strings or file names. The BGT
commands also point you to the NVGT ones (and the other way round) when you
hand them the wrong kind of game.

---

## BGT: the five things you probably want

### 1. Get the code out of a game

```bash
bgt unpack game.exe -o work/
```

Writes `work/game_bytecode.bin`, the game's compiled script, decrypted and
decompressed. The file is named after the executable: `strike.exe` gives
`work/strike_bytecode.bin`.

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

If `crack` finds nothing, the password is computed rather than stored, which is
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
        v1 = 0;
        v2 = string("ZGtz9mdqa2F3ZWx0dXdGSkRLTFNKVklDMTA4MzIx...");
        v3 = string(&v2);
        v2 = get(v3);                       // <- this transforms it
        ret = set_sound_decryption_key(&v2, v1);
        ...
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

## NVGT

```bash
bgt nvgt recover game.exe -o game-source.zip           # just the archive
bgt nvgt recover game.exe -o recovered-game/           # archive + unpacked project
bgt nvgt recover game.exe -o src.zip --check-with nvgt.exe
bgt nvgt decompile game.exe -o game.nvgt               # one file
bgt nvgt disasm game.exe -o game.asm
bgt nvgt extract game.exe game.bin --packs packs/      # raw module + embedded packs
bgt nvgt pack list sounds.dat --key "the key"
bgt nvgt pack extract game.exe --embedded sounds.dat --key "the key" -o sounds/
```

Recovery reads the executable and never runs it. `--check-with` compiles the
*generated* source in a throwaway folder; a pass means "this compiles with that
compiler", not "this behaves like the game".

What NVGT recovery can open is limited to the **packaging profiles it has
verified**. Official NVGT releases get freshly generated encryption parameters
per build, so an executable from a release without a verified profile fails
with a clear error rather than producing a guessed project. Bytecode you
already have (for example exported from your own scripts) is decompiled
regardless of which build made it. See [docs/nvgt.md](docs/nvgt.md).

NVGT's asset packs are a different format from BGT's, and `bgt nvgt pack`
handles them. It reads plain and encrypted packs, including packs embedded in
an executable with `#pragma embed`, and writes packs NVGT's own reader accepts.
Its output has been checked byte for byte against packs written by NVGT
itself.

---

## Every command

| command | what it does |
|---|---|
| `bgt identify game.exe` | BGT or NVGT, and the evidence |
| **BGT** | |
| `bgt unpack game.exe -o work/` | recover the script from an executable |
| `bgt info game.exe` | just the header: overlay, key, sizes |
| `bgt lift module.bin game.exe` | pseudo-source |
| `... -f NAME` / `--calls NAME` | one function, or whatever calls it |
| `bgt disasm module.bin game.exe` | annotated instruction listing |
| `bgt asm module.bin game.exe` | rewrite a module, edit its literals |
| `bgt repack game.exe module.bin -o out.exe` | put a module back into an executable |
| `bgt pack list \| extract sounds.dat` | inspect or extract an SFPv1 asset pack |
| `bgt crack sounds.dat --dict module.bin` | search the script for the pack password |
| `bgt opcodes game.exe` | dump the engine's opcode table |
| `bgt validate a.exe b.exe` | run the whole pipeline over several games |
| `bgt libcheck module.bin game.exe` | score lifted code against BGT's own library source |
| `bgt ghidra status \| install \| decompile` | set up and drive Ghidra |
| **NVGT** | |
| `bgt nvgt recover game.exe -o out.zip` | full source project |
| `bgt nvgt decompile \| disasm game.exe` | single file / instruction listing |
| `bgt nvgt extract game.exe out.bin` | decrypted module, `--packs DIR` for embedded packs |
| `bgt nvgt inspect game.exe` | engine identity evidence as JSON |
| `bgt nvgt pack list \| extract \| create` | NVGT asset packs |
| `bgt nvgt library` | reuse installed include sources, verified by bytecode comparison |
| `bgt nvgt probe` / `keyscan` / `gen-opcodes` | diagnostics; see `--help` |

`bgt <command> --help` (or `bgt nvgt <tool> --help`) for the options.

---

## What you get, and what you don't

**BGT** strips debug information at compile time. You get every function,
class, property and enum **name**, every string literal, the full call graph,
and control flow as `if` / `while` / `break`. You don't get local variable
names, parameter names, line numbers or comments: locals read as `v3`,
parameters as `a0`. So you can rebuild a game faithfully; you cannot recover
its original text exactly.

**NVGT** games compiled in debug mode keep source-section file names, local
and parameter names and line numbers, and recovery uses them. Release builds
are stripped like BGT's. Either way, comments, formatting and the original
include boundaries are gone, and the output says which names are generated.

---

## Does it work on my game?

```bash
bgt validate mygame.exe            # BGT
bgt nvgt recover mygame.exe -o check.zip --check-with nvgt.exe   # NVGT
```

For BGT every stage prints `ok` or `FAIL`. All four titles this has been run
against pass every stage:

| | Psycho Strike | Paladin of the Sky | Manamon 2 | SBYW |
|---|---|---|---|---|
| dialect | tagged | tagged | len2 | tagged |
| classes | 68 | 47 | 1,604 | 154 |
| function bodies | 1,102 | 926 | 9,924 | 2,348 |
| operands named | 100% | 100% | 100% | 100% |
| rebuilds byte-for-byte | yes | yes | yes | yes |
| bodies ending with an empty stack | 100% | 100% | 100% | 100% |

BGT games share one engine, so a title that fails is more likely a BGT *version*
this has not seen than a modified engine. `bgt validate` shows which stage
stops.

---

## If something goes wrong

**"no xproc10 trailer"**: not a BGT executable, or a BGT version that packages
differently. Run `bgt identify`; it may be an NVGT game.

**"Cannot identify NVGT payload size/profile"** / **"Unsupported or corrupt
NVGT payload"**: the executable was built by an NVGT release whose packaging
profile has not been verified. See [docs/nvgt.md](docs/nvgt.md).

**`bgt lift` says "no function bodies were recovered"**: the module parsed but
its function records did not. It will tell you the dialect and where it stopped.

**The executable is UPX-packed**: nothing to do. `bgt identify` says so, and
the commands that read the engine (`lift`, `disasm`, `opcodes`, ...) unpack
its image in memory, checked against UPX's own checksums (NRV2B/2D/2E; LZMA
builds still need `upx -d` on a copy). If you did run `upx -d`, that copy
works too, but the game itself will no longer start from it: the overlay
moved and its trailer still points at the old offset. `bgt identify` reports
that.

**`bgt crack` finds nothing**: that only rules out the candidates it tried, and
it prints how many. The password is probably computed; see step 4 above.

**Ghidra commands fail**: run `bgt ghidra status`. Ghidra needs a JDK 21 or
newer, and the `java` on your PATH is often an older one kept for something else.

---

## Files

```
tools/         the BGT toolkit, bgt CLI, engine identification
tools/nvgt/    the NVGT toolkit (bgtdecomp.nvgt)
tests/         python -m pytest tests/ -q      (no game files needed)
tests/nvgt/    NVGT tests; optional fixtures enabled by env vars (see its README)
extra/nvgt/    the optional C++ bytecode-dump host used by NVGT round-trip tests
docs/          ghidra_workflow.md, nvgt.md
CLAUDE.md      both formats in detail, and why each part is believed
```

`CLAUDE.md` is the reference: how the encryption chains work, how the bytecode
formats are laid out, which parts were read out of a binary and which were
inferred, and what is still open. Read it before extending anything.

---

## Contributing

Contributions are welcome: issues, fixes, and support for engine versions this
has not seen. Two house rules, both from `CLAUDE.md`:

- **Read the reader, don't guess the format.** Format claims should come from the
  engine's own `asCReader` / `pack::create` in the binary (or, for NVGT, its
  published source), not from byte patterns.
- **Keep the repo free of game files and per-title findings.** Run
  `python -m pytest tests/ -q` before opening a PR; the suite uses synthetic
  inputs and owned fixtures only.

By contributing you agree your contribution is licensed under the MIT License,
like the rest of the project.

---

## License

[MIT](LICENSE.md): Copyright KamiKitsune420 (Adel Spence). The NVGT recovery
code is adapted from a third-party MIT project; its notice is in
[NOTICE.md](NOTICE.md), as that license requires.

Use it, modify it, share it and build on it, commercially or not. Keep the
copyright and license notice with copies you pass on.

---

## Disclaimer

**The software is provided as is, with no warranty of any kind.** The authors
are not responsible for any outcome of using it, including damaged files,
broken game installs, or any legal consequence of what you do with what it
recovers.

It is intended for interoperability, preservation and study of games you own or
are authorized to analyze. It ships no game files and no keys; everything it
does is derived from an executable you already have. Recovered strings and code
can contain private information, so review output before sharing it. Whether
extracting or redistributing a particular game's code or assets is lawful where
you live is your responsibility to determine, not this tool's.
