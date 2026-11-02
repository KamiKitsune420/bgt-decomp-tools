# BGT & NVGT Games — Decompilation Toolkit

General-purpose tooling for recovering code and assets from games built with **BGT
(BlastBay Gaming Toolkit)**, the 2010 audio-game engine by BlastBay Studios, and
with its open-source successor **NVGT**.

This document covers BGT in depth. NVGT lives in `tools/nvgt/` (the
`bgtdecomp.nvgt` subpackage, merged from nvgt-source-recovery) and is documented
in `docs/nvgt.md`. The two share a scripting language and almost nothing else:
packaging, encryption, AngelScript version and asset packs all differ.
`tools/engine.py` (`bgt identify`) decides which half an executable needs, and
claims an engine only when that engine's own self-verifying layer agrees.

This folder ships **only this document and the Python tools**. It holds no game
files, no extracted binaries and no per-title findings — those belong in the folder
for the game you are working on. Everything here is reproducible from a game
executable in one command.

---

# What these tools assume, and why it holds

A BGT game is the BGT runtime stub with the compiled AngelScript module appended as
a **PE overlay** — past the last section, so it is never mapped into memory and no
section dump will show it.

The important property: **the runtime is the same across titles.** BGT games do not
need per-title reverse engineering. This has been confirmed against six unrelated
shipped titles — same trailer, same key, same container magic, same
compression, same pack format, all opened by this toolchain unmodified. The two
that needed a change needed it in *this reader's guesses*, not in the format: a
hardcoded size limit and one spelling of a name (see **Crazy Party** below).

The corollary is worth stating because it is a common assumption: a developer
shipping several BGT games is almost certainly shipping **stock BGT**. If a title
does not open, suspect a different BGT *version* before suspecting a modified engine.
What genuinely varies between builds is the **AngelScript version** BGT was compiled
against, which changes how strings are serialized *inside* the module — not how the
module is stored.

---

# The chain

```
game.exe
  |- PE stub (BGT runtime, itself LZ77-compressed inside BGT's exec.bin)
  `- overlay
       |- "<n> "               ASCII decimal + space; n = size of an optional
       |                       embedded pack. Usually 0, giving the bytes "0 ".
       |- AES-256-CBC          key = SHA256(keygen(seed)), IV = key[:16]
       |    |- "<32 hex>=<flag> printf<len>\0"      container header
       |    `- LZ77 blob, ending " <uncompressed length>"
       |         `- AngelScript bytecode
       `- 12-byte trailer      "xproc10\0" + LE u32 overlay offset
```

The AES key is **generated, never stored** — which is why no string search in a BGT
executable ever finds one:

```python
v = seed                       # 0x11 in stock BGT
for _ in range(32):
    v *= 3
    v = 5 if v >= 0x80 else (0xd if v == 0 else v)
    key_material.append(v & 0xff)
aes_key = sha256(key_material)
```

`bgtlib.find_seed()` recovers the seed by trial decryption rather than assuming it,
so a build that changed it still opens. The container header — 32 hex characters
followed by `=` — is a strong enough constraint that a wrong seed is never mistaken
for a right one.

Note the container header is **fixed-shape but not fixed-length**: the declared
length is decimal, so a larger module means a longer header. Compute it, never
hardcode it.

## UPX-packed runtimes

Some titles ship the runtime compressed with UPX. The overlay is untouched --
UPX leaves anything past the last section alone -- so unpacking the script
does not care. What breaks is everything that reads the *engine*: `asBCInfo[]`
is inside the compressed blob. `upx.py` rebuilds the memory image following UPX
3.96's own `PeFile::unpack0`, and `as_opcodes.extract()` reads from that:

1. PackHeader (`UPX!`, just before the second section's raw data) names the
   method, filter and lengths.
2. NRV2B/2D/2E decode to exactly `u_len`; `c_adler` and `u_adler` must match.
   (`u_adler` is taken before unfiltering, so it proves decoding only.)
3. The stream's last dword locates the original PE header and section table.
4. The code range `[codebase, codebase+codesize)` is unfiltered (`filter/ct.h`,
   `filter/cto.h`; ids 0x11-0x16, 0x24-0x26). Unimplemented filters leave code
   filtered and say so -- data sections, where the opcode table lives, are
   never filtered.
5. Relocations are replayed: UPX stores each relocated dword big-endian as
   `value - imagebase - rvamin`. Missing this step leaves every pointer in
   `.rdata` wrong while the data *looks* plausible.

Checked against `upx -d` on a shipped title: `.text` and `.data` identical, and
`.rdata` differs only in the import descriptors, which are deliberately not
rebuilt. `bgt opcodes` on the packed file and on the `upx -d` copy give the
same table. The trailer stores an **absolute** overlay offset, so a `upx -d`
copy (or any PE rewrite) has a stale trailer; `split_overlay` then looks for the
overlay at the end of the PE image, and `bgt identify` reports the staleness,
because BGT's own loader will not find the script in such a copy.

---

# Tools

Pure Python 3. Needs `pycryptodome`. Nothing here needs `capstone` — AngelScript
bytecode is not x86, and `as_opcodes.py` disassembles it directly. (Reach for
`capstone` only if you separately want to disassemble the x86 *runtime*.)

| tool | what it does |
|---|---|
| `cli.py` | `bgt` — one entry point dispatching every subcommand below |
| `bgtlib.py` | the chain as a library — `unpack_file(path)` returns every intermediate |
| `bgt_unpack.py` | CLI: unpack one or more executables, report each layer, write bytecode |
| `bgt_pack.py` | SFPv1 asset packs — parse, list, verify a key, decrypt entries |
| `as_module.py` | AngelScript module reader — dialects, enums, classes, function bodies, and every tail table through to EOF |
| `as_opcodes.py` | recovers `asBCInfo[]` from the executable and disassembles AngelScript bytecode |
| `as_disasm.py` | readable disassembly — resolves calls, literals, globals and members to names, and labels jumps |
| `as_lift.py` | lifts disassembly to pseudo-source — a symbolic stack machine plus control flow |
| `as_write.py` | writes a module back out — byte-exact round-trip, and length-changing edits |
| `bgt_asir.py` | presents a BGT module as the AngelScript IR the NVGT decompiler reads |
| `bgt_api.py` | `bgt api`: the engine's API -- documented, from `bgt.chm`, and registered, from `bgt.exe`'s own declaration strings |
| `bgt_apicheck.py` | `bgt apicheck`: every call in a recovered project's text, against every arity its own build declares -- the check for a title the compiler cannot parse |
| `bgt_audit.py` | `bgt audit`: every callee, string literal and numeric constant the BYTECODE holds, against the recovered text -- the instrument that found the dropped initialiser list and the flattened clock |
| `bgt_signatures.py` | `bgt signatures`: shapes in recovered text that no author would write -- one per bug class in this file, swept, with the delta between two trees |
| `bgt_roundtrip.py` | `bgt roundtrip`: the original bytecode against the RECOMPILED bytecode, body by body -- the only check that compares a recovery against the whole original |
| `bgt_compile.py` | `bgt compile`: runs BGT's own compiler and reads back every diagnostic; `bgt verbs`: which BGT the shell runs for a `.bgt`, and repoint it |
| `bgt_project.py` | `bgt recover`: a browsable, compilable project — files, ZIP, report |
| `bgt_oracle.py` | `bgt oracle`: a source whose answer is known, round-tripped through the engine — the check for whether a recovery is the SAME PROGRAM |
| `bgt_drive.py` | `bgt drive`: runs a recovered game's own functions with keys held down and watches what they answer -- silently, and with no window |
| `bgt_gui.py` | `bgt gui`: a wxPython window over identify, recover and compile |
| `bgt_to_nvgt.py` | `bgt tonvgt`: a recovered BGT project as one NVGT compiles -- and unlike the BGT side it can ask, because NVGT's compiler is a console program |
| `bgt_repack.py` | the chain in reverse — rebuild an executable around a modified module |
| `bgt_crack.py` | harvest candidate passwords from a module and test them against a pack |
| `bgt_validate.py` | run the whole pipeline over several titles and compare, stage by stage |
| `bgt_ghidra.py` | find/install Ghidra + a JDK, install extensions, drive headless decompiles |
| `bgt_kdf.py` | BGT's password → AES-key derivation for encrypted asset packs |
| `bgt_string_crypt.py` | BGT's `string_encrypt` / `string_decrypt`, and the shared key setup |
| `engine.py` | `bgt identify`: BGT or NVGT, decided by each engine's own verifying layer |
| `upx.py` | the memory image of a UPX-packed runtime, so `asBCInfo[]` can be read without `upx -d` (see below) |
| `script_files.py` | `bgt files`: which source files a stripped module was built from -- library files by name, the game's own as segments |
| `nvgt/` | the NVGT half: extraction, `asCReader` for 2.37, decompiler, project recovery, NVGT packs (`docs/nvgt.md`) |
| `bgt_libcheck.py` | `bgt libcheck`: recovered code against BGT's shipped library source -- the lifter, or `--decompiler` for the `bgt recover` path |
| `nvgt/libcheck.py` | `bgt nvgt libcheck`: decompile NVGT's own `include/`, debug and stripped, and recompile it |
| `elias/render.cs` | renders a game's adaptive music at a chosen intensity, by driving the game's own `elias.dll`. **The one non-Python tool here**, and the reason is a hard one: `elias.dll` is 32-bit and the Python on this machine is 64-bit, so no `ctypes` can load it. `csc -platform:x86` ships with Windows, so this needs nothing fetched |
| `elias/predecode.py` | decodes a theme's Ogg stems to raw 16-bit PCM for that renderer (needs `soundfile`, which nothing else here does) |

`docs/ghidra_workflow.md` covers how to find `asCReader::ReadInner`, `asBCInfo[]`,
the KDF and `pack::create` in a binary, and how to verify a transcription.

## Installing

Optional. Everything runs straight from a checkout; installing just adds console
scripts and lets other code `import bgtdecomp`.

```bash
pip install -e .        # then: bgt unpack game.exe -o out
```

The whole workflow through the unified CLI:

```bash
bgt unpack game.exe -o work/
bgt disasm work/game_bytecode.bin game.exe -o work/game.asm
bgt lift   work/game_bytecode.bin game.exe -o work/game.as
bgt crack sounds.dat --dict work/game_bytecode.bin --workers 0
bgt lift   work/game_bytecode.bin game.exe --calls set_sound_decryption_key
bgt pack extract sounds.dat -o sounds/ --key <hex>
bgt asm    work/game_bytecode.bin game.exe \
           --replace sounds.dat=my.dat -o work/modified.bin
bgt repack game.exe work/modified.bin -o patched.exe
bgt validate game.exe patched.exe
```

...or ported to the other engine, which can be compiled on every run:

```bash
bgt tonvgt recovered/ -o ported/          # convert, then `nvgt -c` judges it
```

Or, in one command, the whole thing as a project the compiler judges:

```bash
bgt recover game.exe -o recovered/ --compile
bgt recover game.exe -o recovered/ --extract-data # ...and unpack the packs too
bgt recover game.exe -o recovered/ --no-game-files  # ...without the game's other data
bgt compile recovered/game.bgt            # just the compiler, on any script
bgt oracle                                # does a recovery still COMPUTE the same?
bgt drive recovered/ --scenario ctrl      # ...and does the GAME's own code answer right?
bgt apicheck recovered/ game.exe          # every call, against the build's own declarations
bgt audit    recovered/ game.exe          # ...and did it LOSE a value?
bgt signatures recovered/                 # ...and does the text say something odd?
bgt roundtrip game.exe recovered/game.exe # ...and does it COMPILE BACK to the same thing?
bgt verbs --repoint                       # make double-clicking a .bgt use the BGT that can parse it
```

Extending the reader means reading `asCReader` out of the binary, and the Ghidra
side of that is scripted too — see `docs/ghidra_workflow.md`:

```bash
bgt ghidra status                                    # Ghidra + JDK 21+ present?
bgt ghidra install                                   # fetch it (asks first)
bgt ghidra decompile game.exe --string _builtin_function_ -o readers.c
```

**Analyse `bgt.exe` once and keep the project.** The engine is the authority
for every "what does BGT actually do here?" question this document keeps
asking, and `--project` makes asking cheap: the import and analysis take
about fifteen minutes, and every query after that takes **about twenty
seconds**.

```bash
bgt ghidra decompile "<BGT>/bgt.exe" --string factstub     --project <somewhere outside this repo>/bgt_ghidra_project --max-mem 4G
```

Two things about that, both learned the hard way on a 15.5 GB machine:

- **The heap has to be 4G.** 2G dies with `OutOfMemoryError: Java heap space`
  in `X86Analyzer`, and 5G dies *before* Java starts, with
  `os::commit_memory ... The paging file is too small` -- which is the system
  refusing the reservation rather than Ghidra needing it. 4G commits and
  completes.
- **A failed import leaves a project that cannot be retried into.** The
  second attempt reuses the directory, finds no program in it, and aborts
  with `No program files found within specified project folder: /`. Delete
  the project directory and start over.

Keep the project and its output outside this repository -- it is 25 MB of
engine, not toolkit.

Modules work both ways on purpose — run directly and the script's own directory is
on `sys.path`; installed, the package-relative import resolves instead. Neither form
needs a `sys.path` fixup at the call site.

```bash
# unpack a game
python tools/bgt_unpack.py path/to/game.exe -o /some/scratch/dir

# identify a recovered module and dump its enums
python tools/as_module.py /some/scratch/dir/game_bytecode.bin

# list an asset pack
python tools/bgt_pack.py path/to/data.dat
```

## Tests

```bash
python -m pytest tests/ -q          # everything: BGT, NVGT, integration
python tests/test_toolkit.py        # the BGT known-answer tests alone
```

`tests/test_toolkit.py` holds the BGT known-answer tests,
`tests/test_recovery.py` those for project recovery — the IR adapter, the
compiler driver and the project writer — `tests/test_integration.py` the checks
that join the two halves (embedded-pack walk, NVGT packs, engine
identification, the two integer codecs agreeing), and `tests/nvgt/` the NVGT
suite, whose compiler-backed tests skip unless their
optional fixtures are configured (`tests/nvgt/README.md`). All of it runs on
**synthetic inputs and owned fixtures only** — no game files — so it runs
anywhere. Every subprocess they and the tools launch is given an explicit
`stdin=subprocess.DEVNULL`: a compiler run non-interactively has no use for
stdin, and on Windows inheriting a handle the parent has closed fails the
*spawn* with `WinError 6`, intermittently and nowhere near the real cause.

They deliberately target the things that fail *quietly* rather than loudly:
the encoded-integer boundary at 64, negative lengths rewinding the cursor, overlapping
LZ77 matches, the keygen constant, a pack walk that does not land on EOF, the SWCR
tag rejecting a wrong key, a tail that does not land on EOF, the low-bit table
selector in a global-pointer operand, jump targets counted in instructions, and a
resynchroniser that must refuse rather than run to EOF, the token mapping
between the two AngelScript generations, a default-argument list stored
last-to-first, the global-pointer shift touching only the pointer field, an
inherited-property prefix that carries no flag, a candidate list that must not
swallow the rest of a compiler report, and a project split that must not
reorder declarations.

Run them after any change here. The runtime checks below validate against real game
files, but they cannot catch a regression before you have a game file in front of you.
For that, `bgt validate` over two or more titles is the check that matters.

## Every layer is self-verifying

A wrong guess fails loudly rather than producing plausible garbage. If any of these
pass, that layer is right:

- the trailer magic is `xproc10`
- the ciphertext length is a multiple of 16
- the decrypted head is 32 hex characters followed by `=`
- LZ77 output length equals the length the container declared, **exactly**
- the module begins with `noDebugInfo` then a parsable enum count
- a pack walk ends **exactly** on EOF (`bgt_pack.parse` raises otherwise — a short
  read is never silent)
- the module's **tail sections end exactly on EOF** (`Reader.tail` raises otherwise);
  nothing follows `usedObjectProps`, so this validates every field width before it
- every function body decodes to **exactly** its declared instruction count
- a bytecode operand's maximum **saturates** its table — one more would not fit, one
  fewer would leave the last entry unreachable

---

# The AngelScript module

## Two string dialects

`as_module.py` handles both. They differ **only** in how a string is written; record
layouts, big-endian integers and varints are shared.

| dialect | encoding |
|---|---|
| `tagged` | `0x6E 'n'` = new (`eu(len)` + bytes), `0x72 'r'` = back-ref `eu(index)`, `0x00` = empty |
| `len2` | `eu(v)`; **even** → new string of `v/2` bytes, **odd** → back-ref `(v-1)/2` |

Both append new strings to a running `savedStrings` table that back-references index
into. `tagged` is the older AngelScript; `len2` is newer.

Detection is by trial parse, not assumption — the wrong dialect dies within one or
two records because an enum name has to be a valid identifier.

## Record layout

```
enum := str(name) u32(flags BE) eu(size) str(ns) eu(count) [str(name) i32(value BE)]*count
```

Integers inside the module are **big-endian**. `ReadData` on a little-endian host
fills its destination backwards, which is what makes the stream big-endian —
confirmed by reading the binary, not assumed.

## `ReadEncodedUInt64` — get this right before anything else

It looks like a UTF-8-style continuation-bit varint. **It is not.** The top bit of
the lead byte is a **sign flag**, and the width is a run of set bits below it:

```
0xxxxxxx                value = b                  (0..63)
10xxxxxx + 1 byte       value = (b & 0x3F) << 8  | next
110xxxxx + 2 bytes      value = (b & 0x1F) << 16 | ...
1110xxxx + 3 bytes      11110xxx + 4 / 111110xx + 5 / 1111110x + 6 / 1111111x + 8
```

So `40 5b` is **one** value, 91 — not 64 followed by `0x5b`.

This is the highest-value item in this document, because getting it wrong fails
**quietly**. Every value below 64 encodes to a single byte under either reading, so a
wrong decoder is correct for the large majority of lengths and counts and only
desynchronises at the first value ≥ 64. In one module that was thousands of records
in; in a smaller title it never happened at all, so the same broken decoder produced
a perfect parse and looked correct.

Two consequences:

- **The sign flag is real.** Lengths, counts and table indices are unsigned, so a
  negative result means you are not looking at the field you think you are. Guard it:
  an unguarded negative length moves the cursor *backwards*, and a scan then appears
  to succeed while ending before it started.
- **Check a decoder against known pairs before trusting anything built on it** —
  `3f`→63, `40 56`→86, `40 5b`→91, `40 81`→129, `40 a7`→167, `40 e7`→231. These are
  in `tests/test_toolkit.py`.

## Hard limit on what is recoverable

BGT compiles with `noDebugInfo = 1`. **Line numbers, source filenames and local
variable names are stripped and unrecoverable.** Function, class, property and enum
names survive, as does every string literal.

So a faithful re-implementation of a BGT game is achievable; a byte-identical one is
not. Locals will read as `v3` and parameters as `a0`, and you name them from context.

## Extending the reader

**Every title parses end to end, from offset 0 to the last byte, in both
dialects.** The sections, in the order `ReadInner` reads them: header, enums,
class declarations, funcdefs, the three class passes (interface phase 2, class
phase 2, class phase 3), typedefs, global properties, module functions, global
functions, bind info, `usedTypes`, `usedTypeIds`, `usedFunctions`,
`usedGlobalProps`, `usedStringConstants`, `usedObjectProps`.

`usedObjectProps` is last, so **it must finish exactly at EOF** — there is nothing
after it to absorb a mistake. That one constraint transitively validates every
field width upstream of it, which makes it the strongest check in the format.
`Reader.tail()` raises unless it lands exactly, and `summarize()` returns the tables
under `"tail"`.

On Manamon 2 this reproduces, independently, every count a separate parser had
recorded: 454 global properties, 2,892 module functions, 1,280 global functions,
1,759 `usedTypes`, 8,180 `usedFunctions`, 539 `usedGlobalProps` — and
`usedFunctions[5343]` is `set_sound_decryption_key`, exactly as documented.

| title | dialect | classes | bodies | tail |
|---|---|---|---|---|
| Psycho Strike | tagged | 68 / 68 | 1,102 | ends exactly at EOF |
| Paladin of the Sky | tagged | 47 / 47 | 926 | ends exactly at EOF |
| Manamon 2 | len2 | 1,604 / 1,604 | 9,924 | ends exactly at EOF |
| SBYW | tagged | 154 / 154 | 2,348 | ends exactly at EOF |
| Super Egg Hunt | tagged | 10 / 10 | 141 | ends exactly at EOF |
| Crazy Party | tagged | 550 / 550 | 4,486 | ends exactly at EOF |
| Manamon 1 | len2 | 784 / 784 | 4,719 | ends exactly at EOF |
| The Gate | tagged | 171 / 171 | 1,783 | ends exactly at EOF |

Super Egg Hunt is the fifth, and the first picked up cold after all of the
above: `bgt validate` passed it on every stage, byte-exact rewrite included,
with no reader change. It did find one thing, in the *header peek* rather than
the reader. `bgt unpack`'s one-line dialect probe reads the first enum name's
first byte -- and this module declares **no enums**, so the byte it read was a
class count, and it called a `tagged` module `len2` with no sign of a problem.
The probe now says it cannot tell, which is true and is what the trial parse
is for. A heuristic that answers anyway is worse than one that declines.

SBYW is the fourth title, and the first run after the three above were done. It
passed every `bgt validate` stage with no reader change, byte-exact rewrite
included. What it added was on the lifting side: it is the first title to use
`**` (`POWd`, `POWdi`) and 64-bit shifts (`BSLL64`, `BSRL64`), 19 instructions
the lifter had never needed to model.

Psycho Strike's tail reproduces every count an entirely separate parser recorded:
105 global properties, 288 module functions, 220 global functions, 109
`usedTypes`, 71 `usedTypeIds`, **1,048 `usedFunctions`**, 171 `usedGlobalProps`,
2,660 `usedStringConstants`, 786 `usedObjectProps`.

### The string constant pool resolves completely now

Its entries back-reference the **module-wide** saved-strings table. Reached by a
linear parse from offset 0, **every entry resolves** — 10,181 of 10,181 on
Manamon 2, zero unresolved references.

This supersedes the older note that a scan finds the pool with about a third of its
entries unresolved. Scanning also got the *size* wrong: density-scanning suggested a
17,773-entry table, and four candidate start offsets fit. The linear parse settles
it at 10,181 entries starting `0x3C4C10`, which the `PGA 10050 -> "data.dat"` pin
independently confirms. Do not locate this table by scanning; walk to it.

### The dialects differ in record layout, not only in strings

This is the single biggest trap in the format. `tagged` is not `len2` with a
different string encoding — the *records* differ, and every difference below was
read out of the relevant binary, not inferred:

| what | tagged (strike 0x0041E2A0 etc.) | len2 (rpg 0x0042ACC0 etc.) |
|---|---|---|
| script-object flag | `0x00100000` | `0x00200000` |
| phase 1 shared byte | absent entirely | one byte if `asOBJ_SHARED` |
| in/out + default-arg lists | written **unconditionally** | `paramCount != 0` -- but **per build**, see below |
| funcdef (`funcType 4`) | ends at the namespace | one more traits byte |
| funcdef namespace | plain string | `'n'`/`'o'` tag first |
| interface vftable offset | always read | skipped for interfaces |
| funcType-1 body | no flags byte | flags byte gates everything |
| object variables | `{typeinfo, eu, eu}` | `{typeinfo, eu}` |
| `nObjInfo` | unconditional | inside the `flags & 0x08` block |
| try/catch block | none | present when `flags & 0x10` |
| body trailer | one traits byte | none |
| funcdef-typed params | `_builtin_function_` + a **nested signature** | the funcdef type is named directly |
| `usedObjectProps` entry | `typeinfo` + property **name** (tagged string) | `typeinfo` + property **name** (a `len2` back-reference — see below) |
| global-pointer operands | plain index | `2 * index + tag` |

Two of these are worth calling out because each was a whole afternoon.

**The script-object flag moved.** `IsInterface()` is `(flags & X) && size == 0`,
and X is `0x100000` in the older reader and `0x200000` in the newer. It decides
whether a class block has a behaviour section, so the wrong constant
desynchronises on the first interface and everything after it is garbage.

**The funcType-1 body trailer.** One traits byte, read unconditionally after the
body and *outside* the debug-info block, which funcTypes 2/3/4 jump straight
past. Without it `character::character` comes out exactly one byte short — the
constructor still parses perfectly, with its declared 177 instructions and a
clean `RET` — and the factory record that follows is one byte out, taking the
whole class block with it.

### Two differences are per-build, not per-dialect

`ReadTypeInfo`'s `'a'` (template) form carries a namespace string after the name
in Psycho Strike and Manamon 2, and does **not** in Paladin of the Sky — same
`tagged` dialect, different record. So `as_module` trials both and keeps the one
whose tail lands exactly on EOF, the same way the dialect itself is detected.
`summarize()` reports which won as `template_namespace`.

**The second is the zero-parameter list guard**, and it was tied to the
dialect until Manamon 1 disproved that. The newer reader guards both the
in/out and the default-argument list on `paramCount != 0`; the older one
writes them unconditionally. Manamon 1 is `len2` and writes them
unconditionally, while Manamon 2 is `len2` and does not -- 27 of 27 funcdefs
parse with the guard and 0 of 27 without it. Two builds of one dialect, two
answers, so it is trialled the same way and reported as `unguarded_lists`.

`phone_callback` is the record that shows it, and nothing in the corpus had
exercised a zero-parameter funcdef before -- Manamon 2's twenty-seven all
take at least one parameter:

```
04        return type (void)
00        parameter count = 0
00        inOutFlags count     <- skipped when guarded
04        funcType = 4
00        default-argument count
00 6E 00  owner (none), 'n', empty namespace
01        funcdef traits
```

Nine bytes, landing exactly on the next `'f'`. Guarded, the reader takes the
`04` for the funcType position, reads the real funcType as a type-info and
raises `bad type-info tag 0x04` -- which is a *parse* failure rather than a
quiet one, and that is the only reason it was cheap to find.

Both trials try the assumptions this reader already held **first** and keep
them on a tie, so adding a second field cannot silently re-describe a module
that was already landing on EOF. Paladin, Psycho Strike, Super Egg Hunt and
Manamon 2 all still pass every stage, Manamon 2 with its 9,700 bodies.

Do not assume a third title matches either of these two. Run `bgt validate`.

### The string factory has a third spelling, and one title uses it

`STR` pushes a literal's address **and its length** -- `stackInc` is 2 in
both engines' own `asBCInfo[]`, read rather than assumed -- and the
registered string factory pops both. Whichever name that factory has.

BGT 1.3 calls it `_string_factory_`, and so do Paladin, Super Egg Hunt,
Psycho Strike and Crazy Party. **Manamon 1's fork calls it `$str`**,
and nothing else in the corpus does -- which is checkable in one line, since
the name is a literal in the module:

```
egghunt    $str: False   _string_factory_: True
paladin    $str: False   _string_factory_: True
strike     $str: False   _string_factory_: True
crazyparty $str: False   _string_factory_: True
manamon1   $str: True    _string_factory_: False
```

Knowing only one spelling left both of the slots `STR` pushes on the stack,
so every string literal in that title recovered as

```
name = string(<strlen>, "");
local_4 = string(<strlen>, "Random");
```

-- `<strlen>` being the placeholder for the length slot. It is not source,
it does not parse, and **a parse error cascades**: one unrecognised name
became **24,916 diagnostics** across a 91,310-line project. Fixed, there is
not one `<strlen>` left and the recovery is 91,290 lines.

This is the third time one engine construct has had two names here, after
`%delegate_factory`/`$dlgte` and `$list`/`factstub`. The pattern is worth
stating as a rule: **a registered name is a per-build field like any other**,
and the cheap check is that the name is a literal in the module, so asking
which spelling a title uses costs one search rather than a compile.

**And finding it cost somebody an 8.9 MB modal dialog.** Compiling a whole
91,310-line recovery in the foreground put BGT's own report window on the
screen of whoever was at the machine, holding every one of those 24,916
errors. That is the third time this file has recorded the same lesson from a
new direction -- `capabilities()`, the oracle against a stashed decompiler,
and now this. The driver takes `--timeout` and `bgt recover --compile`
already passes 600 s; what it does not have is a way to ask without
drawing. Prefer the bytecode audits for "did we lose something?", and treat
a whole-title compile as a thing to run deliberately and not while someone
is using the machine.

**Manamon 1 has not been compile-checked since**, deliberately, so its
standings row says so. The `<strlen>` cause is gone, but it was built by a
fork BGT 1.3 is not, and Manamon 2 is already in this document as 33 parse
errors for exactly that reason -- `protected` and `weakref` the installed
engine does not have. A number from the wrong engine is a statement about
the engine.

### Manamon 1 is a third reader generation, and the body is where it differs

Manamon 1 (`VGStorm.com\Manamon\rpg.exe`, 2017-07-30) is BGT, overlay
0xF9C00, stock seed 0x11, `len2`, 55 enums, **784 classes**. It parses end to
end now: 784 / 784 class blocks, 4,719 bodies each decoding to exactly its
declared instruction count, 0 parse errors, a tail landing exactly on EOF and
a byte-exact rewrite. `bgt validate` passes it on every stage.

**Two of its counts are the benchmark's own.** The tool this project was
started against reported 784 classes and 332 globals for this title, and the
tail independently gives 784 and 332 -- numbers reached by a different reader
from the same bytes. The rest: 7 funcdefs, 1,608 module functions, 822 global
functions, 883 `usedTypes`, 808 `usedTypeIds`, 4,087 `usedFunctions`, 415
`usedGlobalProps`, 7,802 `usedStringConstants`, 3,567 `usedObjectProps`.

What it needed was **a third per-build field, and not the one that had been
guessed at**: whether a funcType-1 body opens with a flags byte. It does not.
`asCReader::ReadFunction` is `FUN_004216D0`, and for funcType 1 it calls
`ReadByteCode` straight after the signature:

```
ReadByteCode                       FUN_004245E0 -- eu(instruction count) + instructions
eu(variableSpace)
eu(nObjVar)   nObjVar x { ReadTypeInfo, eu }     <- TWO fields
if nObjVar > 0: eu(objVariablesOnHeap)
eu(nObjInfo)  nObjInfo x { eu, eu, eu }          <- unconditional, not nested
ReadData(&bits, 1)                               <- read-only / private
```

No `flags & 0x04` "body omitted", no `flags & 0x08` gate on the object
variables, no try/catch block, and the debug-info branch dead because
`noDebugInfo` is 1. That is the **older** reader's body shape -- the one this
file had as `tagged`'s -- carried by a `len2` module, with two fields per
object variable where the older one writes three. So `legacy_body` is a
per-build field like `template_namespace` and the zero-parameter list guard,
trialled against the exact-EOF landing, and the object-variable field count
travels with it rather than with the dialect.

### A global pointer's encoding is per build, and the reader says which

A fifth per-build field, after `template_namespace`, the zero-parameter list
guard, `objvar_three` and `legacy_body` -- and the one that had been read off
the wrong field for longest. Whether a global-pointer operand carries a
table-selector bit was keyed to the **dialect**, so Manamon 1, which is
`len2`, was read with Manamon 2's rule. Every one of its **4,117** global
operands resolved to the wrong thing: the 2,122 even ones to a string from
the string table, and the 1,995 odd ones to the global at *half* their index.

Nothing reported it, and the shape of what it produced is why:

```
character@[]@ local_10;
@local_10 = "";            // an empty string, into a handle-to-array
heal_all(local_10);
```

**What found it was the literal audit, not a diagnostic.** The bytecode-vs-text
literal multiset said 12 of Manamon 1's bodies were missing one, and 11 of
those were explained (see below); the twelfth was `sleep_in_bed`, where a
`PshGPtr` had become `""`. A count of lost literals is a thin thread, and it
led to the largest single correctness defect found in this title.

**Three lines of evidence said plain, and then the reader settled it.** The
circumstantial case first, because each line is the kind this file trusts:

| evidence | what it says |
|---|---|
| saturation | max operand **414** against **415** `usedGlobalProps` -- exact |
| the tag bit | operands freely even *and* odd (2,122 / 1,995), so there is none |
| the other reading | its largest even operand is string index 207 of 7,802 -- 97% of the table unreachable |
| where the literals live | `STR` 12,523 against `PGA` 136 |
| width consistency | plain **90.5%**, tag **44.9%** -- and the four titles whose answer is known score 85-94% against 17-43% |

That last one is the instrument worth keeping. AngelScript has a separate
opcode per operand width, so the instruction says what it expects of the
global it names -- `PshGPtr`/`PGA`/`LDG` a pointer, `PshG4`/`SetG4`/`CpyGtoV4`
a four-byte primitive -- and the right reading agrees while the wrong one
scores chance. It is a consistency check with a known expected answer, the
same shape that settled `ALLOC`'s one-based operand, and it was **validated
against four titles whose answer was already known** before being believed
about the fifth.

**And then `asCReader::TranslateFunction` in that title's own binary said it
outright**, which is the rule this document opens with. `FUN_004250C0` puts
all eight of those opcodes in one branch:

```c
else if (op == PGA || op == PshGPtr || op == LDG || op == PshG4 ||
         op == LdGRdR4 || op == CpyGtoV4 || op == CpyVtoG4 || op == SetG4) {
    if (*(uint *)(this + 0x54) <= *(uint *)(instr + 4)) goto Error;
    *(undefined4 *)(instr + 4) =
        *(undefined4 *)(*(int *)(this + 0x50) + *(uint *)(instr + 4) * 4);
}
```

The raw operand is bounds-checked against one length and used **directly** as
the index into one array. No mask, no shift, no branch on the low bit, no
second table. The control that makes the absence meaningful: the *same
function* does shift an operand where it means to -- the jump-offset
conversion for `JMP`/`JZ`/`JS`/... -- and that shows plainly in the
decompilation. `this+0x50` is `usedGlobalProps`, confirmed three ways: `STR`
(op 0x3C) bounds-checks a **word** operand against `this+0x68` and indexes a
different array, `this+0x64`; `ReadInner`'s call order forces the identity of
the reader that fills `this+0x50`, and reading it shows name + namespace +
datatype + flag per entry resolved against the module's property table; and
`FindFunction` fixes the 0x14-byte `asCArray` stride, giving 0x28 `usedTypes`,
0x3C `usedFunctions`, 0x50 `usedGlobalProperties`, 0x64 `usedStringConstants`.

Two things the same read settled in passing, both of which this file had as
inferred from grouping in a *different* binary: `Thiscall1`'s operand really
is a `usedFunctions` index, because `CALL`, `CALLINTF`, `CALLSYS` and
`Thiscall1` all go through that one `FindFunction`; and `ALLOC` resolves arg0
by type and arg1 by `FindFunction(arg1 - 1)` under a non-zero guard, which is
the one-based rule read directly rather than deduced from an owner match.

#### What decides it, and why it is a reading rather than a threshold

`as_opcodes.global_index_is_plain` asks **which opcode this build's literals
arrive through**, which is the mechanism: a build that gives a literal its own
`STR` has no reason to put a selector in a global pointer, and a build whose
literals come through `PGA` must. Counted per module:

| title | `STR` | `PGA` | encoding |
|---|---|---|---|
| Manamon 1 | 12,523 | 136 | plain |
| Crazy Party | 130,243 | 70 | plain |
| Paladin of the Sky | 4,625 | 87 | plain |
| Psycho Strike | 3,637 | 66 | plain |
| Super Egg Hunt | 1,079 | 48 | plain |
| Manamon 2 | 0 | ~149,762 | `2n + tag` |

Three orders of magnitude in both directions, so this is not a threshold with
a tuned constant. A module carrying no literals either way returns None and
the caller keeps its dialect default, because no evidence is the honest
answer there.

**It is answered in two places that have to agree**, which is the failure this
file keeps recording, so the policy is one function and only the counting is
local: `as_disasm` resolves operands for `bgt lift` and `bgt libcheck`, while
`bgt_asir` pre-shifts the operand to `2n + 1` before handing it to the newer
engine's reader, whose own rule is unconditional. The pre-shift used to be
gated on `tagged`; it is gated on this now.

#### The scope, measured both ways

| title | lines | goto | split | calls | files identical to the previous run |
|---|---|---|---|---|---|
| Super Egg Hunt | 6,247 | 0 | verified | 1,608 | **14 / 14** |
| Paladin of the Sky | 27,343 | 0 | verified | 7,110 | **59 / 59** |
| Psycho Strike | 27,469 | 2 | verified | 6,443 | **73 / 73** |
| Crazy Party | 192,603 | 14 | verified | 90,118 | **558 / 558** |
| Manamon 1 | 91,310 -> **90,314** | 0 | verified | 26,548 | 53 / 806 |

Four titles **byte-identical**, and 753 of the fifth's 806 files changed. That
is what a correctly scoped per-build fix looks like, and equal counts would
not have shown it: this file records a change that held every count while
making the output badly wrong, so the diff is the measurement and the counts
are the summary.

#### What the literal audit left on this title

The other eleven, now that the twelfth is explained:

- **Eight are the audit's own artifact.** The recovery writes any byte above
  0x7F as `\xNN` -- deliberately, because a literal has to reach the engine as
  the bytes the module held -- so comparing bytecode *bytes* against the
  literal's *source text* compares an escape against the byte it escapes.
  Every one of the eight is a monster description carrying a Windows-1252
  right single quote.
- **Three are an empty string** the recovery renders as a declaration
  (`string local_3;`) rather than an assignment of `""`, which is the same
  program.
- **One is the original's dead code**, and it is worth stating because it
  looked exactly like a lost line. `sleep_in_bed` computes
  `<global>.name + " slept in the bed.[/]"`, copies it into a slot, and then
  calls `string::opAssign` on that slot with
  `"All manamon have been completely healed."` -- `opAssign`, not
  `opAddAssign`, so the concatenation is **overwritten on the next line**.
  Someone changed the message and left the old one. Dropping a pure
  expression whose value nothing reads is behaviour-preserving, so this stays
  dropped, exactly like `generate_maze`'s discarded comparison.

So **no literal is lost by the decompiler on this title**, which is the
result; the audit's value was the twelfth row, not the eleven.

### A known target BOTH readings satisfy is not a discriminator

This is the expensive lesson of this title, and it is a correction to what
this file said a moment ago. The earlier attempt had a *known target* --
`elemental_node`'s constructor record must end exactly where the factory
that follows it begins, 0x6559 -- and it reported that only three-field
object variables land on it. That was true, and the conclusion was wrong:
**the correct reading lands on 0x6559 as well.**

The two differ by one byte at the *start* of the body, and the object
variables give it back at the end:

| | flagged + three fields | legacy + two fields |
|---|---|---|
| 0x6537 | flags byte 0x09 | instruction count 9 |
| 0x6538 | instruction count 9 | first opcode |
| objvar | `{typeinfo, eu, eu}` | `{typeinfo, eu}` |
| ends | 0x6559 | 0x6559 |

0x6537 and 0x6538 both hold 0x09, which is what makes the two readings
indistinguishable at that record. A one-byte shift through nine instructions
produces nine *different* instructions, and both decoded without complaint --
`PopPtr ; STOREOBJ ; PshVPtr ; PshVPtr ; ADDSi ; REFCPY ; PopPtr ; FREE ;
RET` for the wrong one.

**The factory is what separates them**, and only because its bytecode has a
shape worth recognising. Legacy decodes it as

```
PSF 1 ; ALLOC 1, 2 ; LOADOBJ 1 ; RET 0
```

which is what a default factory stub *is* -- make space, allocate, move the
handle out of the object register, return -- and lands within a byte of the
next record. Flagged decodes four instructions that are not a factory and
overshoot it. So the discriminator was never the offset; it was reading the
instructions and asking whether they are the function.

The rule that survives is narrower than "have a known target": a target only
discriminates if the candidates **disagree** about it. Check that they do
before counting a landing as evidence, and prefer the reader.

### The reader, read -- what each function is and how it was identified

Nineteen sites reference the `LoadByteCode` literal (file 0xD1C18, VA
0x004D2818), one per error path inside `asCReader` (0x0041F210 - 0x00425C5A):
0x41F22C, 0x41F745, 0x41F9FF, 0x41FB64, 0x41FC77, 0x41FD06, 0x41FE26,
0x4200F2, 0x420172, 0x420213, 0x4202A6, 0x42040A, 0x420494, 0x420785,
0x422E91, 0x4230E5, 0x424F89, 0x425ADD, 0x425C5A. Thirteen of them are in one
function, which is the first thing worth knowing.

| function | what it is | how it was identified |
|---|---|---|
| `FUN_0041F210` | `asCReader::Error` | formats the `LoadByteCode` literal, calls the message virtual, sets the flag at `+0xD`, returns -1 |
| `FUN_00423310` | **`ReadEncodedUInt64`** | tests `& 0x7F`, `& 0x7E`, `& 0x7C` for the 8/6/5-byte widths and lifts bit 7 out as the sign flag, reading one byte per virtual call and counting them at `+0x10` |
| `FUN_004232E0` | `ReadEncodedUInt` | `ReadEncodedUInt64` plus the "high dword must be 0 or -1" check -- the 32-bit wrapper every count goes through |
| `FUN_0041F290` | **`ReadInner`** | `ReadData(&noDebugInfo, 1)`, then a count and a loop that reads each enum phase 1 and phase 2; 13 of the 19 error paths |
| `FUN_00421F10` | **`ReadTypeDeclaration`** | takes a phase argument and branches on `== 1`; phase 1 reads name, a 4-byte flags field, `eu(size)` and the namespace |
| `FUN_004216D0` | **`ReadFunction`** | `ReadData(&c,1)`; `'\0'` returns null, `'r'` reads an index into `savedFunctions` at `+0x78`, otherwise allocates, pushes, and calls the signature reader |
| `FUN_004211E0` | **`ReadFunctionSignature`** | name, `$dlgte` shortcut, return type, parameters, in/out flags, funcType, defaults, owner, traits byte, namespace -- in that order |
| `FUN_004245E0` | **`ReadByteCode`** | `eu(count)` then a loop decrementing it once per opcode byte, stepping by `asBCTypeSize[asBCInfo[op].type]` |
| `FUN_00423B90` | **`ReadTypeInfo`** | reads a tag char; `'a'` reads the template name **and a namespace** then `eu(numSubTypes)` |
| `FUN_00423680` | `ReadString` | the `len2` codec, reading into an `asCString` |
| `FUN_00423970` | `ReadDataType` | the only other thing a signature reads per parameter |
| `FUN_00424E80` | `ReadUsedObjectProps` | `ReadTypeInfo` then a **property name** matched against the owner's table -- which is the independent confirmation of the `usedObjectProps` finding above |
| `FUN_004250C0` | `TranslateFunction` | walks the decoded bytecode switching on opcode numbers -- 0x40 `ALLOC`, 0xB8/0xB9, 200 `Thiscall1` |
| `FUN_0040A530` | `asCArray::PushLast` | grows by doubling, falls back to an inline buffer at `+0xC` |

Two of those entries are corrections. `FUN_004216D0` was recorded here as
`ReadTypeInfo` on the strength of its 42 call sites; it is `ReadFunction`,
and the count fits that better -- five sites in `ReadTypeDeclaration`
(destructor, constructor, factory, method, virtual) and the rest across the
tail sections. And `FUN_0041F290` was "a type reader built out of it", which
is backwards: it is `ReadInner`, the top of the whole parse.

`ReadEncodedUInt64`'s **87 call sites** remain the reason this is cheap: one
per field read, so a record's field order comes off the call sequence instead
of off the bytes.

### Two more things the binary settled

**`asBCInfo[]` is in this executable twice**, at VA 0x004C8CDC (file 0xC80DC)
and at VA 0x004CA38C (file 0xC978C), 363 entries apart and otherwise
identical -- only the stray pointer in entry 0's name field differs
(`if_handle_then_const` against `$dlgte`, the literal each copy happens to
sit after). `ReadByteCode` uses the second; `bgt opcodes` finds the first.
That is harmless, and it is worth knowing before concluding that a table
reached through the code is a different table, and both copies index
`asBCTypeSize` the same way.

**That table is 21 entries, and the figure this file used to give for it
was a truncated transcription.** It read
`[0, 1, 1, 1, 2, 2, 3, 3, 2, 3, 2, 1, 2, 3]` -- fourteen, stopping at
type 13 -- and `CMPi` alone is type 14, so a fourteen-entry table cannot
size this instruction set. Read out of BGT 1.3 at VA 0x005054E8 it is

```
[0, 1, 1, 1, 2, 2, 3, 3, 2, 3, 2, 1, 2, 3, 2, 2, 4, 3, 2, 3, 3]
```

Nothing was ever decoded wrongly, which is why this went unnoticed: the
decoder does not use the transcription. `as_opcodes.TYPE_INFO` carries
all twenty used types with their operand counts, and it agrees with the
binary **entry for entry** -- which is also the check that says the
longer reading is right. A number in prose and the table the code
actually uses are two places to keep in step, and only one of them was
ever exercised.

**The table is 203 entries where BGT 1.3's is 200**, and the three extra say
which direction this fork went: `Thiscall1` at 200, and the compiler's own
pseudo-instructions `VarDecl` at 251 and `ObjInfo` at 253. Every opcode 0-199
matches 1.3's numbering and name exactly, which is what lets the same
decompiler read both.

**There is no `_builtin_function_` literal at all.** BGT 1.3 carries it at
0x108138; Manamon 1 carries neither it nor `builtin_function`, which is why
`--string _builtin_function_` returns no functions here.

Two things about the Ghidra run itself, both of which cost time:

- **Import the PE stub, not the executable.** The full 2 MB file dies with
  `OutOfMemoryError: Java heap space` at the 4G heap this file records as
  sufficient for `bgt.exe`, because half of it is the encrypted overlay and
  the string and switch analyzers grind through it for nothing.
  `bgtlib.read_trailer` gives the split; 1,022,976 bytes imports and
  analyses.
- **`--string` finding nobody is the normal case here**, and the four-byte
  immediate trick is what works: compute the literal's VA from the section
  table and search the file for those bytes little-endian, then `--at` the
  hits. That is how all nineteen sites above were found.

**Read the reader; do not infer the format.** `asCReader` is statically linked into
every BGT executable, so the exact record layout for the build you are looking at is
*in the binary in front of you*. Transcribe the branch from Ghidra.

This is not a style preference. Inferring layouts from byte patterns reliably
produces answers that are confident, plausible and wrong: a signature model built
that way parsed at 92.5% while being wrong about three separate fields, because in
the common case two counts were zero and the layout happened to coincide.

Two units traps that do not fail loudly:

- The bytecode length field counts **instructions**, not dwords.
- Jump offsets count **instructions**, not dwords. Reading them as dwords still lands
  on a valid instruction boundary whenever the target happens to be one dword wide,
  so a majority of jumps "resolve" while silently pointing at the wrong instruction.

---

## Function records

Function bodies are marked `0x66 'f'` followed by the name in whichever string
dialect the module uses, then the signature, then an encoded instruction count and
the bytecode. This marker is the same in both dialects.

For `len2` this is now a linear parse, not a scan: 9,924 bodies recovered from
Manamon 2, **every one decoding to exactly its declared instruction count**.

One bad body no longer costs the rest. `Reader.function_or_error()` records the
failure — name, offset, reason, bytes skipped — in `parse_errors` and resynchronises
to the next `0x66 'f'` / `0x72 'r'` record whose name validates as an identifier.
Note that **`0x00` is deliberately not a resync anchor**: it is a complete record on
its own, so nothing follows it to check, and NUL bytes are dense enough that
accepting it stops a byte or two into the record being skipped and reports success
while still desynchronised. This applies to function bodies only — a desync in the
enum or declaration sections means the whole parse is wrong, and those still raise.

If you are working on a dialect whose bodies do not parse yet, anchor-based scanning
still works as a stopgap: `as_opcodes.disassemble()` stops at `RET`, so a correct
alignment terminates cleanly while a wrong one hits an undefined opcode almost
immediately, and real operands are small where a misaligned decode produces absurd
ones. Scan a few byte offsets after the name and keep the alignment that both
terminates on `RET` and yields plausible operands — but the length field counts
**instructions, not dwords**, so never use it as a byte offset.

---

## Naming bytecode operands

`as_disasm.py` turns a decoded body into something readable. Which operand slot
indexes which table was fixed by **range analysis**, not assumption: collect every
operand an opcode takes across the whole module and compare the maximum against each
table's size. The right table *saturates*.

| operand | max seen | table | size |
|---|---|---|---|
| `CALL` / `CALLSYS` / `CALLINTF` | 8179 | `usedFunctions` | 8180 |
| `PGA` (even) / 2 | 10180 | `usedStringConstants` | 10181 |
| `PshG4` (odd−1) / 2 | 538 | `usedGlobalProps` | 539 |
| `LoadThisR` arg0 | 6522 | `usedObjectProps` | 6523 |
| `LoadThisR` arg1 | 1661 | `usedTypeIds` | 1662 |

A saturating maximum makes an off-by-one impossible in either direction. Across
all four titles this resolves **every operand** — 242,245/242,245 on Manamon 2,
54,682/54,682 on Psycho Strike, 57,798/57,798 on Paladin, 110,291/110,291 on
SBYW — with every jump target
landing on an instruction boundary and every `LoadThisR` property belonging to its
enclosing class. Psycho Strike's 6,612 jump targets and 2,352 `LoadThisR` sites
match an independent parser's counts exactly.

**`usedObjectProps` stores the property NAME in both dialects.** This table once
said `len2` stored an index into the owner's property table. It does not: a
`len2` back-reference is a single encoded value, `2 * index + 1`, so a name
written as a back-reference reads perfectly well as an integer and the tail
still lands exactly on EOF. The giveaways were statistical and semantic. All
6,523 of Manamon 2's values are odd, which chance would not produce. Read as
indices they rendered as `menu_properties_object::prop[11939]` (no class has
11,940 properties), and that placeholder still counted as "resolved". Read as
strings, 6,520 name a real property of their exact owner; the other 3 are
`vector::x`, `y` and `z`, members of a registered type with no script
declaration to check against. (It was 6,507 until same-named classes in different
namespaces were told apart -- see "Classes that share a name" below.) The
module still rewrites byte for byte.

**Classes that share a name.** Manamon 2 declares `sound_pool`, `sound_pool_item`,
`tweener` and `action_item` twice -- globally and in namespace `rhythm`. Phase-3
property tables were attached to class blocks **by name**, so both declarations
wrote to one block: the global `sound_pool` lost every property (its
`destroy_sound_callback` among them) and the other was overwritten. They are
paired by **position** now, as `ReadInner` reads them, blocks carry their
namespace, and type names render qualified (`rhythm::sound_pool`) wherever the
namespace is not empty.
The lesson is the same as for `ALLOC`: a field that parses to EOF can still be
the wrong field, and a resolver that returns a placeholder is not resolving.

**A global pointer carries a table selector in some builds and not others,
and both readings fail quietly.** Where it does, the operand is
`2 * index + tag`: tag 0 selects the string-constant table, tag 1 the
global-property table. 149,656 `PGA` operands in Manamon 2 are even
(literals) and 106 are odd (`player`, `current_map`, `save_data`); reading
them all as literals resolves those 106 to a real string from the wrong
table. Where it does not, the operand is a plain `usedGlobalProps` index,
`STR` carries literals separately, and Psycho Strike's `PshG4` saturates at
170 against 171 globals. Applying the other rule there halves every index
and still yields a real global name: `pack_file::open(retreave, ...)` reads
as `pack_file::open(money_wanted, ...)`.

**This file had that keyed to the dialect, and it is keyed to the build.**
See **A global pointer's encoding is per build, and the reader says which**
below -- Manamon 1 is `len2` and plain, and reading it the other way
resolved every one of its 4,117 global operands to the wrong thing.

**Rare opcodes do not need their own evidence when they share a code path.**
`LoadRObjR` and `LoadVObjR` are the *same branch* in `TranslateFunction`
(0xB8/0xB9), running the identical property lookup and type-id lookup that
`ADDSi` and `LoadThisR` use. `LoadVObjR` occurs 36 times in the whole corpus --
far too few to settle by range analysis -- and does not need to be, because
`LoadRObjR`'s 61,421 sites are the same code. Likewise `Thiscall1` (0xC8)
translates identically to `CALL` / `CALLSYS` / `CALLINTF`, so its operand is a
`usedFunctions` index. Check whether the binary already groups an opcode with a
well-evidenced one before going looking for more samples of it.

**`ALLOC`'s second operand is a ONE-BASED `usedFunctions` index**, with 0 meaning
"this type has no script constructor". Read straight it resolves to a real
function that is simply the wrong one — `ALLOC string  menu_properties_object::reset`
— and the owner matches the allocated type in only **322 of 15,619** sites.
Subtracting one takes that to **15,619 / 15,619**, and to 1,793/1,793 and
2,460/2,460 on the other two titles. `asCReader::TranslateFunction` is explicit:

```c
else if (op == 0x40) {                 // ALLOC
    FindObjectType(arg0);              // usedTypes
    if (arg1 != 0) FindFunction(arg1 - 1);
}
```

The lesson that got this right in the end is the `asBCInfo[]` one: range analysis
said the field *could* be a function index, a consistency check said it was not,
and only the binary said which — a field that is off by one looks exactly like a
field that means something else.

## Lifting

`as_lift.py` turns the instruction stream into statements with a symbolic stack
machine. **Zero passthrough across all 1,111,490 instructions in the four
titles** — every opcode is modelled.

**Checked against the library source, mechanically.** `bgt libcheck` compares
every function that appears once in both BGT's shipped `include/*.bgt` and a
recovered module: the sequence of calls in evaluation order, and the string
literals as a multiset. On Psycho Strike, built with the same library version as
BGT 1.3's include folder, **153 of 155** functions have the source's exact call
sequence (107 before the fixes it drove) and **155 of 155** its exact literals.
Of the two left, `dynamic_menu::run_extended` is the game's own library edit (it
checks `alts_pressed` where 1.3 checks joystick buttons). `control::focus`
differs by one `length()` call's position, and the bytecode settles it in the
lifter's favour: `input_box_speak(mask) + " times " + text.length()` compiles
to `.opAdd` calls whose ARGUMENT is evaluated before the receiver is pushed, so
`text.length()` genuinely runs first. The comparison's "order by closing
parenthesis" is the approximation there, not the lift. Manamon 2
and SBYW ship modified library versions, so they score lower for reasons that
are not the lifter's.

What it drove, each a real bug that read plausibly: arguments rendered in
reverse; `return` values taken from whichever path came last; guard clauses
nesting the rest of the body; arms with no join, and `if`/`else` arms, printed
in the opposite order to the source (the THEN arm is the fall-through, so it
now prints first under the negated jump condition); `INC`/`DEC` printed as
`*this.c_form[a0]--` instead of `this.c_form[a0].list_length--` (they act
through the reference register); a receiver passed by address printed with its
`&` -- `&v1 = v2`, `&v6 + v1`, 888 times in Psycho Strike; and a carriage
return written raw inside string literals. Lifted output reads like this (a
game's own `prepare_audio`, which sets its sound-pack key):

```
void <global>::prepare_audio()
{
    ret = get_SCRIPT_COMPILED();
    if (ret) {
        v1 = 0;
        v2 = string("\0\0able to\0\0learn\0...");
        v3 = string(&v2);
        v2 = get(v3);
        ret = set_sound_decryption_key(&v2, v1);
        v2 = string("data.dat");
        v3 = string(&v2);
        ret = set_sound_storage(v3);
    }
    return;
}
```

### The call frame — read, not fitted

Top of stack first, as `asCContext::CallSystemFunction` consumes it:

```
this                 methods only
return address       only when the callee returns a value type on the stack
argument 0           arguments are pushed LAST TO FIRST
...
argument n-1         (deepest)
```

Each `?&in` argument is two slots: the value, above the `TYPEID` pushed first.
`ALLOC` is the one inversion — its destination address is the **deepest** slot,
because the constructor pops its own arguments before ALLOC pops the address.

Each of these replaced an earlier rule that read plausibly and was wrong:

- **Argument order.** `random(95, 105)` compiles to `PshC4 105 / PshC4 95 /
  CALLSYS random`, and `dynamic_menu.bgt` calls
  `add_item_extended(filename, true, name)` where the bytecode pushes `name`
  first. The lifter used to render bottom-to-top, printing **every
  multi-argument call reversed**. It survived review because the positional
  names (`a0`, `v3`) gave nothing to check the order against. The shipped
  library source and constant arguments did.
- **Parameters live at negative offsets.** `SetupParametersAndReturnVariable`
  lays a frame out downward: `this` at 0, then the return address if any, then
  parameters, two slots for int64/uint64/double. Positive slots are locals and
  temporaries. `as_disasm.frame_layout()` computes it, and the disassembly
  header prints it. Naming slots 1..n as parameters, as before, gave
  temporaries parameter names.
- **The return address is `DoesReturnOnStack`**: a registered value type
  returned by value, on **every** call kind. It never applies to handles,
  references, arrays (a reference type) or script classes. Paladin's
  `generate_maze` returns the script class `map` and is followed by
  `STOREOBJ`, i.e. the object register. The old rule applied it to CALLSYS only
  and to handles too.
- **No hidden argument for templates.** This was the one rule marked
  "inferred rather than read"; `bgt.exe` settles it. `GenerateTemplateFactoryStub`
  (`FUN_0046fd30` there; find it through the `factstub` string) emits
  `OBJTYPE <type>; CALLSYS <factory>; RET`, so the object type is pushed *inside*
  the stub. The stub's parameter list drops the hidden `int&in`, and callers
  push only declared arguments. The compiler emits `TYPEID` only for `?&`
  parameters (`PrepareArgument`, gated on token 59).
- **`>>` is the logical shift**; arithmetic is `>>>`. NVGT evaluates `-8 >> 1`
  as 2147483644 and `-8 >>> 1` as -4, so `BSRA` rendered as `>>` changed every
  negative shift.

Four things decide whether the output means anything:

- **Comparisons are two-part.** `CMPi` writes the operands, the *following* jump
  supplies the relational operator. Lifted separately, every `if` reads as `cond`.
- **`JLowZ` / `JLowNZ` follow no compare at all** — they test the low byte of the
  value register, which is what a bool-returning call leaves behind.
- **Pop the callee's declared arity, from the top.** Residue from an imperfectly
  modelled construct then sits *underneath* and is skipped rather than swept into
  the argument list.
- **`this` is at a different end for constructors.** A constructor's target is
  pushed immediately before the call, so it is on top; an ordinary method gets its
  object first. Taking it from the wrong end turns `v1 = string("x")` into
  `string(&v1)` and loses the literal.

**Registers, not just a stack.** The VM has value, object and *reference*
registers, and several opcodes touch those instead of the stack — `LoadThisR`
and `LDG` load into the reference register, `WRTV*` writes through it, all with
`stackInc 0`. Modelling them as pushes was the single biggest source of
imbalance: it stranded a value on every use (2,414 in Psycho Strike) and made
`WRTV4` pop something unrelated, so the write landed on the wrong target.

**Checking the stack model.** `asBCInfo[].stackInc` is read from the binary, so
for every fixed-shape opcode it is the authoritative answer to what the stack
should do — the lifter can be diffed against it mechanically. It is *not* the
reference for `CALL` / `CALLSYS` / `CALLINTF` / `ALLOC`, which depend on the
callee, and it counts slots where the lifter counts values. The end-to-end check
is the stack being empty at `RET`:

| title | functions ending clean | before the call-frame fixes |
|---|---|---|
| Psycho Strike | 1,102 / 1,102 (100%) | 98.0% |
| Paladin of the Sky | 926 / 926 (100%) | 99.2% |
| Manamon 2 | 9,924 / 9,924 (100%) | 95.8% |
| SBYW | 2,348 / 2,348 (100%) | 95.5% |

Every one of the 14,300 bodies ends with an empty stack, and none has a call
that finds too few values. The last dozen came from three more modelling
gaps: `COPY` (a POD value copy: pop the destination, copy from the source
beneath it, leave the destination -- a no-op dropped `v3 = v4` for a returned
`vector`), a callback fetched from an array (`events[i](this)`: the call's
declared return type now travels through the register to the `PshRPtr` that
pushes it), and a funcdef held in a global (globals now push with their
declared type).

"Residue" now means what it should in both directions. A **shortfall** (a
call asking for more values than the stack holds) counts. It used to vanish
into `?` arguments, which hid 21 such calls in SBYW, all engine enums being
treated as returned on the stack. A value the bytecode **deliberately** leaves
(a `REFCPY` source nothing pops, which `RET` discards) does not count.

Besides the call frame, the last step came from opcodes that had been
modelled as no-ops or bare pops, which dropped real statements:

- **`REFCPY`** is a handle assignment: it pops the destination, then copies the
  handle now on top into it, leaving that source on the stack for `RET` to
  discard. As a bare pop, the initialiser `pool = sound_pool(500)` lifted to an
  empty body. It now reads `@pool = v2;`. `RefCpyV` is the same, into a variable.
- **`STOREOBJ` / `LOADOBJ`** move the object register, where handles are
  returned, to and from a variable. As no-ops, variables appeared from nowhere
  and a factory ended `return ret;` instead of `return v1;`.
- **`CallPtr`** calls the funcdef held in a variable. Its `stackInc` of −1 is
  asBCInfo's `0xFFFF` "depends on the callee" marker, not a literal pop. It
  consumes the funcdef's declared arguments, which the lifter now finds from the
  variable's type (a parameter's, or the property it was copied from). Unknown
  types pop nothing rather than guessing.
- **`ClrVPtr`** nulls a handle, so it reads `@v2 = null;`.
- **The reference register is loaded by more than `LoadThisR` / `LDG`.**
  `PopRPtr` pops an address into it, `LdGRdR4` leaves the global's address in it
  (the compound-assignment pattern), and a call returning a reference returns
  an address there. Each was modelled as a pop or not at all, so reads and
  writes came out as a bare `ref`: 30 of them in Psycho Strike, e.g.
  `v3 = ref;` for `v3 = pool.max_distance;`. None remain in any of the four
  titles. A reference-returning call is held until the `RDR`/`WRTV` that reads
  it, giving `v3 = totals[i]` once instead of the call plus `ref`. If nothing
  reads it, it is still emitted where it was, because the call ran.
- **Engine enums return in the value register.** Their flags are not
  serialised, so a call followed by `CpyRtoV4`/`CpyRtoV8` marks its callee as a
  register return (`Module.register_returns`), the same protocol evidence the
  NVGT decompiler uses. The module's own enums and typedefs are known by name.

The rules were adopted because the binary and the bytecode say so, and the
metric followed. Paladin shows why that order matters. A looser return rule,
which counts script classes as returned on the stack, "balances" one more
Paladin body by swallowing an unrelated leftover value at each call.
`STOREOBJ` after that call says the looser rule is wrong, and it was not
adopted. The old template rule's measured benefit (168 stranded values) likewise
disappears once the return address is modelled correctly: these numbers are
reached without it.

A **`?&in` parameter (token 59)** takes two stack slots for one declared
parameter -- AngelScript's variable-argument type passes the value *and* its type
id. Three functions in this corpus take one; the rule is mechanical and worth 82
balanced bodies.

Residue never corrupts output — it sits *below* the popped arity — but it is the
honest measure of what is still approximate.

**Structuring is real structural analysis**, not pattern-spotting: a CFG,
iterative dominators and post-dominators, natural loops from back edges, then
nested `if` / `else` / `while` / `do-while` with `break` and `continue`.
Residual gotos are **3,597 of 408,764 statements (0.88%)** across the four
titles, and 84-95% of function bodies come out entirely goto-free (84.3% Psycho
Strike, 89.8% Paladin, 94.8% Manamon 2, 91.4% SBYW).

**Returns are placed where the source put them.** `return x;` compiles to the
value moved into the register (`CpyVtoR4`, or `LOADOBJ` for a handle) and a
jump to the function's single exit, which runs only cleanup before `RET`. The
lifter used to print a value only at that `RET`, so every path returned
whatever the *last* path in the bytecode loaded -- BGT's own
`sound_pool::destroy_sound` read as always returning false. A register load that
flows only through cleanup to `RET` now emits `return x;` on the spot, and in a
void function a jump to the exit is a `return;`. Guard clauses
(`if (handle.active == false) return;`) come out as the source wrote them
instead of wrapping the rest of the body in a branch.

**Arms that never rejoin keep the compiler's order.** When both arms of a
branch end in their own `return` there is no join point, and either arm can be
the nested one. Nesting the fall-through keeps the bytecode's order -- which is
the source's: `form.bgt`'s `edit_silent` has three guarded returns, and nesting
the jump target instead printed them in reverse.

Three shapes decide whether that output is right, and each was wrong first:

- **Branch-over is the common case.** The compiler emits `if (!c) goto after;`
  around a guarded block, so the branch targets the reconvergence point and the
  guarded body is the *fallthrough*. Read as written it yields an empty `if`
  with the body dangling after it -- valid structure, wrong about what is
  conditional.
- **A header that is also the latch is a `do-while`.** Emitting its statements
  before a `while` runs them once and then spins on an empty body.
- **A pre-tested loop re-evaluates its condition every iteration**, so whatever
  the header computes must stay inside the loop.

And one that the object-model got wrong: **the receiver is pushed LAST**, for
ordinary methods as well as constructors. `dynamic_menu::add_item` settles it --
`VAR 1 / PshV4 2 / VAR 3 / PshVPtr 0 / CALLINTF` is three declared arguments
then `this`. Taking it from the bottom turns the receiver into an argument and
an argument into the receiver, which reads perfectly well and is wrong.

Validated against source nobody here wrote, since BGT ships its own library:
`dynamic_menu::run_extended` recovers the same three nested guards in the same
order as `dynamic_menu.bgt`; `set_speech_mode` recovers exactly the two branches
its short-circuit `||` must compile to; `get_position` comes back as one
`if`/`else` with the `-1` in a branch.

Unmodelled opcodes are emitted as `/* OPCODE ... */` and counted rather than
dropped — a lifter that silently omits what it cannot model reads better and means
less, so the passthrough count is the number that says how much is really
recovered.

# Source file names

**Everything in this section is about a RELEASE build**, which is what
the rest of this file assumed without saying so. BGT's `-c` keeps the
debug information and its `-C` strips it, and a shipped game can be
either -- see **A debug build keeps the names** below, where one is.

**The game's own file names are not recoverable, and nothing will change that.**
They live only in AngelScript's debug information -- each function's script
section -- and BGT always strips it. NVGT strips it too in release builds
(`SaveByteCode(stream, !g_debug)`), so no stripped build stores them, hidden or
otherwise. A search of four BGT modules for script-file names in string
literals found one, which was the name of a sound in a list, not a record of
the game's source. NVGT *debug* builds do keep them, and `bgt nvgt recover`
uses them.

What survives is **structure**, and `bgt files` recovers it:

```bash
bgt files work/game_bytecode.bin game.exe      # BGT: module + exe
bgt files game.exe                             # NVGT: executable or module
```

- **Declarations come out in file order.** The builder handles script sections
  one after another. Types come in one pass and global functions in another,
  and both walk the files in the same order. So any change of file along the
  module's order is a real file boundary. Two of the game's own files side by
  side are still indistinguishable, which gives *where* files split, but never
  how many unnamed files a run holds.
- **Library files are named exactly.** A run that declares what a shipped
  `include/*.bgt` or `*.nvgt` declares *is* that file. A class counts only when
  its methods agree with the source's in both directions, so a game's own
  `menu` isn't claimed. A file counts only when most of what it declares is
  present *and* it explains something no other file does.
- **The two passes merge into one file order.** A file seen in only one pass is
  placed by its neighbours there. The library's own `#include` graph settles
  what they leave open, because an included file is processed straight after
  its includer, so nothing sits between them. That usually pins the main
  file's functions exactly.

**Checked against ground truth.** An NVGT debug build records every
declaration's true file, so the stripped build of the same module can be scored
against it. On all 26 modules of the library corpus that is **439 / 439**, and
the recovered `#include` list matches the harness exactly in **24 of 25**. The
25th, `clear_compiled_basename.nvgt`, is only a `#pragma`, so it compiles to
nothing any build could show. On the four BGT titles the passes never
disagree, and each game's `main()` lands in the first segment.

Every one of these was wrong first, and read plausibly:

- **Inherited methods:** an NVGT class's method list includes them, so no
  derived class matched its source. A class's own methods are the vftable
  entries it owns.
- **Two library files declaring one class** (`sound_pool.nvgt` and
  `legacy_sound_pool.nvgt`): the tie went to alphabetical order. It now goes
  to the better method match, and a file whose every match another file
  explains as well is not claimed at all.
- **Namespaces:** a game's namespaced copy of library code
  (`rhythm::position_sound_1d`) matched the library. The gap-fill between the
  two copies then absorbed the game code in between. Attribution has been
  right about this for a while, and it bit `bgt recover` anyway: the
  attribution is keyed by name, and a *section* was keyed by the bare one,
  so Manamon 2's `rhythm::position_sound_1d` looked up the global entry and
  inherited `sound_positioning.bgt` — moving 71 lines fifty thousand lines
  earlier. Qualify the key wherever a namespace can exist; the same name at
  two scopes is two declarations, and the module keeps them apart.
- **Lambdas** are compiled after every declaration, so their position says
  nothing. They belong to the file of the function whose `FuncPtr` creates
  them.
- **Source quirks:** `pack@open_pack(` and `#include"form.nvgt"` have no space
  where a regex expected one. `form.nvgt` and `speech.nvgt` include each other,
  so "nested" means included by a file *earlier* in the order, not by any file.
- **Direct evidence first:** the order a pass shows outranks the include
  graph, which only settles what the pass order leaves open.

# Recovering a compilable project

`bgt lift` produces pseudo-source: readable, faithful to the bytecode, and not
something a compiler accepts. `bgt recover` produces a **project** — a tree of
`.bgt` files, an entry script that includes them, a ZIP, a report, and, where
BGT is installed, the compiler's own verdict on the result.

```bash
bgt recover game.exe -o recovered/ --compile
```

```
recovered/
  game.bgt                  the entry script: #include for every file, in order
  includes/
    types.bgt               enums, typedefs, funcdefs
    globals.bgt             every global, in declaration order
    dynamic_menu.bgt        a library file, named exactly
    classes/menu.bgt        one class per file, for the game's own classes
    functions/part_1.bgt    the game's own global functions, in recovered segments
  recovery.json             counts, origins, problems, compiler diagnostics
  game_project.zip          the same tree, integrity-checked
```

The original file *names* of a game's own code are not recoverable and never
will be (see **Source file names**), so the layout is generated and says so in
every file header. Library files are the exception: a run that declares what a
shipped `include/*.bgt` declares **is** that file, so those keep their real
names — 7 of Psycho Strike's 68 classes.

**The split must not reorder anything, and it is checked.** `#include` is
textual in BGT, so a project is its files concatenated in include order, and
`bgt_project.verify` compares that concatenation against the one-file render.
This is not a formality: moving a declaration can change global
initialisation order, which compiles perfectly and then behaves differently.
The compiler agrees in practice: the project and the single file report the
same diagnostics, from 12 of Psycho Strike's 75 files.

A mismatch is reported as a **problem** rather than refused, so the project
is still there to read — and `recovery.json` says `verified: false`.

It earned its keep on Manamon 2, which was the only title to fail it, and
for exactly one reason: a 71-line block, `namespace rhythm { void
position_sound_1d ... }`, emitted fifty thousand lines early. The project
still compiled and still read correctly; the concatenation check was the
only thing that knew a declaration had moved. See the namespace note under
**Source file names** for the cause. All four titles that parse verify now.

## Why BGT can drive the other engine's decompiler

The NVGT half already had a decompiler that emits *compilable* source, checked
by recompiling 50 library builds. BGT had a lifter. Rather than write a second
decompiler, `bgt_asir.py` presents a BGT module as the IR that one reads. Two
facts make that sound, and both were checked rather than assumed:

- **The opcode tables are identical.** All 200 opcodes BGT's own `asBCInfo[]`
  declares match the newer engine's numbering *and* name, exactly. The
  decompiler dispatches on the name, so the instruction layer needs no
  translation.
- **BGT is the "legacy" generation `asreader` already models.** Its token ids
  are the older `eTokenType` numbering, recovered by `t + (t>=36) + (t>=64)`:
  BGT's 65/68/79/92 are the newer 67/70/81/94, i.e. bool/int/float/double. The
  only three opcodes whose operand count disagrees are exactly the three that
  reader's legacy mode overrides — `CALLSYS`, `ALLOC`, `CallPtr` — all of them
  pointer-width differences of a 32-bit build.

The agreement is **asserted per module**, not trusted: a build whose own table
declared a different operand count would decode every later instruction of that
body at the wrong offset while still producing real opcode names.

One reader stays one reader. `as_module` remains the only thing that parses
BGT's format — the adapter translates its dicts into dataclasses — for the same
reason `as_write` replays a field trace instead of duplicating the format: two
models of one format drift, and the drift is silent.

## What the module does not record, and what fills the gap

The newer engine saves a declaration for **every** local — offset and type
always, name only with debug info. BGT's generation saves it only for *object*
locals (`objVariableTypes`), so scalar slots have no type at all. That matters
more than readability: a slot with no type cannot be declared, so the
decompiler folds it into the expressions that read it, and folded into
*several* reads a call is written — and run — once per read. One body came out
as a 21,000-character expression calling `enemies_in_range` fourteen times
where the source called it once.

So `bgt_asir.slot_types()` types the scalar slots from the bytecode, which is
a sound source for them: AngelScript has a separate opcode per operand type
for every arithmetic, comparison and two-slot conversion. Object types come
from the engine's own record and win; between inferences a type-tagged opcode
beats a width-only hint, because `SetV4` is as true of an int as of a float.

**A slot serves several source locals, and that has to be recorded, not
resolved.** `clear_pathway` writes slot 1 with `SetV1`/`WRTV1` — one byte,
through a `bool&out` parameter — and reads it with `RDR4`/`CMPIi` as the int it
returns. Typed as either one alone it was 104 errors in that one body. Both
declarations are recorded instead, which is exactly what the newer format holds
for a reused slot and what the decompiler already reads to pick the numeric
type and convert the boolean uses.

Alongside that, the decompiler now refuses to duplicate an impure expression:
a temporary whose **same value** is read twice becomes a variable. Twice means
the same value — a slot written again between the reads is an ordinary reused
temporary, and folding each value into its one read is both correct and what
lets the structurer still see a loop condition as an expression rather than as
a statement before a jump.

### Which slots the source NAMED, read off the compiler's own output

`slot_types` answers what a slot *is*. A separate question decides whether it
is a **variable at all**, and the module does not record it -- which is what
every attempt at the duplication problem has really been about.

BGT compiles, so the question has a known answer: write both shapes and look.

| source | bytecode |
|---|---|
| `int v = bump(); return (v + v);` | `CALL bump ; CpyRtoV4 2 ; `**`CpyVtoV4 1 2`**` ; ADDi 2 1 1` |
| `if (bump() > 3)` | `CALL bump ; CpyRtoV4 1 ; CMPIi 1 3` -- no copy at all |

**A declared variable's initialisation ends in a copy into its own offset; an
expression temporary is consumed straight out of the slot the register left it
in.** That holds for every initialiser shape in the fixture -- a call, a
member read, a second assignment, a loop bound, a snapshot before a mutating
call -- and a ternary does not use the opcode at all: both arms `SetV4`
straight into the destination.

**That is a fact about the compiler, and forcing on it is still wrong.** The
third rejected attempt, and the most convincing one, because it was read from
the engine rather than fitted to a metric. Declaring every
`CpyVtoV4`/`CpyVtoV8` destination that is not in `short_circuit_slots`:

| title | residual gotos |
|---|---|
| Super Egg Hunt | 0 -> **4** |
| Paladin of the Sky | 0 -> **2** |
| Psycho Strike | 2 -> **12** |
| Crazy Party | 14 -> **90** |

Every one of those is a compiler error, so three titles that compile cleanly
stop compiling. The reason is the exclusion, not the idiom: a short-circuit
merge writes its destination with the same `CpyVtoV4`, and
`_short_circuit_slots` is a **shape** test by necessity -- it has to answer
before the simulation starts. Every merge whose shape it does not match
becomes a forced variable, each arm's computation is emitted as an
unconditional statement, and the condition collapses. That is the
`use_screen_reader` defect again, reached from a third direction.

So the knowledge is worth having and the lever is still wrong. Recorded here
rather than in a commit, with the two earlier rejections, so the next attempt
starts from three measurements instead of one.

#### What was adopted instead: a member read goes stale through a call

The bug that prompted all of this does not need the slot declared, only the
fold refused. `_stale_fold` already asks which of the frame's slots an
expression reads, and a **member** reads none -- so a snapshot of one folded
straight through whatever ran in between. Paladin's `calculate_experience`
is four of them:

```
int old_level = level;              LoadThisR ; RDR4 2 ; CpyVtoV4 N 2
int old_strength = strength;        ...three more like it
while (current_exp >= ... ) gain_level();
if (old_level == level) return;
"...Strength has increased by " + (strength - old_strength)
```

Folded, every snapshot was re-read *after* the loop: the guard became
`if (level == level)`, always true, so the level-up message never appeared,
and had it appeared it would have read `+0` to everything. That is what "the
math is very broken" looked like from inside the game.

The receiver for a bare member is **`this`**, deliberately: a method can
change any field, so any call on the object invalidates the snapshot. That is
only broad-sounding, because `bound[1] == self.stmt_count` has already
excluded every read that happens at the moment of its bind -- which is what an
ordinary expression temporary is. What is left is a value the compiler parked
in a slot and read later, and the compiler does that where the source declared
a local.

Measured on the four titles that can be measured here: Paladin gains 8 lines
and the four snapshots, and **not one title's residual goto count, split
verification or `libcheck` score moves**. For a fold change that is the number
that matters.

#### And the duplication family, which the same knowledge closes

The declaration idiom is the right fact; **forcing** was the wrong thing to
do with it. Used as a *threshold* instead it costs nothing, and it closed the
family this file had recorded as open for a long time.

`copy_binds` is the set of binds that arrived through `CpyVtoV4`/`CpyVtoV8` --
the compiler saying "the source named this slot" -- and for those the
duplicate-fold threshold is **two** rather than three. A value the source
held in a local needs no third read to be worth keeping.

That is not either of the rejected attempts, and the difference is exactly
what the engine supplied. `DUPLICATE_CALL_FOLDS` lowered the threshold for
any value whose *text* contained a bracket, which is every condition
temporary, and cost Crazy Party 14 -> 30 gotos. A condition temporary is not
a copy destination at all, so it is not reached from here. And promotion goes
through `_stale_fold`, which only promotes a declarable value and puts the
assignment back **at the bind** -- so nothing is declared that was not read
twice to begin with, and the statements come out in the order the source
wrote them.

**Three more gaps had to be closed with it**, and the first is the one worth
remembering, because it made every rule in this file unreachable for a whole
class of value:

- **The dereferenced read path never asked `_stale_fold`.** `_slot_atom`
  handles a value *pushed from a slot* and asks the whole question;
  `_read_temp` handles an *address dereferenced* and asked only about
  duplication -- while its own docstring claimed both paths came through it.
  An object or string temp only ever reaches a read through `_deref`, so it
  had no fold-safety test at all. Two places answering one question with one
  of them stricter: the shape this file keeps recording.
- **A copy-constructed temp had no bind position.** The constructor handler
  wrote `self.temps[off]` directly rather than through `_bind`, so
  `temp_bound` was never set and `_stale_fold` returned False on the missing
  bind. That is the one kind of temp whose entire purpose is that it was
  taken before something else ran.
- **An indexed read has no receiver syntax.** `_CALL_RECEIVER` looks for
  `name.method(`; `songlist[index]` has none, so "no receiver to be
  invalidated through" let it fold. `_INDEX_BASE` supplies what the value
  indexes.

`assign_song` is the function that needed all four, and it was reported from
the game as wrong music on the recreation floors:

```
    CALLINTF input_recorder::rand ; CpyRtoV4 5 ; CpyVtoV4 2 5
    PshV4 2 -> array<string>::opIndex       string song = songlist[index];
    PshV4 2 -> array<T>::remove_at          songlist.remove_at(index);
    PSF 6 -> string::$beh0                  return song;
```

One `rand`, kept in a local, read twice, with the song taken **before** the
list is shortened. It recovered as two `rand` calls with the read moved past
the removal, so it removed one song and returned a different one -- and at
the last index `songlist[index]` reads off the end of the array. Eight
speakers on a recreation floor, so the eighth threw.

What else it fixed, all of it previously recorded here as known and open:

| duplication | call sites before | after |
|---|---|---|
| `do_damage` (Paladin) | 17 | **13** |
| `interact_in_location` | 9 | **5** |
| `dragon_strike` | 8 | **7** |
| `get_global_slot` | 3 | **2** |

`do_damage` is the one with teeth. All four hp-drain attacks called it twice,
once to say the number and once to apply it, so the enemy healed by a
different amount than it dealt and the number spoken was a third value
again. Super Egg Hunt loses three more, the ones this file lists as accepted
costs: `stick.get_x`/`get_y`, `get_total_distance`, and a menu item callback.

Measured against the commit before it:

| title | lines | goto | split | calls read back |
|---|---|---|---|---|
| Super Egg Hunt | 6,225 -> 6,243 | 0 | verified | 1,611 -> 1,608 |
| Paladin of the Sky | 27,208 -> 27,327 | 0 | verified | 7,142 -> 7,110 |
| Psycho Strike | 27,295 -> 27,467 | 2 | verified | 6,467 -> 6,443 |
| Crazy Party | 188,926 -> 192,485 | 14 | verified | 90,628 -> 90,074 |

**Not one goto count moved**, and Crazy Party's fourteen are the same
fourteen labels in the same four files. That title is the measurement that
matters here, because it is the one every over-broad fold change has broken:
14 -> 30 for the call-text threshold, 14 -> 44 for dropping the declaration
order rule, 14 -> 90 for forcing on the copy idiom.

**The call count falling is the result, not a side effect.** A duplication
count is a correctness number: running a call once per read runs it once per
read. **554 of them on Crazy Party** -- and this file records the rejected
call-text threshold as removing "561 duplicated calls" from that title at a
cost of 16 compiler errors. Almost exactly the same duplications, for
nothing, once the engine is asked which slots the source named instead of
guessing from the shape of an expression.

The line count rising is the same fact from the other side: each of those is
a local the source declared and this had been inlining.

### A `?&` argument carries its type, so the slot's type is the call

A **`?&in` / `?&out` parameter** takes two stack slots for one
declared parameter: the value address and a hidden `TYPEID`. This file already
records that as a stack-layout rule. It is also a **semantic** one, and that
half was missing: the callee *compares* the type id, so handing it a variable
of the wrong type is not a cosmetic difference. `dictionary::get` returns
false and **leaves the variable untouched** when the stored value is not of
the type the caller declared.

That matters because BGT reuses one slot for several source locals, and the
decompiler declares such a slot with its *numeric* type and converts the
boolean uses -- which is right for arithmetic and wrong for a `?&` argument.

Paladin's `load_event_flags` reads its save flags through one reused slot:

```
TYPEID 3  ; bool                 <- what the source declared
VAR    4
dictionary::get("tutorial_text", ...)
LDG tutorial_text ; WRTV1 4      <- a one-byte write
```

Slot 4 also carries an `int` elsewhere in that body, so it was declared `int`
and passed as one. **Every `bool` flag in the save therefore stopped being
restored, silently** -- six of them in Paladin: `tutorial_text`,
`disable_saving`, `initial_intro`, `beat_protector`, `play_wall_sound`, and
`include_a` in `gift`.

**One of those was reported as two separate bugs.** `tutorial_text` came back
false from every load, so the next battle entered the `if (!tutorial_text)`
block -- which speaks the tutorial text *and* sets
`arg0.immune_to_magic = true`. So the player got the tutorial dialogue in a
late-game fight, and the dragon strike scroll did no damage in it, because
the enemy had been made immune to magic by a block that should never have
run. Reading the two symptoms as one cause is what found it.

The fix reuses the path that was already right: a `?&` argument whose TYPEID
type differs from the slot's declared type gets a synthesised out local of
the **TYPEID's** type, exactly as an unnamed slot already did. The named-slot
shortcut was the bug -- it passed the variable and dropped the type.

Measured on the four titles, and the scope is the evidence:

| title | lines | goto | split | calls read back |
|---|---|---|---|---|
| Super Egg Hunt | 6,243 -> 6,243 | 0 | verified | 1,608 |
| Paladin of the Sky | 27,327 -> 27,340 | 0 | verified | 7,110 |
| Psycho Strike | 27,467 -> 27,468 | 2 | verified | 6,443 |
| Crazy Party | 192,485 -> 192,485 | 14 | verified | 90,074 |

Two titles do not move at all and the other two move by the lines the fix
adds. Nothing else in the corpus passes a `?&` argument with a type-mismatched
slot, which is what a correctly scoped change looks like.

**Found alongside it, and now fixed:** a `dictionary::get` whose out
argument is a synthesised local was emitted **twice** -- once as a bare
statement and once as the initialiser of the `__nvgt_ret` that holds its
return value:

```
arg0.get("voice.pitch", __nvgt_out_2_37);
__nvgt_ret_37 = arg0.get("voice.pitch", __nvgt_out_2_37);
```

`get` is a pure read, so nothing observable changed and nothing reported it
-- and it is a duplicated call, which this file counts as a correctness
number, in every save-loading body in the corpus.

**The guard for it existed and fired too late.** `_order_out_arguments`
already clears a call that is still *pending* when it captures it, and the
duplicate is the case where the pending call had already been flushed to a
bare statement before any statement mentioned the out local. There is
nothing to append in that case: the statement is already there, in the
position the bytecode gave it, so it is **rewritten in place** into the
`__nvgt_ret` form rather than emitted a second time. Appending would also
have moved the call, which is the defect `_order_out_arguments` exists to
prevent.

| title | duplicated `get` lines removed | bodies |
|---|---|---|
| Paladin of the Sky | **153** | 13 -- every `deserialize`, `load_event_flags`, `gift::get_gift` |
| Psycho Strike | **40** | 10 |
| Super Egg Hunt | 0 | 0 -- it passes no `?&` out argument of this shape |

Paladin's `load_event_flags` goes from 218 `.get(` lines to 115, one per
flag it restores, and `deserialize_calendar` reads as the source wrote it. No
residual goto, call-sequence score or literal count moves on any of the
three.

### ...and neither is its SIGNEDNESS, which the instruction set names

The round trip's census, run again after the two fixes above, put a new
shape at the top: **`CMPu` -232 instructions in 35 of Super Egg Hunt's
bodies** -- the original compares *unsigned* where the rebuild compares
signed. That is not cosmetic. `array<T>::length()` returns `uint`, so
that title's mode setup is

```
original:  CALLSYS array<T>::length ; CpyRtoV4 v ; SUBIi v v 1 ; CMPu i v
rebuilt:   CALLSYS array<T>::length ; CpyRtoV4 v ; SUBIi v v 1 ; CMPi i v
```

and `length() - 1` on an **empty** array is 4,294,967,295 unsigned and
-1 signed, so the loop bound flips. The original's loop runs and the
recovery's does not.

`_slot_votes` keeps the first vote where two numeric types disagree, on
the stated grounds that *"two numeric types in one slot is a width
difference the bytecode does not usually make"*. Int against uint is not
a width difference, and the bytecode makes it deliberately -- so this is
a case that rule's own justification never covered.

**Which opcodes carry signedness is derived, not listed**, and that is
the whole of it: an integer operation carries signedness exactly when a
`u` spelling of it also exists, because only then did the compiler have
to choose. Asked of BGT's own table:

| | |
|---|---|
| a `u` sibling exists, so **authoritative** | `CMPi`/`CMPu`, `CMPIi`/`CMPIu`, `DIVi`/`DIVu`, `MODi`/`MODu`, `POWi`/`POWu`, `dTOi`/`dTOu`, `iTOd`/`uTOd`, `iTOi64`/`uTOi64` |
| no `u` sibling, so **agnostic** | `ADDi`, `SUBi`, `MULi`, `ADDIi`, `SUBIi`, `MULIi`, `NEGi`, `IncVi`, `DecVi`, `POWdi`, `i64TOi` |

So an agnostic op's `INT` vote is kept apart and used only where nothing
authoritative disagrees. `SUBIi` says four bytes and a whole number;
`CMPu` says the compiler knew the operands were unsigned.

#### Two mistakes in doing that, and both are the same mistake

**I wrote the list by hand first and got four of eleven wrong.** The
opcode is `IncVi`, not `INCi` -- and that is the loop counter, so the
rule did nothing where it mattered: Super Egg Hunt's written project
came out **byte-identical**, the rebuilt executable byte-identical, the
edit distance identical to the digit, and only the one-file render
moved, because the 32 lines were inside library files that are replaced
by the engine's own source on disk. A change that looks measured and
measured nothing is the shape this file keeps recording, and the tell
was there: +32 lines with an identical build.

**Then I derived it from the wrong universe.** `TYPED_SLOT_OPS` lists
`ADDu`, `SUBu` and `MULu` for completeness although no BGT build has
them, so deriving the siblings from that table makes `ADDi`, `SUBi` and
`MULi` authoritative and inverts the rule for the three commonest
integer ops. The universe is **the instruction set the executable
declares**, which is this file's first rule arriving from a new
direction: read the instruction set, not a table about it.

The sibling search has to look wherever the `i` sits, too. A trailing-`i`
rule covers `ADDi`/`ADDu` and `IncVi`/`IncVu`; a **conversion** carries
it at the front, `iTOd` against `uTOd`, and those are exactly the ops
where signedness decides what the bits mean.

#### What it cost

| title | lines | goto | split | calls read back |
|---|---|---|---|---|
| Super Egg Hunt | 5,262 -> 5,294 | 0 | verified | 1,608 |
| Paladin of the Sky | 23,392 -> 23,440 | 0 | verified | 6,952 |
| Psycho Strike | 24,367 -> 24,428 | 2 | verified | 6,406 |
| Crazy Party | 174,547 -> 174,597 | 14 | verified | 90,145 |
| Manamon 1 | 83,318 -> 83,363 | 0 | verified | 26,482 |

`uint` declarations on Super Egg Hunt go **7 -> 42**, and the rebuilt
module's unsigned comparisons **7 -> 92** against the original's 95. Not
one residual goto, call count, split check or `bgt signatures` row moves
on any title, every `bgt audit` comparison is identical, and the round
trip gains two more byte-identical bodies:

| | edit distance | of the original | bodies identical |
|---|---|---|---|
| before | 8,298 | 29.1% | 30 / 137 |
| after | **8,100** | **28.4%** | **34 / 137** |

Modest against the two changes before it, and it is the first one here
that is about *meaning* rather than shape: the others removed statements
the original did not have, and this one changes what a comparison does.

#### ...and where two AUTHORITATIVE votes disagree, the loser needs a cast

The rule above decides what a slot is **declared**. It cannot decide
what every *use* of it is, because one slot serves several source
locals and two of them can be signed and unsigned at once -- two
authoritative votes, not a width difference. `_slot_votes` keeps the
first, which is the right answer for the declaration and the wrong
answer for the other local's uses.

`cs`'s server is the instance, and it is in ground-truth code:

```
source:     int b = get_base_index(map);   if (b > -1) { ...vault report... }
bytecode:   CALL get_base_index ; CpyRtoV4 3 ; CpyVtoV4 2 3 ; CMPIi 2 -1
recovered:  local_2 = get_base_index(map); if (local_2 > -1) {
```

with `uint local_2;` declared, because slot 2 is also the `uint i` of
the loop above. **The engine was asked rather than assumed**, by a
script that writes its answers through `file::write`:

| asked of BGT | answer |
|---|---|
| `uint b = 5; b > -1` | **false** |
| `int s = 5; s > -1` | true |
| `uint8 c = 200; c > -1` | **false** |
| `int8(c) > -1` | **false** |
| `int(c) > -1` | true |

-- the signed literal converts to unsigned, so the comparison can never
pass, and the engine says so with `Implicit conversion changed sign of
value`. That warning is a cost of its own: BGT waits on its modal
dialog, so a project full of them cannot be compiled unattended.

So **the vault dispenser report could never run** in the recovered
server, and `get_base_index` returning -1 for "no base here" is the
whole point of that guard. 16 sites in that one artefact and 1 in
Psycho Strike; Super Egg Hunt, Paladin, the `cs` client, rage room and
constant velocity have none.

`CMPIi` has a `CMPIu` spelling, which is what makes it authoritative --
the compiler had to choose -- so the fix is to render that use through
the cast the signedness it declares implies.

##### The cast is the COMPARISON's width, and the engine refuted the other

A narrow-sibling mapping was written first -- `uint8` to `int8`,
`uint16` to `int16` -- and the table above is why it is wrong: a `uint8`
slot holds its value **zero-extended in four bytes**, so `CMPIi` sees
0..255, while `int8(200)` is -56 and answers the opposite. The cast is
`int` for `CMPIi` and `int64` for `CMPIi64`, whatever the slot's own
width.

Two narrowings keep it to the measured shape:

- **A negative immediate only.** A signed comparison against a positive
  constant reads the same either way. The two-slot `CMPi` form is the
  same question with no literal to key on, and is not done here.
- **A value whose OWN type is already signed needs nothing.** The slot
  is `uint` for another local's sake while what is in it here is, say,
  `array<T>::find`'s `int`. Psycho Strike has three sites of that shape
  -- `weapon::ammunition` is a plain `int` -- and casting them was
  harmless noise, which is how the narrowing was measured: 4 changed
  sites down to the 1 that is a defect.

##### What it cost

| title | lines | goto | split | calls read back |
|---|---|---|---|---|
| Super Egg Hunt | 5,302 (byte-identical) | 0 | verified | 1,608 |
| Paladin of the Sky | 23,396 (byte-identical) | 0 | verified | 6,952 |
| Psycho Strike | 24,419 | 0 | verified | 6,406 -> 6,407 |
| Crazy Party | 174,780 (byte-identical) | 0 | verified | 90,148 |
| Manamon 1 | 83,371 (byte-identical) | 0 | verified | 26,484 |
| cs server | 10,139 | 0 | verified | 3,018 -> 3,034 |

**Four of the six artefacts are byte-identical**, including both big
titles, and the other two move by the casts and nothing else -- no line
count changes at all, because a cast is rendered inside a condition that
was already there. The call counts rise by exactly one per cast, which is
`bgt apicheck` reading `int(` as the call it syntactically is: Psycho
Strike by 1 and the `cs` server by 16.

So the whole scope of this is 17 comparisons in two artefacts, which is
what a correctly scoped change looks like -- and the sweep says the same
from the other side, 17 rows before and 0 after.

The sweep that sized this is `bgt signatures`-shaped and is not in that
command, because the question needs a declared type: an unsigned local
in an **ordering** comparison against a negative literal. Its own first
version grouped declarations by brace depth, which in a class file puts
every method's locals in one set -- so `uint local_1;` in one method
made `int local_1;` in another look unsigned, and it reported 4, 8 and 9
rows on three titles that have 0, 0 and 1 between them. Resolving each
use against the NEAREST declaration above it is what a reader does and
what the hoisting in these files makes correct. **The instrument needed
checking before its baseline could be believed**, for the fifth time in
this file.

The equality form is left alone deliberately and there is none in the
corpus anyway: `uint == -1` compares the same bits either way, so it is
only the ordering comparisons whose answer moves.

### A slot's width evidence is not first-come-first-served

`slot_types` has two kinds of evidence. A **type-tagged** opcode names its
operand's type outright (`SUBi`, `iTOd`, `CMPd`); a **width-only** one says
how many bytes moved (`SetV1`, `RDR4`, `CpyVtoV8`). Where a slot had only
the second kind this kept the **first hint it saw** -- and a slot has
several, because one offset serves several source locals in turn: the
allocator rewrites any one-dword primitive's token to `ttInt` before
matching its free list, so `bool`, `int`, `float` and every enum share one
class.

So a slot read one byte wide and then written four was declared `bool`, and
`_typed_constant` rendered every constant stored into it through that
declaration. **A bool holds 0 or 1, so every other value became `true`,
which is 1.**

A four-byte store cannot land in a one-byte slot, so the **wider** hint is
the declaration and the one-byte one is a boolean use to convert -- which
is the answer `_slot_votes` already gives when the numeric half happens to
be type-tagged (`clear_pathway`), reached here from width alone.

What it was costing, and the first of these was reported as two separate
bugs:

- **Paladin's menus could not be backed out of.**
  `player_menu_callback` reads `allow_escape` one byte wide into slot 5
  and then puts the function's `return -200;` -- dynamic_menu's "the user
  backed out" -- in that same slot. Declared `bool`, the constant rendered
  as `true`, which is 1, which is "the user chose item 1". So escape
  **and** the X key selected the first item instead of cancelling, in the
  pause menu, the shop and the bag. Reported as "escape works as enter"
  and "x is bugged", and they are one line.
- **Paladin's clock ran at one minute a scene.** `time.add_minutes(30)`,
  `(10)`, `(45)`, `(70)` ... came out as `time.add_minutes(1)` **thirty-two
  times**, `time.add_hours(12)` and `(2)` as `(1)`, and three `time.set()`
  calls lost an operand each -- a new game's
  `time.set(2040, 8, 17, 14, 30, 0)` became hour 1 rather than 14. The
  whole in-fiction calendar, and the game gates scenes on it.
- **Psycho Strike's menus returned 1 where they meant -1**, three times:
  the same sentinel defect one title over.

The cost is two Psycho Strike bodies that now read
`int local_4; local_4 = 1; return local_4 != 0;` where they read `bool`
before. Equivalent, and less pretty.

**It is the same defect this file already records from the other side.**
Manamon 1's seven character stats all came out as `1` -- `strength = 1`,
`max_health = 1` -- and that was fixed by typing the constant from its
**destination**. This is the same flattening reached through the **slot**,
and the two are complementary rather than alternatives: one asks what a
constant is being stored into, the other what the slot is.

#### ...and the destination rule had a width blind spot of its own

`_constant_destinations` pairs `SetV4` with `WRTV4` and `SetV8` with
`WRTV8`, and a **`uint8` member is written one byte wide** -- `SetV1` and
`WRTV1`, which it never looked at. So the rule that exists precisely to
stop a bool-typed slot flattening a constant could not see the case where
that slot has *no other evidence at all*: one byte is all there is.

Psycho Strike's `populate_voice_sets` is 10,425 instructions of exactly
that:

```
SetV1 v1, 3 ; LoadRObjR v2 voice_set::gender      ; WRTV1 v1
SetV1 v1, 8 ; LoadRObjR v2 voice_set::hurt_sounds ; WRTV1 v1
```

Every field of `voice_set` is a `uint8` saying how many variants of a
sound that character has, and the recovery read `gender = 1` and
`hurt_sounds = 1`. **25 threes, 28 fours, 24 fives, 21 twos, 19 sixes and
12 eights**, all flattened, in the one function that describes every
character voice in the game -- so every recovered character had one
variant of each sound, or none.

`SetV1` is also the bool-constant opcode, which is what makes the width
pairing safe to widen: the branch fires only where the destination member
is **not** a bool, so `bool_member = true;` is left exactly as it was, and
`uint8_member = 1;` renders the same either way. Super Egg Hunt, Paladin
and Psycho Strike come out with identical line, goto, call and split
figures, and Psycho Strike's constant audit goes **18 rows -> 8**, all
eight accounted for: four are the two stock library files, whose text is
BGT's own source and spells a float constant `-100` where the audit
spells it `-100.0`; three are one-byte `255` constants the text correctly
spells signed (`this.walk(-1, false)` into an `int8` parameter); and one
is `find_best_weapon`'s `int best = -1;`, written three times and read
never -- the original's own dead local, dropped for the same reason
`sleep_in_bed`'s is.

**And Paladin's six are the same three kinds**, which supersedes the note
above that one of them had not been run down: four stock-library float
spellings, `play_me`'s dead `default_volume + 4.0`, and `init_events`'s
`SetV4 4, -1` into a slot nothing ever reads. **So the audit reports no
lost constant on either title**, which is the result -- the same shape the
literal audit reached on Manamon 1, where the value was the one row that
was real and not the eleven that were not.

#### The instrument: every numeric constant, against the text

This was found by an audit, not by a diagnostic, and the audit is worth
keeping. The literal audit compares a body's **string** literals against
the bytecode's; nothing compared its **numbers** -- and a number is where
the quietest defects in this file live, because a flattened `30` is valid
source that compiles, runs and is wrong.

Per body: the multiset of `SetV1/2/4/8` constants in the bytecode against
the numeric literals in the recovered text, skipping 0 and 1 -- both the
commonest and the two a bool can hold honestly. It is `bgt audit` now
rather than a scratch script, and the figures below are the scratch
script's -- see **The audits are one command now**, where three
comparison rules take the same titles further. On Paladin:

| | constants the text does not hold |
|---|---|
| before | **44** |
| after | **6** |

and the six are accounted for: three each in `position_sound_custom_1d`
and `_2d`, which are **stock library files** whose text is BGT's own source
rather than the recovery, so the audit is comparing against a different
artefact; `play_me`'s 4.0, which is the original's own dead store
(`default_volume + 4.0` computed into a slot nothing reads -- the
`sleep_in_bed` shape); and one `-1` in `init_events`, which is a
`SetV4 4, -1` into a slot nothing ever reads -- the same shape.

**And the counts say it is correctly scoped.** Across all five titles that
can be measured here, not one residual goto, call count, split
verification, passthrough or unbalanced-file count moves; two titles gain
lines and three are unchanged:

| title | lines | goto | split | calls |
|---|---|---|---|---|
| Super Egg Hunt | 6,240 | 0 | verified | 1,608 |
| Paladin of the Sky | 27,335 | 0 | verified | 7,110 |
| Psycho Strike | 27,446 | 2 | verified | 6,443 |
| Crazy Party | 192,584 -> 192,626 | 14 | verified | 90,118 |
| Manamon 1 | 90,848 -> 90,852 | 0 | verified | 26,568 |

## The compiler is the judge, and it has to be driven

`bgt.exe` takes a script path and *runs* it. There is no console mode and no
switches: it is a GUI program that reports compilation through a window of its
own class (`bgtgame`) with no child controls. The message is exposed only to
the accessibility tree — which is also how the engine's intended audience reads
it — so `bgt_compile` launches the compiler, waits for the report window or for
the process to exit, and reads the text out through UI Automation. The report
is exactly what a developer sees, file and line and source line and message,
and `Information: Candidates are:` carries the signatures the engine *does*
have for a call that did not match.

Three things about that are worth keeping:

- **A clean exit is not the same as a clean compile.** Some modules make the
  compiler die silently — no window, no message, exit `0xC0000005`. Read
  as success, a module that crashes the compiler looks perfect. A
  compile-only check also has to disarm `main`, or a *successful* compile
  looks exactly like a hang. The reverse trap is worse, because it is
  quiet: the engine reports through its window and *then* exits, and the
  driver dismisses that window so it can finish — so a report and a clean
  exit arrive together. Reading the exit code first threw the report away,
  and Psycho Strike's 33 errors came back as `compiled cleanly`. The text
  is parsed before the exit code is believed.
- **One compiler at a time, and say so when it could not run.** `bgt.exe` is
  a GUI program read through the accessibility tree, and two of them at once
  do not both get read: checking two titles in parallel here gave one real
  report and one blank `nodriver`, which looks like a broken check rather
  than a busy one. Checks take a lock and queue; a stale lock from a killed
  run is cleared rather than waited on. And `nodriver` now carries its
  reason into both the summary line and `recovery.json`, because an outcome
  with no explanation reads like a result — and this is the one outcome
  that is not one.
- **Ask the compiler about the language rather than guessing.** `string[]()`
  is valid and `weapon@[]()` is a parse error, because the parser takes
  `weapon@[]` as the start of a declaration and nothing else; the template's
  own name works as an expression, so a constructor is emitted as
  `array<weapon@>()` while declarations keep the idiomatic `T[]`. Both forms
  were put to the compiler before either was emitted.
- **A parser that drops diagnostics flatters the result.** The first candidate
  list swallowed every later message in the report, so 318 errors came back as
  seven and the recovery looked almost finished. Any count that improves
  suspiciously fast is a count worth re-deriving.

## Where it stands

Every title that parses recovers with **0 unmodelled opcodes and 0 bodies
that failed to decompile**. What the compiler says, and what the project's own
checks say:

| title | lines | goto | unbalanced | split | calls read back | and does it RUN? |
|---|---|---|---|---|---|---|
| constant velocity | 3,805 | 0 | 0 | yes | 1,767 | **yes** |
| Battle of the Hunter | 4,269 | 0 | 0 | yes | 1,334 | **yes** |
| Super Egg Hunt | 5,239 | 0 | 0 | yes | 1,623 | **yes** |
| Field Wars | 7,942 | 0 | 0 | yes | 3,005 | **yes** |
| cs client | 7,963 | 0 | 0 | yes | 2,858 | **yes** |
| rage room | 8,484 | 0 | 0 | yes | 2,369 | **yes** |
| cs server | 9,692 | 0 | 0 | yes | 3,060 | **yes** |
| The Gate | 33,995 | 0 | 0 | yes | 8,681 | no -- **`elias`**, which no stock BGT registers |
| Manamon 1 | 82,099 | 0 | 0 | yes | 26,507 | not asked -- **wrong engine**, see below |
| Crazy Party | 173,813 | **0** | 0 | yes | 90,194 | not asked -- a 174k-line compile is a deliberate spend |
| Paladin of the Sky | -- | -- | -- | -- | -- | **not on this machine any more** |
| Psycho Strike | -- | -- | -- | -- | -- | **not on this machine any more** |
| Manamon 2 | -- | -- | -- | -- | -- | **not on this machine any more** |

**The last column is new and it is the stronger claim.** "Compiled cleanly"
was what this table used to carry, and a compile-only check never runs a
global initialiser -- this file records `Failed to initialize global variable
'recorder'` as a defect that compiled perfectly. `bgt drive` starts the
recovery, holds a key down and reads an answer back, so a **yes** there means
every global initialised, the module loaded, and the engine answered.

**Seven of the ten titles that can be built here run**, and the biggest of
those is a 9,692-line networked game server.

**Every number is from one run of the committed tree.** That is what this
table has rarely been able to say: it carried a mixture of rows from
different commits for most of this project's life. Three titles now say
`--` rather than a figure, because their executables are no longer in the
folders this file names -- Paladin, Psycho Strike and Manamon 2 -- and a
number nobody can reproduce reads as a baseline. Everything above them in
this document that quotes a Paladin or Psycho Strike figure is a measurement
from the commit it was written at, and should be read that way.

**Crazy Party's goto column is the one that matters most.** It is the title
every over-broad fold or structurer change in this file was caught by --
14 -> 30 for a call-text threshold, -> 44 for dropping the declaration order
rule, -> 90 for forcing on the copy idiom -- and it is **0** here, with 46
more calls read back than the figure this table used to carry.

**What the compiler says is now a note rather than a column**, because
the two are different questions and the column kept conflating them. A
diagnostic count is a statement about *this* engine: Psycho Strike's last
measured 34 were 32 uses of the `elias` plugin and one
`tts_voice::speak_to_sound`, none of them the recovery's; The Gate's are the
same plugin; Manamon 2's 33 all start on `protected` or `weakref`, which its
own newer BGT has and this one does not. Where the engine is the right one
and the recovery is clean, the stronger claim is in the table: it **runs**.

**Asking still costs a modal dialog** on whoever is at the machine, which is
why it is spent deliberately and not per commit. `bgt drive` is the cheap
version of the same question -- it compiles and starts the project, so a
**yes** in that column is a compile *and* a run -- and `bgt audit`,
`bgt signatures`, `bgt apicheck` and `bgt oracle` cost nothing at all.

**And a window title is not the check that matters** -- Paladin is the title
that taught it twice. It used to report `command`, because run as a *script*
`get_SCRIPT_COMPILED()` is false and the game takes its own uncompiled-build
path. Then it reported `Paladin of the sky` -- the real one -- while the game
was unusable: no audio, and the menu looping back into `tts_selector`. So the
title moves for reasons that have nothing to do with whether the recovery is
right, in both directions. It is a liveness check and nothing more, which is
exactly why `bgt drive` reads a **value** back instead.

**Manamon 1 joins the table**, and two of its figures are the benchmark
this project was started against: 784 classes and 332 globals, reached here
by a different reader from the same bytes, and 4,909 bodies, which is the
number that benchmark reported as "script functions". It recovers to 806
files with **0 residual gotos**, a verified split, 0 unmodelled opcodes,
**0 bodies given up on** and 26,568 calls read back against its own
runtime. The two it used to give up on were `number_key_pressed` and
`type_effectiveness` -- the same two functions Manamon 2 gives up on, by
name -- and both are fixed under **The tables nothing claims**.

Its line count moved from 91,310 to 90,314 when the global-pointer encoding
was corrected, to 90,848 when those two bodies came back and to 90,852 when a
slot's width evidence stopped being first-come-first-served; the five
`__nvgt_global_init_N` callees this file used to list as declared nowhere
were a defect in the checker: see below.

**Its data extracts now**, which is a separate claim from its source
compiling and is the half that was broken: 2,007 of its 2,007 pack entries
come out decrypted under a key the module computes rather than stores (see
**A key that is a DIGEST**), and 5 of the game's own data files come with
them, `data/tamerdata.dat` among them -- the one no string constant names.
Measured at the current code: **82,099 lines, 0 residual gotos, a verified
split and 26,507 calls read back**.

The standings say `not asked` for it on purpose: the only engine installed
here is BGT 1.3, which is not the fork that built it. See **The string
factory has a third spelling** for what asking anyway cost. Its NVGT port,
which NVGT's own console compiler judges for free, is **1 error** -- a
`Name conflict` on `sleep`, a class the game declares and NVGT has as a
function.

**The Gate is the eighth title, and the second picked up cold with nothing
changed to receive it.** A 2015 VGStorm game (`VGStorm.com\The Gate\gate.exe`,
1.28 MB, overlay 0xE9200, stock seed 0x11, `tagged`): 171 of 171 class blocks,
1,783 bodies, 25 enums, 4 funcdefs, **0 parse errors**, a tail landing exactly
on EOF at 703,499 bytes, and every per-build field the ordinary `tagged`
combination -- `template_namespace`, `objvar_three` and `legacy_body` all true,
`unguarded_lists` false. No reader change, and no new per-build case.

It recovers to 183 files and **34,955 lines with 0 residual gotos, 0 dangling
gotos, 0 unbalanced files, 0 unmodelled opcodes, a verified split and 8,666
calls read back** against its own build's declarations. One body is given up
on, and it is the known shape rather than a crash: an `UnstructuredSwitch` in
`character`, a jump table neither matcher claimed -- the same class as
Manamon's `number_key_pressed` was.

**Its data comes out whole**, which took the chain fork below: the key is
recovered from the module, `sounds.dat` is copied, and **1,153 of 1,153**
entries extract -- 1,148 Ogg Vorbis and the 5 `.epro` themes, nothing refused
and nothing unaccounted for.

The standings say it does not run, for the reason Psycho Strike's 34 were
mostly unavoidable: the game needs `elias`, which no stock BGT registers, so
`elias theme;` fails and every `theme.x()` after it is `Illegal operation on
'int&'` -- one missing engine type and a cascade. `bgt recover` reports the
plugin and copies `elias.dll` into the project, and no amount of recovery
quality can supply a type the engine does not have.

**Two of its registration counts are Psycho Strike's exactly** -- 453 names
and 40 types -- six months later to the day, so VGStorm's fork did not move
between April and October 2015.

**And two titles can no longer be measured the same way.** Psycho Strike's
and Manamon 2's own runtimes are not on this machine, so their modules were
repacked onto BGT 1.3's stub. That works for Psycho Strike, whose figures
above are from such a build -- the opcode table is identical across BGT
builds, so the decompiled text is unaffected, though `engine_gap`,
`method_gap` and the apicheck oracle are 1.3's rather than its fork's and
are not quoted. It does **not** work for Manamon 2: 1.3's table does not
decode that fork's bodies, and `bgt_asir.load` says so rather than
guessing -- `module tail did not land on EOF`. Four titles, not five, until
that runtime is back. **And Paladin has
to be recovered from the game**, not from `paladin_fixed/game.exe`, which is
the 1.27 MB executable `bgt compile --build release` *wrote* from an earlier
recovery. Decompiling that is a round trip rather than a recovery, and it
reads as one: 36,151 lines against the original's 28,223, because recovered
source does not compile to the bytecode the original was built from.

Paladin's window now reads `Paladin of the sky`, which supersedes the note
below about it reporting `command`: that was the uncompiled-build path, and
reaching the real title means the module got further than it used to.

**Two titles compile clean, and the largest does not.** Super Egg Hunt
reports `compiled cleanly` and `--run` opens `Super Egg Hunt Version 1.53`
— the title the original executable shows, checked by launching it — and
Paladin compiles cleanly and runs as a built executable. That is the
end-to-end check: executable in, source out, source back into the engine,
game on screen.

**Crazy Party's 14 errors WERE its 14 residual gotos, and both are 0.**
That row went through three readings before it settled, and the sequence is
the lesson. It said `compiled with 2 warning(s)` at 195,364 lines, and a
later section said a fix had taken those warnings away so "all three titles
now report `compiled cleanly`". Both were written before this title's
residual goto count was re-derived from 0 to 14 -- and **AngelScript has no
`goto`, so each of those lines was an error**: `CarteCombat` (4), `part_6`
(6), `Jeu` (2) and `CombattantSauvage` (2). The loop fix recorded under
**Fixed: the shape, and the attempt that was worse than the goto** took them
to 0, and the standings now show **0 gotos at 173,813 lines with 90,194 calls
read back**.

##### ...and the two warnings were `null` compared with `==`

`if (!((local_6 is local_5) || (null == local_5)))` compares a handle against
`null` with `==` where the language wants `is`. **`null` is a handle
comparison by construction** -- `==` asks the type for an `opEquals` and
`null` has none, which is exactly what the engine warns about -- so the
operator does not need an opcode to vouch for it.

`cmp_is_handle` is set by `CmpPtr` and by nothing else, so a comparison that
reached `null` through any other opcode kept `==`. `_handle_comparison` is
the one answer now, consulted by **both** places that choose the operator:
`_taken_condition`, which renders a jump's condition, and the `TEST_OPS`
branch, which renders a comparison used as a value inside a larger `&&`/`||`.
Two places answering one question with one of them weaker is the failure this
file keeps recording, and the site in the corpus is the second one.

It is **one site in one title**: the other seven titles that can be built
here render byte-identical, and `bgt oracle` is 52/52. A warning matters
because BGT shows one in a modal dialog and waits on it, so an unattended
compile stops there.

The lesson is the one this file keeps paying for from a new direction: the
goto count had been corrected and **the sentences that depended on it had
not**. A number and a claim about that number are two places to keep in step,
and only one of them was re-derived.

**And a window on screen is not the check that matters** — Super Egg Hunt
passed every line of this table while its menu could not be navigated. See
**When a folded temporary stops being the value the bytecode computed**: the
counts above say the recovery is *structurally* complete, and three separate
bugs that compiled cleanly and ran were found by pressing an arrow key.

**A window title is still only evidence that the module reached the engine**,
and Paladin is the title that taught it twice. It used to report `command`,
because run as a *script* `get_SCRIPT_COMPILED()` is false, the game takes its
own uncompiled-build path, and the first titled window that path opens is an
`input_box("command", ...)`. Then it reported `Paladin of the sky` — the real
one — while the game was unusable: no audio, and the menu looping back into
`tts_selector` (see **Every body must match too**). So the title moves for
reasons that have nothing to do with whether the recovery is right, in both
directions. It is a liveness check and nothing more.

**Psycho Strike's 33 are all the installed engine's.** 32 are uses of
`elias`, a plugin type, and one is `tts_voice::speak_to_sound`, which this
engine does not document and the game's own executable registers. Nothing
there is the recovery's.

**On both titles that still report errors, every error is the installed
engine's.** Psycho Strike's 33 are 32 uses of the `elias` plugin type and one
`tts_voice::speak_to_sound`. Manamon 2's 33 are in five files, and each one
starts on `protected` or `weakref<T>`: its own newer BGT has both and this one
has neither, and a parse error stops the compiler, so the rest of each file
follows from the first line. Nothing left on either title is the recovery's.

**SBYW is absent from this table on purpose.** Its executable is no longer in
the folder it was read from, so its numbers could not be re-measured against
the current code and are not quoted as if they were. Everything above it in
this document that mentions SBYW is a *parse* and *lift* result, which stands
— it is only the recovery table that needs a run.

**Manamon 2 got there by three fixes, and the brace count is what found all
three.** It began the day at 68 errors, three unparseable files, 25 residual
gotos and a split that did not verify, and the compiler's own messages said
none of that — they blamed declarations hundreds of lines downstream with
"Expected method or property", which is exactly what a missing engine keyword
looks like. Reporting `unbalanced files` separated the two causes
immediately: the structurally broken files were 2, 10 and 1 braces short
while the `protected` file balanced at zero. What they were:

- a **namespaced section keyed by its bare name**, which moved 71 lines
  fifty thousand lines early and was the whole of the split failure;
- a **jump table claimed by neither switch matcher**, whose arms were emitted
  with ten unmatched `}`;
- **`goto` treated as a terminator** by `_drop_unreachable`, which deleted
  seven live lines of `cure_all_statuses` including its `if (...) {`. The
  structurer's output was valid; the pass broke it.

It now reports 0 unbalanced files, 0 dangling `else`, a verified split, no
problems at all, and 3 bodies given up on and counted — the jump tables
above. 6 residual gotos remain.

## The engine documents itself

`bgt.chm` sits next to `bgt.exe` and answers, authoritatively, every question
of the form "does this engine have that?": one reference page per registered
function, class and method, each carrying its signature verbatim.

```bash
bgt api garbage_collect            # void garbage_collect()
bgt api --list sound_pool          # the type and its methods
bgt api elias weakref --missing    # NOT documented
```

`bgt_api` unpacks it with Windows' own `hh.exe` (the only thing that reads the
format), caches the result outside this repository, and parses the reference
tree -- 125 functions and 25 types with 273 methods, from 413 of its 421
pages. Tutorial pages are skipped, because example code is not an API.

**And example code inside a *reference* page was not.** A reference page is
named after the one API it documents, so `garbage_collect`'s page defines
`generate_garbage` to have something to collect, `get_call_stack`'s defines
`first_dummy_method`, `serialize`'s defines `save`. Every signature on a page
whose name is not the page's own is example code, and eleven of them were
being counted as engine API -- which is the count above moving from 140 to
125. That matters in the dangerous direction: this list is what decides
whether an absence gets reported, so **a name it wrongly holds is a gap it
will not report**. The engine's own registrations settle it, and so does the
help file's own tree -- not one of the eleven has a page. The `PROPERTY`
branch two lines below had applied exactly this rule all along, which is the
recurring shape here: two places answering one question, one of them stricter.

Three things it settles that were guesses before:

- **The documented type list is the oracle for the engine gap.** Searching a
  binary for a name is a guess; this is a list. `bgt recover` uses it, and
  falls back to the binary search only when the help file cannot be read.
  It is not the *whole* list, though -- see **The engine registers itself**
  below, because `bgt.exe` holds a list too, and a longer one.
- **The language has no `goto` and no `protected`.** Neither word appears
  anywhere in the help file. So a residual `goto` can never compile, however
  it is spelled -- and Manamon 2's `protected` really is a newer engine's.
  Confirmed independently since, in the binaries: neither string occurs in
  BGT 1.0's `bgt.exe` or 1.3's, while `private`, `funcdef`, `interface` and
  `cast` occur in both.
- **The command-line options are documented** (Appendix G), and match what the
  installer's shell verbs do: `-c` debug, `-C` release, `-r` the registration
  manager, no space before a quoted path, and a bare `-c` opens a file dialog.

### The PROSE of the help file, which `bgt_api` throws away

`bgt_api` parses the reference tree and skips everything else, because
example code is not an API. That is right for extracting signatures and
it meant the 295 KB of prose beside them had never been read: an
introduction, a one-line `limitations` page, **eight appendices**, a 45 KB
change log and nine tutorials, 421 pages in all. BGT ships no `readme` --
`bgt.chm` is the documentation -- so this is it.

Four things in it are worth having, and the first cost nothing to fix and
should never have been wrong.

#### NVDA's client is LGPL, and its licence is not optional

Appendix F, verbatim: *"you need to include the file called license.txt
along with NVDA's dll (found in the same directory) if you wish to support
this screen reader"*. `redist/screen_readers/nvda/` ships it -- LGPL 2.1,
26 KB -- and it is **the only licence file anywhere in a BGT install**.

`bgt recover` copied the DLL and left it behind. So every recovered
project that speaks through NVDA was redistributing an LGPL library
without its terms, and no count in this document could ever have shown
that: the project compiles, runs and talks exactly the same either way.
It is copied now, as `nvdaControllerClient32-license.txt` -- named after
the DLL so it cannot be taken for the project's own licence or collide
with one, since the LGPL asks that the terms accompany the library and
not that the file keep a particular name.

It is deliberately **not** in the "keep these beside the script" note. The
engine never looks for a licence; that note is about what makes speech
work, and the same appendix names the other half of it --
`screen_reader_set_library_path`, for putting the clients somewhere other
than the script's own folder. System Access carries no licence and must
not grow one: that DLL "has no explicit license attached to it but is
freely distributable".

#### A debug build's file names are a documented feature, not a leak

This file records Screaming Strike shipping its source path
(`D:\My Documents\screamingSstrike\screamingStrike_en.bgt`) and local
variable names, found by reading the module. Appendix H says what that is:
*"Debug builds store a lot of additional information about your script
such as the names of the files on your system that the code is contained
in, line numbers, etc."*, and release builds "exclude this information,
resulting in a smaller executable that is harder to reverse engineer".

Appendix D then describes `script_current_file` as *"the full path and
filename of the script that is currently being executed. If the property
is retrieved from within a compiled game, the path is that of the source
file on the original development machine"* -- which reads like the path
being in **every** compiled game, release included, and would contradict
this document's flat claim that a game's own file names are unrecoverable.

**It does not, and the three release builds made for this were the test.**
`constant velocity`, `cs client` and `cs server` were compiled here with
`-C` from a known directory, and neither the executables nor the decrypted
modules hold one byte of that path. The only `.bgt` in any of them is
`rotu.bgt`, a filename the game itself writes. So the appendix is
describing the debug case and simply does not say so, and the claim stands
-- now confirmed from the engine's own documentation rather than inferred
from a parse.

**And the first run of that test was a false negative**, which is worth
more than the result. `strings -a <exe> | grep -c scratchpad` printed `0`
three times -- because **`strings` is not installed here**, so every
pipeline failed and `grep -c` counted an empty stream. Three confident
zeroes from a command that never ran. The answer only became real when the
same search was done in Python against the bytes. A measurement is not a
measurement until you have checked the instrument ran.

#### The overloadable operators are a LIST, and the set held 6 of 43

`OPERATOR_METHODS` keeps an operator the source writes as syntax out of
the call comparison, and this file records it being *"widened one measured
occurrence at a time, deliberately: a name in here is dropped from BOTH
sides, so every addition makes the comparison weaker"*. `opAdd_r` was
found that way -- one reversed concatenation, in one body, of one title.

The language tutorial prints the whole thing in four tables: six unary,
eleven binary with their `_r` reverses, twelve assignment forms,
`opIndex`, `opEquals` and `opCmp`. **43 names, and the set had 6.** So 37
more `opAdd_r`s were waiting, each costing a reported difference that is
a spelling difference.

The policy was right while there was no authority and is wrong now there
is one: membership is a fact about the language rather than a tuning
parameter, and this document's first rule is to read the authority. The
tutorial prints `op_Ushr_r` for the reverse of `>>>`, which is a typo --
every other reverse is the name with `_r` appended -- so both spellings
are listed rather than guessed between.

**It is inert on every score**, which is the point rather than a
disappointment: dropping the same names from both sides cannot reorder
what remains, so it can only ever stop a spelling being read as a
difference. Measured in-process against the old six on one decompiler,
Psycho Strike is 147 of 149 identical either way.

**And measuring it taught the lesson twice over.** The first run said
147 -> 145, which is impossible for this change and was believed for
several minutes anyway. The cause was that an *unrelated* decompiler
change was sitting in the tree at the same time, so the run measured both
and the result was attributed to the wrong one. Two changes in flight is
one measurement of neither -- which is exactly what this file keeps
saying about structurer work, arriving from the instrument side.

#### `limitations` is one line, and it is about the network object

The whole page: *"The network object is too complicated. We need a higher
level wrapper around it that simplifies common tasks."* Worth knowing
before reading networking code in a recovered game -- `cs` drives
`network` directly across a client and a server, and that is not the
author working around a missing wrapper, it is the only interface there
has ever been.

#### An embedded pack is referred to as `*`, and nothing here handles it

The packaging tutorial documents a feature the chain at the top of this
file already half knows about -- the `"<n> "` field is *"the size of an
optional embedded pack"* -- without recording what a script does with it:

- `#include "packname.dat"` embeds a pack **inside the executable**. The
  engine decides for itself whether an include is a script or a pack, and
  **at most one pack per game** may be included.
- the script then names it `"*"`: `set_sound_storage("*")`,
  `pack_file::open("*")`.
- run from source, `"*"` means the pack file on disk under the name the
  `#include` gave; compiled, it means the copy inside the program.

`bgt recover` cannot follow that. It finds packs by taking names out of the
module's string constants and keeping the ones that name a file beside the
executable with `SFPv` magic -- and `"*"` names no file, so such a title
would report *"loads assets through set_sound_storage and no pack was
found"* while the pack sat inside the executable it was handed.
`bgtlib.unpack_file` already returns the bytes as `embedded_pack`, and
`bgt unpack` already writes them out; **the recovery path never reads that
field at all.**

What a correct recovery needs is all three of: the pack written beside the
project, an `#include` naming it, and the script left saying `"*"` -- and
the original `#include`'s filename is not recoverable, because it was a
directive rather than a string constant, so the written name is this
tool's choice.

**It was latent across the whole corpus, and then a user found one.**
This said all ten titles here have an embedded pack of **0 bytes**, so the
shape was provable and had no sample -- and that is exactly the state in which
a gap is found by somebody playing a game rather than by a test.

**Battle of the Hunter is the sample.** `bth.exe` carries **5,411,932 bytes**
of `SFPv` inside itself, there is no `.dat` beside the game at all, and its
script asks for `"*"`:

```
set_sound_storage("*");
set_sound_decryption_key("wolves111", true);
```

Recovered, it compiled, it ran, and it had no sound -- which is how it was
reported, and which no count in this file could have shown.

**And the report was worse than silent, it was misleading.** With no pack
found, `asset_gaps` lists the `.dat` names in the string constants as what the
game "names". That title's only `.dat` constant is `tunmi13/bth/data.dat`,
which is its **save file**, from `savedata`'s constructor. So the report named
a save path as a missing asset pack, about a game that is missing nothing. A
game that asks for `"*"` is now recognised and told apart from one that names
a pack it cannot find.

All three things a correct recovery needs are done, and it needs all three:

| | |
|---|---|
| the pack written beside the project | `embedded_pack.dat` -- **the name is the toolkit's choice**, because the original `#include`'s filename was a directive and is not recoverable |
| an `#include` naming it | emitted in the entry script, with a comment saying why |
| the script left saying `"*"` | untouched; it already was |

Measured: 20 files, 4,373 lines, 0 residual gotos, split verified, 1,339 calls
read back, the key `wolves111` recovered from the module, **133 of 133 entries
extracted**, and `compiled cleanly`.

**One bug came out of wiring it**, and it is the kind worth recording. An
embedded pack is written straight into the project, so the copy step then
copied it onto itself -- and on Windows that is not a no-op, it is
`PermissionError: the process cannot access the file because it is being used
by another process`, which killed the whole recovery. A pack already where it
belongs is now left alone, which also covers recovering into the game's own
folder.

#### The two reference LAYERS, and the Remarks `bgt_api` throws away

`references/` has two halves, and the split is the one this file already
derives from the registration strings:

| layer | pages | what it is |
|---|---|---|
| `foundation_layer` | 305 | the engine's own API |
| `helper_layer` | 116 | the script classes in `include/*.bgt` |

The helper layer says so outright: *"functions and objects that are
included as part of the BGT distribution, but that are stored as separate
scripts that should be included in a main script"*. That is exactly the
nine documented-but-unregistered types this file identifies by the absence
of a factory registration, named by the documentation instead of inferred.

**The signatures were never the valuable part of these pages.** `bgt_api`
reads a declaration per page and drops the prose, and the prose is where
the semantics are -- 267 `Remarks` blocks in the foundation layer and 91
in the helper layer, 187 KB that nothing here had read. `string_mid` being
1-based does not show in `string string_mid(string, int, int)`, which is
why it took a probe.

##### `"*"` is documented a second time, under the pack functions

`set_sound_storage` and `get_sound_storage` both describe it: *"If you
pass * to this function, the engine will attempt to look for sounds in a
pack file that has been included into the program itself"*, and the getter
returns `*` to say so. So the embedded-pack gap above is documented in two
independent places, and `get_sound_storage()` returning `*` is a second
way a module can be seen to want one.

##### `get_last_error` is reset by EVERY engine call

*"the error is reset for every new call to an engine function or object
method, so you should retrieve the error code before making any other
calls"* -- and *"not affected by calls to any of your own functions or
methods"*.

That is a **precisely documented invalidation rule** for the one class of
staleness this file declines to model. `_stale_fold` ends with *"A bare
call's result can still go stale through engine state -- `reserve_slot()`
hands out a different slot each time -- but that is the duplication case
... and not guessed at here"*. `get_last_error()` is the same shape with
the rule written down: a value built from it is invalidated by any engine
call and by nothing else.

Not acted on, because no title in the corpus has one that moved -- and
finding that out cost the session's **fourth** instrument failure. A grep
said the cs client's source held 5 and its recovery 10, which looked
exactly like a folded call run twice. It is not: AngelScript's property
accessors mean a registered `get_X()` may be written `X`, so that author
writes `last_error` and the recovery writes `::get_last_error()` -- the
same call, two spellings, and the grep counted one of them. (The `::` is
the recovery being right about something subtle: `downloader` declares its
own `get_last_error()` method, so the global needs qualifying.)

##### Three more that change how a recovered body should be read

- **`assert` does nothing in a release build and always returns true.**
  Every `assert` in a shipped game's module is dead code that a recovery
  faithfully reproduces, and it only ever ran for the author.
- **`random` clamps rather than erroring**: *"If max is less than or equal
  to min, min will be returned"*, over a range of plus or minus
  999,999,999. So a recovered `random(x, x)` is not a bug.
- **`random_set_state` really does reproduce a series**, which settles how
  bad the lost call in Crazy Party's `Partie::synchroRandom` is: that
  function exists to burn draws so a client's generator lines up with the
  host's, and with its one `random` call dropped the loop advanced nothing.
  The documentation confirms the generator is a pure function of its state,
  so the desynchronisation is total rather than probabilistic.

One more worth keeping for the fold rules: **`garbage_collect`'s page says
destructor timing is not dependable** -- *"you should not depend on a
destructor of any given class being called at any specific time"* -- but
only for the garbage-collected types, which are *"arrays and script
defined classes"*. A `sound` is reference counted, so its destruction IS
deterministic, which is what makes the borrowed-handle fold's
object-lifetime argument sound for exactly the types it was argued about.

#### Four things the tutorials confirm that were derived the hard way

None of these changes any code. They are worth recording because each was
reached from the bytecode or from a probe, and the manual says the same --
which is the cheapest kind of cross-validation there is.

- **A dictionary lookup that misses leaves your variable alone.** *"If you
  delete or check an entry that doesn't exist, this will not cause any
  syntax or runtime errors to occur, but the variable you are attempting to
  use to retrieve the value will not change."* This file records the same
  behaviour for a **type** mismatch, found through the `?&` TYPEID work and
  the six Paladin save flags that stopped being restored. Same rule, the
  other half of it.
- **A parameterless base constructor is called automatically.** *"imagine
  that the first thing a derived class constructor does is to call a
  parameterless base class constructor. This happens automatically"*, and
  `super(...)` is for choosing a different one. So the call audit's
  commonest benign row -- `super()` where the bytecode names the base
  constructor -- is benign by the language's own definition.
- **Enums must be global.** *"enums have to be defined globally; they
  cannot be defined inside a function"*, which is what makes `types.bgt` a
  correct place to put every one of them.
- **The nesting limit is 10,000 calls**, twice stated. That is exactly the
  frame count in the `person::reset` stack overflow this file records, so
  that trace was the engine hitting its documented ceiling rather than
  anything stranger.

#### The documented escape list does NOT include `\xNN`

The tutorial's table is `\\`, `\"`, `\n`, `\r`, `\t` and nothing else.
This toolkit writes every byte above 0x7F as `\xNN`, which is **not in
it** -- and that is fine, because the engine was asked rather than the
documentation: `"\xac\x71\x96"` compiles with no warning and produces
those three bytes, while the octal `"\254"` is *"Invalid escape
sequence"*. Had the manual been the authority here it would have said no
to a spelling the engine accepts, which is worth knowing about the
documentation's completeness before leaning on it for anything else.

#### The manual's own example code ships inside real games

The performance tutorial prints a `preload` class with `preload_add` and
`reset_preloads`, for keeping sounds in memory so the pool can clone them.
Paladin has all three. It is an **adaptation** rather than a copy -- a
`dictionary` where the manual uses an array, plus an `alert` on failure --
and `reset_preloads` is near enough verbatim.

That makes the tutorials a second source of source nobody here wrote,
after `include/*.bgt`. It is weaker than the library, because a game
adapts an example where it merely *uses* a library file, so it is a
reading aid rather than a scoring oracle. It does explain one round-trip
row: `preload_all` scores **0.015**, which this file already attributes to
a per-item string temp, and the body it is scoring is the manual's shape.

#### ...and reading it needed its instrument checked, like everything else

The help file is 421 pages of compiled HTML, so reading it meant flattening
it to text, and the flattener ate **22,904 characters -- 7% of the manual,
almost all of it inside the code examples.** `<[^>]+>` is not a tag
pattern: the help file writes a raw `<` in its source, so
`for(int x=0; x<50; x++)` lost everything from `<50` onward and the array
chapter read as prose with the arrays missing.

Nothing announced it. The text was fluent, the headings were right, and
the only tell was a sentence that ran into the next chapter's title. That
is the third instrument failure in one session, after `strings` not being
installed and a measurement confounded by two changes at once -- and all
three produced confident, plausible, wrong output rather than an error.

#### Running a script from source is a DEBUG run

Appendix H closes with it: *"When you run a BGT script from source, it is
automatically run in debug mode."* That is the other half of **Run as a
script, a game takes its developer path** -- `bgt compile --run` does not
merely skip `get_SCRIPT_COMPILED()`, it runs the whole thing under a
different build, with the profiler instrumentation the same appendix
describes. One more reason the executable is the only honest way to
exercise a recovery.

### What the documentation does not say, the engine will

A signature is not semantics, and recovered source is only as meaningful as
the primitives it calls. These were put to `bgt.exe` directly -- a script
that calls each one and writes the result to a file through `file::write`,
compared byte for byte against Python:

| primitive | what it actually does |
|---|---|
| `string_hash(s, 2, true)` | raw SHA-512, 64 bytes, NULs and all |
| `string_reverse(s)` | reverses **bytes**, not characters |
| `string_base64_encode(s)` | standard alphabet, standard `=` padding |
| `string_mid(s, start, count)` | **1-based**: `(s, 5, 4)` of `0123456789abcdef` is `4567` |

`string_mid` is the one worth the trouble. Nothing in a decompiled body can
settle 1-based against 0-based -- both read perfectly -- so every recovered
`string_mid(x, n, k)` is `x[n-1 : n-1+k]`, and reading it as `x[n : n+k]` is
off by one in a way that only shows up in the output. The same probe shape
settles any other primitive the same way, and it is cheaper than arguing
about it.

### The engine registers itself, and the binary is the longer list

AngelScript registers everything by handing the engine a **declaration
string**, and that string is a literal in the executable. So the whole
registered interface is sitting in `bgt.exe` -- exact parameter types,
`&in`/`&out`, `const`, and the default arguments the engine gives its own
functions. `bgt_api.registered()` reads it (432 names and 34 types in BGT
1.3, 240 and 23 in 1.0), and `bgt api` consults it alongside the help file:

```bash
bgt api string_compress        # registered, not documented
bgt api --missing network_event weakref
```

**The help file is not the whole list, and the gap has teeth.** BGT 1.3
registers `string_compress`, `string_decompress`, `crc32`, `add_fx`,
`delete_fx`, `hex_string_to_number`, `screen_reader_braille` and
`string_create_from_pointer`, and documents **none** of them -- and
Paladin's save path is
`serialize_all()` -> `serialize()` -> `string_compress()` -> `string_encrypt(...)`.
Asked of the documentation alone, "does this engine have that?" answered no
about a function a shipped title calls. It registers two *types* the help
file omits as well, `network_event` (what `network::request()` returns) and
`library_structure`, so a game using either would have been reported as
needing a newer engine than the one installed.

**Nothing on the four titles moves**, and that is the result rather than a
disappointment: `engine_gap` and `method_gap` are identical before and after
on Paladin, Psycho Strike, Manamon 2 and Super Egg Hunt. The hole is
provable and latent, which is the only honest way to describe it -- the
evidence is `string_compress` and `network_event`, not a changed report.

That gives three sources that answer three different questions, and the
split is clean:

| where a name is | what it is |
|---|---|
| a registration string in `bgt.exe` | engine API -- authoritative |
| a declaration in `include/*.bgt` | library API, which recovers like any script |
| a reference page named after it | documented |
| a signature on some *other* page | example code, and not an API at all |

The five documented functions that are registered nowhere --
`position_sound_1d`, `position_sound_2d`, `position_sound_custom_1d`,
`position_sound_custom_2d` and `convert_to_currency` -- are exactly the
library ones, in `sound_positioning.bgt` and `finance.bgt`. The same split
holds for types: the nine documented types with no factory registration are
`array`, `string` and `vector` (value types) plus `audio_form`,
`dynamic_menu`, `logger`, `number_speaker`, `sound_pool` and `soundtrack`,
which are the helper-layer *script* classes.

Three refusals make this a reader rather than a guess, and each was a real
false positive first:

- **An array return.** `string[]@ find_files(string& in)` was rejected by
  the first pattern, which reported four functions as absent that the help
  file *did* document -- and the documentation disagreeing is the only
  reason it was caught. An extractor that answers anyway, in a new costume.
- **The handle marker sits against either side.** The engine writes a
  factory `network_event @f()` and a getter `network_event@ request()`, so
  demanding whitespace between the type and the name finds the second and
  silently loses all eighteen of the first.
- **A return type and a name must be separated by something.** The type
  pattern backtracks, so a bare `send()` from the import table splits into a
  return type `sen` and a function `d`. Four import names became registered
  types that way. And a file-dialog filter is shaped exactly like a
  declaration (`All Files (*.*)`), which is told apart by the fact that a
  declaration's parameters are *types*.

### A game's own executable is an engine, and it will tell you which one

This is the one that pays for everything above. **A BGT game is the runtime
with the module appended**, and the runtime is not compressed in the game --
only in `exec.bin`, which is how `bgt.exe` carries it. So the same
registration strings are in `strike.exe` and `rpg.exe`, and reading them
gives the whole interface of the build that produced that module:

```bash
bgt api --exe "<game>.exe" weakref garbage_collect    # that build's answer
```

| engine | registered names | types | built |
|---|---|---|---|
| BGT 1.0 | 240 | 23 | 2010-12-30 |
| BGT 1.3 | 432 | 32 | 2014-06-01 00:41 |
| Super Egg Hunt | 432 | 32 | 2014-06-01 00:38 |
| Paladin of the Sky | 432 | 32 | stock |
| Psycho Strike | 453 | 40 | 2015-04-19 21:02 |
| The Gate | 453 | 40 | 2015-10-13 23:04 |
| Manamon 1 | 469 | 44 | 2017-03-15 21:21 |
| Manamon 2 | 509 | 52 | 2019-11-15 02:14 |

Egg Hunt's runtime was built **three minutes before** the `bgt.exe` that
embeds it, which is one compile session: that title is stock 1.3 and the
timestamps say so without being asked.

**Dating the FORK by the build in hand gets it backwards**, and this file
used to call Manamon 1's engine "a 2017 fork". The copy installed here is
**Manamon 1.1** -- the last entry in its own `changelog.txt`, with data files
dated June 2017 and a runtime whose PE timestamp is 2017-03-15 -- while the
game released in 2016, so that date is a *patch's*. And the fork is older than
either: Psycho Strike already registers 453 names in **April 2015**. So the
engine is VGStorm's own fork of BGT throughout, and a build date says when
that copy was compiled and nothing about when the fork began. The practical
consequence is unchanged and does not depend on the date: no stock `bgt.exe`
of any version can parse this title's source.

**The fork has three points now, and Manamon 1 is the middle one.** 453
registrations in 2015, 469 in 2017, 509 in 2019 -- and **37 of Manamon 1's
38 additions over stock 1.3 are also in Manamon 2**, so it is one
developer's engine growing rather than three unrelated builds. Manamon 1
also drops 1.3's `find_by_reference` for the newer AngelScript add-on
spelling `findByRef`, which is the same substitution this fork keeps making
-- compare Psycho Strike's own `substring` giving way to stock `substr`. Its
`elias` binding is already present in 2017.

**Psycho Strike and Manamon 2 are the same custom engine, four years
apart.** Twenty of Psycho Strike's twenty-one additions over 1.3 are in
Manamon 2 as well; the twenty-first is its own `string substring(uint
offset, uint count)`, which Manamon 2 drops for AngelScript's stock
`string substr(uint start = 0, int count = -1)`. Both are VGStorm titles,
so this is one developer's BGT fork and not two.

What Manamon 2's fork adds, read off its own runtime:

- **Crypto++.** `ecdh` (`generate_keys`, `get_public_key`, `get_private_key`,
  `agree(decryption_key@)`), `encryption`/`decryption` with
  `process(string&in, string&out)` and `set_input_format(data_formats)`, and
  `Crypto++ RNG` as a literal in the file. That is the whole of what
  `engine_gap` had been reporting as four mysterious absent types.
- **A much newer AngelScript**, from its stock add-ons: `opImplCast`
  (2.28.1+), `findByRef(const T&in if_handle_then_const value)` (2.30+),
  `get_extended_exception_info(bool showStack=false)`, `formatInt`,
  `parseFloat`, `sortAsc`, `weakref`/`const_weakref`, `dictionaryValue`.
- **`void garbage_collect(int number_of_cycles=0)`**, with the parameter
  named. So a recovered `garbage_collect(int(1000))` is that build's
  signature used correctly, and dropping the argument to match stock 1.3
  would have changed the program.
- `string_regular_expression`, `create_pack_file_index`,
  `set_garbage_collector_panic_threshhold`, and the sized integer types.

#### `elias` is a binding compiled into the engine, not a plugin

BGT has no plugin mechanism -- its `#include` takes a script or a pack file,
and handed a DLL it says "Expected identifier". So the question is how
`elias` becomes a *type*, and the binaries answer it from three directions:

- The `elias` type and its methods are **registration strings inside the
  runtime**, in `strike.exe`, `rpg.exe` and `gate.exe` alike. A DLL cannot
  put them there.
- `elias.dll` is **not in any of those executables' import tables**, and each
  runtime carries its C export names verbatim -- so it is loaded at run time
  rather than at start-up. **The mechanism is DELAY-LOAD, not a hand-written
  `LoadLibrary`**, which this file used to say: `gate.exe`'s data directory 13
  names `elias.dll` with 20 delay-loaded symbols, an IAT at `0x004E2308` and
  its module handle slot at `0x004E33E0`. Both of the original observations
  were right -- absent from the import directory, loaded on first use -- and
  the mechanism between them was guessed.

  That matters because it is far more useful than a guess: the descriptor is a
  **complete symbol-to-slot map**, so every call site is one byte pattern
  away (`FF 15 <slot>`), with no disassembler needed to find them and no
  Ghidra run to pay for. Which is just as well, because importing this stub
  into Ghidra died on `OutOfMemoryError` at the heap the tooling defaults to,
  for the third time in this file.

  **And it explains why no name has a code reference.** A delay-load name is
  an `IMAGE_IMPORT_BY_NAME` read by the loader, so nothing in `.text` pushes
  its address -- which looked at first like the names being unused. The
  control that settled it was `_string_factory_`, whose address *is* found as
  an immediate: the search worked, and the absence was real and meant
  something else.
- The DLL exports **92 functions**, and the split is exactly two halves plus
  setup: **50 `elias_theme_*`, 40 `elias_track_*`, 2 `elias_set_*`**
  (`elias_set_memory_allocator`, `elias_set_float_to_int_converter`). Read out
  of the export directory of the copy that ships with The Gate, not guessed
  from a strings dump -- a name in the strings is as likely to be an import or
  a fragment, and the export table is the authority.

**The fork imports 19 of those 92, and the two builds four years apart import
exactly the same 19** -- no difference in either direction:

```
change_key  create_from_xml  destroy  enumerate_sources  get_basic_info
get_greatest_trigger  get_keys  get_source_count  is_transitioning
play_stinger  read_samples  request_change  set_level  silence  start  stop
set_prebuffer_length_in_milliseconds  set_processing_period_in_milliseconds
set_suggested_thread_count
```

all `elias_theme_*`, and **not one `elias_track_*`** -- which is the
track-authoring half, confirming from the import side what the data says from
the other: a theme arrives as XML, so nothing in the game builds one.

**This file said 23, and said the script side was "seventeen methods" and "15"
in two places. All three were wrong**, and the module is what settled it: a
`usedFunctions` entry records its owner, so the methods a module *calls* on
`elias` are countable without attributing a registration. The Gate calls
**twenty**, with these signatures --

```
bool   load(const string&in, const string&in)     void set_immediately(bool)
bool   start(int, int)                            void set_key(int)
bool   pause()      bool resume()                 void set_rendezvous(bool)
bool   set_level(int, int)                        void set_stinger(int)
bool   silence()    bool close()                  void set_urgency(int)
bool   get_playing()                              void set_volume(double)
bool   get_transitioning()                        double get_volume()
bool   get_immediately()                          int get_key()
int    get_greatest_level()                       int get_urgency()
```

-- which already exceeds both of the numbers this file carried, so neither
needed a second measurement to be refuted.

#### The C API, read out of the call sites

Elias Software's SDK header is not public -- it was licensee-only, and this is
a 2015 build -- so the authority is the game's own calls, which is this file's
first rule applied one layer out: read the caller.

cdecl puts every argument on the stack, so the pushes before a call give the
arity and the `add esp, N` after it corroborates. **Both are needed**, because
MSVC folds cleanups: `elias_set_memory_allocator` has no `add esp` of its own
and its 8 bytes turn up in the `add esp, 0x14` after the *next* call, which
cleans 8 + 12. Count pushes; use `add esp` as the check.

| signature, as `gate.exe` calls it | what the game passes |
|---|---|
| `elias_set_memory_allocator(alloc, free)` | its own two allocator functions, before anything else |
| `elias_theme_create_from_xml(&theme, xml, char *err, 1024, 0)` | the `.epro` text, and a 1,088-byte error buffer it zeroes first |
| `elias_theme_get_basic_info(theme, 0, 0, 0, 0, &a, &b)` | seven args, four of them NULL -- it wants only the last two |
| `elias_theme_get_source_count(theme, &count)` | |
| `elias_theme_enumerate_sources(theme, callback, user)` | **a callback**, and its own context |
| `elias_theme_destroy(theme)` | |
| `elias_theme_start(theme, cb, 0, x, level, max, y, z, flag)` | **nine**, and the second is a callback |
| `elias_theme_set_level(theme, a, b, c, d, key, flag)` | **seven** |
| `elias_theme_change_key(theme, a, b)` | three |
| `elias_theme_read_samples(ctx, buffer, &count)` | |
| `set_prebuffer_length_in_milliseconds(theme, 500)` | and `set_processing_period_in_milliseconds(theme, 250)` |

**Zero is success**, consistently: every call is followed by `test eax, eax`
and a jump that treats non-zero as the error path, and on failure the game
calls `elias_theme_destroy` and gives up.

##### Arity is not two just because a script method takes two arguments

The script method `elias::start(int, int)` takes two, and the C function takes
**nine** -- `add esp, 0x24` after the call, nine pushes before it. The same
mismatch runs through the family: `set_level` is seven and `change_key` is
three where the script shows two, one and one. Reading the script binding's
arity onto the C function is the mistake, and it is not a cosmetic one: a
harness that calls `elias_theme_start(theme, 1)` gets error **3** and spends a
while looking for the cause in the wrong place, which is exactly what happened
here.

MSVC's folded cleanups make this worse rather than better -- `change_key`'s
twelve bytes turn up inside the `add esp, 0x28` after `set_level`, so the
cleanup after a call is the total of that call and any earlier one that was
deferred. **Count the pushes.**

##### The source protocol, which is the whole of how audio gets in

`elias_theme_start`'s second argument is a function pointer, and that is where
the audio comes from. elias calls it with an opcode and the opaque handle the
resolve callback returned:

```
int source_callback(int op, void *handle, void *arg3, int arg4)
```

| op | what gate.exe does with it |
|---|---|
| 3 | prepare the source; fail the whole call if it returns false |
| **1** | **read `arg4` samples into `arg3`**, returning how many were really read |
| 2 | seek |
| 4 | finish, and release |

Two things that read straight off the instructions and would be guesses
otherwise. **The samples are 16-bit**: elias advances the shortfall pointer
with `lea edi, [edi + eax*2]`, two bytes per sample. And **elias zero-fills a
short read itself** (`rep stosd` / `rep stosw` over the remainder), so a host
that runs out of audio gets silence rather than stale buffer, and need not pad.

**So the handle is opaque to elias and means whatever the host decides.** That
is the part worth having: `gate.exe` returns a pointer to its own object whose
`+0x1c` holds a reader with a vtable, and elias never looks inside -- it only
hands the pointer back to the callback it was given. Any harness may define
its own handle, and the only contract is the four opcodes above.

##### Driven from outside the game, with no installs

Proven rather than argued, and it needs nothing fetched: 32-bit PowerShell
lives in `SysWOW64` on every 64-bit Windows and `csc.exe` ships with the .NET
Framework, so `csc -platform:x86` builds a 32-bit harness that can load a
32-bit DLL. Python cannot, on this machine, because the only Python here is
64-bit.

What that harness gets, against `The Gate`'s own `elias.dll`:

```
elias_set_memory_allocator(alloc, free)   -- host allocators, called 372 times
elias_theme_create_from_xml(...)          -> 0, a live theme handle
elias_theme_get_basic_info(...)           -> 44100, 2
elias_theme_get_source_count(...)         -> 91
elias_theme_enumerate_sources(...)        -> 0
elias_theme_destroy(theme)                -> 0, and 372 frees: no leak
```

**Three of those are cross-checks rather than outputs.** `44100, 2` is
`boss.epro`'s own `sample_rate` and `channels`; **91** is exactly the number of
`filename` attributes in that file, counted independently; and the allocator
being entered at all proves the two function pointers were taken as declared.

`enumerate_sources` returns **15** when the callback declines a source, and
stops at the first one -- so that is the host-refused code, worth knowing
before reading a 15 as something structural.

**The five unread arguments all tolerate zero**, which closed the last gap
cheaply. Args 1, 2, 5 and 6 are the theme, the callback and the script's level
and maximum; args 3, 4, 7, 8 and 9 come from fields of the game's wrapper
(`+0x34`, `+0x38`, `+0x40`, a byte at `+0x3c`), and chasing five setters
through the binary turned out to be unnecessary -- trying zero for each took
one build. What those fields *mean* is still unread, and the renderer says so
rather than implying they are understood.

#### Rendering a theme, which is the whole chain working

```bash
csc -platform:x86 -out:render.exe tools/elias/render.cs
python tools/elias/predecode.py boss          # Ogg stems -> raw 16-bit PCM
render.exe <game>/elias.dll boss.epro pcm/boss out.wav <level> [seconds]
```

Measured on The Gate's `boss` theme -- 91 sources, **0 missing**, which is the
closed-set claim above holding in practice rather than on paper:

| level | Bass | Strings | Brass | Perc | peak | centroid |
|---|---|---|---|---|---|---|
| 1 | 16 | 14 | 9 | 8 | 5,897 | 1,155 Hz |
| 3 | 16 | 14 | 9 | 12 | 6,851 | -- |
| 7 | 18 | 10 | 13 | 12 | 8,520 | 1,339 Hz |
| 12 | 18 | 16 | 13 | 15 | 8,603 | 1,666 Hz |
| 19 | 18 | 19 | 17 | 15 | 2,835 | -- |

**Exactly four stems play at any level, one per track**, all in key 0 -- which
is what a four-layer theme should do -- and the variation each track picks
rises with the level. The audio is real music by its spectrum: energy spread
23/60/17 across bass, mid and treble, and the **spectral centroid climbs with
intensity**, 1,155 -> 1,339 -> 1,666 Hz, which is what brighter layers
entering sounds like. A buffer echoed back would not do that, and neither
would silence.

Three honest gaps, recorded rather than smoothed over:

- **The trigger-to-level mapping is not understood, only shown to be
  monotone.** Level 1 picks track 1's trigger 16, which is not `<= 1` by any
  reading, so "trigger is the intensity threshold" is wrong as stated. What is
  established is that raising the level never lowers a track's chosen trigger,
  across four levels and four tracks.
- **Level 19 -- the greatest trigger -- renders mostly silence** (11% non-zero
  against ~95% at every lower level). Whether the level must be strictly below
  the maximum, or the render simply caught a transition, is not settled.
- **`op 2`'s arguments are unread.** It arrives with `arg3` and `arg4` both
  zero, immediately before each group of reads, so the renderer treats it as
  rewind and that is consistent with every observation -- but a seek that
  carries a position would look the same until a title needed one.

##### elias never opens a file, and that is the whole design

The surprise, and the thing that makes the 19-of-92 import list make sense:
**nothing in elias does I/O.** `enumerate_sources` takes a function pointer,
and elias calls back into the host once per source the theme names. The
callback reads the source descriptor's filename at `+0x14`, skips it when
`+0x20` is already set or the name is empty, and otherwise looks the name up
in the host's own array and hands over the audio.

So the `base_folder` half of `elias::load(xml_text, base_folder)` never
reaches elias at all -- it is the *binding's* own, used to resolve each
callback against the pack. That is why a theme's sounds can live inside
`sounds.dat` while elias has no idea packs exist, and why none of the 92
exports takes a path.

It also sets the price of driving the DLL from outside a game: a harness has
to implement that callback, which needs the layout of elias's source
descriptor rather than just a signature. Reading the two fields the game
touches is not the same as knowing the struct.

#### A registration block can be read by POSITION, and it UNDERCOUNTS

Worth its own note, because the mechanism bites any count taken this way.
AngelScript takes the owner type as a separate argument, so a declaration
string carries no owner and `registered()` cannot attribute one. What it does
carry is **position**: a type's registrations are emitted together, so the
declarations between the first and last known `elias` method are that type's
block. In `gate.exe` that block is contiguous from `0x0c8b6c` to `0x0c8d9c`
and holds **24** declarations -- the twenty above plus `request_change(int)`,
`play_stinger(int)`, `get_rendezvous()`, `get_stinger()` and `get_pan()`.

And `void set_volume(double)` is **not in it**, although the module proves it
is an elias method. It occurs **once in the whole file**, at `0x0c6444`, inside
another type's block: an identical declaration is **pooled**, so it is emitted
where it was first needed and every later type's registration points at that
one copy. `sound` declares `void set_volume(double)` too.

So a block read by position is a floor that undercounts by exactly the
signatures a type shares with another -- and `set_volume(double)`,
`get_volume()`, `set_pan(double)` and `get_playing()` are all shapes several
audio types have. The elias type has **at least 25** methods; the module's own
table is the authority on any particular one.

So it is a **BGT built to use that DLL**, which is the second of the two
possibilities and not the first. Manamon 2 has it too, so it came with the
fork rather than with Psycho Strike.

#### ...and a registration is not a USE, which is a mistake worth not making

This file says "Its `elias` binding is already present in 2017", about
Manamon 1, and that is a statement about the *engine*. Asked of the **module**,
the answer is the opposite and it is worth having explicitly:

| | |
|---|---|
| the runtime registers `elias` and its methods | **yes** -- 12 of them |
| the module uses the type | **no** -- absent from `used_types`, and `elias` occurs **0 times** in the module's bytes |
| `elias.dll` ships beside the game | **no** -- only the two screen-reader clients |

It could not use it either way: the DLL is `LoadLibrary`'d at run time, so a
game that ships without it has no elias at all. The three `stinger` hits in
that module are monster descriptions -- *"streaks of red and yellow circling
its stinger"*.

So VGStorm's fork is **one shared engine build** carrying everything its
author had accumulated, whether a given title touches it or not. Psycho Strike
and **The Gate** are the titles that use elias; Manamon 1 inherits the binding
and ignores it.
Answering a question about a module with a fact about the engine is the same
error as `string_compress` being registered and undocumented, pointing the
other way -- and this file has the general form of it already: **a name a
check wrongly holds is a gap it will never report.**

**What elias IS, which settles how far reverse engineering it could go.**
ELIAS is commercial adaptive-music middleware by Elias Software -- an
authoring tool that exports XML and a runtime that ships in the game, with the
hierarchy Project, Theme, Track, Level, Variation, Segment. So `elias.dll` is
a licensed third-party product rather than anything in this corpus's
authorship, and the job splits three ways: the *binding* is already read (the
23 `elias_theme_*` C names the fork imports and the 15 script methods it
registers, both out of any game's own runtime); the *theme data* a game ships
is that game's content and reading it is ordinary asset recovery; and the
*engine* is Elias Software's, so a port should load the DLL the game already
ships rather than transcribe it.

**Two of those three are now done rather than pending**, because The Gate
ships `elias.dll` and five themes. See the two sections above for the binding
and the section below for the data. What is left is the engine, and that is
the half a port should not write.

### The theme format: plain XML, inside the pack, with nothing to decode

`elias_theme_create_from_xml` says a theme arrives as XML, and The Gate's
pack is where it arrives. Of its **1,153 entries, 1,148 are SWCR-encrypted
and 5 are not** -- and those five are the themes:

```
sounds/music/elias/boss/boss.epro                       10,775 B
sounds/music/elias/carmilla_battle/carmilla_battle.epro  12,508 B
sounds/music/elias/final_battle/final_battle.epro         8,836 B
sounds/music/elias/horror_1/horror_1.epro                11,013 B
sounds/music/elias/horror_2/horror_2.epro                11,939 B
```

`.epro` is an Elias **pro**ject export, it is stored unencrypted beside the
audio it names, and it needs no reverse engineering at all: each one parses as
XML with `<theme>` as its root. The whole vocabulary, taken from all five
rather than from one -- 18 elements, every attribute:

| element | attributes |
|---|---|
| `theme` | `bars`, `channels`, `mode`, `sample_rate`, `tempo`, `time_signature`, `volume` |
| `defaults` | -- |
| `audio_loop_track`, `audio_stinger_track` | `id`, `name`, `volume` |
| `key` | `value`, `name` |
| `trigger`, `stinger` | `value`, `length`, `filename` |
| `fade_in`, `fade_out`, `crossfade` | `minimum`, `maximum` |
| `reverb` | `mix`, `damping`, `size` |
| `agility` | `value`, `strict` |
| `agility_points` / `beat` | -- / `point` |
| `pickup` | `beats` |
| `progression` | `mode` |
| `rendezvous` | -- |
| `fade` | `value` |

Read the hierarchy off that and it is the middleware's own, with the names the
data uses rather than the ones the marketing uses: **theme, track, key,
trigger**. A `key` is the musical key (`value="0" name="C"`), a `trigger`
value is the **intensity level** -- which is why the script method is
`set_level(int, int)` and the C export is `elias_theme_set_level` -- and every
`<defaults>` entry is overridden per track where the composer wanted it.

The audio is named relative to the theme's own folder and the convention is
mechanical: `audio/<track_id>_<key>_<trigger>.wav`. So `boss`'s Bass track in
C at level 7 is `sounds/music/elias/boss/audio/1_0_7.wav`.

| theme | loop tracks | stinger tracks | keys | triggers | tempo | time |
|---|---|---|---|---|---|---|
| boss | 4 | 5 | 18 | 59 | 90 | 4/4 |
| carmilla_battle | 4 | 5 | 18 | 81 | 90 | 6/8 |
| final_battle | 4 | 4 | 16 | 43 | 136 | 6/4 |
| horror_1 | 4 | 6 | 20 | 58 | 80 | 6/8 |
| horror_2 | 4 | 6 | 20 | 49 | 120 | 3/4 |

Four loop tracks every time -- `boss` names them Bass, Strings, Brass, Perc --
layered to build intensity, with stingers fired over the top.

**Every theme is a closed set, which is the check worth making**: of the files
each one names, **0 are missing from the pack**, and of the pack entries in
each theme's folder, **0 are unreferenced**. So the theme data recovers whole,
and a port has everything it needs from the game side.

#### ...and the engine's own validator agrees, which is the cross-check

The vocabulary above was derived from five shipped themes, and five samples
cannot say which attributes are *required* or which combinations are illegal.
`elias.dll` answers both, in 31 message-shaped strings that are its XML
validator talking:

| the validator says | so |
|---|---|
| `No theme element was found.` | `<theme>` is the root, as the data shows |
| `No <bars\|channels\|mode\|sample rate\|tempo\|time signature> attribute was specified for the theme.` | **all six are mandatory**; `volume` draws no such message, so it is optional |
| `There are no tracks in the theme.` | at least one track |
| `One or more tracks in the theme are missing their id attribute.` | `id` is mandatory per track |
| `Both a default agility element and a default agility_points element was specified.` | **`agility` and `agility_points` are mutually exclusive** |
| the same, for `rendezvous` | the `<rendezvous>` block has its own pair, under the same rule |
| `The default pickup element has a missing beats attribute.` | and `progression` likewise needs `mode` |
| `One or more of the beat elements ... is missing their point attribute.` | `<beat>` requires `point` |

The exclusion is the part the data could not have given: `horror_2` uses
`agility_points` with twelve `<beat point="...">` children while the other
four use a scalar `agility value="..."`, and nothing in five files says
whether a theme may carry both. The engine says no.

So the format is specified from two independent directions that agree -- the
themes a composer actually shipped, and the validator that accepted them --
which is the same shape as checking a reader against a tail that lands on EOF.

#### How the script drives it, read out of the recovery

`play_theme` is the load sequence, and it answers what the two strings of
`elias::load` are -- the XML **contents**, and the folder its filenames are
relative to:

```
theme.set_key(0);
<read sounds/music/elias/<theme>.epro -- from disk when run as a script,
 from the pack through pack_file::get_file when compiled>
theme.load(<that file's bytes>, "sounds/music/elias/" + <theme>);
theme.set_volume(music_volume);
theme.start(level, max_level);
```

So the binding resolves the theme's `filename` attributes against that second
string **through the pack**, which is what `elias_theme_enumerate_sources` and
`elias_theme_get_source_count` are imported for: the fork asks the theme what
sources it wants, reads each one itself, and hands over the samples. elias
never touches the file system, which is why none of its 92 exports opens a
file.

And the adaptive half is one function and a monitor:

```
void monitor_elias() {
    int level = default_elias_mode();
    if (level == last_level) return;
    last_level = level;
    set_theme_level(level, -1, false);
}
```

`default_elias_mode()` computes the level from the game state -- +50 for every
live enemy within 25 units of the player that is not a friendly, not type 12
and not invisible, +45 per weapon lying on the ground -- and `set_theme_level`
clamps the pair so the maximum is never below the current. That is the whole
of what the middleware is for, in a game: the music's intensity tracks how
much trouble the player is in, and the composer's layers and crossfades do the
rest.

#### What that is worth to the gap checks

`engine_gap` and `method_gap` corroborated an absence by searching the
game's raw bytes for the name. A registration is proof where a substring
match cannot be told from a coincidence, so both now ask the game's own
runtime and keep the raw search only as the fallback for a runtime whose
strings cannot be read.

It found a false negative immediately. **`string::insert` was hidden by
`array::insert_at`**: `insert` is a substring of `insert_at` and
`insert_last`, which BGT 1.3 registers, so Manamon 2's use of the newer
AngelScript `string::insert` went unreported while `string::erase` -- a
name nothing else contains -- was reported. Manamon 2's method gap is 3,
not 2. Nothing else moves on any of the four titles.

### What else the two binaries differ on

The compiler's diagnostic table is a per-version artifact -- a message
exists only if the code path that emits it does -- so diffing the two
installed engines' strings gives a **list** of what the language gained,
where `capabilities()` launches a compiler to ask about one item of it.
BGT 1.0 has none of `namespace`, `mixin`, `final`, `override`, `shared` or
`auto`, nor default arguments; 1.3 has all of them. `protected`, `weakref`
and `goto` are in neither, which independently confirms what the help file
said about Manamon 2 and about residual gotos.

**And `garbage_collect()` takes no argument** -- the registration string
says so, matching the help file. So a recovered Manamon 2 calling
`garbage_collect(int(1000))` is not a decompilation error but one more
newer-engine gap, alongside its `protected` and `weakref`.

## Which BGT compiled it, and an entry script that declares something

Two things that between them cost a user an afternoon, both because the
toolkit was quiet rather than wrong.

**BGT 1.0 has no default arguments at all.** A recovered module uses them
wherever the original did, so compiling a perfectly good project with 1.0
gives a cascade that reads exactly like a broken decompilation:
`Expected ')' or ','` at the `=`, then "Expected method or property",
then "Unexpected token '}'" at the end of the class. The same project
compiles cleanly under 1.3.

`bgt_compile.capabilities()` answers which install this is, and
`bgt recover --compile` reports **which** `bgt.exe` it used, saying so
plainly when that one cannot parse what the source contains. The missing
fact was never the diagnostics; it was whose.

### Asking the file instead of the compiler

This section used to say there is no version string in `bgt.exe` and no
version metadata on the file, so the installs could only be told apart by
putting something to them. Both halves were wrong, and the correction is
worth more than the fact: **BGT 1.0 carries the AngelScript library version
`2.20.2`** as a literal (1.3 carries none), and both carry a PE
`TimeDateStamp` -- 2010-12-30 for 1.0 and 2014-06-01 for 1.3. Neither of
those is the *capability*, though, which is why the better answer is a
different one.

The capability is in the file too, twice over:

- **The engine registers three of its own functions with a default
  argument** -- `string_create_from_pointer(uint, uint size=0)`,
  `tone_synth`'s `void f(float, float y = 0, float z = 0)`, and
  `dictionary::call`'s ten `?&in paramN=null`. A registration string goes
  through the same parser a script does, so this is **the feature in use**
  rather than a marker that might coincide with it. BGT 1.0 has none.
- **And the compiler carries the diagnostics for a bad one**: `Failed while
  compiling default arg for parameter %d in function '%s'` and two others.
  A message exists only if the code path that emits it does.

`_default_args_in_binary` requires both markers to agree, and on the two
installs here they do -- 1.3 both, 1.0 neither, matching what the probe had
already measured. Where they disagree it returns `None` and the probe
decides, because two markers pointing opposite ways is the case a reader
should decline rather than answer.

**Why bother, when the answer was already cached once per install:** the
probe launches the compiler, and a compiler that *rejects* the probe puts a
modal error dialog in front of whoever is at the machine. That is the 1.0
case -- the very one worth knowing about -- and `bgt verbs --repoint` pays
it again per candidate it considers.

**What the markers prove is not symmetric, and the code says so rather than
implying otherwise.** A registration using the feature proves support;
neither marker appearing is the absence of the implementation's own strings,
which is strong evidence and not a proof. So a negative is believed only
from a file whose interface is *legible* -- at least 50 registrations, where
1.0 has 240 and 1.3 has 432. Everything is absent from a file this cannot
read: a stub, or a packed `bgt.exe` whose strings sit inside the compressed
image, which is not hypothetical when BGT's own runtime ships exactly that
way inside `exec.bin`. Without that guard a packed engine would be reported,
confidently, as having no default arguments.

**A test must not write to the user's cache**, which this one had been doing
all along. `capabilities()` remembers its answer on disk, and the test that
pins "an inconclusive check is not an answer" hands it a throwaway 13-byte
`bgt.exe` -- so every run appended an entry to the real
`%TEMP%/bgt_capabilities.json`, thirty of them on this machine. Nothing was
ever read back wrongly, because a temp path never recurs; a test that used a
stable path would have poisoned the answer for a real install.

**And the compiler this toolkit picks is not the one a person reaches.**
BGT's installer registers five shell verbs for a `.bgt` file, and
installing 1.0 after 1.3 leaves three of them pointing at 1.0:

| verb | after installing 1.0 over 1.3 |
|---|---|
| `open` (double-click) | **BGT 1.0** |
| `run` ("Run Script") | **BGT 1.0** |
| `compile` ("Compile Script") | **BGT 1.0** |
| `compile_debug`, `compile_release` | BGT 1.3 |

So a project that reports `compiled cleanly` here gives a hundred
`Expected ')' or ','` on a double-click, which is how it was reported.
`bgt_compile.shell_verbs()` reads them out of the registry and
`verb_warnings()` names any whose engine cannot parse what was just written.

### Repointing them, which needs no administrator

Naming the fault is not fixing it, and "use Compile Script (Debug) instead"
is a workaround a person has to remember every time. `bgt verbs` shows what
the shell will run and `--repoint` changes it:

```bash
bgt verbs                      # what the shell runs for a .bgt file
bgt verbs --repoint            # point open/run/compile at a BGT that parses this
bgt verbs --restore            # remove the override again
```

Three things decide the shape of it, and each is what makes a change to
somebody's machine safe to offer at all:

- **It writes `HKEY_CURRENT_USER`, never `HKEY_LOCAL_MACHINE`.** The machine
  key needs an administrator and would change the association for every
  account on the box. The per-user key needs neither **and wins anyway**,
  because `HKEY_CLASSES_ROOT` is a merged view in which HKCU outranks HKLM.
- **The undo is structural, not a saved copy.** `--restore` deletes the
  override and HKLM's own value applies again *by construction*. There is no
  backup file to lose, and no way for a restore to write a path that was
  never registered.
- **Only the executable is substituted.** The rest of the command string is
  kept verbatim, because the switch is the whole difference between running a
  script and compiling it -- `open` passes it bare, `compile` passes
  `-c"%1"`, `compile_release` `-C"%1"`. Rebuilding the command from a table
  of switches would work right up until BGT's installer used a different one,
  and a `compile` verb that quietly started *running* the game instead would
  look exactly like a repoint that had worked.

It refuses rather than guesses when the target cannot parse a default
argument -- including when the probe was inconclusive -- since repointing a
verb at a *second* engine with the same gap reports success and fixes
nothing.

**And the check that was supposed to confirm this would have denied it.**
`shell_verbs()` read HKLM first and stopped on the first hit, which is the
wrong way round: the shell resolves a ProgID through the merged view, where
the per-user key wins. With an override in place the old order went on
reporting the *overridden* path -- so the fix would have worked while the
only thing able to see it said it had not. It reads `HKEY_CLASSES_ROOT` now,
which is what the docstring always claimed.

**Verified against the shell, not against the registry.** Reading your own
write back through your own function proves nothing about what Windows will
do with it. Two independent checks, in order of strength: `AssocQueryStringW`
-- the shell's own resolver -- reports the 1.3 path for `open`, `run`,
`compile` and for the *default* verb, which is the double-click; and a
`ShellExecuteW` of a probe script whose only unusual feature is a default
argument reaches `main()` and leaves its file behind, which BGT 1.0 could
never do, because it stops at the `=`.

Both installs were put to each failing shape rather than assumed:

| shape | BGT 1.3 | BGT 1.0 |
|---|---|---|
| `bool b = false` | accepts | `Expected ')' or ','` |
| `int b = -2` | accepts | `Expected ')' or ','` |
| `int b = )` | **accepts** | `Expected ')' or ','` |
| `double[] d(256);` | accepts | `Expected ';'` |

**`capabilities()` was answering from runs that never happened.** A check
that comes back `nodriver`, `timeout` or `crashed` carries no diagnostics,
and `not report.errors` read that as "this compiler is fine" -- so BGT 1.0
was reported as *supporting* default arguments, and the whole warning this
section exists for never fired. One busy lock is enough, because two checks
cannot run at once. An inconclusive outcome is now not an answer.

**And asking has a cost that lands on a person.** Probing launches the
compiler, and a compiler that rejects the probe shows a modal error dialog
on whoever is at the machine -- which happened repeatedly, once per run,
while chasing this. The answer is cached to disk keyed by the executable's
path, size and mtime, so it is asked once per install rather than once per
process. A diagnostic that interrupts the user every time is a cost, not
just a slow path.

**"The script section is empty" was not cosmetic.** BGT reports warnings
in a modal dialog and waits on it, so an unattended compile stops there;
and a warning nobody can explain invites the conclusion that an entry
script of nothing but `#include` lines is why a recovery does not run.
It is not — `#include` is textual, so the module is the concatenation, and
`main()` inside an included file runs, which was checked directly with a
two-file probe rather than argued. The entry script carries the module's
own declarations inline instead of only includes, and Super Egg Hunt went
from `compiled with 1 warning(s)` to `compiled cleanly, and ran`.

**It is worse than a stalled compile, and "not cosmetic" understated it:
BGT writes NO EXECUTABLE for a script section it calls empty.** Measured
directly -- an includes-only entry script compiles with that warning, the
driver dismisses the window, the engine exits 0, and either no file appears
or a truncated copy of the runtime stub does. 901,120 bytes of BGT with no
`xproc10` trailer and no script attached, which Windows then declines to
launch at all: "not a valid application for this OS platform". Driven by
hand with `-C` and no driver at all, BGT sits on its dialog with no
executable written and exits without writing one.

**And the fix was a proxy for the requirement, which failed.** Inlining
"the types section" is not the same as inlining *something that declares
something*: a module with no enums, typedefs or funcdefs still gets a
`types.bgt` section, holding the decompiler's comment banner and nothing
else. So the entry script stayed empty, `bgt recover --compile` reported
`compiled cleanly`, and the build was a stub. `inline_prefix` takes as many
sections from the front of the order as it needs before one declares
something -- a **prefix**, because the inlined text is emitted ahead of
every `#include`, so inlining anything else would move a declaration, and
`verify` compares sections against the one-file render and could not see
that happen.

**`bgt compile --build` now checks the artifact rather than the report.**
A clean report is not evidence that a file exists: the executable is
written only after the report window is answered. `_unbuilt` requires a
file that is newer than whatever was there before -- a stale executable
from an earlier good build is exactly what makes a failed build look like
a good one -- and that `bgtlib.read_trailer` accepts it. The outcome
`nobuild` carries its reason, because an outcome with no explanation reads
like a result.

## A literal has to reach the engine as the bytes the module held

This is the worst failure shape in the whole toolkit, because everything
reports success: the project recovers with 0 errors, compiles cleanly, opens
its own window with the right title, and has **no sound**.

The engine reads source as bytes, and a recovered literal is bytes. Every byte
above 0x7F used to be emitted as a *character* into a UTF-8 file, so `0xAC`
became `C2 AC` and the engine got two bytes where the module had one. For
ordinary text that is invisible; for Super Egg Hunt's pack key, which is a
32-byte AES blob in a literal, it is fatal and the engine says so exactly
once, in a pane next to the window title:

```
Error streaming logo.ogg.  Decryption failed because the key was incorrect.
```

Two cases, and the test between them is decoding rather than taste:

- **The bytes are valid UTF-8.** Then the characters they decode to encode
  back to exactly those bytes, so they are written as themselves — Crazy
  Party's `caractère` stays `caractère` *and* stays correct. Correctness here
  is by construction, not by luck: the round trip is the criterion.
- **They are not.** Then no character spelling can be trusted and every byte
  from 0x7F up is written `\xNN`.

**BGT was asked rather than assumed**, the way everything else here is:
`"\xac\x71\x96"` compiles with no warning and produces those three bytes,
raw bytes in a byte-preserving file do too, and the octal form `"\254"` is
`Warning: Invalid escape sequence`. The probe wrote all three spellings to a
file through `file::write` and the bytes were read back.

`test_regressions.LiteralRenderingTests` renders **all 256 byte values**,
passes the result through UTF-8, and parses it back with an unescaper written
from the lexer's rules rather than as `_esc`'s inverse — an inverse built from
the same table would agree with a wrong table.

Afterwards, `bgt compile --run` on the recovered project reports `compiled
cleanly, and ran: it opened a window of its own titled 'Super Egg Hunt Version
1.53'` with **no runtime complaint at all**.

**What found it was the engine talking, so that is now read.** The driver had
the line in `raw` the whole time; `Report.runtime_complaints` pulls what the
engine said at run time out of what it said about the source, and the summary
carries it. A clean compile says nothing about whether the project has the
files it opens, and this is the one check that costs nothing.

## A staged copy does not sit where its includes point

`bgt compile` stages the script into `_compile_check/` so the executable the
compiler writes lands there instead of in the project. BGT resolves an include
against the *including script's* directory, so the copy looked for
`includes/classes/player.bgt` beside itself and reported, truthfully, that
there is no such file — one error, blaming the first file it could not find.

Only `bgt recover --compile` knew that, with a `'#include "includes/'` →
`'../includes/'` string replace of its own. So `bgt compile` on the project
`bgt recover` had just written — the obvious next command — failed, which
reads as a broken recovery. One `bgt_compile.stage` now disarms `main` and
repoints every relative include with `relpath`, and the CLI, the GUI and
`bgt recover` all go through it. The GUI had the opposite half of the same
bug: it compiled in place, so the engine's output landed in the folder being
read.

## A window, for people who read screens with a screen reader

`bgt gui` is a wxPython front end over `identify`, `recover` and `compile`.
It calls the same functions the CLI does with the same defaults, so the
command line stays the reference and anything the window reports can be
rechecked in one command.

These are audio games, and that decides the design rather than decorating it:

- **Stock controls, and a label on every one.** The label goes on twice —
  as the `StaticText` beside the field and as the control's accessible name —
  because which one a screen reader picks up varies, and a field announced
  as "edit" is a field nobody can fill in. `tests/test_gui.py` asserts it,
  with the generic names taken **from wx itself**: `CheckBox` defaults to
  `check`, not `checkbox`, and a plausible-looking list would have let the
  real case through.
- **The log is a read-only multiline text box**, because that is the one
  widget a screen reader can review line by line afterwards. Progress is
  appended, so nothing already said is overwritten.
- **Finishing raises a dialog.** A screen reader announces a dialog without
  being asked and does not announce a label that quietly changed, so the end
  of a job arrives as a message box while the detail stays in the log.
- **Work runs on a thread**, every widget touch through `wx.CallAfter`.
  Recovering Crazy Party takes minutes, and a frozen window cannot even say
  it is still working.
- **There is no Stop button.** `recover` has no cancellation point, and a
  button that cannot stop what it claims to invites you to believe a
  half-written output folder is consistent. The controls disable instead,
  and closing mid-job asks first.
- **A "Check it runs" button**, because that is the question the other three
  do not answer. It drives the recovered project through `bgt drive` -- no
  sound, no window -- and reports whether the engine answered the key it was
  given, which means every global initialised and the module loaded. A
  recovery that compiles can still fail to start, and this file records
  several that did.

## The stock library files come from BGT, not from the module

A shipped `include/*.bgt` is not what anyone is trying to recover. It
comes with the engine, and its real source has the parameter names and
the comments, which compilation threw away:

```
decompiled:  int play_stationary(string arg0, bool arg1, bool arg2 = false)
BGT's own:   int play_stationary(string filename, bool looping, bool persistent=false)
```

So a run attributed to a shipped file is replaced by that file, and the
decompiled sections for it are dropped. **Games edit this library
constantly**, though, and substituting over an edit silently undoes it,
so each of the following has to pass. Every one of them is here because a
title broke when the check was weaker:

- **It must declare no types of its own.** `form.bgt` declares four
  enums, and `types.bgt` already carries every enum in the module, so
  taking the stock file too is four "Name conflict" errors. Psycho
  Strike, 33 errors to 37.
- **Every member must exist in the stock file.** Super Egg Hunt's
  `dynamic_menu` has `is_main`, and its `dynamic_menu_item` an
  `item_id`, which stock BGT has never heard of. The first version of
  this compared class *names*, which matched, and the game's own code
  then failed against the engine's class.
- **Every signature must match, parameter types and all.** Paladin's
  `dynamic_menu::set_tts_object` takes its own `voice_manager@` where
  stock takes `tts_voice@`, and Super Egg Hunt's `sound_pool::update`
  takes three ints where stock takes two. The names match in both cases,
  which is exactly why names were not enough: Paladin went from 0 errors
  to 2, at the call site rather than the definition.

- **Every body must match too.** This was the one check that *reported*
  rather than blocked, on the argument that a body difference is either
  the game's edit or this decompiler's own rendering and the comparison
  cannot tell them apart. That is true and it is not the point, because
  **the costs are not symmetric**: keeping the decompiled copy loses
  parameter names and comments in a file nobody was trying to recover,
  while substituting over a real edit replaces the game's code with the
  engine's and says nothing.

  Paladin's `sound_pool` — the audio engine — matches on every member and
  every signature and differs in four bodies, so it was being replaced
  wholesale. `sound_positioning.bgt` still substitutes on all three
  titles because it genuinely matches, which is the readability this was
  for; `sound_pool` no longer does.

  **This was adopted on the argument, not on a measured fix, and that
  distinction was briefly lost.** It was first claimed as the cause of a
  recovered Paladin playing no audio and looping through its TTS voice
  selector, on the evidence that `--no-stock-includes` changed the window
  title from `command` to `Paladin of the sky`. A window title is not
  causation, the symptom survived the change, and the real explanation was
  elsewhere (see **Run as a script, a game takes its developer path**).
  The rule stands on the cost asymmetry alone; it fixed nothing known.

`bgt libcheck --decompiler` is what says which differing bodies are the
game's edits and which are this decompiler's rendering, and
`--no-stock-includes` keeps everything decompiled.

A note on reading that report: Super Egg Hunt's `number_speaker.bgt`
differed on `speak_next` before the fold fixes below and matches now. A
"differs" line is a statement about the decompiler as much as about the
game, so it moves as the decompiler improves.

`#include` and `funcdef` lines are stripped from the copied file: the
entry script lists every file in order, and `types.bgt` already declares
the funcdefs, so leaving either in is a duplicate declaration.

**A file written is not a file registered, and the ZIP is where that
showed.** `substitute_stock` writes the engine's copy itself, while
`project.files` was appended to as each *decompiled* group was written — so
every substituted file was missing from the file list, from the count, and
from `game_project.zip`. Unzipping Super Egg Hunt gave an entry script that
included `number_speaker.bgt` and `sound_positioning.bgt` and two files that
were not there, which from outside is indistinguishable from "it does not
copy the stock includes" and is how it was reported. The list is built from
the include order and from what is actually on disk now, so the three claims
cannot drift apart.

`recovery.json` also listed `includes/types.bgt` as included when the entry
script had inlined it. A file list nothing reads is still a claim about the
project: `includes` is what the entry script really includes, `inlined` is
the one section it carries instead, `order` is the concatenation the split
check uses, and the inlined section is no longer also written as a file
nothing includes.

## The assets, which the script will go looking for

A recovered script still calls `set_sound_storage("data.dat")`, and if the
pack is not where it looks the engine does not politely do without sound —
it can die at startup. So `bgt recover` always reports what the project
needs, and can bring it:

```bash
bgt recover game.exe -o out/                  # copies the packs: the default
bgt recover game.exe -o out/ --extract-data   # ...and unpack their entries too
bgt recover game.exe -o out/ --no-data        # bring nothing, and cannot play audio
```

**Copying is the default, and the two are not alternatives.** Both of those
were wrong and both were reported from real runs. A project whose script calls
`set_sound_storage("data/bgm.dat")` with no pack beside it reports

```
ERROR!  dialog  could not load pack data/bgm.dat.
```

and plays nothing, so opt-in was the wrong default for the one thing that
makes a recovery runnable. And copying and extracting answer different
questions — "can this run?" and "what is in the pack?" — so forcing a choice
meant the obvious way to get the assets out also produced a silent game.

Finding the packs takes two pieces of evidence, because neither alone is
enough. The *names* come from the module's string constants, since the calls
pass locals (`set_sound_storage(local_8)`) and the literal never reaches the
call site. The *filter* is the `SFPv` magic of a file sitting beside the
executable, which is what separates `data.dat` from the `log.txt`,
`save.bin`, `.` and `/` that are also in those constants.

**Finding nothing is the case that matters.** Recovering from a copy of the
executable — the normal thing to do — finds no pack beside it, and silence
there is the whole problem. So the module's own calls are the fallback
evidence: `set_sound_storage` means it opens a pack at all, and
`set_sound_decryption_key` means the entries are encrypted and the key is a
separate hunt (`bgt crack`). Either way the report says so.

Three things this turned up:

- **A pack may have a footer, and refusing it was stricter than the engine.**
  `pack::create` writes the entry count in the header and `pack_file` reads
  exactly that many, so bytes after the last entry are never read. Crazy
  Party's `data.dat` carries 32 of them after 2,425 entries whose record
  magic every one validated, and the old "must land exactly on EOF" rule
  meant the one pack this toolkit could not open was one the game opens
  without complaint. The per-entry magic is the real self-check; trailing
  bytes are counted and reported now.
- **`tag_index` without payloads answers "no keys", which is wrong.** The
  `SWCR` tag lives in the payload, so asking after `parse(load_data=False)`
  reports every pack as unencrypted — and a 372 MB pack cannot be loaded
  just to ask. `bgt_pack.survey` reads each entry's 20-byte header at its
  known offset instead, which is cheap and cannot give that answer.
- **...and `key_matches` had the same silent zero, which is worse.** It reads
  `e.encrypted` and `e.tag`, both of which need the payload, so handed
  unloaded entries it reports that a key opens **0 of 1,153** -- and a correct
  key reported that way is indistinguishable from a wrong one. The Gate's key
  looked like that for several minutes, having *already* been verified against
  the tag `survey` read out of the headers: two of this toolkit's own
  self-verifying layers disagreeing, with the wrong one sounding confident.
  Both functions refuse now, through one `_require_payloads` guard that names
  the three ways to ask properly, and only when **no** entry was loaded -- a
  pack that genuinely holds nothing encrypted still answers.
- **A string constant is data, and two guards follow from that.** A name must
  not reach outside the game's folder, and an entry name must not write
  outside the extraction folder. `os.path.commonpath` raises `ValueError`
  across drives rather than returning a verdict, and Crazy Party's constants
  hit exactly that, so the exception is the answer — different drive,
  therefore outside — rather than a crash out of `bgt recover`.
- **Packs need not sit beside the executable.** Super Egg Hunt keeps seven in
  a `data/` subdirectory and names them `data/bgm.dat`, so the name from the
  string constants is joined to the game's folder rather than looked for in
  it. Both guards above are what make joining a module's string to a path
  safe.

### Extracting means decrypting, and the key is in the module

`--extract-data` used to answer *"holds 16 encrypted entries and needs its
key: bgt crack …"* for every pack and write nothing. That reads like advice
and is really a gap: the key is whatever the script passed to
`set_sound_decryption_key`, and the script is in the file being recovered.
`pack_keys` searches for it, and extraction decrypts with what it finds —
Super Egg Hunt's seven packs, **344 of 344 entries, every one valid Ogg
Vorbis, from one key**.

An entry whose key does not verify is **skipped and counted**, never written.
A file of ciphertext named `music.ogg` is worse than no file, because it looks
like the extraction worked.

**The harvest could not have found that key, and the reason is a quiet one.**
`module_strings` accepts a literal only if every byte is printable ASCII, NUL
or whitespace — which is right for a blind scan and discards exactly the
literal a game stores a key in. BGT's idiom is

```
set_sound_decryption_key(string_decrypt(h_key, "af-dc7=rqp+"), true);
```

where `h_key` is a 32-byte AES-CBC blob. So `bgt crack` reported *3,392
candidates, 0 hits* while both halves of the password sat in the module, and a
negative result over a candidate set that **cannot contain the answer** is the
most convincing kind of wrong.

Two things fix it, and both are narrow:

- `as_module.literal_is_cipher_shaped` — a whole number of 16-byte blocks, at
  least one, mostly bytes that are not text. `module_strings` takes an
  `accept` predicate so the blind scan's own filter is unchanged.
- `bgt_crack.harvest_encrypted` — every blob decrypted under every text
  literal. The cross product is affordable **because `string_decrypt` is
  self-checking**: BGT wraps a plaintext as `printf<len>\0<data>`, so a wrong
  pairing is rejected by the format and never reaches the pack. On Super Egg
  Hunt it yields exactly **one** candidate, `puppiesandpandas`, which opens
  every entry.

A pack key is confirmed by one AES block against the tag each entry stores, so
none of this is guesswork: `tag == AES-ECB(key, 16 zero bytes)` cannot be
satisfied by a wrong key. `bgt_pack.survey` returns the tags themselves now,
not only how many, because that is all a search needs.

### A key that is a DIGEST, and the caller read mechanically

The harvesters above reach a password that is *stored* -- as a literal, as a
run of literals, or as a blob plus the literal that decrypts it. **Manamon 1's
is none of those: it is a hash.**

```
set_sound_decryption_key(get("\x00\x00able to\x00\x00learn\x00...irgjeoijeiorjgiojriorjegiore\x00\x00"), false);

string get(string arg0) {
    s = string_base64_decode(arg0);
    for (i = 0; i < 218; i++) {
        s = string_hash(s, 2, true);
        if (i > 100 && i % 84 == 0) s = string_reverse(s);
        ...keep the iteration whose 64 bytes hold the most NUL bytes...
    }
}
```

So no literal in that module is the password and no composition of literals
can be, which is why `bgt recover --extract-data` answered *"holds 1,829
encrypted entries and its key was not recovered"* on a title whose key was
fully determined by the file in front of it. The same negative result this
file records for Super Egg Hunt, one level deeper -- and the same lesson:
**a search over candidates that cannot contain the answer is the most
convincing kind of wrong.**

Two harvesters close it, and neither is a sweep.

**`callsite` reads the caller**, which is what this file has advised doing by
hand since the section above was written. The argument list at each
`set_sound_decryption_key` is bracket-matched out of the recovered text, its
literals are taken, and every script function it names contributes the
literals in its body. Literals come back through `bgt_audit.unescape`, written
from the engine's lexer rules, because a seed holds NUL bytes and the text
spells those `\xNN`. On Manamon 1 that is **2 seeds** where the module has
82,169 literals.

**`hashchain` walks the chain and offers every step.** The point is what it
does *not* do: the game's selection rule -- most NUL bytes, of 218 iterations,
with a reversal at every 84th past 100 -- is not modelled at all. Whichever
digest the game keeps is somewhere in the chain, and checking one costs
**one AES block** against the tag the pack stores, so the cheap thing is to
offer them all and let the pack say which. Manamon 1's is iteration 111, and
`bgt_kdf.aes_key` of it satisfies `285d062b...` exactly.

Four chains per seed, because that is the engine's whole hashing surface:
`string_hash(data, algorithm, binary)`, and the help file lists exactly two
algorithms -- **1 SHA256, 2 SHA512** -- each with a binary or a hex result,
and a chain over the hex form is a different chain. Each step offers the
digest, what the chain carries forward, and both reversed, since
`string_reverse` is in the same family. 2 seeds, 12,289 candidates, under
three seconds.

#### A reversal FORKS the chain, so the chain forks -- and a title needed it

This said the harvester would not reach a reversal falling *before* the
iteration the game keeps, because that forks the chain, and that such a title
was the case for reading the function by hand. **The Gate is that title**, and
reading the function by hand is what found it -- after which the fix was
cheaper than the next read would have been.

Its `get` is Manamon 1's, line for line, with one character different: the
test is `>=`, so the **last** iteration holding the maximal NUL count wins
where Manamon's `>` keeps the first.

| | Manamon 1 | The Gate |
|---|---|---|
| reversal at iteration | 168 | 168 |
| iteration the game keeps | **111** | **175** |
| on the plain line? | yes | **no -- seven hashes past the fork** |

So the values wanted are not only `H^n(seed)` but `H^m(reverse(H^n(seed)))`,
and the reversed value was already being *offered* at every step while nothing
ever continued from it. `harvest_hashchain` now walks a forked line from each
step's reversed value, and `CHAIN_FORK_DEPTH` is its own smaller number
because a kept iteration sits a few hashes past the reversal that produced it,
never hundreds.

**Measured in both directions, which is what says the change is the cause:**

| | candidates | The Gate's key |
|---|---|---|
| `fork_depth=0` -- the old behaviour | 12,282 | **not found** |
| as it now stands | 3,158,010 | **found**, in 81 s of testing |

and the password it returns is the one a direct simulation of the recovered
`get` returns, byte for byte, with the AES key then opening **1,148 of 1,148**
encrypted entries -- every one valid Ogg Vorbis, in a pack whose entries are
all named `.wav`.

**One level of forking, deliberately.** Two titles reverse once in 218 rounds,
so a second level would square the cost to buy a shape nothing has shown. The
selection rule is still not modelled, which remains the point: whichever
iteration the game keeps is somewhere in what the harvester yields, and one
AES block against the pack's tag says which.

The cost is real and worth stating: the chain is 43x the candidates it was, so
a `bgt recover` that has to reach this shape spends a minute or so where it
used to spend seconds. A pack that opens is worth a minute.

**And the chain is never seeded from the whole module.** 82,169 literals times
four chains times 512 steps is 168 million candidates spent to avoid reading
one function, so without the recovered text both harvesters yield nothing and
say so in the counts. The seeds come from the call site or they do not come.

### A path the script BUILDS is in no string constant

`data_packs` finds what the script opens, by name, and a name is as far as
that can go. **Manamon 1 reads its trade data from `data/tamerdata.dat`, and
the module holds `"tamerdata.dat"` and `"data/"` as two separate literals.**
The path it opens is never a string in the file, so no search for one can
find it, and `bgt recover` brought the 314 MB pack and left a 4.4 MB file
behind -- a recovered game that loads, speaks, and has no tamers in it.

So the question is not what the module names. It is **what the game shipped**,
and the game's own folder is the only record of that. `game_files` brings
everything beside the executable, minus four kinds, and each exclusion is
reported rather than applied quietly:

| not brought | why |
|---|---|
| the executable | it is the input |
| `unins000.exe`, `unins000.dat` | the installer's bookkeeping, not game data |
| anything already brought | the packs, the plugin and screen-reader DLLs -- so a 314 MB pack is not copied twice and `--no-data` is not undone by the back door |
| any other `.exe` or `.msi` | a program is not data, and a recovered project holding somebody else's executable invites running the wrong thing. **Named in the notes**, never dropped silently |

The output folder is skipped when it sits inside the game folder, which is an
ordinary thing to ask for and would otherwise copy the project into itself.
`--no-game-files` turns the whole thing off.

It is `bgt recover`'s default, for the reason the pack copy is: the engine
opens `data/tamerdata.dat` by that relative path, so the file has to be at
that relative path beside the script, and nothing in any report would ever
have said otherwise.

#### A containment guard that failed CLOSED, and reported success

Found while measuring the above, and it is the worst shape in this file:
**the check said no and the run said it had finished.**

`_inside` decides where a pack entry and a game file may be written -- a
string constant out of a module can name anything, so this is the guard that
keeps an extraction inside its own folder. It compared `commonpath`'s answer
against the caller's own string, and `commonpath` normalises both the
separator and the case. So

```bash
bgt recover game.exe -o C:/somewhere --extract-data
```

-- a path with forward slashes, which is how half the world writes one on
Windows -- put **every entry of every pack outside the directory it was about
to be written to.** Super Egg Hunt reported `puppiesandpandas` recovered,
seven packs copied, and `extracted 0 entries` seven times, with no error and
exit 0. Case is the same trap one step on: `c:\users` against `C:\Users`.

Both sides are normalised now, and the fix is worth the four lines twice
over, because the symptom is indistinguishable from a key that was not found:
**344 of 344** of that title's entries extract again, every one valid Ogg
Vorbis, which is the figure this file already recorded and had no way to
notice losing.

#### An entry can be plaintext in the pack and still be encrypted

Manamon 1 extracts 2,007 of 2,007 entries, and only **1,829** of them are
audio. The other 178 are every one of its `data/rooms/*.dat` map files, each a
multiple of 16 bytes and none with a recognisable header -- because the pack
stored them *unencrypted* and the **game** encrypts their contents itself with
`string_encrypt`, reading them back through `string_decrypt`.

So there are two encryption layers and they are independent: `SWCR` per pack
entry, with the key `set_sound_decryption_key` installs, and `string_encrypt`
per *file*, with a key the script passes at each call site. An extraction that
honours the first can still write 178 opaque blobs, and both the pack and the
extraction are right about every byte.

The second key is recoverable the same way the first is, and more cheaply:
`string_decrypt` is self-checking -- BGT wraps a plaintext as
`printf<len>\0<data>` -- so a candidate is confirmed or rejected outright with
nothing to recognise by eye. Manamon 1's is one of the NUL-joined runs its own
source passes to `string_decrypt`, which the `runs` harvester already yields,
and it opens **178 of 178**. What comes out is base64-keyed dictionary text --
`MjlfMjM=` is `29_23`, a tile coordinate -- which is the same serialisation
shape as that title's `tamerdata.dat`.

Recorded, not done: writing the decrypted form as well as the stored bytes is
a second extraction layer with its own choices -- what to name it, and the
fact that the stored bytes are what the game reads and must not be replaced.

#### ...and the folder it reads into must not nest inside its own name

A pack extracts to `assets/<the pack's own stem>`, which keeps Super Egg
Hunt's seven apart. The Gate's pack is `sounds.dat` and **its entries are
already named `sounds/music/...`**, so joining the two gave
`assets/sounds/sounds/music/elias/boss/audio/1_0_7.wav`.

Nothing breaks -- the engine reads the pack, not the extraction, so the
project still runs -- and it is nobody's layout, in the half of the output
that exists for a person to read.

The prefix is dropped only when **every** entry carries it, and that
condition is the whole of the correctness argument: removing one common
prefix from every name cannot make two names collide, while removing it from
some of them can. A pack holding both `data/a.ogg` and `a.ogg` keeps the
names the pack wrote, doubled folder and all, because the alternative is two
entries at one path and one of them silently overwriting the other.

Super Egg Hunt and Manamon 1 are unaffected, which is checked rather than
assumed: neither names its entries after its pack, and both re-extract to
exactly the figures recorded above.

#### Extraction reads one entry at a time

`parse(load_data=True)` keeps every payload in memory at once, which is the
whole pack -- 314 MB for Manamon 1, more for Crazy Party -- so extracting one
meant holding all of it to write it out piece by piece. An entry records its
own offset, so `Entry.load(handle)` reads them one at a time and the memory is
bounded by the largest single sound. A short read raises rather than returning
what was there, because half a sound written to disk is a file that looks
extracted.

**Extracted assets are not what the script opens.** It still calls
`set_sound_storage("data/bgm.dat")`, so `--extract-data` gives a project that
compiles, runs, and says `could not load pack data/bgm.dat.` — which the
report says first -- though it no longer arises on its own, because
copying is the default and `--extract-data` now adds to it rather than
replacing it.

## Compiling without the GUI

`bgt.exe` has no documented switches, and the installer's own shell verbs are
where they are written down:

```
HKLM\SOFTWARE\Classes\bgtscript\shell\compile_debug   bgt.exe -c"%1"
HKLM\SOFTWARE\Classes\bgtscript\shell\compile_release  bgt.exe -C"%1"
```

**No space before the path.** With a switch the engine compiles to an
executable beside the script; without one it *runs* the script. `bgt compile`
uses `-c` by default, which is a stronger check than running: nothing of the
program executes, so a game cannot open a window and sit there, and the whole
module still has to satisfy the compiler.

Two things about that to keep in mind:

- **The report dialog blocks it.** The engine shows one modal window for
  warnings as well as errors and waits on it before writing the executable.
  The driver dismisses it, which is why `_drop_unreachable` exists: a warning
  nobody can answer is a compile that never finishes.
- **`--run` has to look *past* that dialog.** It used to report the first
  window with a title, which with any warning at all is the report -- so a
  title that compiled with warnings and then ran was indistinguishable from
  one that only compiled. Run mode now dismisses a `Compilation*` window and
  keeps waiting, and reports the script's own window title when it appears.
  That is what `bgt compile --run` answers: `compiled with 1 warning(s), and
  ran: it opened a window of its own titled 'Super Egg Hunt Version 1.53'`.
- **`--build` built nothing at all, and said it had.** This section used to
  report that building a module this size hangs, with a small script building
  fine "so the mechanism works". Both halves were wrong, and from the same
  cause: **a PowerShell parameter named `$Switch` silently breaks every
  `switch` statement in that script.** The driver chose its mode with

  ```powershell
  param(..., [string]$Switch = "run")
  $flag = switch ($Switch) { "debug" { "-c" } "release" { "-C" } default { "" } }
  ```

  and that statement matched nothing, so `$flag` was always empty, no switch
  reached the engine, and BGT **ran** the script instead of compiling it. A
  disarmed entry point exiting 0 is exactly the compile-only success case, so
  the report read `compiled cleanly` while no executable existed -- in either
  mode, for as long as the option existed. Run mode passes no flag at all, so
  it was correct by accident and hid the whole thing, and the "hang" was run
  mode sitting in a game that had opened a window.

  Renaming it to `-Mode` is the entire fix. `bgt compile --build release`
  now builds Paladin's 28,028-line recovery to a 1.27 MB executable that
  `bgt identify` reads as `BGT (overlay 0xDDC00, key seed 0x11)` -- the same
  overlay offset and seed as the original -- and a two-line script builds in
  both modes. There is no module-size limit here; there was a parameter name.

  The lesson is the one this file keeps relearning from the other direction:
  the earlier note was not a guess, it was a *measurement* of a run that
  never happened. `tests/test_recovery.py` now asserts the driver declares no
  `$Switch`, that its mode really is chosen by a `switch`, and that the name
  Python passes is the name the driver declares.

Each of these was found by the compiler, and the quiet bugs *behind* them were
found by reading what it said rather than by inspection:

- **The global-pointer pre-shift touched the value field too.** The older
  dialect has no table-selector bit, so a global pointer is pre-shifted to
  `2n + 1` — but `SetG4` carries the value being stored in the other operand,
  and shifting that rewrote every constant assigned to a global. `const int
  male = 1` came out as 3, which is a plausible constant and not a plausible
  bug.
- **A derived class re-declared its base's properties.** A derived class's
  property table opens with its base's, in the base's order, and this
  generation records no flag to say so. Re-declared, every one is a name
  conflict: 1,700 of the first 1,827 errors. They are marked with the bit the
  newer format uses rather than dropped — the entries are still needed to
  resolve a member access by name — and only when the table really does open
  with the base's, because marking by position would hide a real property.
- **`STR`'s string index is a word operand here and a dword one there.** Left
  in the word field it resolves to whichever literal sits at index 0: a real
  string, in every body that has one.
- **A folded short-circuit outlived its slot.** `(A && B)` is bound to its
  slot so later reads see the whole value; left there after the slot was
  assigned again, every later read came back as that stale expression — 104 of
  the errors were one `clear_pathway` temporary read six times.
- **A constructor's generated member initialisation is not source.** A member
  declared by value but held by reference is created by code the compiler puts
  at the top of every constructor. `_refcpy` already dropped the store for
  exactly that reason; what was left behind was the creation, `@local_3 =
  weapon@[]();`, which is not expressible at all. The whole eight-instruction
  idiom is skipped now, and it is identified by the member being declared *by
  value* — the same shape with a handle member is a real assignment.

  **And there is exactly one member in the corpus where that is wrong.**
  Manamon 1's `piano::piano_pool` is declared by value and constructed
  with an argument:

  ```
  PshC4 500 ; CALL <global>::sound_pool ; STOREOBJ 3
  PshVPtr 3 ; PshVPtr 0 ; ADDSi piano::piano_pool ; REFCPY ; FREE 3
  ```

  The constructor recovered as `filepath = string(); this.reset();`, so
  **the 500 survived nowhere** and the member was left to the default
  construction the compiler generates. The lost-call mechanism cannot
  help: putting `sound_pool(500);` back as a statement hands the pool to
  nobody, and assigning it would copy a different object into the member
  rather than store the one the original stored.

  **Fixed, by putting the number where the array length already goes.**
  `_member_array_sizes` is the hook -- the sized-array factory's length
  survives only on the declaration for exactly the same reason -- and it
  takes a second shape now: a call feeding `STOREOBJ ; PshVPtr ; PshVPtr
  ; ADDSi ; REFCPY` into a member that is declared BY VALUE, whose callee
  is that member's own type, with a constant argument. The declaration
  comes out `sound_pool piano_pool(500);`.

  **And "a constant argument" was too narrow, which a sixth title showed.**
  The rule took exactly ONE parameter and exactly one `PshC4` before the
  call, because the one member in the five-title corpus that needed it was
  `sound_pool piano_pool(500)`. Field Wars' `text_input` has four members of
  a class whose constructor takes **three**:

  ```
  PshC4 40 ; PshC4 500 ; PshG4 KEY_BACK ; CALL key_hold
  STOREOBJ 6 ; PshVPtr 6 ; PshVPtr 0 ; ADDSi text_input::back ; REFCPY
  ```

  Skipped, the declaration stood alone as `key_hold back;` -- and a class
  whose only constructor takes arguments has no default one, so that is
  **"No default constructor for object of type 'key_hold'"** once per member
  and a class that cannot compile at all. Reported from a user's own run.

  `_written_arguments` reads **any** number of them, walking backwards from
  the call because arguments are pushed last to first -- the call-frame rule
  this file derives from the bytecode -- so `KEY_BACK, 500, 40` comes out in
  source order. Two kinds qualify and nothing else: a literal, and a **named
  global**. The global is the half worth having, because rendering
  `PshG4 KEY_BACK` as its *value* would compile and read as a magic number,
  and the constant is what the author wrote.

  Put to the compiler before being emitted, as the one-argument form was: a
  member declaration carrying three arguments, one a `const` and one an
  engine key constant, `compiled cleanly`.

  **The scope is one class in one title, measured across the corpus**: Super
  Egg Hunt 0, The Gate 0, Manamon 1 one single-argument member and no
  multi-argument one -- which is `piano_pool` still recovered exactly as
  before. Field Wars recovers to 9,048 lines, 0 residual gotos, a verified
  split, 3,001 calls read back, and `compiled cleanly`.
  Each of those three conditions is what keeps it to the one member that
  loses something, and the sweep is why: of the 38 constructor bodies in
  the corpus with a one-argument call feeding this shape, Paladin's two
  are the array-length form and all 35 of Crazy Party's are **handle**
  members, which are a real assignment and are rendered. Run over the
  five titles, the rule now names **exactly one member in Manamon 1 and
  nothing anywhere else** -- Paladin's two `input_recorder` arrays and
  Crazy Party's five `CarteCombat`/`LumiereCoucher` arrays are the
  pre-existing length form, every one of them an array. Anything that
  is not a constant is left alone rather than guessed at.

  **Swept across all five titles**, constructor bodies where a `CALL`
  with at least one argument is followed by `STOREOBJ` and a `REFCPY`
  into a member: Super Egg Hunt 0, Psycho Strike 0, Paladin 2, Crazy
  Party 35, Manamon 1 1 -- and **only the Manamon 1 one loses its
  argument**. Paladin's two are the sized-array shape, whose length is
  on the declaration; all six of Crazy Party's non-array ones
  (`Plateau::tileDeBase <- Tile(6)` among them) are **handle** members,
  and every one of those is rendered. So the by-value/handle test this
  entry already turns on is what keeps thirty-seven of thirty-eight safe,
  and one by-value member with a constructor argument is the hole.

- **A GLOBAL of a script class must be declared with its constructor
  arguments, not assigned one.** `T x = T(a, b);` needs two things a class
  with only an argument-taking constructor does not have -- a **default
  constructor** to make `x` and an **opAssign** to copy the temporary in --
  and the compiler says both:

  ```
  key_hold left = key_hold(KEY_LEFT, 500, 50);
  No default constructor for object of type 'key_hold'
  No appropriate opAssign method found in 'key_hold'
  ```

  **This is the `piano::piano_pool` defect reaching globals**, and that fix
  could not have covered it: it accepts only a *constant* argument, and a
  global's are routinely computed. Battle of the Hunter's is
  `get_DIRECTORY_APPDATA() + "/tunmi13/bth/data.dat"`.

  The form is the whole fix -- `key_hold left(KEY_LEFT, 500, 50);` constructs
  in place and needs neither -- so this is not a tidier rendering, it is the
  only one that compiles. Put to the compiler before being emitted, because
  the first probe asked two questions at once and answered neither: a sized
  array of a class with no default constructor fails on `array<T>`'s own
  **"The subtype has no default factory"**, and the *cascade* from that is
  `Compiling <unknown> things` and then "Only objects have constructors" --
  which reads exactly like a verdict on the syntax and is not one. Asked
  again with the two separated, `needs_args a(5);`, `has_default[] c(4);` and
  `int[] d(8);` all compile cleanly.

  **A generated initialiser makes the same shape worse**, because it cannot
  compile at all -- it declares the class by value, so the default
  constructor is needed a second time:

  ```
  savedata sd = __nvgt_global_init_95();
  savedata __nvgt_global_init_95() {
      savedata sd;                                   // no default ctor
      string local_6 = (get_DIRECTORY_APPDATA() + "/.../data.dat");
      savedata@ local_7 = savedata(local_6, "wolves111");
      sd = local_7;                                  // no opAssign
      return sd;
  }
  ```

  So `_fold_to_construction` collapses a body that amounts to "construct this
  type and store it" back onto the declaration and emits no helper. A local is
  substituted only when it is declared once and **read exactly once**, because
  folding one read twice would duplicate whatever computed it -- which this
  file counts as a correctness defect rather than an untidiness -- and
  anything in the body that is not a plain local declaration means the
  initialiser does real work and the fold is refused.

  **One cascade ends with it**, which is what the error count hides: Battle of
  the Hunter reported 40 further errors of the form *"Use of uninitialized
  global variable 'sd'"*, plus two for `up` and `down`, and every one of them
  was a consequence of the declaration above it failing. 5 real defects, 47
  diagnostics.

  Measured against the commit before it, with the change stashed so the
  baseline is this code and not a stale tree: **Egg Hunt differs in three
  files and every difference is this transformation** --

  ```
  sound_pool environment = sound_pool(500);             -> sound_pool environment(500);
  sound[] classic_found = array<sound>(8);              -> sound[] classic_found(8);
  egg[] eggs = array<egg>(250);                         -> egg[] eggs(250);
  time_object[] time_objects = array<time_object>(25);  -> time_object[] time_objects(25);
  ```

  -- 5,302 lines, 0 residual gotos, split verified, and still **`compiled
  cleanly`**. Its call count falls 1,608 -> 1,607, and that is `bgt apicheck`
  being right rather than a lost call: a construction spelled as a declaration
  is a declaration, and this file's own rule is that a declaration is not a
  call.

- **`CallPtr` names its variable in the other operand.** It takes one operand
  here and two there, and the funcdef-holding variable is the *second* one --
  which is where everything downstream looks. Left in the first, the call read
  slot 0 as its target (`this`) and took the slot *number* as its argument
  count: `this(local_8, <?>, <?>, ...)`, nine arguments for a nine-ary nothing,
  in 20 of Paladin's errors.
- **The sized array factory's length was thrown away.** The array template has
  a factory that takes a length (`double[]@ factstub(uint)`) and another that
  takes an initialiser-list buffer (`string[]@ factstub(int&in)`); the first
  is by value and the second by reference, which is the only thing that tells
  them apart. Dropping the length left two of `input_recorder`'s members
  unsized, and its constructor then wrote past the end of them -- which the
  engine reports as `Failed to initialize global variable 'recorder'` and
  nothing else. The length survives only on the member's *declaration*, since
  the store that applies it is generated prologue and is dropped.
- **Two matchers for one construct, and nothing owns the gap.** A computed
  jump is recognised twice: strictly in the simulation (`_begin_switch`, which
  demands the exact five-instruction prologue) and loosely in the structurer
  (`_dense_switch_pattern`). When *both* decline, the table's entries are
  never consumed: each becomes a `goto`, and each arm is emitted as an
  ordinary block — closing brace and all — with nothing that opened it.
  Manamon 2's `number_key_pressed` is a `switch` over 0..9 that came out with
  ten unmatched `}`, so the file could not parse and the compiler blamed a
  `return true;` hundreds of lines further on. An unclaimed table now raises
  `UnstructuredSwitch`, which gives up on that one body and counts it, rather
  than emitting most of it and corrupting the file. **The three bodies left
  are diagnosed rather than mysterious now** -- see **The three tables
  nothing claims** below. Eight sites in Manamon 2,
  none in any other title. Half-emitting a construct is worse than refusing
  it, because the damage lands somewhere else.
- **The last link of a switch chain may be a compare, not a table.** Where
  one of those ranges holds a *single* value there is no table to build, so
  the compiler emits `CMPIi sel, K ; JZ case ; JMP exit` instead. Read as a
  table that is not there the chain simply stops, and the compare is left
  behind as a branch to the switch's own exit -- a block the switch handler
  has already consumed, so it is a `goto` to a label that is never emitted.
  Super Egg Hunt's `submit_score` is one switch written both ways, `case 1..3`
  as a table and `case 27` as a compare, and it was the single error in that
  title's whole recovery.
- **A pass with no test can stop working and nothing fails.**
  `_drop_unreachable` deletes the statements that follow a `return` in a
  block, because BGT reports warnings in a modal dialog and waits on it. Its
  pattern's word boundaries were replaced by literal **backspace bytes** when
  it was edited -- a `\b` eaten by a shell -- which matches nothing, so
  `return` and `goto` silently stopped terminating a block while `break;` and
  `continue;` went on working. Output stayed valid and two "Unreachable code"
  warnings per title looked like something the compiler had a right to say.
  Paladin's four are gone, and both the pass and the dialect probe now have
  tests.

  **It happened again, and nothing caught it for however long it had been
  there.** `method_gap`'s documentation test carried the same two bytes --
  `re.search(r"\b%s\b")` arriving with a literal backspace in place of each
  `\b` -- so the branch that
  skips a method the help file *does* document never fired, and the help
  file is the whole oracle there: a *list* of a type's methods makes an
  absence provable where a substring search for a short name cannot. A
  third instance was a raw `0x1C` written into a bytes literal in
  `test_toolkit`, which is real data (`len2` writes `2 * length`, and
  "phone_callback" is 14 characters) spelled in a way no reader can see and
  no reader can tell from an eaten escape.

  So the bytes are what get checked now: no file under `tools/` or `tests/`
  may hold a control character other than tab, LF or CR. A pattern that
  matches nothing does not fail a test -- it just makes its branch dead --
  which is why this needed a test about *bytes* rather than about behaviour.
- **A constant that is only ever stored is typed by where it is stored.**
  `slot_types` types a slot from the opcodes that *compute* with it, which
  says nothing about `pool.pan_step = 1.5`: `SetV4 v2, 0x3FC00000` is width
  only, no float opcode touches slot 2, and in Psycho Strike's `main` that
  slot is a bool elsewhere -- so it compiled to `pool.pan_step = true`. The
  destination's declared type settles it, and it has to be the *constant*
  that gets typed, not the slot: declaring the slot makes it a variable, and a
  variable is no longer folded into its use. Tried that way first,
  `sound_pool::reset` went from nine lines identical to BGT's own source to
  thirty-six lines of slot traffic -- a fix that read as a fix and made the
  output worse. Cross-validation is what caught it, exactly as it is supposed
  to.
- **One source `switch` is several jump tables.** A dense `switch` compiles to
  a bounds check, a normalisation and a computed jump into a table of jumps --
  and a switch over scattered values becomes a *chain* of such tables, each
  guard sending the value on to the next range. Read one table at a time, the
  first switch's extent swallows the later ranges' bodies, which come out as
  `return` statements with no `case` above them: `day_to_word` answered
  "twentieth" for every day from 13 to 31. Merged, it is one switch with all
  fourteen cases the source wrote. **And a gap of more than five splits the
  table** -- see **Reading the compiler, not only the reader** below, where
  that constant comes from and what it is worth.
- **...and a merged chain must lose the first table's own range guard.** The
  guards before `JMPP` are simulated as ordinary branches -- only the span
  *after* it is skipped -- so the guard that sends out-of-range values to the
  *next* table survives the merge as a real `if`, and merging has just moved
  its target inside the switch. Every case the later tables contributed then
  sits inside `if (day <= 3)` and cannot be reached, so a seven-case switch
  answered its default for four of them.

  **The case list was right, which is why this outlived the merge that was
  supposed to fix it.** All seven cases are present, correctly merged, in the
  right order, with the right bodies -- and `scattered_switch(21)` returned
  `"none"`. No count, brace check, split verification or compiler diagnostic
  can see that; `bgt oracle` found it on its first run by calling the
  function. One table keeps its guard, because then the guard's target *is*
  the switch's exit and the `if` is a redundant bound rather than a wrong one.

  **And a shipped title was affected.** Super Egg Hunt's `cabinet::mode_check`
  is a switch over 6, 10, 14 ... 42, 48, which came out wrapped in
  `if (count <= 42)` -- so `case 48`, the one arm that is not just another
  `play_mode()` call, could never run. That arm awards the `allaboard`
  trophy, which a recovered build therefore could not give you. The recovery
  is **four lines shorter** for losing the guard, and that is the only sign
  of it anywhere in the counts: 0 residual gotos before and after, split
  verified before and after, `libcheck --decompiler` 43/47 before and after,
  `compiled cleanly` before and after.
- **A `for` header may not hoist the increment** when something jumps straight
  to the condition. That jump is a `continue` in a loop whose increment is
  part of the body; hoisted into the header it would run on that path too.
- **The funcdef placeholder names no funcdef.** `objVariableTypes` records a
  funcdef-typed local as `_builtin_function_` with no signature, so with more
  than one funcdef in the module there is nothing to resolve it to. A slot
  recorded that way *and* used by integer opcodes is a reused slot, and the
  placeholder is the half that cannot be declared.

## A build newer than the one installed

Manamon 2's 28 diagnostics are all *parse* errors, and they are not about the
recovery: its source says `protected` and `weakref<character>`, and both
strings are in its own `rpg.exe` and in neither BGT 1.0's nor 1.3's compiler.
It was built with a newer BGT. A parse error stops the compiler before it
checks anything, so those 28 are also all it can say about a 171,223-line
module.

`bgt recover` reports this from the one piece of evidence available: a type the
module uses, does not declare, appears in the game's own executable, and does
not appear in the installed compiler or its `exec.bin`. For Manamon 2 that
names five: `weakref`, and a Crypto++ family -- `ecdh`, `encryption`,
`decryption` and `decryption_key`. (`protected` is a keyword rather than a type, so it
is found the same way by hand and not by that check.) Saying so is the
difference between a report and a mystery -- and it is why a diagnostic count
is only ever a statement about *this* engine.

**It can also be one method of a type the engine does have**, which is the
same finding one level down and needs the documentation to prove: a *list* of
a type's methods makes an absence provable where a binary search for a short
name does not. Psycho Strike calls `tts_voice::speak_to_sound`, which returns
the speech as a `sound@`. BGT 1.3 documents `speak`, `speak_interrupt`,
`speak_interrupt_wait`, `speak_to_file` and `speak_wait`, and not that one --
and `speak_to_sound` appears in the game's own `strike.exe` and in neither
`bgt.exe` nor `exec.bin`. `method_gap` reports it next to the plugin, with the
same corroboration `engine_gap` uses.

That closes Psycho Strike out: **all 33 of its remaining diagnostics are the
installed engine's absences** -- 32 uses of the `elias` plugin type and this
one method -- and none of them is the recovery's.

## Reading the calls back, where the compiler cannot

The section above is the problem: Manamon 2's 33 diagnostics are all *parse*
errors, a parse error stops the compiler before it checks anything, and the
largest recovery in the corpus has therefore never had a single call read
back by anything. `bgt recover --compile` is the measure, and on the title
that most needs measuring it measures nothing at all.

`bgt apicheck` reads them back, and `bgt recover` now runs it on every
project without being asked. **The simulation pops a callee's declared arity
by construction**, so an arity mismatch cannot exist in the IR -- which is
exactly why the check belongs on the *text*. The rendered source is a
different artefact: it has been through temporary folding, slot promotion,
scope qualification and stock-include substitution, and every one of those
has dropped a real argument at least once in this file's history.

The oracle is three sources, and none of them is a guess:

| source | what it knows |
|---|---|
| the module's own `usedFunctions` | every callee's parameters and defaults **as the engine that compiled this module declared them** -- so a fork is checked against its fork |
| the game's own runtime | the whole registered interface of that build (`bgt_api.registered`) |
| the recovered text | the script's classes, methods, globals, locals and parameters |

A name may legitimately carry several arities, from overloads and from
methods of unrelated types sharing a name, so a call is judged against all
of them and reported only when **nothing** fits. That is deliberately weaker
than resolving the receiver's type, and it is what makes a false alarm
impossible from an overload the check failed to consider.

**What it will not judge, it counts rather than guessing at.** AngelScript
registers every constructor and factory under the literal name `f`, with the
owner type as a separate string argument, so `vector @f()` and `void
f(float, float y=0, float z=0)` sit in the binary with nothing to say which
type either belongs to. Taking the union of every `f` would accept nought to
three arguments for anything, which is not a check. A call through a
funcdef-typed local is declined for the same reason: the arity is the
funcdef's, not the variable's.

| title | calls read back | what the compiler can say |
|---|---|---|
| Super Egg Hunt | 1,607 | compiled cleanly |
| Psycho Strike | 6,462 | 33, every one the engine's |
| Paladin of the Sky | 7,145 | compiled cleanly |
| Manamon 2 | 51,249 | **nothing** -- 33 parse errors stop it |
| Crazy Party | 90,494 | compiled cleanly |

**156,957 calls, and not one mismatch.** That is worth nothing on its own --
a check that reports nothing may simply be blind -- so it is measured in
both directions. Injecting a defect into the recovered text finds it every
time: an argument dropped from `string_replace(a, b, c, d)`, an argument
added to `key_pressed(x)`, and a callee renamed to one nothing declares are
all reported, and four of its five guards move the measurement when broken
(the fifth guards the *declared-name set*, which it moves by 2,198 names on
Manamon 2 without any current call depending on it). And the four titles the
compiler *can* judge come back clean from both, which is the cross-validation
rather than the absence of evidence.

Five things had to be right, and each was wrong first:

- **Comments and strings are scrubbed in ONE left-to-right pass.** Each
  construct can contain the other's opener, so two regexes in sequence
  desynchronise. Manamon 2 calls
  `url_get("http://www.vgstorm.com/playmmn.txt")`, and a comment pass run
  first eats `//www.vgstorm...` as a line comment and takes the closing
  quote with it -- after which every quote in the rest of the file pairs
  with the wrong partner. That reported a one-argument call as taking ten,
  and then thirty-three.
- **A declaration is not a call.** `string serialize(dictionary@ d)` in a
  class body is a definition; read as a call it is a two-argument call to
  the engine's one-argument `serialize`, and every class in Manamon 2 that
  declares one produced that. What tells them apart is the token before the
  name -- a declaration has a *type* there.
- **A funcdef in call position is a delegate, not a call.**
  `pathfinder_callback(arg0.callbackPf)` binds one method; it does not call
  the callback with the five arguments it declares. Read the other way it
  reported all thirteen of Crazy Party's delegates.
- **...and a name-keyed oracle unions, it never replaces.** `event` is a
  global funcdef in Manamon 2 **and** the class `rhythm::event`. Replacing
  its entry with the delegate's arity threw the class's constructor away and
  reported five good `event()` calls as taking too few arguments -- the same
  collision as `string::insert` hiding behind `array::insert_at`, one level
  up.

- **A type's marker run repeats, and a handle array has two.** The pattern
  for `<type> <name>` at a declaration accepted `T`, `T@` and `T[]` -- one
  marker -- so it could not see `interact@[]`, `collect@[]@` or
  `dynamic_menu_item[]@` at all. Every handle-array declaration in every
  title was therefore invisible to the declared-name set: locals,
  parameters, globals and functions alike.

  What it cost was **five false alarms on Manamon 1**, and they were
  convincing ones: `__nvgt_global_init_256`, `266`, `285`, `301` and `303`
  reported as declared by nothing, when each was declared in the very file
  that called it -- and they are exactly the five of that title's 171
  generated initialisers whose return type is a handle array. The other 166
  were seen.

  This is the third instance of one family: `bgt_api`'s array return
  (`string[]@ find_files(string& in)`, four functions wrongly reported as
  absent) and its handle marker against either side (`network_event @f()`
  against `network_event@ request()`, eighteen factories lost). A type has
  more spellings than it looks like it has, and a pattern that enumerates
  them will miss one.

  **The direction matters and the fix is measured in it.** This set decides
  whether an absence gets reported, so widening it makes the check weaker:
  a declaration it cannot see is a false alarm, but a name it wrongly held
  would be a gap it never reports. Checked across every recovered project
  on disk, the wider pattern adds only genuine declarations -- `T[]@`,
  `T@[]`, `T@[][]` -- and the only reported outcome that moves is those
  five, to zero. It does not make them *checked*: their arity is still not
  judged, because the script-declared name set carries names and not
  arities, so they move from a false alarm into the declined-and-counted
  bucket. Judging a script function's own arity is a widening of its own
  and is not done here.

The honest summary is that this found no defect in the current recovery and
closed the one thing that looked like one: a `tmp0(local_7, <?>, <?>, ...)`
in a stale Manamon 2 project, which is the old `CallPtr`-operand bug and
renders `local_6(local_7)` under current code. What it changes is that
Manamon 2 is no longer unmeasured.

## Reading the calls and the literals back against the BYTECODE

`bgt libcheck` compares a recovered body against BGT's own library source,
which is the right instinct and reaches **149 of Paladin's 926 bodies**. Every
bug ever reported from playing these games has been in the other 777, and
those had never been compared against anything.

There is a better oracle than source for them, and it was in hand the whole
time: **the module**. A call instruction is a call and a `STR` operand is a
literal, so for every body the bytecode gives the exact multiset of callees and
of string constants, and the decompiler cannot lose or invent one without being
wrong. Two audits, both over all 753 bodies that pair unambiguously:

| audit | Paladin's answer |
|---|---|
| callee multiset per body | 26 bodies missing a call -- **all** of them `super()`, a member's generated construction, or a base constructor |
| literal multiset per body | **4 bodies missing 134 literals between them** |

The literal one is what found the bug below. Compared as a **multiset**, not a
sequence: the text's order is "sorted by closing parenthesis", which this file
already records as an approximation of evaluation order, so a sequence diff
would measure the approximation instead of the recovery.

### The audits are one command now

```bash
bgt audit recovered/ game.exe                  # all three
bgt audit recovered/ game.exe --constants      # ...or one
```

Three audits over every body that pairs unambiguously by `owner::name` on
both sides -- callees from `CALL`/`CALLSYS`/`CALLINTF`/`Thiscall1`/`ALLOC`,
literals from `STR` and `PGA`, numeric constants from `SetV1/2/4/8` -- each
a multiset against the recovered text, reported with the body's name and
the file and line it landed in. The module is found the way a person would
expect: `--module`, else the `*_bytecode.bin` that `bgt recover` already
wrote beside the project, else unpacked from the executable into a temp
file. **A row is a lead and not a verdict**, so rows are not a failure
exit; pairing *nothing* is, because an audit that measured nothing must not
read like an audit that found nothing.

Four benign kinds recur, and knowing them is most of the triage: `super()`
where the bytecode names the base constructor; a value-declared member's
generated construction; an empty string the recovery renders as a
declaration rather than an assignment of `""`; and the original's own dead
store.

#### Three comparison rules, each measured by being defeated

The scratch script that found the flattened clock compared *spellings*, and
most of its surviving rows were that rather than a defect. Three rules take
them out, and each was measured by turning it off again:

| rule turned off | Paladin | Psycho Strike | Super Egg Hunt |
|---|---|---|---|
| all three on | 1 literal / 2 constants | 1 / 2 | 1 / 0 |
| an escape is not the byte it escapes | **16** literals | **23** | **9** |
| a number is a number, not a spelling | **177** constants | **201** | **33** |
| the same bits have two honest readings | **55** constants | **94** | **9** |

- **An escape is not the byte it escapes.** The recovery writes any byte
  above 0x7F as `\xNN`, deliberately, so comparing bytecode bytes against
  the literal's source text compares an escape against the byte it escapes
  -- the eight Manamon 1 rows this file already records as the audit's own
  artifact. The unescaper is written from the lexer's rules rather than as
  the inverse of the renderer's table, for the reason
  `LiteralRenderingTests` records: an inverse built from the same table
  would agree with a wrong table.
- **A number is a number, not a spelling.** The bytecode's `-100.0` and the
  text's `-100` are one constant, which is what the four stock-library rows
  on each title were. Compared with a **relative** tolerance only: an
  absolute one looked harmless and hid everything, because the float
  reading of a small integer is a denormal a hair above zero and almost
  every body's text holds a zero.
- **The same bits have more than one honest reading.** A one-byte `255` is
  the `-1` the text spells in `this.walk(-1, false)`; a stripped module does
  not record which the source wrote, so both readings are offered -- at the
  opcode's own width and the operand field's width, and no narrower. An
  int8 reading offered for a four-byte store would be one more way for a
  lost constant to find a match and go unreported.

So Paladin's constant audit is **44 rows -> 2** and Psycho Strike's
**18 -> 2**, which supersedes the 6 and 8 recorded under **The instrument**
below: the rules absorb those rows instead of the prose having to explain
them. What is left on either title is the original's own dead store.

#### ...and the rule that nearly made it blind

The benign-call set declined any callee whose name starts `get_` or `set_`,
on the sound grounds that a property accessor is written `pool.pan_step`
and never appears as a call in the text. BGT registers
**`set_sound_storage` and `set_sound_decryption_key` as ordinary global
functions**, so both were declined -- and a name a check wrongly holds is a
gap it will never report. Of all the calls in a BGT game those two are the
difference between a recovery with sound and one without.

An accessor is invisible only when the callee is a **method**, because a
property access needs a receiver. Measured, that moved several hundred
calls per title out of the declined pile with no new rows at all: Paladin
20,398 -> 20,167 declined, Psycho Strike 15,443 -> 15,147.

**And it is measured in both directions**, which is the standard
`bgt apicheck` set and the reason to trust a zero. Four defects injected
into a synthetic project -- a dropped literal, a constant flattened to 1, a
deleted call, a high byte written as a character -- each come back, in
`tests/test_audit.py`; and injecting a flattened `time.add_minutes(30)`
into a copy of Paladin's real tree reports it by body and value. Every
audit also prints how much it declined, because that number is the
difference between "nothing lost" and "nothing looked at".

### `bgt_libcheck.calls` could not see a method called on an indexed receiver

The first result was in the checker, and it is worth stating before the
finding, because it flattered `bgt libcheck --decompiler`'s own scores for
as long as it stood. Its pattern was

```
(?<![\w.])(?:[A-Za-z_]\w*\.)*([A-Za-z_]\w*)\s*\(
```

-- a dotted chain of plain identifiers. `global_interacts[slot].add_event(...)`
has a `]` in the chain, so the chain alternative cannot reach `add_event`, and
starting the match there instead fails the `(?<![\w.])` lookbehind, because the
character before it is a dot. **So every method called on an indexed receiver
is invisible to it.** Reused for the audit it reported 67 lost `add_event`
calls in `other_stuff`, all 67 of which are present.

A checker that under-reports is the same shape as everything else in this file:
the first version of the audit was *more* convincing for being wrong, because
67 lost calls in one function is exactly what a real defect looks like.
(That artifact is gone with the pattern, below.)

**Fixed, and the receiver was the wrong thing to describe.** The chain was
never doing any work -- `a.b.c.m(` captures `m` with or without it -- so the
fix is to delete it rather than teach it brackets:
`(?<!\w)([A-Za-z_]\w*)\s*\(`, the whole identifier the paren opens
against. **Adjacency to the `(` is what identifies a call; a receiver never
was.** A chain taught to span `[...]` would stop at a nested `[`, and,
because `finditer` resumes past whatever the match consumed, would swallow a
call written *inside* the subscript -- so `a[fetch(i)].m()` would have traded
the outer loss for an inner one. Tracking no brackets at all loses neither.

**No score moved, and that is not the same as the fix being inert.** Per
title, the calls the comparison now reaches that it could not see before:

| title | pairs touched | calls compared, source | recovered | newly seen per side |
|---|---|---|---|---|
| Paladin of the Sky | 11 / 47 | 77 -> 109 | 93 -> 125 | **32** |
| Psycho Strike | 24 / 149 | 452 -> 502 | 456 -> 506 | **50** |
| Super Egg Hunt | 11 / 47 | 90 -> 122 | 101 -> 133 | **32** |

In all 46 touched pairs the newly seen multiset is **identical on both
sides**, which is why the scores hold at 39/47, 144/149 and 43/47. So the
blindness was costing 11-42% of the calls this checker compares at all, and
the recovery was right about every one of them -- the scores stand because
the recovery is correct here, not because the shape is absent.

`sound_pool::play_extended_1d` is the one worth reading, because it is the
function this file records as having once run `reserve_slot()` forty-five
times. It was being scored on **one** visible call; it now compares nine --
`reserve_slot, reset, update, load, reset, seek, update, play_looped, play`
-- in evaluation order, matching exactly. A ratio of 1.00 over one call was
close to meaningless. Paladin's `pause_sound` and `resume_sound` rise from
0.67 to 0.80 and 0.91 and **still differ**, by the same single `is_playing`:
that title's `sound_pool` asks its `input_recorder` where stock BGT asks
`items[slot].handle.playing`, which is the game's own library edit and
exactly what this check is for.

**An indexed receiver was not the only receiver that is not a plain
identifier.** A string literal is another, and `calls` blanks literals
before matching, so `" items deleted.".opAdd_r(n)` was unreachable for the
same reason and became reachable with the same fix -- reporting a difference
in Psycho Strike's lifted `audio_form::delete_list_selections` where
`form.bgt` writes `speak(selections.length() + " items deleted.", true)`.
`OPERATOR_METHODS` is the list that keeps an operator the source writes as
**syntax** out of the comparison, and it did not hold the reversed spelling
the engine registers for `<number> + <string>`. So `opAdd_r` belongs there
on the same ground `opAdd` does, and that is why it was added rather than to
restore a number: with it the lifter is back to 153/155, and `opAdd_r` is
the only `op*` name the whole corpus produces that the set did not already
hold. The set is widened one measured occurrence at a time, deliberately --
a name in it is dropped from **both** sides, so every addition makes the
comparison weaker.

### An initialiser list was dropped, so the array came out EMPTY

`string[] lines = {"a", "b", ...}` compiles to AngelScript's
initialisation-list protocol: `AllocMem`, `SetListSize`, one `PshListElmnt`
write per element, then the template's **list factory** taking the buffer.

The newer engine's list factory is the behaviour `$list`, and that path already
rendered the buffer as `{...}`. BGT's older AngelScript reaches the same
factory through a **generated template factory stub** --
`string[]@ factstub(int&in)` -- and the `factstub` branch dropped every
by-reference argument on the stated grounds that a list buffer is "an
engine-internal object with no name source can write". True, and the conclusion
was wrong: the buffer has no name, but **the list it carries is the source**.

So `{"a", "b", ...}` came out as `array<string>()`.

**Nothing reports an empty array.** It is valid source, it compiles, it runs,
and every loop over it runs zero times -- so no exception, no diagnostic, no
line count out of place. What it costs, measured as the lists the fix
recovers that nothing rendered before:

| title | lists | elements |
|---|---|---|
| Crazy Party | 118 | **681** |
| Paladin of the Sky | 3 | **134** |
| Super Egg Hunt | 4 | **52** |
| Psycho Strike | 1 | **6** |
| Manamon 1 | 0 | 0 -- see below |

Paladin's biggest is 114 lines of dialogue for the ship's passengers, built
in `create_room_passengers` and looped over to create a `person` each. With
the list empty the loop ran zero times, so **the ship had nobody generic to
talk to** -- the shape of "it works but something is missing" that no count
in this document can see.

**The first figures for this were wrong in the flattering direction, and
how they were wrong is the useful part.** They said 896 elements for Psycho
Strike and 157 for Super Egg Hunt, counted by totalling every `SetListSize`
in the module. That counts lists that were never lost: a list initialising a
**global** is rendered by `_global_list_expr`, which reads the literals
straight out of the initialiser function's bytecode and never reaches the
factory at all. Nineteen of Psycho Strike's twenty lists are global, and so
are three of Super Egg Hunt's six -- `female_names`, `male_names`,
`surnames`, `trophy_list`, `modes` -- and they were in the recovery the whole
time. The honest measure is the one above: lists the new path renders, which
is **0 for every title before the fix** and is counted by scanning the braces
with string literals skipped, because a comma inside `"a, b"` is not a
separator either.

**And Manamon 1 does not have the bug at all**, which is worth knowing
before assuming a sixth title does. Its fork registers the list factory
as the behaviour `$list`, the way the newer engine does, so its 13 lists and
101 elements were already being recovered -- its whole project is
**byte-identical** before and after. The factory spelling tracks the engine
generation exactly as every other per-build field in this document does.

`$list` and `factstub` now go through one `_list_literal`, because two places
answering one question is the failure this file keeps recording, and this is
the same question asked by two engine generations.

**Two guards make it a recovery rather than a guess:**

- **The buffer must be accounted for completely.** The number of element
  writes seen has to equal the size `SetListSize` declared, or the list is
  refused. A list rendered one element short would compile and run and be
  wrong, which is worse than one that is empty, because the empty one at least
  matches what the old code did.
- **An element that names a frame slot is refused.** The declaration is hoisted
  to the top of the body, so a slot name in it reads a value the slot does not
  hold yet -- and may not be declared at all.

### A scalar element's value is in the SLOT, and `bgt oracle` said so

The fix was written for strings and `bgt oracle` broke it on the first run,
which is the whole reason that command exists. A string element is written by
constructing into the element's own address; a **scalar** one is not:

```
SetV4 3, 7 ; PshListElmnt 2, 1 ; PopRPtr ; WRTV4 3
```

The constant goes into a frame slot and `WRTV4` copies it through the reference
register. Capturing the slot captures its *name* wherever that slot is also a
named variable elsewhere in the body, so `int[] v = {7, 11, 13}` recovered as
`{local_3, local_3, local_3}` -- the wrong value three times, and an undeclared
name. The constant the last `SetV*` parked in the slot is the element, and it
is remembered across exactly the `PshListElmnt`/`PopRPtr`/`WRTV*` window that
consumes it: any other instruction invalidates it, so a stale constant can
never be read back as an element.

**The new shapes were measured in both directions.** `list_of_strings`,
`list_of_ints` and `list_in_a_global` pass at 50/50 with the fix and, with it
stashed, the recovered fixture **throws**: `Index out of bounds` in
`int list_of_strings()`, because `names[0]` indexes an empty array. A shape
that cannot fail is not a check, and this one fails loudly.

**And a check that costs somebody a modal dialog is a cost.** Running the
oracle against the stashed decompiler put a BGT runtime-error box on the
screen of whoever was at the machine -- the same lesson this file records for
`capabilities()`, arrived at from a new direction. The bytecode audits above
answer "did we lose a literal?" without launching anything, and they are the
cheaper place to ask.

### What the audits leave, and what they cleared

What is left on Paladin after the fix is one lost literal pair, and it is not
the decompiler's: `generate_maze` compares
`global_interacts[slot].interact_name == "dungeon_entrance"` and **discards the
result**. There is no `CpyRtoV4` after the `opEquals` and no jump that reads
it, so the statement has no effect -- the original wrote `==` where it meant
`=`, and the dungeon doors never got their names. Dropping a pure expression
whose value nothing reads changes nothing, so it stays dropped and is recorded
here instead.

The call audit's 26 are explained: `super()` where the bytecode names the
base constructor, and a member's generated construction (`rec_timer` in
`puck::puck`).

**One of them is a defect, and this file said it was not.** It read:
*"and `steel_wall::act`, where two `dragon_strike` call sites in the
bytecode are the two arms of one source call."* They are two arms, and
they are **two different calls** -- they differ in the third argument:

```
 59  CMPIi 8 2 ; JNZ -> L0            ; multiple_choice() == 2 ?
 61  SetV1 4 0 ; PshC4 10 ; <combo>
 73  CALL dragon_strike               ; (combo, 10, FALSE, false)
 74  CpyRtoV4 12 ; CpyVtoV4 11 12     ; into slot 11, never read on this path
 76  pool.resume_all() ; JMP -> exit
 82  L0: SetV1 4 1 ; PshC4 10 ; <combo>
 94  CALL dragon_strike               ; (combo, 10, TRUE,  false)
 95  CpyRtoV4 3 ; CpyVtoV4 11 3 ; CMPIi 11 10   ; ...and READ
```

The menu is `"Try scroll[nc]Listen to scroll"`, and choice 2 takes the
fall-through arm, whose result is stored and never read before the
`return` -- so the store was dropped and the call went with it. **Listening
to a scroll at a steel wall did nothing at all.** The other arm survives
because its result is compared against 10.

Two arms of one source call would have been benign, which is why the
wrong reading was comfortable. Reading the third operand is what
separates them, and it takes one look at the disassembly.

**And the audits cleared the thing they were built to investigate.** The report
was that music does not play on some maps, and the map-music path is faithful
at every step that could cause it:

- **`create_world`** -- 115 maps, every one given a non-empty `bgm`. Its 348
  bgm / `reset` / `insert_last` events were compared against the bytecode's in
  order, event for event: **zero mismatches**, which matters because `world` is
  a value array, so a `bgm` store that landed after its `insert_last` would be
  a map with no music.
- **`map::map_setup`**, **`change_music`**, **`map::deserialize`**,
  **`assign_song`** and **`input_recorder::is_playing`** -- read against the
  disassembly instruction for instruction, all faithful. `change_music`'s early
  return, the `nighttime_bgm` guard, the fade to -50 dB and the `?&out` string
  temporary in the loader are all the original's.
- **Every music track named in the module appears in the recovery** -- 117 of
  the 128 files in `audio/bgm`, the other 11 being named nowhere.

One hypothesis died cheaply and is worth recording so nobody pays for it
twice. Several of Paladin's `bgm` literals carry capitals -- `Analytics`,
`Genesis`, `Purgatory`, `Tower_of_fear` -- while `data.dat` stores every one of
its 128 bgm entries in lower case, so a case-sensitive pack lookup would lose
exactly "some maps". **It is case-insensitive**, which was put to the engine
rather than argued: a probe built a pack holding `audio/bgm/analytics.ogg` and
`pack_file::file_exists`, `list_files` and `sound::stream` all answer yes to
`audio/bgm/Analytics.ogg` and to `AUDIO/bgm/analytics.ogg`.

## Compiling it back: the original bytecode against the RECOMPILED bytecode

Every other check here compares a recovery against something *smaller*
than the program. `bgt audit` compares a body's callees, literals and
constants as **multisets**, so it cannot see a statement that moved, a
comparison whose operator changed, or a conditional that lost its guard.
`bgt libcheck` compares against BGT's own library source, which reaches
149 of a title's 926 bodies. `bgt apicheck` asks only whether a call
could resolve. `bgt oracle` runs 51 shapes nobody shipped. None of them
answers the question the whole project is pointed at: **does the recovered
source mean what the original meant?**

The compiler answers it, and the answer is a number:

```bash
bgt recover game.exe -o out/
bgt compile out/game.bgt --build release
bgt roundtrip game.exe out/game.exe
bgt roundtrip game.exe out/game.exe --detail sound_pool::verify_slot
```

Both modules are parsed, their bodies paired by `owner::name`, and each
pair diffed instruction for instruction. What is compared, and what is
deliberately not:

- the **opcode sequence**, which is the whole point;
- every operand that **names** something -- a callee, a literal, a global,
  a member, a type -- taken as the name, because a rebuild reorders every
  table and an index means nothing across two modules;
- every operand that is a **constant**, taken as its value;
- a **jump**, taken as its relative distance in instructions, which is
  comparable between two bodies of one shape where a label number is not;
- a **frame slot**, renumbered first-seen for the strict score and dropped
  for the loose one. The compiler allocates slots in its own order, and a
  recovered body with one local more shifts every later offset, so
  comparing raw offsets would report every body as differing and mean
  nothing by it.

Which operands are slots comes from `asBCInfo[].type` -- AngelScript's own
`asBCType` enum, where `asBCTYPE_wW_rW_DW_ARG` spells the shape out. The
transcription is **checked against the build's own table**: every entry's
operand count has to equal the count the decoder steps by, and a
disagreement raises rather than being tolerated, because a wrong mapping
would read a constant as a slot and renumber it away -- so a flattened
constant would compare equal and nothing would say so.

### It is calibrated against a known answer

A comparison nobody has calibrated is worth nothing, and this one has an
oracle built in. `bgt recover` substitutes **BGT's own shipped source**
for a library file that matches, so those bodies are compiled from source
this project did not write -- and every one of them comes back
**instruction for instruction identical**: all four of Super Egg Hunt's
`position_sound_*` bodies, one of them 110 instructions, and
`number_speaker::speak`, `speak_next` and `speak_wait`.

So the compiler is deterministic, equal source really does give equal
bytecode, and **every differing body is a difference between the recovered
source and the original's** rather than noise from the engine. That is the
whole licence to read a difference as a lead.

### The edit distance is the measurement; the exact-match count is not

A body usually differs for several independent reasons at once, so closing
one of them leaves it differing. The first real fix measured against this
**halved Super Egg Hunt's distance while the exact-match count did not
move at all**:

| | instructions added or lost | of the original's 28,564 | bodies identical |
|---|---|---|---|
| before | 19,504 | 68.3% | 29 / 137 |
| after | **13,950** | **48.8%** | 29 / 137 |

and the module the engine wrote went from 119,103 bytes to 110,501 against
the original's 106,166 -- oversize from **+12.2% to +4.1%**. Quoting the
exact-match count alone would have reported that fix as worthless.

### Two titles, and Paladin's compiler column re-run

| title | bodies paired | identical | with slots | edit distance | of the original |
|---|---|---|---|---|---|
| Super Egg Hunt | 137 / 210 | 29 | 29 | 13,950 | 48.8% |
| Paladin of the Sky | 798 / 926 | **271** | 270 | 72,029 | 56.1% |

Paladin pairs 798 bodies and **loses none** -- the only labels in the
rebuilt module that are not in the original are its six generated
`__nvgt_global_init_N`. Its strict score is one lower than its loose one,
which is the first evidence that the slot half of the comparison does any
work at all: one body uses its frame differently while doing the same
things in the same order.

**And it compiled cleanly**, which is why the standings' compiler column
now carries two rows that were measured at the current code rather than
inherited from the commit they were written at. The column is still the
expensive one -- asking costs a dialog on somebody's screen -- but on a
title that compiles cleanly the dialog is the success one the driver
dismisses, which is a cost worth paying once per measurement.

### Every figure above was overstated, and by one cause

**A correction, and the direction it runs in is the useful part.** The
distances first published for all of this were 3 to 6% too high and the
identical-body counts too low -- Paladin's 256 was 271 -- and one
unmapped operand is the whole of it.

`RefCpyV` is `PSF dest` + `REFCPY`, so its second operand is the same
object type that `REFCPY` carries in its first and `FREE` in its second.
Both of those are mapped in `as_disasm.OPERAND_ROLES`; **`RefCpyV` had
no role at all**, so it printed as a bare index -- and this comparison
resolves a named operand BY NAME precisely because a rebuild reorders
every table. Unmapped, the type index read as a changed constant, so
every handle copy in every body counted as a difference. On Super Egg
Hunt that is **1,182 of the 9,282** instruction-edits last reported.

It is `{1: "objtype"}` now, and the evidence is a cross-check rather
than a resolution: **all 3,456 `RefCpyV` operands in two titles resolve
to a type, and in every one of the 2,807 cases where the slot is also
freed the type AGREES with the paired `FREE`.** That matters because
resolving alone is weak evidence -- `ChkNullV`'s slot, `AllocMem`'s size
and `PshListElmnt`'s byte offset all "resolve to a type" too, being
small integers landing inside a table, and none of them is one. That is
this file's own rule about a resolver that returns a placeholder,
arriving from the measuring end.

| Super Egg Hunt | edit distance | of the original | bodies identical |
|---|---|---|---|
| session start | 19,504 | 68.3% | 29 / 137 |
| after the dead handle | 13,950 | 48.8% | 29 / 137 |
| after the scratch-slot fold | 8,298 | 29.1% | 30 / 137 |
| after signedness | **8,100** | **28.4%** | **34 / 137** |

Every point re-derived from the same stored builds, so the series is one
measurement rather than four. `bgt libcheck` is unmoved by the mapping
(43/46 on this title), which is the check that says the disassembler's
other readers do not depend on the gap.

### A low ratio means MISALIGNMENT, not a defect

The first thing worth knowing before reading a row. `preload_all` scores
**0.015** over 560 instructions -- almost nothing matching -- and it is
not a defect at all:

```
original:   preload_add("audio/se/cecil/strikestart.ogg");   // a temp per item
rebuilt:    local_0 = "audio/se/cecil/strikestart.ogg";
            preload_add(local_0);                            // one declared local
```

Both reach `preload_add` with the same bytes. The original constructs and
destroys a string temp per item where the recovery assigns into one
declared local, so **every item is offset by one instruction** and the
sequence matcher cannot align any of it. The rebuilt body is even
*shorter* -- 478 against 560 -- because it builds one string where the
original builds ninety.

So a ratio is a measure of alignment. Sort by it to find the bodies worth
reading, never to rank how wrong they are, and read the delta and the diff
before concluding anything. The same caution the rest of this file gives
about `libcheck` scores applies here with more force, because this
comparison is per instruction and a one-instruction phase shift is total.

### Splitting the residue: what could change behaviour, and what is spelling

The distance is two things added together and the fixes for them are
nothing alike, so the residue has to be split before any more is spent
on it. Per differing body, five multisets from each side's bytecode --
the callees by name, the string literals, the numeric constants, the
globals touched, the members touched -- and **both sides are bytecode,
which is what makes this cleaner than the text audits.** Those compare
an escape against the byte it escapes and a number against its
spelling, and need three rules to undo it; here `"a"` is `"a"` and `30`
is `30` on both sides by construction.

Super Egg Hunt, 137 paired bodies:

| | bodies | |
|---|---:|---|
| byte-identical | 34 | 24.8% |
| same content, different plumbing | 83 | 60.6% |
| **content differs** | **20** | **14.6%** |

So **117 of 137 bodies do the same things to the same values**, and
twenty could differ in behaviour. That is the number worth working on,
and it is a seventh of what the instruction count suggests.

**The plumbing has to be excluded or the answer is meaningless.** Asked
with object lifecycle calls counted -- `string::$beh0`, `$beh2`,
`opAssign`, the string factory -- it says 53 bodies differ, and almost
all of that is a string local the source never declared being
constructed, assigned and destroyed. Our plumbing differing from the
original's plumbing is not a behaviour difference.

Of the twenty, three shapes recur and two are explained:

- **`check_motd` duplicates a literal, and it is free.** The original
  keeps the base URL in a string local read twice; the recovery folds
  the literal into both reads. Same bytes, one extra construction --
  the designed cost of restricting the scratch-slot fold to repeatable
  values, visible here for the first time.
- **`cabinet::mode_check` gains `cabinet::count` and the constants 48
  and 6**, which is the retained switch range guard below, reconstructed
  as source. Behaviour-neutral and unfaithful, exactly as recorded.
- **Five bodies where the ORIGINAL reads a global or member more times
  than the rebuild** -- `check_time_objects` is `-6` globals and `-4`
  members. A repeated read collapsed into one is safe where nothing
  changed in between, which is what `_stale_fold` is for; it is **not
  established** that this is all it is. `chicken::walk` reads clean and
  the original still makes two more reads each of `chicken::x` and
  `chicken::y` than our source, and why is not known. That is the one
  unexplained shape and the next thing to read.

### What dominates the remaining distance, and it is one shape

**A string literal routed through a declared local instead of being the
argument.** It is the same finding as the dead handle alias one type over:
an object slot the compiler materialised, treated as a source variable.
The compiler reuses one slot for every literal in a body -- construct,
pass, destroy, construct again -- and `objVariableTypes` names it, so the
decompiler declares it and emits an assignment per literal:

```
local_6 = "wargrounds";
starting_map = get_map_slot(local_6);        // get_map_slot("wargrounds")
```

It is behaviour-identical, and it is most of what is left. **Sized by
asking the output**, per literal assignment, by how many times that
value is read before the slot is written again:

| | Super Egg Hunt | Paladin of the Sky |
|---|---:|---:|
| read once, slot reused after | 408 | 1,897 |
| read once, slot used once | 17 | 144 |
| read three times or more | 40 | 229 |
| assigned and never read | 1 | 6 |
| **total `local_N = "...";`** | **468** | **2,281** |

So about 90% are read exactly once per value -- 425 lines of Egg Hunt's
5,780 and 2,041 of Paladin's 25,942, **near enough 8% of the output on
each**. And the 83-87% that reuse the slot say the fold has to be per
VALUE rather than per slot, which is how `temp_bound` already works.

#### ...and the engine names the discriminator outright

The question a fold like this has to answer is the one this file keeps
calling unanswerable: did the source NAME this slot? For a string it is
answerable, because the two cases call different functions. Counted over
the window `STR ; <factory> ; PshRPtr ; PSF v ; CALLSYS ?`:

| what consumes the literal | Super Egg Hunt | Paladin |
|---|---:|---:|
| `string::string(const string&in)` -- a copy-constructed TEMPORARY | 544 | 2,759 |
| `string& string::opAssign(const string&in)` -- a DECLARED local | 2 | 20 |

**And the first reading of that was too strong, so here is the accurate**
**one.** A copy construction is an *initialisation*, and a declared local
is initialised too -- `string s = "x";` copy-constructs into `s`. What
the split really says is that **`opAssign` is a RE-assignment to a slot
already constructed**, which only a declared local has: a temporary is
constructed at each use and destroyed after it. So Paladin's original
re-assigns a string local 20 times and its recovery writes 2,281 such
lines, which is the mismatch; the constructor alone does not name the
case.

What separates a reused temporary slot from a declared local is therefore
**how many construction SITES target it**. A declared local is
constructed once, where it is declared; the compiler's scratch slot is
constructed afresh at every use, which is exactly the 83-87% the census
above calls "slot reused". Two sibling scopes each declaring a local at
one offset would give two sites and be folded, which is behaviour-
identical and reads better, so the error that costs anything is the other
one -- a single-site temp staying a variable, which is the status quo.

Two independent counts agree closely: 2,759 copy-constructions against
2,041 literal assignments read once, in a title where some literals are
arguments never parked in a slot at all. That agreement is the reason to
believe the sizing; the mechanism above is what the rule has to turn on.

**And the lever is already in place**, which is what makes this worth
trying rather than guessing at. The constructor handler branches on
`self.is_named(dst.offset)`: a named slot gets `_emit_assign` and an
unnamed one goes to `temps` with `temp_bound` set. So routing a reused
slot's construction down the second path puts it under every fold-safety
rule in this file -- `_stale_fold` promotes it if it goes stale, and the
duplicate-bind pass promotes it back to a variable if it is read twice.
The safety net is the existing one; only the classification changes.

#### Done, and narrowed twice on the way

`_reused_object_slot` is the rule, and it takes three things -- two of
them added because the first form broke a title:

1. **More than one construction site at the offset.** Read from the
   instruction stream for the `PSF v ; CALLSYS $beh0` form, and
   discovered during simulation for the `ALLOC` form, which is carried
   into the next pass exactly as a duplicated bind is -- `ALLOC` names
   its destination on the stack, so only a pass that has RUN knows it.
2. **No `opAssign`-family write to the slot.** The engine only
   re-assigns something already constructed, so a slot it re-assigns is
   one the source declared. Without this, Manamon 1's `battle` came out
   with four `local_27 = local_27;` no-ops and that title carried **51**
   self-identical lines against the one it has.
3. **A value that costs nothing to re-evaluate** -- in practice a
   literal. This is the one that matters, and the measurement that
   forced it is the worst kind of defect in this file.

##### The shape that forced the third condition

Without it the rule is much bigger -- Crazy Party **190,735 -> 162,719
lines**, Egg Hunt's round-trip edit distance 13,950 -> 7,145 -- and it
duplicates calls, because the duplicate-read counter cannot see these
reads. Manamon 1's `handle_beta_registration`:

```
before:  local_9 = input_box("Registration", "Please enter the key ...");
         if (local_9 == "" && ...) exit();
         if (!varify_key(local_9)) { ... }
         key = local_9;

after:   if (input_box(...) == "" && ...) exit();
         if (!varify_key(input_box(...))) { ... }
         key = input_box(...);
```

-- **the player is asked for the key three times**, which is the
`file_menu` defect again, and 111 more call sites across that title
(`menu_get_item_name` +44, `input_box` +8, `url_get` +6). Slot 9 has six
construction sites and no `opAssign`, so it looks exactly like scratch.

**Why nothing promoted it back** is worth recording, because it is the
same incompleteness this file records for the lost call: `fold_reads` is
counted in `_read_temp`, and these reads never reach it, so a value read
three times has no entry at all and the duplicate-bind pass has nothing
to act on. Lowering the threshold for such binds was tried and is inert
for the same reason.

A literal cannot have that problem: re-evaluating it duplicates nothing.
And it is where the mass is anyway, so the condition costs less than it
sounds.

##### And one attempt that was worse than both

Taking the decision ONCE, before the simulation, by dropping the slot's
name -- which is the tidier design, since routing a *named* slot's
construction to `temps` leaves it half a variable. It is worse: an
unnamed slot folds into every read, so Egg Hunt's call count went 1,608
-> **1,669** and Paladin's 6,952 -> **7,000**. The half-measure is the
one to keep, which is not the conclusion the design argument predicted.

##### What it cost and what it fixed

| title | lines | goto | split | calls read back |
|---|---|---|---|---|
| Super Egg Hunt | 5,780 -> **5,262** | 0 | verified | 1,608 |
| Paladin of the Sky | 25,942 -> **23,392** | 0 | verified | 6,952 |
| Psycho Strike | 25,870 -> **24,367** | 2 | verified | 6,406 |
| Crazy Party | 190,735 -> **174,547** | **14** | verified | 90,145 |
| Manamon 1 | 89,712 -> **83,318** | 0 | verified | 26,481 -> 26,482 |

`local_N = "...";` lines: Super Egg Hunt **468 -> 20**, Paladin
**2,281 -> 126**, Manamon 1 **6,493 -> 826**. Not one residual goto
moves, every split verifies, all three `bgt audit` comparisons are
identical on every title, `bgt libcheck --decompiler` holds at 39/46,
43/46 and 144/148, and `bgt oracle` is **51/51**.

**And the round trip is the number this was for.** Both titles that can be
built here, measured against their own originals:

| | edit distance | of the original | bodies identical |
|---|---|---|---|
| Super Egg Hunt, before this session | 19,504 | 68.3% | 29 / 137 |
| ...after the dead-handle fix | 13,950 | 48.8% | 29 / 137 |
| ...after this | **8,298** | **29.1%** | **30 / 137** |
| Paladin, after the dead-handle fix | 72,029 | 56.1% | 271 / 798 |
| ...after this | **36,799** | **28.7%** | **292 / 798** |

Both still `compiled cleanly`. Super Egg Hunt's distance has more than
halved across the session and Paladin's has very nearly halved in one
change, which is the most any single change here has moved it.

Two defects fall out of it, and neither was the target:

- **Paladin's receptionist reports the right floor.** The wrong-floor
  defect two sections up needed the stale-fold widening that was
  rejected for costing 1,567 lines; it does not need it any more.
  Folding the literal scratch slot away means slot 6 is no longer a
  variable carrying two different map names, so each `world[...].name`
  is rendered where it was computed:
  `string_trim_left(improve_map_name(world[your_cabin].name), 6)` for the
  room and `improve_map_name(world[your_floor].name)` for the floor,
  which is the original.
- **Manamon 1's pause menu gets its seventh item back.** This file
  records it as one of the two lost calls *the census cannot see* --
  masked because all six surviving `menu_add_item` lines read
  identically. With each literal folded into its own call the texts are
  distinct, nothing masks anything, and the body goes from six items to
  seven: Party, Inventory, Manapedia, Save Game, Exit game, Unknown
  Gifts, Options. **So the fix for that one was not the wider signal at
  all**, and the signal is still worth building for the other half
  (`coin::act`, which never reaches a slot).

The cost is **five self-identical no-op lines** -- one in Paladin's
`map::deserialize` and four in Manamon 1 -- where a literal construction
folds and a following `opAssign` renders `local_1 = local_1;`. Harmless
and ugly, and counted here rather than suppressed, because this file
already records two `x = x;` lines that are the ORIGINAL's own and a
blanket suppression would lose them. Manamon 1's `double_assign` goes
**20 -> 14** in exchange, and Paladin's stays at 6 with the receptionist
row replaced by a benign `arg0 = string_reverse(arg0);`.

### What it says the distance is MADE of

Bucketed over all 108 of Super Egg Hunt's differing bodies rather than
sampled, because the first two bodies opened said two different things and
neither was evidence about the rest:

| opcode | added | removed | net | bodies |
|---|---:|---:|---:|---:|
| `RefCpyV` | 1,245 | 232 | **+1,013** | 74 |
| `PopPtr` | 1,030 | 12 | **+1,018** | 74 |
| `FREE` | 1,005 | 129 | **+876** | 74 |
| `PshVPtr` | 895 | 69 | **+826** | 81 |
| `NOT` | 31 | 263 | -232 | 70 |
| `SetV1` | 94 | 261 | -167 | 75 |

The first four are one shape in three quarters of the bodies: **an object
slot the compiler materialised, declared and assigned as a source local**.
That is the dead handle alias, and fixing it is the measurement above --
see **...and the window was hiding 353 dead assignments in one title**.

The `NOT`/`SetV1` rows are the other half and are not a defect: the
original computes `!x == false` through `NOT` and `CMPi` where the recovery
writes `if (x)`, which is the bool-literal simplification this file records
as deliberate. It is behaviour-identical and it is still distance, which is
worth knowing before reading every row as a bug.

### Two things it found immediately, neither of them the thing it was for

**Paladin's receptionist tells you the wrong floor.** `handle_file_menu`
builds one greeting out of two map names, and the bytecode keeps each in
its own slot:

```
PshG4 your_floor ; PshGPtr world ; opIndex ; ADDSi map::name ; RDSPtr
ALLOC string                            ; slot 6 = world[your_floor].name
VAR 6 ; PSF 16 ; CALL improve_map_name  ; ...read AT ONCE, into slot 16
PshG4 your_cabin ; ... ; ALLOC string   ; slot 6 REBUILT, cabin this time
VAR 6 ; PSF 12 ; CALL improve_map_name  ; read again, into slot 12
```

so the source is
`"...Your room number is " + string_trim_left(improve_map_name(world[your_cabin].name), 6)
+ ", located on " + improve_map_name(world[your_floor].name)`.
The recovery renders

```
local_6 = world[your_floor].name;          // dead
local_6 = world[your_cabin].name;
... string_trim_left(improve_map_name(local_6), 6) ... improve_map_name(local_6) ...
```

-- **both calls get the cabin's name** and the first assignment is lost.
It is the `get_percent_of_range` family again (rule seven, the slot test),
reached through a **string** slot: slot 6 is written by a *behaviour*
(`PSF 6 ; CALLSYS string::_beh_0_`), which `slot_writes` cannot see, and
rule ten closed that hole only for a value that IS a slot. The value here
is `improve_map_name(local_6)`, a computed one, which rule ten excluded --
measured, because counting behaviour writes for computed values made every
string literal's scratch slot a write and cost Paladin's `map::deserialize`
56 lines. So the exclusion has a price and this is it. Not fixed here; the
narrowing to try is a behaviour construction into a **named** slot only,
since the literal scratch slots that caused the 56 lines are unnamed temps.

**It is pre-existing, and the dead code was MASKING it.** The same two
assignments and the same two reads are in the recovery at the commit
before, and `bgt signatures` did not report them, because
`@local_13 = world;` sat between the two assignments and its
`double_assign` pattern wants a name assigned twice *in a row*. Removing
353 dead statements is what let the sweep see it -- so Paladin's
`double_assign` row count going 5 -> 6 and Psycho Strike's 11 -> 12 is the
instrument getting sharper, not the recovery getting worse. **A signature
count rising is not automatically a regression**, which is the opposite of
how this file has read that number until now, and the way to tell is to
diff the two trees at the row rather than trust the count.

**And a substituted stock file can add declarations the game never had.**
The round trip reports `number_speaker::set_sound_object` and
`number_speaker::stop` as existing only in the REBUILT module. Super Egg
Hunt's own `number_speaker` declares four bodies -- the constructor,
`speak`, `speak_next`, `speak_wait` -- and BGT 1.3's shipped
`number_speaker.bgt` declares those plus those two, so the game was built
against a different version of that file and the substitution introduced
two methods the original program did not have.

`_why_not_stock` checks members in **one direction only** -- "the game's
class has a member the engine's does not" -- while this file's own rule is
that methods must agree *in both directions*. The two extra are dead code
and compile, so nothing reports them; they are still two declarations that
were not in the program. The fix is not simply to decline the substitution:
those three bodies are the calibration above, byte-identical because they
ARE the engine's source, and declining would trade them for decompiled ones
that differ. Taking the engine's file and **dropping the members the game's
module does not declare** gets both, and stripping is already how `#include`
and `funcdef` lines are handled there. Recorded, not done.

### The receptionist, run down -- and the sixth rejection

The wrong-floor defect above was chased to its cause, and the cause is
**a third place that writes an object slot, which nothing recorded.**

This file already has two: `slot_writes`, built from opcodes that name a
slot in an operand, and `behaviour_writes`, which catches a constructor
reached as `PSF v ; CALLSYS $beh0`. The commonest object construction in
the corpus is neither:

```
PSF 1 ; STR "Product_Id" ; CALLSYS _string_factory_ ; PshRPtr
      ; ALLOC string string::$beh0
```

`ALLOC` names its destination on the **stack** -- pushed deepest,
because the constructor pops its own arguments first -- so no operand
mentions slot 1; and the `PSF` that pushed it sits four instructions
back, before the literal and the factory, so the `PSF`-adjacency rule
cannot see it either. Two places answering one question is the shape
this file keeps recording; this was a third place that answered it
**nowhere**.

`_alloc` records it now, as the simulation passes it, which is all
`_stale_fold` needs -- it asks whether a write lies between a bind and a
read, and every write before the current position is already in. **On
its own it changes no output**: all four recovered trees that can be
measured here are byte-identical with it and without it, because the
rule that would consult it is gated. So it is a condition rather than a
fix, in for the same reason the `CallPtr` one is: the next title to need
it should not have to pay for finding it again.

#### The gate, removed and measured and put back -- the sixth rejection

`_stale_fold` consults `behaviour_writes` only for a value that IS a
slot, and this file justified that narrowing as costing 56 lines "for no
correctness at all". **The lines were right and the "for nothing" was
wrong**, which the round trip is what found: the receptionist's folded
value is `improve_map_name(local_6)`, a COMPUTED value, so the gate let
it through and it was re-read after slot 6 had been rebuilt.

Removing the gate fixes it exactly:

```
local_6 = world[your_floor].name;
local_16 = improve_map_name(local_6);        <- the floor, taken FIRST
local_6 = world[your_cabin].name;
local_16 = (... string_trim_left(improve_map_name(local_6), 6)
            ... ", located on " + local_16 ...);
```

and it is **safe on every count this file measures**:

| title | lines | goto | split | calls |
|---|---|---|---|---|
| Super Egg Hunt | 5,780 -> 5,786 | 0 | verified | 1,608 |
| Paladin of the Sky | 25,942 -> 26,000 | 0 | verified | 6,952 |
| Psycho Strike | 25,870 -> 25,870 | 2 | verified | 6,406 |
| Crazy Party | 190,735 -> 191,844 | **14** | verified | 90,145 |
| Manamon 1 | 89,712 -> 90,106 | 0 | verified | 26,481 |

Not one residual goto, call count or split check moves, `bgt signatures`
**improves** -- `double_assign` 3 -> 2 on Egg Hunt, 6 -> 5 on Paladin
(that row is the receptionist) and 20 -> 13 on Manamon 1 -- and the suite
and the oracle pass.

**It was still put back, and the round trip is what decided it.** The
+1,567 lines are concatenation chains decomposed into one statement per
link:

```
before:  local_4 = (("The garden..." + get_possessive(local_4))
                     + " back give " + this.name + ...);
after:   local_22 = "The garden like collection of plants on ";
         local_21 = get_possessive(local_4);
         local_2  = (local_22 + local_21);
         ...
```

Both are correct -- seven of Manamon 1's `double_assign` rows were
already right before the change, so that count falling is not seven
fixes. What the chain decomposes for is that **every string literal is
constructed into a NAMED scratch slot**, so a value mentioning one is
stale by this rule. And asked of the goal rather than of taste, the
round trip says it buys nothing: Super Egg Hunt's edit distance goes
**13,950 -> 13,959**, nine instructions the wrong way, because the
compiler recombines what the decomposition split.

So: safe, one confirmed defect fixed, 1,567 lines of readability spent,
and no movement toward byte-for-byte. **The order is what is wrong, not
the rule.** The cost is entirely those named literal scratch slots, and
folding them away is the change one section down -- after which this one
costs almost nothing and still fixes the receptionist. It is recorded
here with its five-title table so the next attempt starts from the
measurement instead of re-deriving it, which is the whole point of the
five rejections above.

### ...and a third: a retained range guard is the COMPILER's, not source

`day_to_word` comes back 148 -> 253 instructions, and part of that is the
string class above. The rest is the range guard, emitted **twice** in the
rebuild where the original has it once:

```
original:  CMPIi v0 31 ; JP exit ; CMPIi v0 1 ; JS exit ; CMPIi v0 12 ; JMPP
rebuilt:   CMPIi v3 31 ; JP exit ; CMPIi v3 1 ; JS exit
           CMPIi v3 31 ; JP exit ; CMPIi v3 1 ; JS exit     <- again
           CMPIi v3 12 ; JP ... ; JMPP
```

because the recovery writes

```
if (arg0 <= 31) { if (arg0 >= 1) { switch (arg0) { case 1: ... } } }
```

and the compiler then emits the switch's OWN prologue bound on top of the
two `if`s. This file records why one guard is kept -- *"One table keeps
its guard, because then the guard's target IS the switch's exit and the
`if` is a redundant bound rather than a wrong one"* -- and that reasoning
stands: dropping every guard is what made a merged chain's later cases
unreachable.

What the round trip adds is that **the guard is not in the source at
all.** The original's two compares are the compiler's own switch prologue,
so the author wrote a bare `switch` and the recovery has reconstructed
the prologue as an `if`. Behaviour-identical, and unfaithful. The shape to
look for is a retained guard whose bounds are exactly the switch's own
case range -- that one is the prologue and can go, where a guard that
bounds something narrower is a chain link and must stay. Recorded, not
done; it needs the chain cases measured, which is what broke the last two
attempts at this.

### What it cannot do

**It needs a build, so it needs the engine**, and a whole-title compile
puts BGT's modal report on the screen of whoever is at the machine -- the
cost this file records from three directions. So it is a thing to run
deliberately: on a title that compiles cleanly the dialog is the success
one the driver dismisses, and on one with 24,916 errors it is an 8.9 MB
window. Super Egg Hunt and Paladin are the two that compile cleanly here.

And it cannot be run at all for a title whose own runtime is missing or
whose fork the installed BGT cannot parse, which is Manamon 1 and Manamon 2
-- the same restriction as the compiler column of the standings, for the
same reason. The bytecode audits are what cover those, and they cost
nothing.

## Run as a script, a game takes its developer path

`bgt compile --run` and double-clicking a recovered entry script both *run*
it, and `get_SCRIPT_COMPILED()` is false for a script. A game that branches on
that does not take the path its players see.

Paladin is the clearest case and it cost a wrong diagnosis. Its recovered
build played no audio and looped through the TTS voice selector -- arrows
cycling voices, enter saying "success", nothing else -- which reads exactly
like a decompiler bug in `dynamic_menu`. It is not. An instrumented build,
with an `alert` before every `return -1` in `run_extended` and one printing
what `file_menu` received, fired **none of them** and reported

```
Please enter command line code
```

which is Paladin's own uncompiled-build prompt. `file_menu` was never
failing. Four of the ten `get_SCRIPT_COMPILED()` sites in that title gate
sound loading, so a script run has no pack open and no voice configured, and
the selector is where it sends you.

So **run mode proves the module reaches the engine and nothing about
behaviour**, and the way to exercise a recovered game is the executable:
`bgt compile --build release`, which works now (see **`--build` built nothing
at all** above -- for a long time it did not, and quietly). The lesson for diagnosing the next one is the
cheap part: an `alert` before each suspect return answers in one run what
reading the source argues about for an afternoon.

## A recovered game keeps its own licensing, and reads the same store

Worth knowing before concluding that a port behaves differently from the
original. A game's registration check is ordinary script code, so it recovers
like everything else and **still runs**: Super Egg Hunt's `match_id` and
`register_check` come back in full, the latter called from inside the menu
loop, and it `exit()`s the process when the stored id does not match.

It reads the *same* store, too. `game_data.setup("LWorks", "Super Egg Hunt",
false)` keys the settings by company and product rather than by executable
path, so a recovered build sees whatever the installed original wrote. A
registered install stays registered in the port, and an unregistered one
stays unregistered -- neither is something the recovery changes.

### A head-tested loop whose `continue` is in the middle of its body

The worst shape in this file so far, because what it broke was a *feature*
rather than a line: Paladin's recovered build could not be registered at
all, and nothing reported anything. The project recovers with 0 residual
gotos, a verified split and `compiled cleanly`, and the game runs.

`register_software` prompts for a name, then for a key, and validates:

```
L1: SetV1 t,1 ; CpyVtoR4 t ; JLowZ L4   ; a literal while(true); exit is L4
    key = input_box("Key", ...)
    JLowZ L5                            ; key != "" -> L5
    if (get_last_error() == -12) { "cancelled."; return; }
    "This box cannot be left empty."
    JMP L1                              ; <- the CONTINUE, mid-body
L5: if (get_key(name) == key) { ...write...; "successfully"; return; }
L7: "Sorry, the name and key you provided appears to be invalid."
    JMP 0 -> L4                         ; <- the BREAK, target is the NEXT event
L4: if (done) return; else JMP L3       ; back to the name prompt
```

Three separate things have to be right, and all three were wrong:

- **The loop's extent is the header test's exit target, not the last back
  edge.** `plain_latches[-1]` claims the last backward jump to a header as
  the loop's tail. Here that jump is a `continue` in the *middle* of the
  body, so the body was cut off at it -- and the forward `JLowZ L5` over it
  then looked exactly like a `break`. The validation ended up inside the
  branch where the key was left **blank**, compared against `""`.
- **A conditional header is a head-tested loop, not a `while (true)`.** The
  plain-latch path claimed the header *branch* itself, so the loop's own
  condition came out as a nested `if (true)` inside `while (true)` -- the
  visible tell that the header test was not read as the loop's.
- **A `break` whose target is the next instruction compiles to `JMP 0`.** A
  jump to the next event normally skips no source action and is dropped as
  a fallthrough. Falling through stays *inside* the loop, though: at the end
  of a body it goes round again. Dropped, an invalid key re-prompted for the
  key instead of returning to the name, and the `if (done) return;` after
  the loop became unreachable.

So an entered key was never checked and a blank one was checked against the
derived key: **registration could never succeed**, which is how it was
reported.

**The guard has to be narrow, and the first version was not.** Demanding
only that the header branch past the latch cost Paladin's
`storyline_scroll` a residual goto -- which is a compiler error, so the
project stopped compiling -- because with the plain-latch path refused and
nothing else claiming it, the loop was not recognised at all. What separates
the two is whether any event sits **between the back edge and the header's
exit**: those events are the rest of the body, and losing them is the bug.
Where the back edge is the last event before the exit, the `while (true)`
reading loses nothing and is what every other title relies on.

Measured against the commit before it, on the four titles that can still be
measured here:

| title | lines | goto | split | compiler |
|---|---|---|---|---|
| Super Egg Hunt | 6,231 -> 6,229 | 0 | verified | compiled cleanly |
| Paladin of the Sky | 27,208 -> 27,200 | 0 | verified | compiled cleanly |
| Psycho Strike | 27,307 -> 27,293 | 2 | verified | 34, unchanged |
| Crazy Party | 188,904 -> 188,902 | 14 | verified | not re-measured |

Super Egg Hunt's **written project is byte-identical** -- its two lines are
in the one-file render of a file that is replaced by BGT's own source -- and
`bgt libcheck --decompiler` is unchanged on both titles it can score, 39/47
and 43/47. Not one goto count moved, which for a structurer change is the
number that matters.

It also de-nested two real Paladin blocks that were wrapped in `if (true)`:
the air-hockey prompt, which now recovers the `continue`/`break` pair the
source wrote, and the whole coin-transfer routine.

**And a wrong diagnosis came first, from reading the output instead of the
header.** The rendered source is entirely consistent with L5 being the
loop's *exit*, belonging after it -- every line of it. Only the header's own
`JLowZ L4` says otherwise, and L4 is past L5 and L7.

### What a probe over the recovered path does and does not settle

Worth doing before blaming a decompiler, and worth writing down because it
came back ambiguous. A probe that renames the game's `main`, calls
`setup_registry()` and reports only booleans and lengths -- never the stored
name or key -- says:

```
is_registered=0  username_len=11  key_len=9  derived_len=9  derived_matches=0
```

So the store and the value names are right (BGT puts them under
`HKCU\SOFTWARE\Games\<company>\<product>`, with the `Games\` prefix the
`settings` type adds), the values are read, and `get_key` returns a key of
the right shape -- `string_left(4) + "-" + string_trim_left(4)`, nine
characters -- that **disagrees with the stored one**.

And `get_key` is faithful. It was checked against the bytecode instruction
by instruction: both loop bounds (948, 296), `string_hash(s, 2, true)` then
`string_hash(s, 2, false)`, the special iterations 400/490/750/911, 149, 479
and `(i > 679) && (i <= 687)` from `JP`/`TNP`, the clamp at 60, `MULIi 4 6
2`, the three `string_mid` triples, the `"-"` separator and the `opAdd`
nesting. `remove_character_from_string` matches too, down to `ADDIi 4 -2 1`
for the `arg1 + 1`.

So the disagreement is **not explained**, and that is the honest state. What
it is not: the recovered `register_software` cannot have written those
values, since the only `write_string` pair sits behind the comparison that
fails. The remaining candidates need the title's *own* executable to
separate, and that is exactly what is no longer on this machine -- so the
next step is to fix the entry flow and register again, because the broken
flow could never have accepted anything.

## The screen-reader client, which decides whose voice the game has

These are audio games, and a recovered one that calls `screen_reader_speak`
needs `nvdaControllerClient32.dll` beside its script to reach NVDA. Without
it the engine **does not fail** -- it falls back to SAPI, so the game talks,
in the wrong voice, and nothing in any report says why.

BGT ships both clients under `redist/screen_readers/`, so `bgt recover`
copies them in rather than mentioning them: `nvdaControllerClient32.dll` for
NVDA and `SAAPI32.dll` for System Access. Only when the module actually calls
one of the `screen_reader_*` APIs, which is what makes it evidence rather
than a DLL scattered into every project, and a client BGT does not have is
reported with the consequence rather than skipped.

**The ZIP had the same ordering bug as the stock library files.** Plugin DLLs
were copied *after* the archive was written and appended to `project.files`
afterwards, so they were listed in `recovery.json` and absent from
`game_project.zip` -- and the archive's own "holds n of m files" check ran
before the append, so it passed. Everything a project needs beside its script
is now copied before the ZIP.

## The other way a game needs a DLL: the script loads it itself

`elias` is a type a *plugin* registers, and `plugin_dlls` finds its DLL by
matching the file's stem against a type the module uses but does not
declare. That is good evidence and it is the wrong shape for the second
case, which leaves no trace of that kind at all.

**BGT ships a `library` type**, and it is stock, documented and ordinary.
Read out of `bgt.exe` -- the registration block is one function, so the
whole interface comes out together:

```c
RegisterObjectType      ("library", 0, asOBJ_REF)   // size 0, flags 1
RegisterObjectBehaviour ("library", FACTORY, "library @f()", ...)
RegisterObjectMethod    ("library", "bool load(const string& in)", ...)
RegisterObjectMethod    ("library", "bool unload()", ...)
RegisterObjectMethod    ("library", "dictionary@ call(const string& in, "
                         "?&in param1=null, ... ?&in param10=null)", ...)
RegisterObjectMethod    ("library", "bool get_active()", ...)
```

Three things there that the help file does not say. `call` takes **exactly
ten** optional parameters, where the documentation writes the whole tail as
`? list_of_parameters`. There is an undocumented **`active` property**. And
the signature is a `const string& in`, so a script names its DLL with an
ordinary **string literal** -- no type, nothing for `plugin_dlls` to match.

### What `library::call` does, read rather than inferred

`library_structure` -- the registered-but-undocumented type -- is one
resolved export: the decompiled `GetProcAddress` site reads the symbol name
out of a `std::string` at `+0x64`, stores the `FARPROC` at `+0xA4`, and on
failure formats `GetProcAddress failed for '%s' : Error code %d` and
**throws a C++ exception**. So a missing *export* is a runtime error
(`library exception (%s)`), not a `false` from `load`. The signature string
is parsed first, with `Signature parse error "..."` when it will not go; the
token tables beside it (`CDECL STDCALL FASTCALL PASCAL cdecl ...` and
`FAR EXPORT const volatile struct class enum WINUSERAPI WINAPI __in_opt
__in`) say it accepts a C declaration with a calling convention and skips
the Win32 and SAL decoration. I did not reverse the grammar past that, and
nothing here depends on it.

### Manamon 2 is the live case, and it would have been left behind

`sqlite3_legacy::load_library` calls `library::load("sqlite3.dll")`, and the
game ships `sqlite3.dll` beside `rpg.exe` with `Unable to locate
sqlite3.dll.` as its own error text. Recovered without it the project
compiles, runs, and loses whatever that database held -- the same shape as a
missing asset pack, one layer over, and `bgt recover` had no way to see it.

`script_loaded_dlls` brings it, on the same pair of evidence the pack search
uses, because neither half is enough alone: the **name** comes from the
module's string constants, since the call site passes a local; the
**filter** is a PE file of that name sitting beside the executable. The
module must really call `library::load` or `library::call`, or any `.dll`
mentioned anywhere would qualify -- and a system DLL is never brought, which
matters because a game folder may well hold one. On the four titles it finds
`sqlite3.dll` for Manamon 2 and nothing at all for the other three.

It is copied without being called a plugin, and a missing one is a note
rather than a problem: nothing needs it to **compile**. That is exactly why
it was invisible.

## Plugins: a type no stock engine has

Psycho Strike uses `elias`, and the installed BGT 1.3 has no such type, no
plugin directive, and no mention of either. The game's own executable has both
`elias.dll` and the registered `elias @f()`, so the build that produced it had
that plugin compiled in. **Compiled in is exactly right, and the binaries
prove it** -- see **`elias` is a binding compiled into the engine, not a
plugin** above: the type's seventeen methods are registration strings inside
the runtime, `elias.dll` is absent from the import table and loaded with
`LoadLibrary`, and the script methods are a thin binding over about twenty of
the DLL's ninety-two exports. Manamon 2's fork has it too.
`bgt recover` reports it — a DLL named after a type
the module uses but does not declare is evidence, where a list of every DLL in
the file would not be — copies the DLL into the project, and says in the entry
script that compiling needs that engine build. It deliberately does **not**
emit `#include "elias.dll"`: this engine's `#include` takes a script or a pack
file, and handed a DLL it says "Expected identifier".

## A clean compile is not the check that matters

Compiling proves the source is valid BGT and that every call resolves. It does
not prove the program does what the original did: an argument dropped to make
a call match, or a condition inverted, compiles perfectly. So `bgt libcheck`
scores this path too, against BGT's own shipped library -- source nobody here
wrote:

```bash
bgt libcheck work/game_bytecode.bin game.exe --decompiler
```

On Psycho Strike, of the 149 library functions that appear exactly once on
both sides: **144 have the source's exact call sequence in evaluation order**,
4 more are within 80%, and **148 of 149 have its exact string literals**. The
lifter, measured the same way over 155 functions, gets 153 and 155 -- it is
still the better-validated path for reading one function, and this is the path
that compiles.

That check found the duplication the compiler cannot see:
`sound_pool::play_extended_1d` called `reserve_slot()` forty-five times where
the source calls it once and keeps the result in a local. **That is fixed**
-- see the fold rules below, cases one and four -- and `play_extended_1d`,
`play_extended_2d` and `play_stationary_extended` now have the source's exact
call sequence on Crazy Party where all three differed.

**It was never only a readability problem, which is why it is worth stating
plainly.** Running a call once per read runs it once per read: `reserve_slot`
reserves a different slot each time, and Paladin's `file_menu` re-opened its
menu for every comparison it made against the result. A duplication count is
a correctness number.

Where a difference survives, read it as a lead rather than a verdict, and
re-read it after a decompiler change: Super Egg Hunt's `number_speaker.bgt`
differed on `speak_next` before the fold fixes and matches now. Shape
differences that are not defects do occur -- stock ends a loop with
`if(current.handle.playing==false) { slot=i; break; }` where the recovery
writes `if (local_4.handle.get_playing()) { continue; }` and the assignment
after it, which is the same program -- and the way to tell is to read both,
which is what the report is for.

## The engine compiles, so a known answer is available

`bgt libcheck` validates against source nobody here wrote, which is the right
instinct and reaches 149 of a title's 926 bodies. **The stronger version is to
write the source yourself**, because then the answer to "what should this do?"
was decided before the bytecode existed:

```bash
bgt oracle                 # one command; needs only a BGT install
```

```
oracle.bgt  --BGT-->  oracle.exe  --run-->  report A
                          |
                     bgt recover
                          v
                 recovered project  --BGT-->  exe  --run-->  report B
```

A mismatch between A and B is a decompiler defect, named by shape, **with no
game file involved** -- so it lives in this repository, where per-title
findings cannot. The fixture is generated from a string in `bgt_oracle.py`
rather than shipped as data, so this folder still holds only the document and
the Python tools.

Each of the 51 values is chosen because getting it wrong is *silent*. The
`declared_*` family calls a `bump()` that returns a different number every
call, so a fold that duplicates it computes something the source never did;
`counter` is the module's duplication detector, and any duplicated or dropped
call moves it. `temp_in_condition`, `temp_in_short_circuit` and
`ternary_result` are the other half, and they are why "fold less" is not the
fix. The rest are one per bug class this file records: the snapshot across a
mutating call, the stale read across a `remove_at`, the mid-body `continue`,
the clamp, the base-class override, the reused string slot in a `||` chain,
the scattered `switch`, stacked case labels, a guarded compound assignment, a
`do-while`, an out parameter, and a literal above 0x7F.

**It paid for itself on the first run, three times over.** The fixture was
written to settle the declaration idiom above, and it found two more defects
and one stale claim:

- **A recovered project with no types section built no executable at all**
  -- see the empty-script-section note below, which this upgraded from a
  warning to a build failure.
- **A scattered `switch` lost every case after the first table** -- below.
- **The clamp is not open.** This file listed "a computed value bound on one
  path and read past the join" as remaining work in two places. It recovers
  exactly as written, and did so at the previous commit too, so the item had
  simply outlived its fix. A stale open question costs as much as a stale
  number.

**And one it found and did not fix.** `"" + bump() + "," + bump() + ","
+ bump()` answers `3,2,1` from the engine and `2,3,1` from the recovery.
That order is not arbitrary: `opAdd` evaluates its **argument** before the
receiver is pushed, so a left-nested concatenation runs its operands
right-to-left, and the bytecode agrees -- three `CALL bump` into slots 7, 5
and 1, in that order, consumed as `slot1 + "," + slot5 + "," + slot7`.
(That also confirms from the source side what `control::focus` settled from
the bytecode: `text.length()` genuinely runs first there, and the
"order by closing parenthesis" in `libcheck` is the approximation.)

The recovery keeps the first call in the right place and swaps the other
two, because a folded call's statement is positioned by the `opAdd` that
consumes it rather than by the `CALL` that produced it -- and the
innermost `opAdd` is the *last* instruction of the three. It is present at
the previous commit too, so it is not new.

It is **not** in `bgt oracle`, deliberately, so that command stays a
green gate; the fixture above is the whole repro. The exposure is narrow --
it needs two or more impure operands in one concatenation, where a getter is
the normal case -- and the symptom is a string built in the wrong order,
which compiles, runs, and reads perfectly.

#### It was built, measured three ways, and REJECTED -- the fifth

This file said "no new evidence is needed for that change, only the
work". The work was done and the sentence was wrong: what was needed was
a measurement, and the measurement says do not take it.

The mechanism is sound and read rather than fitted. `PshV4` pushes a copy
of a temp's atom and its text is rendered only when a later call pops it,
while `_append_stmt` places that statement at the **consuming**
instruction; every `opAdd` result is an object slot, so each chain link is
its own statement and the links run innermost-first, which is the reverse
of the push order. Giving an operand its own position -- an `origin` on
the atom and a generated local emitted at the bind, exactly as
`_order_out_arguments` does for a deferred out-call -- fixes the order,
and the chain's own statements cannot be reordered because each reads the
slot the previous wrote.

| attempt | placements (Paladin + Strike) | sites fixed |
|---|---|---|
| every placeable value on the stack, prefix-stopped | 50 + 52 | **1** |
| ...only where a later impure call is in the same flow region | 35 + 33 | **1** |
| ...only where the pop order was observed to differ from the push order | 1 + 8 | **0** |

One site, in a title's `calculate_experience_formula`, whose six operands
are pure engine date and time getters -- so nothing observable changes --
against **102 generated locals in 23 files**, +75 lines on Paladin and
+102 on Psycho Strike, and one `bgt libcheck` score moving the wrong way
(Strike 144 identical -> 143, on `control::focus`, which is the case this
file already records as libcheck's own "order by closing parenthesis"
approximation being the thing that is wrong). Super Egg Hunt stays
byte-identical and no residual goto moves, so it is not a dangerous
change -- it is an expensive one that buys almost nothing.

**What tipped it was that the prize had already been taken.** On an older
base the same change removed a real duplication --
`party[recorder.rand(...)].strikes[recorder.rand(...)]`, four rolls where
the source makes one, indexing a different party member than the one whose
strike name it returns and reading off the end at the last index. On the
current base `calls_checked` is **identical on all three titles** with and
without it: the fold-safety rules and the `copy_binds` threshold hoist that
roll already. So the ordering fix, judged alone, is one unobservable site.

Three things the attempt established that are worth more than the diff:

- **A call's own arguments are evaluated right to left by the engine too**,
  so `random(f(1, 10), f(5, 30))` is *already* faithful -- the bytecode
  computes the second argument first and the recovered text evaluates it
  first. The pop order is therefore the wrong oracle: `_call` pops in
  parameter order, so observing it calls a correct rendering "overtaken".
  What would have to be observed is the statement each value lands in,
  since two values folded into one statement are ordered by construction.
- **The operands that matter carry no position to place.** In the one site
  that is wrong, the string operands are object slots consumed as pointer
  atoms with no origin, and the numeric one is only out of order relative
  to *them*. Precision and coverage pull against each other because the
  thing to be ordered is a mix of placeable primitives and unplaceable
  object slots, and only the broad rule reaches both.
- **A guard can go dead without anything failing.** The attempt needed
  "every read so far must still be waiting on the stack" thirteen commits
  ago, when BGT's own `sound_pool::play_stationary_extended` reserved two
  slots where the source reserves one. Instrumented on the current base it
  never fires: the promotion that now takes that slot happens first. Keep
  such a guard on its mechanism, never on a measurement that has expired.

Two things make it a check rather than a demo:

- **A check that cannot run is worse than no check**, because it is counted.
  `OracleError` is distinct from a mismatch and says why: no compiler, a
  build that wrote nothing, an executable that would not start, a report that
  was never written. The NVGT round-trip fixture was inert through 774 lines
  of decompiler change, and that is the trap being avoided.
- **A stale report reads as a pass.** The report file is deleted before each
  run, so a previous run's answer can never be read as this one's.

What it does *not* do is cover a title's own code: 31 shapes are 31 shapes.
It is the fastest way to find out whether a change broke a construct, and
`measure.py` over four titles is still what says whether it broke a *program*.

## Running a GAME's own code, silently

`bgt oracle` runs 51 shapes written here. `bgt libcheck` reaches the
functions BGT ships source for -- 47 to 155 of a title's hundreds. Every
bug ever reported from playing these games has been in neither set, and
the only instrument that has ever found one is somebody pressing a key.

```bash
bgt drive recovered/ --scenario ctrl
bgt drive recovered/ --watch "k_ctrl(1)" --hold KEY_LCONTROL
bgt drive recovered/ --watch "player.x" --hold KEY_RIGHT --for 1000 --every 100
```

It calls any function of a recovered project with any keys held down,
samples any expressions on a clock, and prints a table. The engine's own
`force_key_down(int)` supplies the input and `file::write` the output,
because a BGT script has no stdout: the engine is a GUI program.

**It makes no sound and opens no window**, and both halves were measured
rather than assumed:

- `set_sound_master_volume(-100.0)` is the engine's own registered master
  gain, so a game that loads and plays its whole soundtrack does it into
  silence. These are audio games; a harness that drove them audibly could
  not be run while anybody was using the computer.
- **A forced key does not go through a window.** Asked directly, a script
  with no window at all answers `down=1 pressed=1` after
  `force_key_down(KEY_LCONTROL)` -- which matters twice over, because
  `bgt_compile.check` treats a window of the script's own as an outcome
  and kills the process to report it. The first version called
  `show_game_window` and was killed before it could write its table; the
  run came back `started` with no rows, which reads like a broken
  recovery.

### It reproduces a reported bug and its fix, in both directions

The control-key defect this file records was reported as *"when I press
control to fire the weapon it is like it is stuck"* and found by reading
the bytecode. Driven, with the LEFT control held:

| Field Wars, `k_ctrl(1)` | answer |
|---|---|
| recovered before the fix | **0** |
| recovered after it | **1** |

That is the whole of the defect, in one command, with no sound and
nothing on screen. `k_ctrl(2)` is `key_released` and reads 0 in both,
which is the control that says the 0 means something.

### Three things it has to get right

- **`main` is not in the entry script.** It is one of the game's own
  global functions, so `bgt recover` writes it into
  `includes/functions/part_0.bgt` -- consistently, across every title
  here. `bgt_compile.stage` renames `main` in the script it is handed,
  which is right for a compile-only check, where `-c` means nothing runs
  and disarming is cosmetic. To RUN one, the file that really declares it
  has to be found. It is renamed for the run and **restored in a
  `finally`**, from a copy taken before it was touched: a run that left a
  project with no `main` would look exactly like a broken recovery, and
  the next thing anybody would do is blame the decompiler.
- **The probe lives in the project directory.** BGT resolves everything
  relative against the *script's own* directory -- an `#include` and
  `set_sound_storage("data/bgm.dat")` alike -- and this file already
  records a staged copy one level down being given repointed includes and
  *still* reporting `could not load pack data/bgm.dat.` So it goes in
  beside the entry under a reserved prefix, exactly as `check_project`
  does, and nothing has to be rewritten or guessed.
- **`string(bool)` is `1`, not `true`.** All five of `string(bool)`,
  `string(int)`, `string(double)`, `"" + bool` and `"x" + int` were put to
  the compiler before one was picked, and then the engine was asked what
  they *produce*. A canned scenario expecting the word would have reported
  a correct recovery as wrong, which is the shape this file keeps
  recording.

### What it cannot drive

A game's own main loop, because that loop does not return: Field Wars'
movement lives inside `game()`, so there is no function to call and no
tick to sample between. Driving those needs the loop broken into steps,
which is a change to the recovery rather than to the harness and is not
done here. A tool that implied otherwise would be worse than one that
says so -- and the honest limit is still wide, because an input reader,
a menu helper, a formula and every library class ARE functions.

## When a folded temporary stops being the value the bytecode computed

The fold is **load-bearing**, which is why this took three attempts and two
measured rejections. Promoting every compiler temporary to a variable takes
Super Egg Hunt from **0 residual gotos to 182** and, since AngelScript has no
`goto`, from **0 compiler errors to 187**: a loop condition promoted to a
statement before a jump stops being a loop condition. So "fold less" is not
the fix, and the diagnostic count is not the metric. The question is *when* a
fold stops being faithful, and there are four answers so far. Every one of
them produced a program that recovered with 0 errors, compiled cleanly, ran,
and did the wrong thing -- and every one surfaced in a **menu**, because a
menu is the first thing a player touches and the only part of an audio game
whose misbehaviour is unmistakable from the outside.

**One: the receiver was mutated in between.** `dynamic_menu::add_item` keeps
the length *before* resizing, and BGT ships the source to prove it:

```
int new_index = item_list.length();          // the source: length BEFORE
item_list.resize(new_index + 1);
item_list[new_index].option = filename;

item_list.resize((item_list.length() + 1));  // folded: re-read AFTER
item_list[item_list.length()].option = arg0; // ...out of bounds
```

That is an out-of-bounds write, and Super Egg Hunt's and Crazy Party's
recovered menus both died on the first item they added with `A runtime error
occurred.` (Both titles keep their own `dynamic_menu`, for real edits, so the
stock substitution does not hide it.)

"A statement ran in between" is too broad a test -- it costs 46 residual
gotos, because a value computed before a loop body and read at the latch has
statements in between and has not changed. What is required is that something
ran **that touched what the value reads**: `item_list.length()` is invalidated
by `item_list.resize(...)` and by nothing else in that function, which is
precisely the dependency the source expressed by keeping the result in a
local. A repeatable value -- a constant, a plain variable, `this` -- still
folds, so conditions stay expressions.

Two details in that test are each worth a title:

- **The receiver is the whole expression, not its first word.**
  `this.terrain.getTailleX()` has receiver `this.terrain`; taking the leading
  identifier makes it `this`, and since almost every statement in a method
  mentions `this`, the test matches everything. That promoted a reused scratch
  slot inside two nested `for` loops and cost Crazy Party **4 residual gotos
  and 4 compiler errors** -- caught only because the second title was
  measured.
- **Mentioning a receiver is not touching it.** `@local_7 = this.terrain;`
  reads `this.terrain` and cannot change it. What counts is a call *on* the
  receiver or an assignment *to* it, never its name on the right of one.

With both: Super Egg Hunt **0 gotos, +19 lines, compiles cleanly**; Crazy
Party **0 gotos, 0 errors**, and three of the four `sound_pool` bodies that
differed from BGT's shipped source now match it -- including
`play_extended_1d`, which is where the forty-five `reserve_slot()` calls
were. Only `reserve_slot` itself is left, and that one is a shape difference
rather than a defect (see the section above).

**Two: the value was computed on only one path.** The simulation walks the
bytecode linearly, so a store inside a branch and a read after the join look
like one straight line. `dynamic_menu::run_extended` sets a joystick flag
inside a branch and reads it in the arrow condition after it, and the fold
carried the constant that branch happened to store across the join:

```
if (key_pressed(KEY_UP) || key_pressed(KEY_I) || true)      // always taken
if (key_pressed(KEY_DOWN) || key_pressed(KEY_K) || false)   // dead operand
```

The game launched, spoke its menu, and **the arrow keys did nothing** -- which
is how it was reported, and is not something a compiler or a window title can
tell you. A forward conditional jump that starts before the store and lands
after it but at or before the read says the store is skipped on the other path
while the read happens either way; the value is then promoted, with its
assignment put back at the store's own position. Events are sorted by bytecode
position rather than kept in append order, which is what lets a promotion
insert its assignment where the value was computed instead of where it is
read.

**Two and a half: the rule is about the PATH, and only about the path.**
This test read `value.kind == "const"` before consulting the path, on the
argument that both bugs it caught were constants. A parameter copy proved the
line was in the wrong place. `dynamic_menu::run_extended` opens with

```
bool initial = auto_speak_first;        // the parameter, copied
```

and clears it at **five** sites once the first item has been announced. A
parameter is *repeatable* -- reading it again costs nothing and yields the
same thing -- so the fold took it before the path test could run: every read
became `arg3`, which never changes, and all five `initial = false;` stores
went with it. The block then re-armed `speak_item` on every iteration, so
arrowing to an item and stopping made the menu say its name again, and again,
forever. It is the same defect as `|| true` and `if (false)`, and what decides
it is whether the slot is written again on another path.

So the test is the path, not the kind. It said `const`, then *repeatable*,
and each narrowing left real stores on the floor -- the third one being
`sound_pool`'s clamp, `int true_y = listener_y; if (listener_y <
delta_backward) true_y = delta_backward;`, a **computed** store that folded
away so the call received `delta_forward` and positioned 2D sound from the
wrong y.

**That boundary was measured, and the measurement went stale.** Promoting
computed values was rejected for taking Paladin from 0 compiler errors to 16,
with holds like `__nvgt_hold_7_116 = __nvgt_out_7_215;` as the evidence --
and those names say what really caused it: a *fresh local per promotion*,
which was separately fixed to one name per slot (see below). Re-measured
after that fix, promoting any declarable conditional bind holds all three
titles at 0 residual gotos with a verified split, leaves every `bgt libcheck`
score untouched, and takes Paladin's empty-bodied `if`s -- the signature this
class of bug leaves behind -- from 33 to 9 and Super Egg Hunt's from 5 to 4.
A value with no declarable type still folds, because a slot that cannot be
declared cannot be a variable.

It is worth knowing what else came back with it, because it was never only a
menu bug. `sound_pool`'s distance code is

```
int true_x = listener_x;                        // the parameter, copied
if (listener_x < delta_left) true_x = delta_left;
else if (listener_x > delta_right) true_x = delta_right;
```

-- a clamp, written exactly this way. Folded, `true_x` was `listener_x`
everywhere and both assignments vanished, so every recovered title positioned
its sounds from the **unclamped** coordinate. Nothing reports that: it
compiles, it runs, and the audio is simply in the wrong place.

**Three: the value was computed before a loop and read inside it.** The same
problem through a back edge, and the one that mattered most. `dynamic_menu`
declares `bool speak_item = false;` before its loop, and every arrow branch
inside the loop sets it true; the read at the top of the loop runs once per
iteration while the initialisation ran once. Folded, the loop read

```
if (false) {            // ...speak the current item
```

so **the menu never spoke anything**. Arrowing worked perfectly --
`menu_position` moved, wrapped and bounded exactly as the source says -- and
for an audio game that is indistinguishable from the arrow keys being dead,
which is how it was reported, twice. A read inside `[loop head, back edge]`
whose value was bound before the head is promoted.

Nothing about this is visible to the compiler, to a window title, or even to
`bgt libcheck`'s call-sequence score: `if (false) { speak(...) }` *contains*
the call, in the right order, with the right literals. It took someone
pressing an arrow key.

**Four: the value is read three or more times, and it is a call.** The duplication
`bgt libcheck` had been measuring all along, and it is not a readability
problem. `file_menu` keeps one menu result and compares it three ways:

```
int result = menu.run_extended("Select an Option.", true, 1, true);
if (result == -1) return "";
if (result == 0 || result == -200) return "cancel";
return menu.get_item_name(result);
```

Folded into all four reads, Paladin's recovered `file_menu` **ran its menu
four times**. Every comparison re-opened it, so a selection was consumed by a
comparison and the menu came back — which is what "it keeps putting me in the
tts selection menu" looks like from the player's side.

This one cannot be fixed at the read: by the time a second read proves the
value is used twice, the first has already folded the call inline. So it takes
a second simulation that knows in advance — and `_body` already re-simulates a
function while each pass discovers more, for lvalues, so the fold counts ride
along: pass one records `(slot, bind position) -> folds`, and the next
promotes every pair folded more than once. Counting only *new* pairs each
round is what makes it terminate, since a promoted bind is no longer folded
and would otherwise be rediscovered forever.

**The threshold is three, and it is measured rather than principled.** At two
it cost Crazy Party **36 residual gotos and 36 compiler errors** against 0 --
the same structuring damage every over-broad promotion in this section causes.
The duplications worth catching are far worse than doubled anyway:
`file_menu` reads one result 4 times and `play_extended_1d` read one
`reserve_slot()` 45 times. A two-read duplication is left folded and
`bgt libcheck` still counts it.

**A fresh instance of exactly that, found while triaging the lost
calls.** Crazy Party's `VanneAFermer::placeZone` opens
`PshC4 140 ; PshC4 120 ; CALLSYS random ; CpyRtoV4 4 ; ADDIi 1 4 12`,
so slot 1 holds `random(120, 140) + 12` -- and it is read exactly
twice, once as the terrain's width and once as the loop bound that
places the valves. It recovers as

```
@local_12 = Terrain((random(120, 140) + 12), 1, ...);
local_15 = ((random(120, 140) + 12) - 1);
```

**two rolls, so the map is one width and the loop fills another.** The
bind arrives through `ADDIi` rather than `CpyVtoV4`, so `copy_binds`
does not lower the threshold for it and two reads fold. One more
datum for "the threshold is the wrong lever", and the first instance
of it where the value is a *roll* rather than a menu result.

**And lowering it only for a value that CALLS something is not the narrowing
it looks like.** `_is_repeatable` rejects any text with a bracket in it, so
it cannot tell `do_damage(a, b)` from `(y - backward_range)`: re-evaluating
the second costs nothing, while the first rolls the damage again. Measured,
that removes **561 duplicated calls** from Crazy Party and costs that title
**14 residual gotos -> 30**, which is 16 compiler errors, while Paladin,
Super Egg Hunt and Psycho Strike all hold and compile. The duplications it
would fix are real and some are serious -- Paladin's four hp-drain attacks
each call `do_damage` twice, once to say the number and once to apply it, so
the damage spoken is a different roll from the damage dealt; `walk` calls
`interact_in_location` twice per direction; `get_global_slot` is called
either side of the `remove_at` that changes its answer. It was still
rejected, because 16 new errors on a title that compiles cleanly is not a
trade this file takes.

What the measurement says is that **the threshold is the wrong lever**. The
folds that must stay folded are the ones inside a *condition*, and the ones
worth promoting are in plain statements -- and `stmt_count` does not
separate them, because nested `if` conditions emit no statement between
them. That was tried too: it refolded Super Egg Hunt's
`int(string_to_number(local_29[1]))` into **five** reads, including a
`switch` selector, which HEAD had correctly kept as a variable. Finding the
real distinction is the open work; both wrong answers are recorded here so
the next attempt starts from them.

### Five: the value is an expression built out of a variable

Case one asks whether the *receiver* of a folded call was mutated. A value
that is not a call at all slips past it, and so does `_is_repeatable`:
`arg0.interacts[local_2].mode` is kind `prop` with no call in its text, so
both halves of that test call it repeatable, while the slot it reads gets
reassigned. The test used to ask whether the whole value *was* one variable,
which a property read through one is not.

Paladin's `add_event` is the whole bug in five lines. Replacing an event has
to keep the old interact's mode *before* removing it, because afterwards
there is nothing left to read it from:

```
int mode = arg0.interacts[slot].mode;   // slot 12
arg0.interacts.remove_at(slot);
slot = arg0.add_event(..., gslot);      // slot 2 rewritten
global_interacts[slot].set_mode(mode);
```

Folded, that last line read `arg0.interacts[local_2].mode` with `local_2`
now holding the *new* event's index and the element it named already
removed. `init_events` runs on every load, so **every save that had ever
replaced an event died with `Index out of bounds`** -- reported from a
tester's machine as a seven-frame stack ending in `add_event`.

So the question is every slot the expression *reads*, not whether the whole
value is one. Intersecting the identifiers in its text with the frame's own
names is what keeps a property or method name out of the answer:
`arg0.interacts[local_2].mode` names three things and only `local_2` is a
slot. Super Egg Hunt renders **byte-identical** under this, Paladin gains
two lines and Psycho Strike six, and no title's goto count, split or
`libcheck` score moves -- which is what a correctly scoped fold change looks
like.

### Six, seven and eight: one question asked of the wrong things

`_stale_fold` asks whether anything has run that touched **what this value
reads**. Three things it reads were not in the answer, and each cost a
reported bug. They are one discovery read three ways, which is why they
are here together.

#### Six: the value reads a GLOBAL, which is not one of the frame's slots

`slot_writes` cannot see a global, and `_CALL_RECEIVER` finds nothing in
`current_bgm` or `int(default_volume)` to be invalidated through. So a
snapshot of a global folded straight across whatever ran in between, and
the test came back False through the branch whose own comment says "no
receiver to be invalidated through".

It is the member-snapshot rule one scope out, and it takes the same
argument. `this` is a bare member's receiver because a method can change
any field of its object; a global's receiver is the whole program, because
**any function can write any global.** So an intervening statement
invalidates it if it assigns that global or if it contains a call at all.

Two reported Paladin bugs, one cause:

- **Leaving the pause menu did not bring the map's music back.**
  `pause_menu` opens `string old = current_bgm;`, plays `the_menu`, and
  restores `old` on the way out -- and `change_music` ends
  `current_bgm = arg0;`, which is the whole reason the source saved it.
  Folded, the restore read the global the menu music had already
  overwritten, so it called `change_music(current_bgm, ...)`; and that
  function's first guard is
  `if (lower(current_bgm) == lower(arg0) && music is playing) return;`, so
  it did **nothing at all** and the menu music simply kept playing.
- **The music volume keys were not live.** `waiting` keeps
  `int old = int(default_volume);`, then page down and page up adjust
  `default_volume`, then

      if (default_volume != old) { ...clamp to -24..-4...;
                                   music.set_volume(default_volume); }

  Folded, that guard became `default_volume != double(int(default_volume))`
  -- always false, the steps being whole numbers -- so the keys moved the
  global and never reached the sound. The change only took effect at the
  next track, where `change_music` applies `default_volume` itself, which
  is exactly what "it does not happen live" means from the outside. The
  clamp never ran either, so the value could drift outside its own range in
  the meantime.

#### Seven: ...and the SLOT test was asked only of REPEATABLE values

"Which slots does this value read, and has one been written since?" has
nothing to do with whether the value is repeatable -- and it sat inside the
`_is_repeatable` branch, so an expression **built out of** a reassigned
slot was never asked at all. A cast is kind `call`, so it fell through to
the receiver test, and `_CALL_RECEIVER` finds no `name.method(` in
`double(local_3)`.

Paladin's `get_percent_of_range` is the cost. Its source is one expression
per branch:

```
return int((double)a0 - (double)(a0 - a1) * ((double)a2 / 100.0));
```

and the compiler parks each operand in slot 3 in turn, converting each to
double as it goes. All three `double(local_3)` temps outlived the next
write to slot 3, so all three rendered the same name:

```
local_3 = (arg0 - arg1);
local_3 = arg2;
local_3 = arg0;
local_3 = int((double(local_3) - (double(local_3) * (double(local_3) / 100.0))));
```

-- `a0 - a0 * (a0 / 100)`, with `a1` and `a2` gone and the first two
assignments dead. All three of its callers scale something by the player's
level (`damage /= get_percent_of_range(1, 10, player.level, false)` among
them), so the scaling stopped happening above level 1.

**And the first attempt at this was too broad, measurably.** Hoisting the
test unconditionally cost Super Egg Hunt 0 residual gotos -> **2** -- two
compiler errors on a title that compiles cleanly -- and Paladin a body it
gave up on and 134 duplicated calls. The reason is the guard the
non-repeatable path already carried and the hoist jumped over: **within one
statement the bind and the read are the same moment.** A loop condition
built out of the loop variable is exactly that -- `(local_4 < local_2)`,
with the latch writing `local_4` -- so asked without the guard every such
condition is "stale", gets promoted to a statement before a jump, and
stops being a loop condition. With it, `get_percent_of_range` still
answers, because the compiler's own dead stores into slot 3 are statements
between each bind and its read.

**The shape is worth grepping for**, alongside the empty `if` arm: a name
assigned twice in a row and then read several times in one expression.
Across Paladin there are exactly four, two of them this function; the other
two read the same value at every read and are faithful.

#### Eight: and assigning a FIELD of an object changes the object

`_mutates` asked for a call *on* the receiver or an assignment *to* it, and
`voice.rate++` is neither -- so a snapshot taken before it survived it.
Paladin's `tts_selector` keeps one in each of its six settings branches:

```
int old = voice.rate;
voice.rate++;
if (voice.rate == old) { } else { speak("Rate, " + voice.rate + "."); }
```

Folded past the increment that is `if (voice.rate == voice.rate)`, always
true, with the **empty** arm taken -- so rate, pitch and volume all changed
**silently**, in both directions, and nothing in the TTS selector said what
they had become. Six of them, and the empty arm is what pointed at them:
this file already records that an `if` with an empty arm is a condition
that has lost its value.

**The arm stays empty, and the count does not move.** The source wrote the
announcement in the `else`, so the compiler emitted a branch over an empty
fall-through and that is what the structurer renders:
`if (local_12 == voice.rate) { } else { speak(...); }`. What was wrong was
the condition, not the shape -- so Paladin's ten empty arms are still ten,
and the signature is a lead rather than a metric. The other four are read
and faithful: two are the original's own `if (c) { } else { ... }`, one is
`if (continue_story()) { }`, a call run for the keys it polls, and one is
`if (local_10.is_empty()) { }` in `load()`, where the bytecode is
`CALLSYS dictionary::is_empty ; JLowZ 0 ; LABEL` -- a branch to the very
next instruction with nothing in between, so the original's own `if` body
is empty.

**That last one is worth keeping**, because it is not ours and it explains
a report. `load()` tests whether the deserialized save dictionary came
back empty and then does nothing about it, and the next statement is
`deserialize_all(...)` -- which is exactly the null-pointer trace a tester
sent back from a Paladin build. The guard the author wrote is there; its
body is not, in the shipped bytecode.

#### What these cost, measured -- and the two titles that are not here

Each rule was measured alone before being taken together, because the
first version of the seventh broke two titles and a combined measurement
would have said only that something had. Alone, on the titles that show
structural damage fastest: the global rule gives Paladin +28 lines and
Super Egg Hunt +0; the field-write rule +18 and +0; the slot test, once
narrowed, +15 and +0 with Psycho Strike +12; the width pairing of the
section before this one, +0, +0 and +0. Together:

| title | lines | goto | split | calls | passthru / bodyerr / unbal |
|---|---|---|---|---|---|
| Super Egg Hunt | 6,240 | 0 | verified | 1,608 | 0 / 0 / 0 |
| Paladin of the Sky | 27,335 -> 27,393 | 0 | verified | 7,110 | 0 / 0 / 0 |
| Psycho Strike | 27,446 -> 27,529 | 2 | verified | 6,443 | 0 / 0 / 0 |
| Crazy Party | 192,626 -> 192,686 | **14** | verified | 90,118 -> 90,115 | 0 / 0 / 0 |
| Manamon 1 | 90,852 -> 90,977 | **0** | verified | 26,568 | 0 / 0 / 0 |

Super Egg Hunt is byte-identical; Paladin and Psycho Strike move by the
lines the four rules give back and by nothing else. `bgt libcheck
--decompiler` holds at 39/47 call sequences and 46/47 literals on Paladin,
and every duplication count this file records holds exactly: `do_damage`
13, `interact_in_location` 5, `dragon_strike` 7, `reserve_slot` 8.

**The last two rows were owed for a commit, and they are paid.** The run
was stopped by the host for system memory partway through Crazy Party, so
this section went in with three rows of five and said so; the undertaking
was that if that title's fourteen had moved, the rule that moved them came
out and was recorded as rejected with its number. **They did not move.**
Crazy Party is 14 residual gotos before and after, and they are the same
fourteen labels in the same four files -- `CarteCombat` 4, `part_6` 6,
`Jeu` 2, `CombattantSauvage` 2 -- with the split still verified and
passthrough, body errors, unbalanced files and dangling `else` all 0.
Manamon 1 is 0 before and after. That matters more than the two line
counts, because this is the title the three rejections above were caught
by: 14 -> 30 for a call-text threshold, -> 44 for dropping the
declaration-order rule, -> 90 for forcing on the copy idiom.

**Manamon 1 is also where the diagnosis shows most**, which is the thing a
line count cannot say. Counting the text-side signatures a collapsed value
leaves -- see **The signatures, swept** -- that title goes from 9
self-identical lines to **1** and from 12 tautologies to **4**, and three
of its classes lose the `pool.volume_step = pool.volume_step;` this file
records as unfixed as far as any measurement showed. Crazy Party barely
moves on the same sweep (3 -> 3 and 21 -> 19), which is its own result: a
title that keeps fewer snapshots has less to lose by folding them.

It cost one measurement to find that out, and the measurement was cheap
only because the tools were frozen first. A copy of the committed `tools/`
tree and `BGT_TOOLS` pointed at it is what lets the verdict on a commit be
taken while the working tree has already moved on.

**What is cross-validated is the diagnosis**, which is a different claim
from the counts and is what says the rules are about BGT rather than about
Paladin. Psycho Strike carries every one of the defects and nothing was
looking for them there: `if (base.log_cursor != base.log_cursor)`, a whole
branch that could never run; `this.damage = this.damage;`, a save and
restore around something that changes it, collapsed to a no-op; two
`pool.volume_step = float(double(pool.volume_step));` of the same shape;
its own copy of `get_percent_of_range`, wrong the same way; and 10,425
instructions of flattened `voice_set` counts. All of them come back.

Counting lines whose two sides are textually identical -- the signature a
collapsed snapshot leaves -- gives the same answer from the other
direction, and that count is `bgt signatures` now: see **The signatures,
swept** below for all five titles measured by one instrument, including
the two this paragraph used to say the run had not reached. Manamon 1 goes
**9 -> 1** on it and loses the `pool.volume_step = pool.volume_step;` in
three of its classes that this file recorded as unfixed.

**And both of Paladin's survivors are the original's own, but not both
`arg0 = arg0;`.** One is, confirmed against the bytecode as `VAR 0 ;
PshVPtr 0 ; GETOBJREF 1 ; CALLSYS string::opAssign`. The other is
`breakfast_time`'s
`global_interacts[receptionest_slot].speech = global_interacts[receptionest_slot].speech;`,
and its bytecode is two operations rather than one:

```
ADDSi interact::speech ; GETREF 1 ; CALLSYS string::opAddAssign
PshRPtr                                  ; the reference it RETURNS
ADDSi interact::speech ; CALLSYS string::opAssign
```

-- `speech = (speech += "[/]Oh, and your friend Gabriel's room is ...")`,
which assigns the member to itself after the append. The recovery renders
both operations, in order, which is faithful. The conclusion stands and the
detail was wrong, which is the cost of grepping one signature by hand: a
count is not a list.

### Nine: a global read THROUGH A METHOD on it is still a global read

The sixth rule above is right and was asked in the wrong place. A value
that reads a global goes stale through any call -- any function can write
any global, which is the `this` argument for a bare member one scope out
-- and `_stale_fold` put that question only to a value with **no
receiver**. A global object is almost always read through a method on it,
so the commonest shape a global takes in these games never reached the
rule: `int(default_volume)` was caught and `int(music.get_volume())` was
not.

What decided it instead was the receiver test -- whether a later statement
calls a method on `music` or assigns it -- which is strictly weaker and
cannot see the case even in principle, because the statement that changes
the volume names a handle **alias** of the global:

```
int old = int(music.get_volume());
fade(local_5, music.get_volume(), -20.0, 250.0, false);   // local_5 IS music
storyline_scroll(...);                                    // the scene
fade(local_5, music.get_volume(), double(old), 250.0, false);
```

Folded, that last argument re-read the volume the first `fade` had just
taken down, so the restore faded -20 dB to -20 dB and **the music stayed
ducked** until the next track change, where `change_music` applies
`default_volume` itself. `good_thus_far` and `bomb_hockey` are both of
those, and `battle` is the same rule over `music.get_position()` --
snapshotted before the battle music and read afterwards to resume the
map's track where it left off, so it resumed from wherever the battle
music had reached. "The music is kinda bugged in some places" is three
bodies, and none of them is the music code.

**And the same rule reached a different defect in `rec_timer::real_elapsed`.**
There the folded value is a `dictionary::get` on `recorder.system_data`,
so folding it moved the call PAST the `int(stored)` that reads its own out
argument:

```
CALLSYS dictionary::get          ; fills slot 8, returns the bool in 5
i64TOi 4 8 ; CpyVtoV4 1 4        ; elapsed = int(stored)  -- AFTER it
NOT 5 ; JLowZ                    ; if (!ok)
```

The recovery converted the slot before the call filled it, which is "an
out argument copied before the call that fills it" -- one of the three
bugs the **Conventions** list at the end of this file records as having
compiled cleanly and been caught only by running.

#### The name match is broader than the rule, and two fixes come from that

This is the part worth reading twice. `_stale_global` asks "does this
value read a global?" by taking every identifier in the value's text and
keeping the ones the module declares as globals. **A member whose name
happens to match a global matches too**, and `x.current` does not read the
global `current`.

Manamon 1 declares `character@ current;`, and two of the bodies this
change fixes are fixed through that collision rather than through the
rule:

```
local_8 = int(this.user.stat[0].current);        // restored by this change
heal(local_1, local_12);
this.speak_heal_message(int((this.user.stat[0].current - double(local_8))));
```

Folded, that last line was
`current - double(int(current))` -- **zero** -- so every healing item in
Manamon 1 announced that it had healed nothing, and `magic_restorative`
said the same about magic points. Both are real and both are now right.

**No receiver-based test could have caught them**, which is why the
coincidence is worth keeping rather than tightening away for now: `heal`
changes `this.user.stat[0].current` through `local_1`, an alias taken two
statements earlier, so neither `_CALL_RECEIVER` nor `_INDEX_BASE` nor
`_prop_receiver` names anything an intervening statement mentions. The
only rules that reach it are the "any call invalidates" kind. So the
state of this is: the code is broader than its justification, the breadth
is measured across five titles and costs nothing, and the question it
raises -- whether a member read snapshotted across a call should go stale
unconditionally, the way a global's does -- is measured on eight titles
now and **not adopted**: see **Measured on eight titles, and not
adopted**, which carries the one-clause change and its numbers.

#### What it cost, measured on all five

| title | lines | goto | split | calls |
|---|---|---|---|---|
| Super Egg Hunt | 6,240 | 0 | verified | 1,608 |
| Paladin of the Sky | 27,393 -> 27,254 | 0 | verified | 7,110 -> **6,957** |
| Psycho Strike | 27,529 -> 27,489 | 2 | verified | 6,443 -> **6,403** |
| Crazy Party | 192,686 -> 192,678 | **14** | verified | 90,115 -> **90,105** |
| Manamon 1 | 90,977 -> 90,901 | 0 | verified | 26,568 -> **26,476** |

Not one residual goto moves -- Crazy Party's fourteen are the same
fourteen -- and passthrough, body errors, unbalanced files, dangling
`else` and the split check are unchanged on every title. Super Egg Hunt is
byte-identical. The call counts fall because of the `get` deduplication
below, not because a call was lost: 153 on Paladin, 40 on Psycho Strike,
92 on Manamon 1 and 10 on Crazy Party, every one a `dictionary::get` that
had been emitted twice. `bgt signatures` moves on exactly two titles and
exactly one shape -- Paladin's identity casts 4 -> 2 and Manamon 1's
15 -> 13, which are the four snapshots above.

**The cost is `real_elapsed`, and it is readability.** Promoting one value
advances the statement counter, so the two later `int(recorder.mode)`
reads in that body are no longer bound in the statement that reads them
and promote behind it -- three extra assignments that say nothing. The
cascade is pre-existing rather than new here, and correct-and-noisier is
the right side of that trade.

### Ten: an object slot is written by a BEHAVIOUR, and nothing asked

`slot_writes` answers "has this slot been written since the value was
bound?", and it was built from the opcodes that name a slot. **A string
is not filled by one.** It is filled by pushing its address and calling
the constructor -- `PSF n` then `CALLSYS string::$beh0` -- and emptied by
`$beh2`, so no entry in `_SLOT_WRITE_OPS` mentions slot `n` at all and
the question could not be asked about an object slot.

This file already records that sentence, for `_short_circuit_slots`, one
place over. Two places answering one question with one of them blind is
the shape it keeps recording, and this is the half that was never told.

Manamon 1's `skill::will_fail` is the cost:

```
CALLINTF character::special_immunity        ; fills slot 1, the &out reason
PSF 3 ; PSF 1 ; CALLSYS string::opAssign    ; slot1 = slot3
STR "" ; $str ; PSF 3 ; CALLSYS string::$beh0    ; slot3 = ""
PSF 3 ; PSF 1 ; CALLSYS string::opEquals    ; slot1 == slot3
```

-- `if (reason != "") { arg1 = reason; arg2 = ""; }`. The out string is
taken by value into slot 1, so slot 1's atom reads `local_3`; nothing
could see slot 3 being rebuilt as `""` in between, and the condition came
out `if (local_3 != local_3)`. Always false, so **a skill's failure
reason was never spoken** -- the player got the generic "The move
failed!" every time -- and `unknown_gift::give` took its `else` arm,
"You can't obtain this gift yet.", whatever the real reason was.

Two things make the rule narrow enough to be safe, and both are read
rather than tuned:

- **The receiver of a behaviour is the address pushed LAST**, so only a
  `PSF` immediately before the call counts. In
  `PSF 3 ; PSF 1 ; opAssign` slot 1 is assigned and slot 3 is merely
  read, which is the call-frame rule this file derives from the
  bytecode and confirms from `MakeFunctionCall`. An operator counts only
  when it **assigns**: `opAdd` returns a new value and leaves its
  receiver alone.
- **For a computed value it counts only where the slot is NAMED**, and
  both halves of that are measured. Counted for every slot, every
  string literal's scratch slot becomes a write -- so
  `(arg1 + local_1)`, which merely mentions one, stops folding, and
  Paladin's `map::deserialize` gains **56 lines** of literals pushed
  into slots for no correctness at all. Not counted at all, a value
  whose text reads a named slot folds past the statement that rebuilt
  it, which is a base loading at its own health value -- see **A value
  that reads a NAMED slot after that slot is rewritten** below. The
  narrowing this file prescribed twice is the one that holds: a scratch
  slot is an unnamed temp, and a named slot is one the source declared.

| title | lines | goto | split | calls |
|---|---|---|---|---|
| Super Egg Hunt | 6,240 | 0 | verified | 1,608 |
| Paladin of the Sky | 27,254 -> 27,256 | 0 | verified | 6,957 |
| Psycho Strike | 27,489 | 2 | verified | 6,403 |
| Crazy Party | 192,678 -> 192,693 | 14 | verified | 90,105 |
| Manamon 1 | 90,901 -> 90,913 | 0 | verified | 26,476 |

Psycho Strike and Super Egg Hunt render byte-identical and Paladin moves
by one body -- `input_recorder::start_playing`, where a string copy now
gets a name. Not one residual goto moves.

#### What it found next door, diagnosed and open

`input_recorder::rand` reads an out argument **before the call that fills
it**:

```
211  CALLSYS dictionary::get      ; fills slot 5
215  i64TOi 3 5                   ; int(local_5)   -- AFTER it
216  CpyVtoV4 1 3
```

and the recovery emits `local_1 = int(local_5);` first, so the value
converted is whatever slot 5 held before. That is the defect
`_order_out_arguments` exists to prevent, and the reason it does not
reach this one is read rather than guessed: an out argument is given a
synthesised local only when the slot is **unnamed** or its type
disagrees with the `TYPEID` (`if not self.is_named(off) or wrong_type`),
and only those calls are registered in `deferred_out_calls`. A **named**
slot passes straight through, so nothing records that the call writes it
and nothing can order it.

`rec_timer::real_elapsed` is the same shape and is fixed, by accident of
scope: its receiver is the global `recorder`, so the ninth rule above
promotes the value and the call lands at its own position. `rand`'s
receiver is `system_data`, a member, so nothing reaches it. Fixing it
properly means registering a named slot's out-call too, which is a
change to what gets deferred and wants its own measurement.

### A call whose result NOTHING READS is dropped, call and all

Diagnosed and **not fixed**, with the sites named, because it is the
most serious thing in this file that is still open.

Dropping an expression whose value nothing reads is behaviour-preserving
**only if the expression is pure**, and this file leans on that twice
already: `generate_maze`'s discarded comparison and `sleep_in_bed`'s
overwritten concatenation are both correctly dropped. A **call** is not
pure, and the rule does not distinguish them.

The first `bgt audit` ever run on Manamon 1 is what found it. 701 of its
bodies are missing a call, and 695 of those are a base constructor the
text writes `super()` -- the benign kind this file already records, in a
title with 783 classes. The decompiler-side census that superseded it
finds **six real losses in five bodies**:

| body | lost | what it does |
|---|---|---|
| `sound_pool_item::load_sound` | `load`, `stream` | the sound pool never loads or streams a file |
| `::confirm_entering_cindar_f4` | `enter_confirmation` | the call is the WHOLE function: no confirmation prompt |
| `::confirm_entering_kingdom_f6` | `enter_confirmation` | the same, at the other dungeon |
| `berserk::act` | `random(1, 100)` | the original's own dead roll -- and the next draw picks the confusion target |
| `character::calculate_score` | `local_25(local_13, true)` | a call through a funcdef-typed local, in the high-intellect AI path |

`calculate_score`'s is the subtle one and it needed the bindings read:
`skill::effect_points_formula` is bound at two sites, and one of them,
`sound_wave_formula`, spins a `roulette_wheel_selector` -- which calls
`random`. The original discards the formula's value too, so the only
observable difference is the RNG stream; narrower than `load_sound`, and
real.

`load_sound` is the whole defect in eleven instructions:

```
SetV1 2 0 ; CpyVtoV4 1 2             ; bool ok = false;
LoadThisR stream_sound ; RDR1 2 ; JLowZ L0
    PSF 3 ; $beh0                    ; string tmp = filename
    VAR 3 ; handle ; CALLSYS sound::stream
    CpyRtoV4 2 ; CpyVtoV4 1 2        ; ok = <the result>
    JMP L1
L0: ... CALLSYS sound::load ; CpyRtoV4 2 ; CpyVtoV4 1 2
L1: RET
```

`ok` is written and never read -- the original's own dead local -- so
the recovery drops the store, and the call goes with it. What is left
is `if (stream_sound) { local_3 = filename; return; } local_3 =
filename;`: two branches that copy a string and do nothing. **A
recovered Manamon 1's sound pool loads nothing at all.**

Psycho Strike's three `enemy_count` rows are the same shape and were
triaged as benign on the grounds that `enemy_count` is pure -- which is
true, and is exactly why the shape went unnoticed: the first four
instances anyone looked at were harmless.

**And do not size this defect by counting unread results**, in either
direction. A forward slice over Crazy Party finds **519** `random` call
sites whose value is never observed, and **12** of them are lost; the
other 507 are emitted as an assignment to a slot that got declared or
promoted. "Nothing reads the result" is necessary and nowhere near
sufficient, so the census -- which asks what reached the output -- is
the authority on what is lost, and a result-liveness count is not even
an upper bound worth quoting.

#### Two more are real and the census cannot see either -- one each way

The audit's original six included `coin::act` losing `update_sound_2d`
and `pause_menu` losing a `menu_add_item`, and the census reports
neither. I was about to drop both rows as the audit over-reporting.
**Both are real**, and checking them is what found the instrument's two
blind spots:

- **`coin::act`: the call never reaches a slot at all** -- **fixed.**
  Its `sound_pool::update_sound_2d` leaves its result in the value
  register and the next thing to touch that register was a `Cast`,
  which overwrote it without flushing -- and a `Cast` takes its own
  operand off the **stack**, so the register's pending call has
  nothing to do with it and was simply dropped. The census is built on
  slot binds, so it never saw this half: **a coin's 2D position was
  never updated as it moved.**

  `CpyVtoR4`'s handler has flushed for exactly this reason since the
  value-register work -- its comment says "preserve its side effect
  before the register is reused" -- so this is that rule at the branch
  that did not have it, and the body now reads

  ```
  if (y < 0) { y = 0; }
  game.update_sound_2d(slot, x, y);
  @local_15 = cast<coin_collector@>(owner);
  ```

  It is the one of the 16 unserved overwrites with a named instance
  behind it, which is why it is the one taken: the enumeration says
  where the rule is missing and not which absence costs anything.

  **And it is inert on everything else.** Super Egg Hunt, Paladin,
  Psycho Strike and the `cs` server render byte-identical with it and
  without it, and that server still matches its author's source in 194
  of 196 functions:

  **Enumerated, which this file set as the next step: 27 sites write
  `value_reg`, and 16 of them have no flush above them that could
  reach them.** A flush counts only when it sits above the site at an
  indent no deeper than the branch the site is in -- which is what
  separates an enclosing handler's flush from a sibling branch's, and
  getting that wrong is why the figure took three readings:

  | how "served" was read | answer |
  |---|---|
  | anything above it in the handler | 24 of 27 -- and it counts `STOREOBJ`'s clear for `Cast` |
  | only inside the site's own branch | 5 of 27 -- and it misses the flush at the top of `_call` |
  | above it, at no deeper an indent | **11 of 27**, and **12** since `Cast` was given one |

  The 16 are the register LOADS (`LdGRdR4`, `CpyGtoV4`, `LDG`, `LDV`),
  the two `TEST_OPS` sites, the three property loads (`LoadThisR`,
  `LoadRObjR`, `LoadVObjR`), `PopRPtr`, `STOREOBJ`, `Cast`, `_refcpy`,
  `_alloc` and the three in the constructor branch. **`Cast` is served
  now**, on the strength of the one named instance; the other 15 have
  none, and flushing at all of them is the broad change this file
  records as tried and wrong at a rebind.

  **And the obvious way to find out which of the 16 cost anything does
  not work**, which is worth more than the answer would have been. The
  instrument: walk every body, and for each instruction note whether a
  pending call was live before it and gone after it without being
  written out. It took two corrections -- a cleared marker is the
  NORMAL case when the value was captured into a slot, which it
  counted 798 times on one title; and a `?&out` call is written out
  LATER by `_order_out_arguments`, which it counted five more times on
  the server -- and then answered **0 dropped** on Super Egg Hunt,
  Paladin, Psycho Strike, the `cs` server and Manamon 1.

  Run as a control against a build with the `Cast` flush taken back
  out, it still answers **0** on Manamon 1 -- in a title whose
  `coin::act` demonstrably loses a call there. A `Cast` does not clear
  the marker at all, so the call stays pending and is dropped further
  on, at a point where its text does sit in some temp or register that
  nothing ever reads. Deciding whether that counts as captured IS the
  lost-call question, so a per-step detector cannot answer it: its
  zeros mean nothing, and the post-pass census stays the only sound
  instrument. Recorded so the next reader does not build it again.

  Two things that count stops short of, and both matter before acting
  on it. A **clear** is not a flush: `pending_value_call = None`
  discards the call, and five of the eleven "served" sites are
  dominated by one of those -- legitimately, where the call's text is
  already inside the expression being built, and not otherwise. And an
  unserved overwrite only loses something when nothing else writes the
  call out, which `_flush_pending_call` also does at a jump, at a
  `RET` and at every statement -- so 16 is the number of places that
  do not ask, not the number of lost calls. The census remains the
  authority on what is actually lost.

  So the enumeration supports the conclusion this file already drew --
  one place should own the question -- and does not by itself say which
  of the 16 to change. Flushing at every overwrite is the broad version
  of a change this file records as tried and wrong at a *rebind*, where
  it emitted every intermediate of a built-up expression *and* folded
  it into the final statement.
- **`pause_menu`: seven call sites, one text** -- and **it is no longer
  lost**, which this file records elsewhere and had not joined up here:
  folding each literal into its own call made the seven texts distinct,
  so nothing masks anything and the body renders all seven items. Read
  again now, it is 7 of 7.

  The blind spot it demonstrated is still real and now has no instance
  in the corpus. **The wider signal was built and is inert**: counting
  a text's call SITES against its occurrences in the output, with
  `opCmp` excluded because the following jump renders it as a
  comparison rather than as its own text. Every title that can be
  measured here, and the `cs` server, renders byte-identical with it.
  So it is not taken -- a detector with nothing to detect is one more
  thing to keep in step -- and it is recorded here with the exclusion
  it needs, because the next instance will want it.

**And the fix for both is the same signal, one step up.** Compare the
number of call *sites* the simulation rendered for a text against the
number of occurrences of that text in the output -- which is `bgt
audit --calls`'s own comparison, done per body inside the decompiler so
the answer carries a position. It subsumes the bind-based signal, it
reaches the value-register half for free, and it has a hazard the
bind-based one does not: a call the renderer spells as *syntax* rather
than as a call would never match its own text. `opCmp` is exactly that
-- `cmp_pair` lets the following jump render it as `a < b` -- so it
would be reported lost on every title.

That is the next attempt, and it is deliberately not this one. The
change here is measured on five titles; widening the signal in the
middle of that measurement is how the previous attempt came to change
7,627 lines.

#### Taken, and a BIND is not a CALL

The attempt above was made, and the hazard it predicted was not the one
that bit. Counting occurrences is right; counting them against **binds**
is not.

`_lost_calls` collected `(position, text)` once per `_bind` of a call
value, deduplicated by position, and reported any site past the number
of times the text appears in the output. On eight titles that claimed
**11** recovered calls -- and seven of the eleven were a call emitted
twice over, as a bare statement ahead of the expression that already
held it.

**`weaponloop` is the one that showed it**, because the `cs` server came
with its author's source:

```
source:    if(players[i].name==x or players[i].safe()
              or teammates(weapons[i].owner.name,players[i].name))

emitted:   teammates(weapons[local_1].owner.name, players[local_39].name);
           if ((... || players[local_39].safe())
               || teammates(weapons[local_1].owner.name, ...)) {
```

One call, bound **three** times -- the register capture, then a copy on
the way into each of the two `||` merges -- so the census saw three
sites, found one occurrence, and emitted two. That is the duplication
this file counts as a correctness defect, and it is how it was caught:
the server fell from 194 of its author's 196 functions to **193**, which
is the only instrument in this project that could have said so.

**`Atom.origin` was tried as the identity and cannot be it.** A copy
inherits it, which is exactly why it looked right. The probe settles it
in one line: the call runs at **3621** and its two origins are **3623**
and **3631**, because `_value_origin` stamps where a value was first
*bound* -- the right answer for its own question, *"has anything run
since"*, and the wrong answer for *"is this the same call"*.

So the record to ask is the instruction. `invocation_sites` keeps every
position an impure call was rendered at -- a **set**, because `_body`
re-simulates a function once per pass and a list would count each call
once per pass -- and `call_binds` keeps only the fact that the value
reached a slot, which is the census's guard and nothing more: a call
rendered inline as an argument, or spelled as syntax the way `opCmp` is
under `cmp_pair`, never reaches one and is not its business.

#### What it cost, and the one call it found

| title | lines | calls | goto | split |
|---|---|---|---|---|
| Super Egg Hunt | 5,302 | 1,607 | 0 | verified |
| **The Gate** | 34,943 -> **34,944** | 8,665 -> **8,666** | 0 | verified |
| Battle of the Hunter | 4,373 | 1,334 | 0 | verified |
| Field Wars | 9,021 | 3,001 | 0 | verified |
| rage room | 8,683 | 2,369 | 0 | verified |
| cs server | 10,130 | 3,033 | 0 | verified |
| cs client | 8,178 | 2,858 | 0 | verified |
| constant velocity | 3,883 | 1,767 | 0 | verified |

**Seven of eight are byte-identical**, and the eighth gains one line:

```
local_18 = (create_main_character() ? 1 : 0);
if (local_18 == 0) { speak("Cancelled", true, false, true); continue; }
load_resources();                         <- this
if (music.get_playing()) { ...fade out... }
```

`main_menu`, at the moment a new game starts. A recovered Gate began
one with **nothing loaded**, and no count in this file could have shown
it -- the project recovers clean, compiles, and runs.

**Confirmed by the instrument that is not this one**: `bgt audit
--calls` on that title goes from 144 bodies and 158 values the text does
not hold to **143 and 157**, which is the bytecode saying the same thing
from the other side.

All four ground-truth scores are exactly as they were -- rage room
291/292, the `cs` client 218/218, the server 194/196, constant velocity
94/95, 0 differing on all but the server's one -- and `bgt oracle` is
**52/52** with its `counter` at 13, which is the shape that rejected the
webs attempt and the reason that attempt is recorded above rather than
taken.

**One real lost call across eight titles, where counting binds claimed
eleven.** That ratio is the measurement: a census that over-reports does
not merely add noise, it writes a duplicated call into the output.

#### What the Cast flush cost, measured

| title | lines | goto | split | calls |
|---|---|---|---|---|
| Super Egg Hunt | 5,302 | 0 | verified | 1,608 |
| Paladin of the Sky | 23,442 | 0 | verified | 6,952 |
| Psycho Strike | 24,431 | 0 | verified | 6,406 |
| Crazy Party | 175,334 | 0 | verified | 90,148 |
| Manamon 1 | 83,406 -> **83,407** | 0 | verified | 26,482 -> **26,483** |
| cs server | 10,876 | 0 | verified | 3,018 |

Five of the six are **byte-identical**, the server included, which is what a
fix with one named instance behind it should look like.

Not one residual goto, dangling goto, split check, body error,
passthrough or unbalanced file moves anywhere, every `bgt signatures`
shape holds, and `bgt oracle` is 52/52.

#### Sized, by the first call audit ever run on Crazy Party

751 of that title's bodies are missing a call and 529 are a base
constructor. Of the 222 that are not, **200 bodies are `round`** -- and
that class went into this file untriaged, because the first thing I did
with it was generalise from one body and get it wrong. It is triaged
now.

`MenuMap::placeZone` loses two, and in that body the bytecode is
`iTOd ; CALLSYS round ; dTOi`. From that I wrote that all 200 were an
identity the conversion folder removes. **The mechanism was wrong and
the verdict was right**, which is the least useful way to be half
correct, and it took a sweep of all 612 `round` sites in the title to
say so:

| the result of a `round` call is | sites |
|---|---:|
| read | 316 |
| in a slot the body never mentions again | 292 |
| unread within its own live range | 4 |

`round` is **pure** -- `double round(double, int)`, and the module's own
`usedFunctions` record gives its origin as `application` -- so a dropped
`round` costs nothing unless its argument is impure or its result is
observed. It is not an identity being folded; it is a pure call whose
result the ORIGINAL never reads. Two centre coordinates per minigame,
computed and discarded, which the author presumably stopped using.

Two corrections of detail. **The 200 is bodies, not rows**: 302 rows in
200 bodies. And `PechePerle::placeZone`, the body I said refuted the
class, renders its `round` perfectly and is reported for a different
callee entirely -- a `random(8, 15)`. So that body was evidence against
my *mechanism* and never against the verdict.

#### Fixed: the refusal's stated reason was not true

`TapisRoulantBonus::placeZone` recovers its escalator positions now:

```
before:  @local_28 = array<int>();                      // EMPTY
after:   int[] __nvgt_list_29_478 = {0, int(round(double((local_6 / 2)), 0)), local_6};
         @local_28 = __nvgt_list_29_478;
```

so the loop over it places escalators and `random(0, length())` is a
real range again. The guard refused any element naming a frame slot on
the grounds that *"the declaration is hoisted to the top of the body, so
a slot name in it reads a value the slot does not hold yet"* -- and **a
generated list local is not hoisted.** It is emitted where the list
factory is called, which is after every element has been written, so the
slot names are valid there. The claim was never checked; the output
shows `string[] __nvgt_list_19_1320 = {...};` sitting in place in every
title that has one.

**`bgt oracle` is what says so without an engine run of a whole title**,
and the shape took two tries. Written with locals initialised from
constants it was **inert** -- every element constant-folds, so no
element names a slot, the guard never fires and it passed with the
refusal and without it. That is the third inert shape this file has
recorded writing, and the fix is to make the value one the decompiler
cannot fold: a PARAMETER, which renders as `arg0` and is exactly what
the guard matched on.

```
lifted:   int[] __nvgt_list_5_32 = {0, local_1, (local_1 * 3), (local_1 + (local_1 * 3))};
refused:  @local_4 = array<int>();
```

-- and the four reads that follow then index an empty array, which is
the same `Index out of bounds` the existing list shapes throw. The two
recoveries were compared as TEXT rather than by running the second one,
because running it puts a BGT runtime-error box on somebody's screen,
which this file records as a cost and which I paid once before
remembering.

| title | lines | goto | split | calls read back |
|---|---|---|---|---|
| Super Egg Hunt | 5,294 | 0 | verified | 1,608 |
| Paladin of the Sky | 23,440 | 0 | verified | 6,952 |
| Psycho Strike | 24,428 | 2 | verified | 6,406 |
| Crazy Party | 174,597 -> **174,665** | 14 | verified | 90,145 -> **90,148** |
| Manamon 1 | 83,363 | 0 | verified | 26,482 |

Super Egg Hunt and Paladin are **byte-identical** -- neither has a refused
list -- and Crazy Party is the only title that has any, so the scope is one
title, **68 lines and three calls**. The three are the `round` calls that
went with the empty array. `bgt oracle` is 52/52 and the suite passes.

**That 68 was first published as 118**, and the mistake is worth keeping
because it is the one this file keeps recording in a new costume: the run
that measured the list fix was launched after the signedness commit, so it
had signedness in it, and subtracting the base from *before* that commit
credited this change with the other one's lines. A delta is only a delta
against the base it was actually measured from, and the way it was caught
was re-running the title on the committed tree and getting 174,665 again --
the same figure, from a different base, which cannot both be right.

#### One `round` row is real, and it is a different defect

Of the 302, exactly one lands in a slot the body reads:
`TapisRoulantBonus::placeZone`, where the result is element 1 of
`int[] local_28 = {0, centreX, maxX}`. The list is **refused** -- this
file records the guard, *"an element that names a frame slot is
refused"*, because the declaration is hoisted above the slot's write --
so the array comes out `array<int>()`, empty; the loop over it runs zero
times and **no escalators are placed on that minigame's map**, and
`random(0, local_28.length())` becomes `random(0, 0)`. Nothing then
reads the slot, so the `round` that filled it looks dead and goes too.

Putting the call back does **not** fix this one: the array is still
empty. It is the initialiser-list guard needing a way to emit the
declaration where the elements are already computed, and it is recorded
here as its own open defect rather than counted with the lost calls.

**Fifteen rows are real, standing for sixteen calls:**

| lost | rows | what it costs |
|---|---:|---|
| `random` | 12 | **13** rolls -- the RNG advances, so every later draw changes |
| `Jeu::joueSon` | 2 | no win/lose jingle at the end of a minigame, no stage-cleared sound |
| `JoueurTerrain::bouge` | 1 | `VaisseauEnnemi::suisPattern` -- the enemy ship never moves |

**The worst of them is not a minigame.** `Partie::synchroRandom` exists
to burn draws so a networked client's RNG stream lines up with the
host's, and its whole loop body was the one `random(0, 9)` inside it:

```
if (!random_set_state(graineRandom)) { dis("Erreur sur le settage ..."); }
for (local_7 = 0; local_7 <= numRandom; local_7++) {
}
```

An empty loop. The generator is never advanced, so every client
desynchronises from the host from that point on -- in a title that
explicitly synchronises its RNG. One dropped call, and it breaks
multiplayer.

Three corrections to what this file said about the `random` class. It is
**not** "nine minigames' `placeZone`": eight `placeZone` bodies, plus
`Jeu::addBebeDragon`, `CombattantSauvage::lanceCombat` and
`synchroRandom`. It is **13 rolls in 13 rows**, and the thirteenth is
worth a sentence: `ZrCourChateau::placeZone` loses two `random(55, 60)`
whose texts are identical, the first census reported one of them, and
the position deduplication reports both. So that pair is **not** an
instance of the shared-text under-report after all -- deduplicating by
the call's own position rather than by its text is what fixed it, and
the one surviving instance is `pause_menu`, where the text really is in
the output. And `BateauVolant::placeZone`'s row is benign: the roll
inside the lost `round` is the same one the surviving `Terrain(...)`
carries, 20 sites against 20 occurrences.

**And `getVariable` was never real.** `Basique::getVariable` is
`dictionary::get` on a member -- a pure read -- and the body's one impure
call, `modVariable(1.0)`, survives. It was in the table above because I
had not read it. The same goes for every `Terrain::getCentreX/Y`,
`getMaxX/Y`, `array<T>::get_length` and `Joueur::getNbPiece` row: pure
member reads plus arithmetic, read out of their own bodies.

So the defect is **22 CENSUS rows over five titles, standing for 23
calls**: Crazy Party 15, Manamon 1 6, Paladin 1, and none at all on
Psycho Strike or Super Egg Hunt -- plus two the census cannot see at
all, both on Manamon 1, which is its own finding and is below.
Every figure in the sentence this replaces was wrong:
it said 17, 4, and 3 pure ones on Psycho Strike, with Paladin clear.
Psycho Strike's four really are all pure -- `character::enemy_count` is
63 instructions that read the `fighters` array and increment a local, and
its `calendar()` is a generated return temporary -- and Paladin's one is
the `steel_wall` scroll above.

#### Why the existing flush does not reach it, and why the obvious fix

`FREE` already flushes an unconsumed call atom: a temp whose value
nothing read is emitted as a bare statement at the end of its life. Two
things keep `load_sound` out of it:

- **These slots are primitives and are never freed.** `FREE` is for
  object slots; a `bool` in slot 1 has no end of life but the `RET`.
- **The two calls are in different arms.** The simulation walks the
  bytecode linearly, so by `RET` slot 1 holds whichever arm ran last
  and the other arm's call is already gone. An end-of-body flush would
  recover `load` and still lose `stream`.

And flushing at a **rebind** is already recorded here as tried and
wrong, with the measurement: a rebind is not proof the previous value
went unread, so every intermediate of a built-up expression gets
emitted *and* folded into the final statement -- Paladin's
`clock::reset` came out running `get_time(false)` five times.

So the fix is the **two-pass** mechanism this file already uses for
`duplicate_binds`: `_body` re-simulates a function while each pass
discovers more, so pass one can record every bind that was never read,
and the next emits each at the position the bytecode computed it --
which is inside the arm it belongs to, because events are sorted by
bytecode position rather than kept in append order. Counting only the
binds a pass newly discovers is what makes it terminate, exactly as it
does there.

#### The first attempt at it, measured and rejected

That mechanism was built. It works on the defect -- `load_sound` comes
back as `handle.stream(local_3);` in one arm and `handle.load(local_3);`
in the other, each in the right place -- and it is **far too broad**:

| title | lines changed | residual gotos |
|---|---|---|
| Paladin of the Sky | **7,627** | 0 |
| Psycho Strike | **5,745** | 2 -> **4** |
| Super Egg Hunt | **2,264** | 0 |

Two new residual gotos is two new compiler errors, and a diff that size
is not a fix, so it was reverted rather than tuned.

**The mechanism was right and the signal was wrong, which is the part
worth keeping.** Pass one was asked for "every call bind with no entry
in `fold_reads`", and `fold_reads` is incremented in exactly one read
path -- `_slot_atom`, the value pushed from a slot. A temp read through
`_read_temp`, through `_deref`, or consumed straight off the simulation
stack as an argument never touches it. So **"no entry" is not "never
read"**; it is "not read through that one path", which is most of the
call binds in a body.

#### Fixed, by asking the OUTPUT instead of a read counter

The last entry said the next attempt starts by making the read count
complete -- every read path marking the bind. It does not, and that is
the whole of what was wrong. **A read counter is a proxy; whether the
call's text reached a statement is the thing itself**, and it cannot be
incomplete for the same reason a tail that lands exactly on EOF cannot
be nearly right. So `_lost_calls` collects the text of every statement
the simulation emitted and asks, of each call parked in a slot, whether
its text is in any of them. No new bookkeeping in any read path, and
nothing to keep in step.

Three things then had to be right, and each one was wrong first.

**One: `Atom("call", ...)` is the kind for any computed expression.**
A negation, a comparison, an addition -- so the atom cannot say whether
a value was produced by *calling* something. Asked of the atom, the
first census reported `!use_hyper`, `false`, `(local_6 == "")` and
`(count - 6)`: **115 rows on Super Egg Hunt**, a title with no lost
call at all. What answers it is the four sites that set
`pending_value_call`, because those are the ones that really did render
a call instruction.

**Two: a construction is not a call.** Two of those four sites render
one -- an engine behaviour (`$beh0`, `$fact`, `$list`) and the generated
factory a script class gets, whose name is the class's own and whose
return type is that class. A constructed object nothing keeps is the
compiler's generated member initialisation, which this file already
records as not source and which `_refcpy` already drops, so emitting it
would add a statement that hands the new object to nobody.

**Three: dropping a value nothing reads is faithful only if computing
it is PURE**, and that is the half the first attempt never had. It is
also the half that is computable -- see **Purity, computed** below.

One detail is not a principle and cost a measurement: the
deduplication is by the **call's own position**, not by its text. One
call copied from the slot the register left it in to the slot a dead
local owns is two binds of one call, and emitting both is the
duplication this file counts as a correctness defect -- while two
separate calls that happen to read alike are two calls, and
`load_sound` is exactly that shape with one in each arm of an `if`.

#### Purity, computed -- and the direction its errors run

`tools/nvgt/purity.py` answers "may a call to this be dropped?" from
two sources, because the module answers one half and not the other:

- **A script function's purity is a fixpoint over the module.** Assume
  every body pure, then mark impure any that writes a global (`SetG4`,
  `CpyVtoG4`), writes through the reference register (`WRTV1/2/4/8`,
  `REFCPY`, `RefCpyV`, `COPY`, and the twelve `INC`/`DEC` opcodes, which
  this file already records as acting through that register), or calls
  something not yet known pure; repeat until nothing changes. Paladin
  clears 27 of its 926 bodies and Manamon 1 247 of 4,909, which is the
  measure of how conservative it is.
- **A registered function has no body, so it needs a list**, and the
  list is 61 names each checked against the engine's own declaration
  with `bgt api`. Two mechanical membership rules rather than a
  judgement: a *method* is listed only if **every** registered overload
  of that name is marked `const`, which is the engine saying it does not
  modify the object; a *global* only if its signature takes its inputs
  and returns a value.

**`find` is the name that shows why a spelling is not evidence.** All
three of its registered overloads are `const`, and one of them is
`vector[]@ find(int&in, int&in, int&in, int&in, string) const` -- which
is `pathfinder::find`, a search that **calls back into script** through
`pathfinder_callback`. The `const` marker says nothing there, and the
name would have been a lost call never reported again. `opIndex` and
`opCmp` are out by the const rule as well (each has a non-const
overload), and `maximum`/`minimum` are out because **this engine neither
documents nor registers either one** -- two names I asked for from
memory and the engine does not have.

**The errors run one way and the file says which.** A name wrongly in
the pure list is a lost call that will never be reported again; a name
missing from it costs one statement in the recovered source. So the set
grows one checked name at a time, and `bgt audit --calls` stays the
independent check on it -- nothing in that file is evidence about
itself.

Three conservatisms are deliberate, and each has a price worth knowing:

- **A virtual dispatch is never pure.** The function the module records
  for a `CALLINTF` is the class that *declared* the method, not the
  override that will run -- this file derives that from Paladin's
  `person::reset`, where the unqualified call recursed forever. So the
  resolved callee's purity says nothing, and the opcode is part of the
  answer rather than the callee alone.
- **`WRTV4` writes wherever the register points and the bytecode does
  not say**, so a function that writes one of its own *locals* through a
  reference is reported impure too. Psycho Strike's `enemy_count` is
  exactly that: 63 instructions that read the `fighters` array and
  increment a counter -- pure -- whose body uses `RefCpyV` for the
  borrowed-handle alias this file records as the compiler's own. So its
  three dropped calls come back as three statements that do nothing.
- **A call operand is a signature stub, not a body.** `asreader` builds
  a fresh `Function` for a `usedFunctions` entry and reads only its
  signature, so `instr.func_ref` for a call of a script function carries
  no bytecode at all -- the brief for this work asserted the opposite and
  was wrong. The stub is resolved to its body by the signature both
  paths build from the one `_read_function_signature`, with parameter
  names excluded, because those live only in debug info: a body from a
  debug build has them and a stub never does. Exact match or nothing --
  a looser key could only turn an *unresolved* callee, reported impure,
  into a resolved one that might be reported pure, which is the unsafe
  direction. On real modules 2,155 of Paladin's 2,350 script-call
  operands resolve, and the analysis sees 926 of 926 bodies and 4,909 of
  4,909.

#### What the fix cost, measured on all five

| title | lines | goto | split | calls read back |
|---|---|---|---|---|
| Super Egg Hunt | 6,240 | 0 | verified | 1,608 |
| Paladin of the Sky | 27,256 -> 27,257 | 0 | verified | 6,957 -> **6,958** |
| Psycho Strike | 27,495 -> 27,498 | 2 | verified | 6,403 -> **6,406** |
| Crazy Party | 192,725 -> 192,765 | **14** | verified | 90,105 -> **90,145** |
| Manamon 1 | 90,919 -> 90,925 | **0** | verified | 26,476 -> **26,481** |

Super Egg Hunt is byte-identical, every split still verifies, and
passthrough, body errors, unbalanced files and dangling `else` are 0 on
every title. **Not one residual goto moves** -- Crazy Party's fourteen
are the same fourteen -- which is the number this file records every
over-broad fold change being caught by, and it is the whole difference
from the first attempt: that one changed **7,627** lines on Paladin and
took Psycho Strike from 2 residual gotos to 4.

Both baselines were taken from a frozen copy of the committed `tools/`
and reproduce the standings exactly -- 192,725 / 14 / 90,105 and
90,919 / 0 / 26,476 -- which is what says the two columns are
comparable rather than merely adjacent.

**The call count rising is the result, not a side effect**, exactly as
it was for the duplication work: a call read back is a call the program
makes. And not one text signature moves on any title -- `bgt signatures`
is identical before and after on all eight shapes -- which is the point
rather than a disappointment. **A lost call leaves nothing in the text
to sweep for**, which is why it took a bytecode audit to find it and why
that audit exists. Counting entirely empty recovered bodies was tried as
a cheaper signature and does not move either (Egg Hunt 3, Paladin 7,
Psycho Strike 35, before and after), so it is not one.

#### The oracle shape, and the two inert ones that came first

`bgt oracle` has a shape for this now, and writing it is the part worth
recording, because **the first two I wrote passed at the commit that has
the defect**. A check that cannot fail is the trap that whole command is
organised against, and I nearly padded it with two of them.

| shape | what came back |
|---|---|
| `bool ignored = (bump() > 0);` | kept -- a bool slot typed numeric is read back as `(call() ? 1 : 0)`, and that conversion IS a read |
| `int ignored; if (w) ignored = bump();` | kept -- an uninitialised local is promoted to a variable by the write itself |
| `int ignored = 0; ignored = bump();` | **lost**, which is `load_sound`'s own shape |

So the local has to be an `int` and it has to be initialised, and the
way to find that out was to compile all five candidates in one probe and
read what the recovery made of each -- one compile, and no argument.
`bgt oracle` is **51/51** with the fix and **49/51** without it,
`dead_local_other` 1 -> 0 and `counter` 13 -> 11.

Two things about that probe are worth keeping. A module of nothing but
an enum and global functions fails dialect detection ("neither dialect
parses a coherent module head"), so a probe needs a class in it -- the
same hole the Super Egg Hunt header peek found, one level down. And a
scratch file named after a stdlib module is a trap this project has now
paid for twice: a `dis.py` in the instrument directory shadowed the
`dis` that `inspect` imports, so it ran itself on import and printed a
disassembly where a decompiled body belonged.

#### What came back, per title

| title | lines added | of which a real loss |
|---|---:|---:|
| Super Egg Hunt | 0 | 0 |
| Paladin of the Sky | 1 | **1** -- the `steel_wall` scroll |
| Psycho Strike | 3 | 0 -- the `enemy_count` conservatism above |
| Crazy Party | 40 | **16** |
| Manamon 1 | 6 | **6** |

Each line is one carried call, and the census agrees with the line
delta exactly: Crazy Party's 40 are **13 `random` + 2 `joueSon` + 1
`bouge`**, which are the 16 real ones, and **24 pure getters the
analysis cannot clear** -- 20 `Terrain::getCentre*`/`getMax*`, plus
`getVariable` and `getNbPiece`. Every one of those 24 is a `CALLINTF`,
which is the virtual-dispatch conservatism above, so the whole gap
between the two columns is that one rule. It is the right side of the
trade: a statement that does nothing costs a line, and a lost call
costs a feature. The gap is also the purity analysis declining to
claim something it cannot prove, and it is the right side of that trade:
a statement that does nothing costs a line, and a lost call costs a
feature.

### A value that reads a NAMED slot, after that slot is rewritten

Every fold rule above asks the question at a READ of a temp. Two
whole classes of value never reach one, and both are the same defect:
a value whose *text* names a slot the source declared, read after
that slot has been rewritten. The compiler writes a reused slot and
consumes it as it goes, so the writes and the uses interleave, and
rendering the slot's NAME means every use gets whatever it held last.

#### One: the value is bound, and the slot is rebuilt by a behaviour

Rule ten records a behaviour write -- an object slot filled through a
pushed address, which no opcode names -- and counted it **only for a
value that IS a slot**. `cs`'s `load_bases` is what that cost, and it
was the last row keeping that title's recovery from its author's
source:

```
source:     base@ b = base(stn(parts[0]), stn(parts[1]),
                           stn(parts[2]), name, owner, code);

recovered:  local_16 = local_14[0];
            local_16 = local_14[1];
            local_16 = local_14[2];
            ... eight lines of file opens ...
            local_16 = local_3.read(0.0);        // the HEALTH file
            @local_24 = base(double(int(stn(local_16))),
                             double(int(stn(local_16))),
                             double(int(stn(local_16))), ...);
```

Three `stn` calls, each rendered with the slot's name, and by the call
the slot holds the health file's contents -- so **a base's three
coordinates were all its health value**, and every base in a saved
game loaded in the same place. It comes out as
`base(double(local_15), double(local_17), double(local_18), ...)` now,
with `health = local_21`, which is the source.

Super Egg Hunt's is a save-slot mix-up of the same shape:

```
before:  local_6 = ("M" + 6);
         local_6 = ("M" + 7);
         if (int((double(int(stn(decrypt(read_string(local_6), h2))))
                  + stn(decrypt(read_string(local_6), h_key)))) == 311)

after:   local_6 = ("M" + 6);
         local_17 = double(int(stn(decrypt(read_string(local_6), h2))));
         local_6 = ("M" + 7);
         local_17 += stn(decrypt(read_string(local_6), h_key));
         if (int(local_17) == 311)
```

-- the source adds what is stored under `M6` and `M7`, and the
recovery read `M7` twice, so the "allmixedup" trophy was tested
against a total it could never reach.

#### Two: the value is on the STACK and was never bound at all

`_snapshot_pushed` is the other half, and no rule here could have
reached it: these values are read by the CALL, which pops them off the
simulated stack and renders them at the call site, so there is no read
of a temp to ask about.

```
local_17 = parts[6] ; CALL stn ; push
local_17 = parts[5] ; CALL stn ; push
...   six times
CALL safezone
```

Each pushed value is `stn(local_17)` -- a call whose text names the
slot -- so the recovery built
`safezone(stn(local_17) x6)`: **six bounds that are one number**, for
every safe zone and every platform in every map of that game. It now
reads

```
local_17 = local_13[6];
double __nvgt_held_17_264 = stn(local_17);
...
@local_16 = safezone(stn(local_17), __nvgt_held_17_328,
                     __nvgt_held_17_312, __nvgt_held_17_296,
                     __nvgt_held_17_280, __nvgt_held_17_264);
```

Three things keep it narrow, and the first is what makes it safe at
all:

- **Only a value still waiting on the stack can be affected.** Once
  the call has consumed its arguments there is nothing to snapshot, so
  an ordinary reused scratch slot is untouched -- which is why three of
  the five titles do not move by a line.
- **A value that IS the slot is written as whatever the slot held**,
  usually another slot's name, and the recursion is free: if that slot
  is written while this value still waits, the same rule fires again.
- **A value whose type is not known is left alone** rather than
  declared wrongly. An undeclared name does not compile at all, where
  a stale read does.

#### Swept, which is how both halves were sized

A call that reads one slot for two or more of its arguments, with that
slot written more than once just above. It is `bgt signatures`' ninth
shape now rather than a scratch script, for the reason every other one
is in there: the class cannot come back unnoticed, and a signature for
a fixed bug class should read 0.

| title | before | after the first half | after both |
|---|---|---|---|
| cs server | 38 | 32 | **0** |
| Crazy Party | **181** | -- | **31** |
| Manamon 1 | 2 | -- | **0** |
| Super Egg Hunt | 0 | 0 | 0 |
| Paladin of the Sky | 0 | 0 | 0 |
| Psycho Strike | 0 | 0 | 0 |

Crazy Party's 181 are mostly its localisation lookups:
`lng(local_7, local_13, local_4, local_7, local_7, local_7, local_7)`,
where the source passes a key and then four empty strings, and all
five render as the key -- so every localised string in that game was
padded with its own key.

**And its 31 survivors are the author's own**, which is the sweep
being a lead rather than a verdict, exactly as this file keeps saying.
Every one is a `setZone` or a `getJt` passing one coordinate twice --
`setZone(t, local_38, 1, local_38, local_7 - 1, ...)` is a vertical
wall at `local_38`, and a minigame map is full of them. The *fix* is
narrower than the sweep by construction: it fires only where a write
really lands between the push and the call, which a wall's two equal
coordinates never have.

The sweep had to be bracket-matched rather than written as a regex, and
that is worth a line: a pattern with one level of nesting in it cannot
see `base(double(int(stn(local_16))), ...)`, which is exactly the shape
at issue, so the first version reported 9 rows where there are 38 and
under-reported the baseline it was meant to measure.

#### What they cost

| title | lines | goto | split | calls | bodies given up |
|---|---|---|---|---|---|
| Super Egg Hunt | 5,296 -> **5,302** | 0 | verified | 1,608 | 0 |
| Paladin of the Sky | 23,438 -> **23,442** | 0 | verified | 6,952 | 0 |
| Psycho Strike | 24,431 | 0 | verified | 6,406 | 0 |
| Crazy Party | 174,682 -> **175,334** | **0** | verified | 90,148 | 0 |
| Manamon 1 | 83,363 -> **83,406** | 0 | verified | 26,482 | 0 |
| cs server | 10,787 -> **10,876** | 0 | verified | 3,018 | 0 |

Psycho Strike is byte-identical, Super Egg Hunt and Paladin move by
the holds the first half gives back and by nothing for the second, and
not one residual goto, dangling goto, dangling `else`, unbalanced
file, passthrough, body error, split check or call count moves
anywhere. Against the games with source, **`cs`'s server reaches 194
of 196**, with one difference left -- `base::lockpick`, whose
recovered body matches its source line for line when the two are read
side by side, so what differs is the comparison's ordering rather than
the recovery.

Paladin's four lines are the hotel receptionist's greeting, and they
are a faithfulness gain rather than a fix: the floor name is taken
where the bytecode takes it, before the cabin name is built, instead
of both being folded into one concatenation. Both read the same two
map names, so nothing observable changes.

### Twelve: a call nobody reads has still RUN, and it closed the file first

The worst of this family so far, because the recovered code is in the
wrong ORDER rather than merely duplicated -- and the engine's own
declaration is what makes it invisible.

`cs`'s `get_file_size` is four lines:

```
sizer.open(filename, "rb");
size = sizer.read();
sizer.close();
```

and it recovered as **`close()` before `read()`**. A closed file reads
empty, so every size came back 0 -- and the same shape reaches
`file_get_contents`, `file_put_contents`, `load_bases`,
`base::load_vault`, `teamload` and `map::mapload`, which is that server's
whole save and load path.

**`bool file::close() const` returns a bool, and nobody reads it.** So the
call goes down the value-returning branch: parked in `pending_value_call`
and written out later by `_flush_pending_call`, which appends its event at
the right position and **never touches `stmt_count`**. Every fold-safety
rule measures `bound[1]` against `stmt_count`, so between the call and the
flush `close()` had not run as far as any of them could tell, and the
read's value folded forward over it.

The engine is full of that shape: `open`, `close`, `seek`, `write` and
most of its setters answer `bool` and are called for the effect.

#### Three attempts, and the first two are rejected with their numbers

The fix is one sentence -- a call that ran has run -- and where to say it
took three goes, because the guards it has to pass are load-bearing.

| attempt | what it counted the pending call for | Paladin |
|---|---|---|
| 1 | every "has anything run" test | **1 body given up on**, 20 calls lost |
| 2 | ...and the receiver guard removed outright | **2 bodies**, 156 calls lost |
| 3 | only where it MUTATES a receiver of this value | nothing moves |

Both rejected attempts also grew four titles by 1,681 and 406 lines. What
they broke is the guard this file already warns about -- *within one
statement the bind and the read are the same moment* -- which is what
stops a loop condition built out of the loop variable from being called
stale, promoted to a statement before a jump, and ceasing to be a loop
condition.

So the pending call is admitted through that guard **only when
`_mutates` says it touches one of this value's own receivers**.
`local_2.close()` touches `local_2`, which `local_2.read(0.0)` reads;
nothing else in these bodies qualifies.

#### What it cost

| title | lines | goto | bodies given up | split | calls |
|---|---|---|---|---|---|
| Super Egg Hunt | 5,294 -> 5,296 | 0 | 0 | verified | 1,608 |
| Paladin of the Sky | 23,440 | 0 | 0 | verified | 6,952 |
| Psycho Strike | 24,431 | 0 | 0 | verified | 6,406 |
| Manamon 1 | 83,363 | 0 | 0 | verified | 26,482 |

Three titles do not move at all and the fourth moves by two lines. Not one
residual goto, call count, split check or body error anywhere -- which for
a fold-safety change is the whole of the measurement.

And against the games that came with their source:

| | before | after |
|---|---|---|
| cs server | 186 / 196, 6 differ | **189 / 196, 4 differ** |
| cs client | 214 / 218, 2 differ | **216 / 218, 0 differ** |
| constant velocity | 94 / 95, 0 differ | 94 / 95, 0 differ |
| rage room | 290 / 292, 0 differ | 290 / 292, 0 differ |

**Crazy Party is owed**, as it is for the loop fix: the run that would
give it was stopped by the host for system memory twice tonight. The new
branch can only fire where a pending call mutates a folded value's
receiver, and the four titles above cover that shape, but the row is left
unquoted rather than guessed.

#### The four rows left are one more shape, diagnosed and not fixed

`file_get_contents` is the clearest:

```
source:     string r = tempfile.read();
            tempfile.close();
            return r;

recovered:  local_1.close();
            return local_1.read(0.0);
```

Here the read folds into the **`return`**, and `_bind` has a shortcut for
exactly that: a value bound to the return slot of a function returning a
value type is parked in `temps` and the method returns **before setting
`temp_bound`**. So `_stale_fold` is asked, finds no bind position, and
answers False -- not because nothing ran but because it cannot tell.

That is the same defect this file records as *"a copy-constructed temp had
no bind position"*, in a second place -- and it is **three** lines deep,
not one. The attempt is recorded here because each layer of it was a
separate wrong guess and the next person should start from the bottom.

1. **Record the bind position** on the return-slot shortcut. Necessary and
   not sufficient: nothing changed.
2. **Ask the question at the read.** Two sites render `return <temp>;`
   straight out of `temps` and neither asked `_stale_fold` -- the third
   read path in this file to skip it. Routed through one `_returned_temp`
   helper: still nothing changed.
3. **`_stale_fold` opens with `if off <= 0: return False`, and the return
   slot IS 0** for a global function and -1 for a method. So every return
   value was excluded by construction. Relaxed for the return slot only:
   still nothing changed.

What finally showed the cause was instrumenting rather than guessing a
fourth time: **`stmt_count` is 0 from entry to `RET` in that body.** Every
statement in `file_get_contents` is a discarded value-returning call --
`open` answers `bool`, `close` answers `bool`, the `read` is returned --
so every one goes out through `_flush_pending_call`, which appends an
event and never touches the counter. Each fold-safety rule compares
`bound[1]` against `stmt_count`, so in a body like this one *nothing can
ever be seen to have run*.

Making the flush count fixes the ORDER and breaks something else:
promoting the return slot emits its assignment and the `return` vanishes,
so the function ends `local_0 = local_4;` and would not compile. That is
attempt 4, reverted.

#### Fixed -- and the four layers that order prescribes are all INERT

The order recorded above was *teach the promotion to keep the
`return` first, then count the flush, then the three layers*. All four
were built. **All four are inert**: with them in, every title that can
be measured here renders byte-identical, `bgt libcheck` does not move,
and `__nvgt_retval` -- the hold they emit -- appears nowhere in the
corpus. They are removed rather than kept, because one of them relaxes
the `off <= 0` guard that exists to refuse `this` and the frame's
negative parameter space, and a condition with nothing behind it is a
liability on the next title. The measurement stays, as a test, so the
next reader starts from it instead of from the order.

Instrumenting the body rather than guessing a fifth time gave the
answer in one line:

```
DETAIL off 0 bound (43, 1) pos 52 value local_1.read(0.0)
       pending [] receivers ['local_1'] stmt_count 1 pend_pos 39
```

The close ran at **39** and the bind is **43**, so by the time anything
asks, the close is already behind the bind. And 43 is not where the
read ran:

```
PSF 2 ; CALLSYS file::read       ; 25  -- the value
PSF 4 ; PSF 2 ; opAssign         ; 33  -- string r = f.read();
PshVPtr ; CALLSYS file::close    ; 39  -- f.close();
PSF 0 ; PSF 4 ; opAssign         ; 43  -- return r;
```

**A copy of a value is not where the value ran**, and `temp_bound` was
the only record of either -- so everything between the two became
invisible, and the bytecode had those four source lines in the right
order the whole time. The question belongs at the read of the slot the
value was copied OUT of, which is why nothing done at the return slot
could ever have fixed it.

##### The two questions a bind is asked, and why they need two answers

This is the whole of the fix, and getting it wrong cost a Paladin
regression that is worth more than the fix itself.

`Atom` carries an `origin` now -- where the value was computed -- and
`_stale_fold` reads it as `ran`. **It is used for the invalidation
window only.** Three other things are keyed on a bind and every one of
them is about the STORE rather than the value:

| asked of a bind | which position |
|---|---|
| has anything run that touches what this value reads? | the value **ran** |
| is this store skipped on another path? (`_conditionally_bound`) | the **store** |
| was this bind folded more than once? (`duplicate_binds`) | the **store** |
| where does a promoted assignment go? (`_promote_temp`) | the **store** |

Answering all four with the earlier position -- which is what writing
the origin into `temp_bound` does -- made two unconditional stores in
Paladin's `other_stuff` look conditionally bound, and the short-circuit
chain they belong to collapsed:

```
before:  if ((local_6 != 0) || !world[local_9].ends_demo) {
             init_events(world[local_9].name);

after:   local_5 = 1;
         local_5 = ((local_5 == 0) ? 1 : 0);
         local_5 = (world[local_9].ends_demo ? 1 : 0);
         local_5 = ((local_5 == 0) ? 1 : 0);
         local_5 = local_5;
         if ((((local_6 == 0) ? 1 : 0) == local_5) || (local_5 != 0)) {
```

-- each arm's computation emitted unconditionally and the guard reading
one value, so **which maps get their events initialised changes**. That
is the `use_screen_reader` defect, reached from a new direction, and it
came with 155 lines of slot traffic on Super Egg Hunt as well. Split in
two, Egg Hunt and Psycho Strike are **byte-identical** and Paladin
loses two lines of dead copy.

Three more things decide which values carry an origin at all, each
measured:

- **An origin already on the atom wins outright.** That is the whole
  inheritance; the test below decides only whether to STAMP a value
  that has none. Asking the test first threw away an origin a
  conversion had carried.
- **A conversion carries its source's origin**, because a conversion is
  not a computation: `int(stn(local_16))` ran when `stn` ran.
- **Only a value that really is a CALL is stamped, and `a.kind ==
  "call"` is not that test.** That kind is what every computed
  expression gets -- `(registered ? 1 : 0)` and `(count - 6)` among
  them. `call_sites` is the record of every call the body rendered;
  `invocations`, which `_lost_calls` reads, holds only the **impure**
  ones, and purity has nothing to do with when a value ran.

##### Counting the flush is the wrong lever, and cheaply shown

A value-returning call whose result nothing consumes is written out by
`_flush_pending_call`, which **did not advance `stmt_count`** -- so in
a body where every statement is one of those, and this engine declares
`open`, `close`, `seek` and `write` as returning `bool`, the counter
stayed at 0 from entry to `RET` and nothing could ever be seen to have
run. That is a real hole, and counting it does not close it: the
counter advances when the statement is written **out**, which is later
in simulation order than the position it is written **at**. So a value
bound in between looked stale when nothing had run, and `main()` came
out

```
local_5 = netport;
n.setup_server(local_5, 20, 500);
```

The position was knowable all along. `flushed_calls` records
`(position, text)` and `_stale_fold` asks about them by position,
between where the value ran and where it is read -- the same shape as
the pending-call admission beside it, and no counter moves.

##### ...and a DESTRUCTOR is not a write

Found on the way, while the four layers were still in: `cs`'s
`list_members` and six more bodies gained a generated local holding a
plain variable for nothing, because `behaviour_writes[1]` held position
**142**, and 142 is `PSF 1 ; $beh2` -- the destructor the epilogue runs
on every object local. `behaviour_writes` is the record of the writes
no opcode names, and it was built from every `$beh`. A destructor is
not one, which is the dual of a sentence this file already has:
*"destructing a value is not reading it"*.

**It is inert now** -- the holds it was fixing came from the layers --
and it is kept anyway, for the reason the `FREE`-must-exist condition
is kept: counting a destructor as a write is a wrong claim waiting for
the first title that reads a value past a slot's end of life. The
spelling trap is already paid for, too: `$beh2` in the module,
`_beh_2_` as the disassembler prints it, which is the
`%delegate_factory`/`$dlgte` lesson one more time.

#### What it cost, measured

Against the games that came with their own source, which is what
decides this one:

| | before | after |
|---|---|---|
| cs server | 189 / 196, **4 differ** | **193 / 196, 1 differs** |
| cs client | 216 / 218, 0 differ | 216 / 218, 0 differ |
| rage room | 290 / 292, 0 differ | **291 / 292**, 0 differ |
| constant velocity | 94 / 95, 0 differ | 94 / 95, 0 differ |

Five more of those authors' functions have their exact call sequence.
What is left on the server is **one** difference and two near ones, and
none of the three is this defect. `base::lockpick` differs by one
`unlock()` moved across a `send` whose argument holds a `random`, and
read side by side the recovered body matches its source line for line
-- so the difference is in the comparison's ordering rather than in the
recovery, which is the `control::focus` case this file already
records. `check_items_around_me` is the same shape, and `load_bases`
differs for the NAMED-slot defect below.

And on the standings titles:

| title | lines | goto | split | calls | bodies given up |
|---|---|---|---|---|---|
| Super Egg Hunt | 5,296 | 0 | verified | 1,608 | 0 |
| Paladin of the Sky | 23,440 -> **23,438** | 0 | verified | 6,952 | 0 |
| Psycho Strike | 24,431 | 0 | verified | 6,406 | 0 |
| Crazy Party | 174,686 -> **174,682** | **0** | verified | 90,148 | 0 |
| Manamon 1 | 83,363 | 0 | verified | 26,482 | 0 |

**Super Egg Hunt and Psycho Strike are byte-identical** and Paladin
moves by two lines -- a dead `local_12 = local_6;` before
`random_set_state`, now gone. Not one residual goto, dangling goto,
dangling `else`, unbalanced file, passthrough, body error, split check
or call count moves anywhere, and every `bgt audit` comparison is
identical before and after.

The six rows this was for are all right now -- `file_get_contents`,
`file_put_contents`, `base::load_vault`, `load_bases`, `map::mapload`
and `get_mapdata` -- and the first of them comes out as the source
wrote it, with the slot named rather than held:

```
string file_get_contents(string arg0)
{
    file@ local_1;
    string local_4;
    @local_1 = file();
    local_1.open(arg0, "rb");
    local_4 = local_1.read(0.0);
    local_1.close();
    return local_4;
}
```

#### What it uncovered next: an argument shuffled through a NAMED slot

Diagnosed, swept, and **not fixed**, because it is a change of its own.

The compiler shuffles each argument of a call through one scratch slot
and pushes as it goes, so the writes and the pushes interleave. A push
of a **named** slot pushes its NAME, and `_slot_atom` hands back
`var_atom(off)` without asking anything -- so every argument reads
whatever the slot held last:

```
local_9 = players[local_32].z;
local_9 = players[local_32].y;
local_9 = players[local_32].x;
play2(local_12, local_16, int(local_9), int(local_9), local_14, ...);
```

The source is
`play2("invopen", players[i].x, players[i].y, players[i].z, ...)`, so
**every positional sound in that server plays with all three axes equal
to x.** The map loader is worse: `safezone(stn(local_17) x6)`, and a
`platform` the same -- six bounds that are one number. It is what the
last two of that title's `libcheck` rows are, `load_bases` among them.

It is `get_percent_of_range`, which this file records as the
scratch-slot version of exactly this, asked of a slot the source
NAMED. No rule here reaches one, because a named slot is not a temp.

**Swept: 38 rows on that server alone**, by looking for a call that
reads one slot for two or more of its arguments with that slot written
more than once just above -- 38 before this change and 38 after, which
is what says the two are separate defects rather than one.

The sweep had to be bracket-matched rather than written as a regex, and
that is worth a line: a pattern with one level of nesting in it cannot
see `base(double(int(stn(local_16))), ...)`, which is exactly the shape
at issue, so the first version reported 9 rows where there are 38 and
under-reported the baseline it was meant to measure.

The fix shape, for whoever takes it: at a write to a named slot,
substitute every value already on the simulated stack that reads it
with what the slot held. The recursion is free -- the substituted value
is usually another named slot's name, and if that slot is written while
this value is still on the stack the same rule fires again -- and a
computed value needs a local of its own rather than a substitution,
because writing the expression at the call would RUN it there.

### Eleven: a snapshot of a MEMBER is stale once that member is assigned

`_prop_receiver` gives `this` for a bare member, and deliberately: a
method call on the object can change any field. What it cannot see is
the simplest write of all. **`curseur += arg0;` names no `this`**, so
the member rule asked whether anything had touched the object and missed
the statement that moved the very thing being snapshotted.

Crazy Party's `CodexOmbre::moveCurseur` is the shape, and six more of
its classes have it:

```
int old = curseur;
curseur += arg0;
if (curseur < 0) curseur = 0;
else if (curseur >= liste.length()) curseur = liste.length() - 1;
if (curseur != old) joueSon("item", ...);
```

That guard plays the cursor sound only when the clamp did not eat the
move. Folded it is `curseur != curseur`, always false, so **arrowing
through those menus made no sound at all** -- the same symptom as Super
Egg Hunt's silent menu, in seven minigames plus the lift, the dice and
`ZrArcEnCiel`. Manamon 1's `coin_collector` is the same over `game_x`,
where the guard decides whether to move the 2D listener at all.

**And `audio_form`'s type-to-search is worse, in a library file Crazy
Party edits** -- so BGT's own `form.bgt` settles what the shape should
be. It keeps one snapshot for two guards:

```
if (list_position == list_position) { ...search again from the top... }
if (list_position != list_position) { speak(list[list_position].item); }
```

The first is always true, so the wrap-around search runs even when the
downward search succeeded and overwrites the find with the first match
from the top; the second is always false, so the item found is never
spoken. Typing a letter in any of that title's forms jumps to the wrong
entry, silently.

**If you assign to X, a snapshot of X is stale.** That is as narrow as a
fold rule gets -- `_mutates` wants an assignment or an increment to that
exact path, so a statement that only reads the member leaves it folded --
and it is the one thing the member rule never asked.

| title | lines | goto | split | calls |
|---|---|---|---|---|
| Super Egg Hunt | 6,240 -> 6,240 | 0 | verified | 1,608 |
| Paladin of the Sky | 27,256 -> 27,256 | 0 | verified | 6,957 |
| Psycho Strike | 27,489 -> 27,495 | 2 | verified | 6,403 |
| Crazy Party | 192,693 -> 192,725 | 14 | verified | 90,105 |
| Manamon 1 | 90,913 -> 90,919 | 0 | verified | 26,476 |

Super Egg Hunt and Paladin are identical on every count, the other three
move by the snapshots the rule gives back, and not one residual goto,
call count, split check, passthrough or unbalanced count moves anywhere.

**The sweep is where the result shows.** `bgt signatures` counts
tautologies -- a condition comparing something with itself, which is what
a collapsed snapshot leaves -- and on the two titles this rule reaches:

| title | tautologies |
|---|---|
| Crazy Party | 19 -> **2** |
| Manamon 1 | 4 -> **0** |
| Paladin of the Sky | 1 -> 1 -- the author's own typo in `battle`, correctly kept |
| Psycho Strike | 0 -> 0 |

Crazy Party's whole networking menu comes back with it: a chain of
`if (local_51 == "liste") ... else if (local_51 == local_2)` over one
reused string slot, which had collapsed into comparisons against the
last literal assigned.

#### The two that are left are one line, and they are the open question

#### Measured on eight titles, and not adopted -- the seventh rejection

This asked, for a long time, whether a member read snapshotted across a call
should go stale unconditionally the way a global's does, and said *"two sites
now say yes and no measurement says what it would cost."* The measurement
exists now.

The change is **one clause**: in the `value.kind == "prop"` branch of
`_stale_fold`, after the `_mutates` test, also

```python
for text in self.stmt_texts[ran[1]:]:
    if _ANY_CALL.search(_mask_strings(text)):
        return declarable
```

which is exactly what `_stale_global` already does, for the same reason one
scope out: what moves the object may be a method on something ELSE holding a
handle to it, which no receiver test can see.

| | |
|---|---|
| byte-identical | Super Egg Hunt, Battle of the Hunter, Field Wars, rage room, cs client, constant velocity |
| moved | The Gate +35 lines, cs server +16 |
| residual gotos, dangling, unbalanced, splits, call counts | **unchanged everywhere** |
| ground truth | cs server **194 of 196**, cs client **216 of 218** -- exactly as before |

So it is **safe and buys nothing here**, and the 51 lines are the shape the
sixth rejection already records: a string concatenation decomposed into one
statement per link, because every literal is constructed into a named scratch
slot and a call sits between the snapshot and its read.

```
string local_9;
local_9 = ("destroymsound " + local_6);
local_6 = (local_9 + local_10);
```

**The two sites that motivated it are in the two titles this could not be
measured against**: Crazy Party's `DeRetournable::bouge` and Manamon 1's
healing items. Both are 80,000+ line recoveries, and this file's rule is to
adopt on a measurement rather than on an argument -- so it is written down
here with its eight-title result, and the next attempt starts from that
instead of from the question.

What would settle it: run those two titles with the clause above and compare
the residual goto count, which is the number every over-broad fold change in
this file has been caught by, against 0 and 0.

`DeRetournable::bouge` snapshots both coordinates into declared locals
and compares them after the move:

```
LoadThisR DeRetournable::x ; RDR4 1 ; CpyVtoV4 3 1     ; int oldx = x;
LoadThisR DeRetournable::y ; RDR4 2 ; CpyVtoV4 4 2     ; int oldy = y;
...
if (x != oldx || y != oldy) { ...the tile flips... }
```

Nothing between the snapshot and the read assigns `x`, and nothing names
`this`: what moves the object is a method on **another** object that
holds a handle to it. So no receiver-based test can see it, and neither
can this rule -- which makes it the second piece of evidence for the
question the ninth rule left open, after the Manamon 1 healing items:
**should a member read snapshotted across a call go stale
unconditionally, the way a global's does?** Measured on eight titles and
**not adopted** -- safe, and it buys nothing there, while the two sites
that motivated it are in the two titles it could not be measured
against. The section above carries the clause and the figures.

### The signatures, swept

```bash
bgt signatures recovered/
bgt signatures recovered/ --against ../previous/     # the delta
bgt signatures recovered/ --detail tautology         # the rows
```

Eight shapes, one per bug class this file records, swept over a recovered
tree. Each is here because a real reported bug left it behind: a
self-identical line and a tautology are a collapsed snapshot, inside a
statement and inside a condition; an empty `if` arm is a condition that
has lost its value, and two empty arms is the stronger form that found the
folded `||` chain; a double assignment followed by a multi-read is one
scratch slot carrying several operands (`get_percent_of_range`); an
identity cast is a value converted twice and changed by neither; a bare
read is the borrowed handle hoisted out of its guard; and the same call
three times in one statement is a call run once per read.

**It is a lead and not a metric**, which the two Paladin survivors above
demonstrate: the original wrote both of them. Files replaced by BGT's own
source are skipped by default, because their text is the engine's style
rather than this decompiler's.

What it is FOR is the delta, and the four fold-safety rules measured by it
across all five titles -- the width-fix commit against the one after it:

| title | self-identical | tautology | double assign | identity cast | duplicated call |
|---|---|---|---|---|---|
| Super Egg Hunt | 0 | 0 | 3 | 1 | 0 |
| Paladin of the Sky | 5 -> **2** | 7 -> **1** | 8 -> **5** | 6 -> **4** | 8 -> **6** |
| Psycho Strike | 1 -> **0** | 1 -> **0** | 13 -> **11** | 3 -> **1** | 2 -> **0** |
| Crazy Party | 3 | 21 -> **19** | 36 -> **35** | 5 | 22 -> **21** |
| Manamon 1 | 9 -> **1** | 12 -> **4** | 24 -> **20** | 18 -> **15** | 3 -> **1** |

Super Egg Hunt does not move because its project is byte-identical.
Manamon 1 moves most, in a title where nothing was looking for any of it,
and Crazy Party barely moves at all -- which is its own result rather than
a disappointment: a title that keeps fewer snapshots has less to lose by
folding them.

#### The empty arms, triaged -- ALL TWENTY are the authors' own

`empty_arm` is this file's own signature for *"a condition that has
lost its value"*, and it has stood at about twenty rows across the
corpus with nobody reading them. **The bytecode answers most of it
outright**: a conditional branch whose offset is 0 jumps to the very
next instruction, so its arm is empty in the ORIGINAL -- and the
compiler deletes unreachable code itself, so an empty arm there is the
source's. Counted per module:

| title | empty arms in the text | empty in the BYTECODE | left |
|---|---|---|---|
| Super Egg Hunt | 3 | 0 | 3 |
| Paladin of the Sky | 2 | **2** | 0 |
| Psycho Strike | 4 | **4** | 0 |
| Crazy Party | 6 | **5** | 1 |
| Manamon 1 | 5 | **3** | 2 |
| cs server | 0 | 0 | 0 |

So fourteen are the author writing `if (c) { }` -- Manamon 1's
`if (key_pressed(KEY_Q)) { }` and `if (tamer_data !is null) { }` are
both `JLowZ 0` with nothing between the branch and its target -- and
the second question closes the other **six**: **is the slot the arm
writes ever READ?** In every one of them it is not, so dropping the
store and leaving the arm empty is faithful.

- **Super Egg Hunt's three** are a joystick dead zone.
  `browse_trophies` has `if (absolute(double(stick.get_x())) < 100.0)
  { }` twice, and the arms store `false` into slots 18 and 19 -- which
  are initialised `false` before the loop, set `true` in the key
  branches, and **never read**. The author's own dead flags, like
  `find_best_weapon`'s `int best = -1;`.
- **Manamon 1's experience curve is safe**, which was the one worth
  being nervous about: `experience_formula` has
  `if (int(power(level, 3)) > 150) { }` for levels at or below 10, and
  a dropped store there would change the XP curve of the whole game.
  The bytecode clamps `local_16` to 150 and never reads it -- the
  accumulator the function returns is a different slot.
- **Manamon 1's `teleport`** opens `bool x = false; if (event !is null)
  x = true;` and never reads `x` again, in 434 instructions.
- **Crazy Party's is the author's own bug**, and it is the nicest of
  them. `LancerBoulet::gereBoulet` has three nested empty arms, which
  is as alarming as this signature gets, and the bytecode is a
  speed-dependent delay:

  ```
  SetV4 14, 400
  if (f <= 2.0)      local_14 = 300
  else if (f <= 1.0) local_14 = 200
  else if (f <= 0.5) local_14 = 100
  PshC8 400.0 ; chronoVitesse.hasReached(...)
  ```

  Slot 14 is written four times and **never read**, and the argument
  the timer is actually asked about is the literal `400.0`. The author
  wrote the ladder and then forgot to use it, so the ball speeds up
  every 400 ms whatever the player's pace -- in the shipped game. That
  is the fourth defect of the original's own this file has found while
  checking its own output, after `generate_maze`'s discarded
  comparison, `load()`'s empty guard and `battle`'s self-comparison.

**Nothing is open.** Twenty rows, twenty explanations, and the two
questions that settle them cost one disassembly each.

#### ...and the identity casts, all 22 of them, are conversion chains

`identity_cast` is the next-biggest unread set -- 13 on Manamon 1, 5 on
Crazy Party, 2 on Paladin, 1 each on Super Egg Hunt and Psycho Strike
-- and this file describes it as *"`double(int(x))`: a value converted
twice and changed by neither"*. Read, every row is one of two things,
and **neither is an identity**:

- **A widening chain from a narrower slot.** `interact::mode` and
  `base_pitch` are `uint16`, `internal_stat::stat_type` is a `uint8`,
  and Psycho Strike's `experience_to_next_level(uint8 arg0)` opens
  `double(int(arg0))`. The engine's `dictionary::set` takes an `int64`,
  so `int64(int(mode))` is `uint16` -> `int` -> `int64`: the compiler's
  own two steps, rendered.
- **A truncation the source wrote.** `double(int(string_to_number(s)))`
  truncates a double and widens the whole number back, which is what
  the author asked for; Crazy Party does it three times to compute a
  sound's pitch, and `int(int8(uint(character_to_ascii(c))))` is three
  deliberate steps in one expression.

**So the shape is only an identity when the inner argument is already
integral, and the text cannot tell.** `double(int(d))` loses the
fraction and `double(int(i))` loses nothing, and they are the same
eleven characters. That makes `identity_cast` the weakest of the nine
shapes -- it is kept because the collapsed snapshot it was written for
(`fade(..., double(int(music.get_volume())), ...)`) really does look
like this, and because its count still MOVES usefully: the fold rules
took Paladin 6 -> 4 -> 2 and Manamon 1 18 -> 15 -> 13. A row is to be
read with the declared type in hand, which is one grep.

#### `double_assign` was 105 rows, and 81 of them were a CHAIN

The biggest unread set, and the reason it was unread: it counted the
**destination** of an assignment as a read of it. BGT's own idiom is a
chain --

```
local_1 = string_replace(local_1, "north", string(0), true);
local_1 = string_replace(local_1, "northeast", string(45), true);
local_1 = string_replace(local_1, "south", string(180), true);
```

-- and every line of it mentions the name twice, so a chain of three or
more scored. The shape is about one value read twice in **one
expression**, so only the right-hand side counts now:

| title | before | after |
|---|---|---|
| Super Egg Hunt | 3 | **0** |
| Paladin of the Sky | 6 | **2** |
| Psycho Strike | 9 | **1** |
| Manamon 1 | 17 | **2** |
| Crazy Party | 30 | **6** |
| cs server | 40 | **13** |

#### ...and what is left points straight at the hardest open defect

Three of the 24 are read, and all three are the `use_screen_reader`
collapse: one slot carrying both operands of a short-circuit, with the
condition reading one of them twice. The text is enough to be sure --
`if ((x != 0) && (x != 0))` is never what a two-operand `&&` meant.

- **Paladin's gift eligibility.** `gift::get_gift` builds
  `!is_in_party(for_character)` and then `for_character != ""` through
  one slot, and the guard that prints *"You can not obtain this yet."*
  reads it twice. Which gifts a player can claim is therefore wrong.
- **Paladin's difficulty guard**, in the save loader: `!is_registered()`
  and `difficulty == 2` through one slot, and the condition comes out
  `if ((!is_registered() ? 1 : 0) == local_4 && (local_4 != 0))` --
  which is not even the same SHAPE as an `&&` of two tests.
- **Psycho Strike's `home::reset_rebels`**, which this file already
  records from the structurer side: `if ((local_2 != 0) && (local_2 !=
  0))` where the source has `!arg0` and `!rebels[i].former_rebel`, so
  which rebels get removed is wrong. Finding it twice over, from two
  unrelated instruments, is the cross-validation this project runs on.

**All three are fixed** -- see **Fixed, in two halves** below, where
`double_assign` reaches 0 on all three titles.

One more is read and is NOT a collapse: Manamon 1's `paladine`
constructor reads `get_possessive(this.name)` twice in one sentence,
which is the same value both times and is what the author wrote. Its
FIRST assignment -- the sentence about the spirit horse -- looks
unread, which is a different question and wants its own look.

##### Fixed, in two halves -- and the fourth attempt is why it is narrow

`_conditionally_bound` carries the argument already -- *"a
short-circuit merge slot is never one of these, however much it looks
like one... promoting it makes each operand's computation an
unconditional statement, so every term is overwritten before the `if`
reads it"* -- and the guard that acts on it lives in `_diamond_bind`,
which `_conditionally_bound` reaches only **after** its `cond_spans`
test. So the argument was made and never applied to the half that fires
first, which is the half these three guards go through.

**The fourth attempt exempted every slot in `short_circuit_slots`**, and
that is too much. It fixed both Paladin guards and broke Psycho Strike's
`find_likely_request`:

```
before:  int local_1 = -1;
         if (local_1 == -1) {
             if (arg0.loyalty <= 0) local_1 = 2;
             else if (...) local_1 = 0;
         }
         return ((arg0.bordum >= 100) || (local_1 != 0)) ? 1 : 0;

after:   if (-1 == -1) { if (arg0.loyalty <= 0) { } else { ... } }
         return ((arg0.bordum >= 100) || false) ? 1 : 0;
```

-- the `|| true` defect, re-made from a new direction, in a function
that decides what a character asks for.

**The separating fact is which END of the merge a slot is.** A
destination may be a source variable the compiler REUSED, because the
merge's result *is* that variable's value -- slot 1 above is the slot its
`||` stores into. An arm-only slot cannot be: it holds a piece of the
right-hand operand and exists only while that operand is computed. So
`_short_circuit_slots` keeps `merge_dests` as it goes, `merge_operands`
is the difference, and the fold rules exempt the second only.

Two narrowings were tried before that one and neither separates the two
bodies, which is worth recording because both sound right:

- **Read past the merge.** A variable carries its value onward, so
  something reads it there. `find_likely_request`'s slot IS the merge's
  destination, so its last read is the merge itself and it qualifies as
  the compiler's.
- **Written outside every arm.** True of `local_1 = -1` -- and also
  true of the gift's operand slot, whose left-hand half is computed
  before the jump.

##### The second half: a merge LABEL may carry the arm's scope cleanup

The exemption fixed two of the three and not `home::reset_rebels`, and
the reason was one instruction upstream of every fold rule: **that
merge was not in the pre-pass set at all.**

`_short_circuit_slots` looks for `<jump> ; SetV dest,0|1 ; JMP merge`
and then asks whether the instruction *at* `merge` loads `dest`. An arm
that indexes an array borrows a handle, so the arm's scope releases it
before the merge reads anything -- the same reason this file records for
a `break`, which emits its destructors before its own `JMP`:

```
    JLowNZ -> L1 ; SetV4 2,0 ; JMP -> L2
L1: ... opIndex ; RefCpyV 3 ; ... ; CpyVtoV4 2,4
L2: FREE 3            <- the merge LABEL: the borrowed array handle
    CpyVtoR4 2        <- ...and the load, one instruction on
```

So the label was read, the load was missed, and slot 2 was forced to be
a variable -- in a body where it serves the loop bound **and** both
operands of the `&&`:

```
before:  local_2 = rebels.get_length();
         if (local_1 >= local_2) break;
         local_2 = (arg0 ? 1 : 0);
         local_2 = ((local_2 == 0) ? 1 : 0);
         local_2 = (!rebels[local_1].former_rebel ? 1 : 0);
         if ((local_2 != 0) && (local_2 != 0)) { } else { ...remove... }

after:   for (; local_1 < rebels.get_length(); local_1++) {
             if (!arg0 && !rebels[local_1].former_rebel) continue;
             rebels[local_1].reset();
```

**The loop came back with it**, which is the second time in this file a
collapsed condition turns out to have been hiding a `for` header: the
bound was in the same slot, so folding the operands away let
`_find_latch` see it.

Only cleanup that cannot touch the destination is skipped -- a `FREE` or
`ClrVPtr` of *another* slot, and the markers that compile to nothing. A
`FREE` of the destination is not cleanup before the merge, it is the end
of the value's life, so the run stops there.

##### What the pair cost

| title | lines | goto | split | calls |
|---|---|---|---|---|
| Super Egg Hunt | 5,302 (byte-identical) | 0 | verified | 1,608 |
| Paladin of the Sky | 23,442 -> **23,396** | 0 | verified | 6,952 |
| Psycho Strike | 24,431 -> **24,419** | 0 | verified | 6,406 |
| Crazy Party | 175,334 -> **174,780** | 0 | verified | 90,148 |
| Manamon 1 | 83,407 -> **83,371** | 0 | verified | 26,483 -> 26,484 |
| cs server | 10,876 -> **10,139** | 0 | verified | 3,018 |

**Crazy Party's goto count does not move**, which is the number this
family is judged by: the three earlier rejections took it 14 -> 30, -> 44
and -> 90, and this file's own undertaking was that if it moved, the change
came out with its number. It is 0 before and after, with 90,148 calls read
back and the split still verified. Manamon 1's one extra call read back is
a call site the text now spells once rather than folding, not a call that
was missing.

The two halves are separable, because the cheap titles were measured
at each: the exemption alone is Paladin 23,400 and Psycho Strike 24,431,
and the merge locator takes those to 23,396 and 24,419.

**`double_assign` reaches 0 on all three cheap titles** -- Paladin 2 -> 0,
Psycho Strike 1 -> 0, Super Egg Hunt already 0 -- which is the whole of
what that sweep had left after its own narrowing, and every one of the
three was a real collapsed guard. Nothing else in `bgt signatures` moves
but Paladin's `identity_cast`, 2 -> 3, and that row is the save loader
reading `facing = int8(int(...))` in one expression where it used to
route the same chain through a scratch variable: the same program, one
line shorter, and the weakest of the nine shapes (see **...and the
identity casts**).

Every `bgt audit` comparison is identical before and after on both
titles that can be audited here -- Paladin 25 call rows and 2 constant
rows, Psycho Strike 41 and 2 -- `bgt oracle` is 52/52, and the four
games that came with their own source hold exactly: the `cs` server 194
of 196, its client **218 of 218** (see below), rage room 291 of 292
and constant
velocity 94 of 95, with 0 differing on all but the server's one.

##### The trace that found it, worth repeating rather than re-deriving

`gift::get_gift`'s bytecode is a textbook `&&` merge, and reading it was
not what answered the question:

```
CALL is_in_party ; CpyRtoV4 7 ; NOT 7      ; the LEFT operand, in slot 7
SetV1 8 0 ; NOT 8                          ; a materialised `true`
CMPi 7 8 ; JZ -> L6                        ; the test, by COMPARE
SetV4 8 0 ; JMP -> L7                      ; the short-circuit store
L6: ... string::opEquals ; CpyRtoV4 7 ; NOT 7
    CpyVtoV4 8 7                           ; the arm's store
L7: CpyVtoR4 8 ; JLowZ                     ; the merge
```

What promotes slot 7 is `_conditionally_bound` -- rule two, the value
computed on one path and read past the join -- and that was found with
`sys.settrace` on the method, recording the line each call returns from,
over `ModuleDecompiler._body` for the one function. **Two guesses from
reading the code came first and both were wrong**, which is the whole
argument for the trace: a fold rule's answer depends on four tables and
a position, and the method that fires is not the one that looks
likeliest.

#### A NESTED short-circuit, and the copy that hid its bool test

A different mechanism from the chain below, found from a second report on the
same title -- *"when I press control to fire the weapon it is like it is
stuck"* -- and **fixed**.

`_begin_bool_merge` folds `(A op B)` only where it can tell the merged value
is a bool, and on a compiler scratch slot the width inference is the weaker
witness, so the bytecode is asked instead: a slot loaded and tested with
`JLow*` is a bool, because those follow no compare and test the low byte,
which is the bool protocol and nothing else. This file already records
widening that test once, for a `FREE` sitting between the merge and the jump.

**A nested short-circuit puts a COPY in the way.** Field Wars' `k_ctrl` is
one condition built of four `&&` pairs joined by `||`, each pair holding its
own inner `||`:

```
return (mode == 0 and (key_down(LCTRL)     or key_down(RCTRL)))
    or (mode == 1 and (key_pressed(LCTRL)  or key_pressed(RCTRL)))
    or (mode == 2 and (key_released(LCTRL) or key_released(RCTRL)))
    or ...
```

The inner merge's result is stored into the outer chain's own slot, and it is
*that* slot the jump tests:

```
59  CpyVtoV4 4, 1     <- the inner merge's result
61  CpyVtoV4 2, 4     <- copied again
63  CpyVtoR4 2
64  JLowZ             <- the bool test, two slots along
```

Looked for on slot 4 the test is not there, so all three inner `||` pairs
were declined -- each emitted as an `if` with two empty arms, each **losing
its LEFT operand**:

```
if (key_pressed(KEY_LCONTROL)) { } else { }
...
|| ((arg0 == 1) && key_pressed(KEY_RCONTROL))
```

`k_ctrl` is how that game reads the control key, so `k_ctrl(1)` answered for
the RIGHT control alone and firing the weapon with the left one did nothing
at all. `k_shift` is the same function one key over, with the same three.

So `_tested_as_bool` follows a copy whose source is the slot it is asking
about, up to `_BOOL_COPY_HOPS` of them -- bounded, so a long copy chain
cannot become an open-ended search for a test that is not there. Only a copy
**of** the slot carries the question onward; a copy *into* it is a different
value.

#### What it cost: two titles, and nothing else moved

| title | lines | goto | split | calls read back |
|---|---|---|---|---|
| Field Wars | 9,048 -> **9,021** | 0 | verified | 3,001 |
| The Gate | 34,955 -> **34,943** | 0 | verified | 8,665 |
| Super Egg Hunt, BTH, rage room, cs client, cs server, constant velocity | unchanged | 0 | verified | unchanged |

Field Wars' `empty_arm` goes **10 -> 1** and its `bgt audit` is identical
before and after -- 1 call row, 0 literals, 0 constants -- so nothing was
lost to get there. The Gate's audit is identical too, at 144 / 2 / 3.

`bgt oracle` is **52/52**, and all four games that came with their own source
score exactly as they did: rage room 291/292 and the `cs` client **218/218**
with 0 differing, constant velocity 94/95, the `cs` server 194/196.

Six of eight titles unchanged and the two that move losing only the lines
these empty arms occupied is what a correctly scoped fix looks like.

#### A CHAIN of three or more terms, and why the obvious fix is REJECTED

The two halves above are right and they are not the whole of it. A
**chain** -- `a && b && c && d` -- is a different shape from a single
`&&`, and nothing in this file had looked at one. **This section is a
diagnosis and an instrument, not a fix**: four attempts are recorded
below, every one of them measured, and every one rejected for breaking
something else.

`CompileBooleanOperator` nests to the left, so five terms is four merges,
and the allocator hands a scratch slot out again once a merge's
destination has been consumed. Field Wars' player movement is five terms
over **three slots**, so two of them are a destination twice:

```
L118: CpyVtoR4 14 ; JLowNZ L119 ; SetV4 22,0 ; JMP L120   dest 22
L120: CpyVtoR4 22 ; JLowNZ L121 ; SetV4 24,0 ; JMP L122   dest 24
L122: CpyVtoR4 24 ; JLowNZ L123 ; SetV4 14,0 ; JMP L124   dest 14  <- again
L124: CpyVtoR4 14 ; JLowNZ L125 ; SetV4 22,0 ; JMP L126   dest 22  <- again
L126: CpyVtoR4 22 ; JLowZ  L127                           the `if`
```

Every one of those is a **destination**, and the fold rules exempt only
the ARM operands -- `_conditionally_bound` says so outright, because a
lone destination may be a variable the compiler reused, which is Psycho
Strike's `find_likely_request`. So every slot here is promoted to a
variable, every arm's computation becomes an unconditional statement, and
the later merges overwrite the earlier terms:

```
source:     flytimer.elapsed > flytime && !inac && me.x < maxpos
                && key_up(KEY_LSHIFT) && key_up(KEY_RSHIFT)

recovered:  local_24 = (flytimer.get_elapsed() > flytime);
            local_14 = local_24;                       // the TIMER, parked
            ...
            local_14 = (inac ? 1 : 0);                 // ...overwritten
            if (key_down(KEY_UP) && (local_14 != 0) && (local_24 != 0)
                && (local_21 != 0))
```

-- the flight timer computed, parked, overwritten and never tested, and in
the companion block two terms tested twice with `!inac` gone. **The game
compiled, ran, and nothing moved on a held key**, which is how it was
reported: *"none of the timers work when it comes to walking"*. The timers
were never the problem.

#### The `cs` server has it too, and its author's source names the cost

The nine rows on that title are what makes this more than one game's
movement, because its source is in hand and `part_0.bgt` is the game's
**own** code rather than a library file. Every one is a permission check
in the command dispatcher:

| the author's `server.bgt` | recovered |
|---|---|
| `!players[i].dev and players[i].tempdev and players[i].admin and flag==1` | `!dev && tempdev && (local_16 != 0) && (local_16 != 0)` |
| `!dev and !tempdev and !admin` | collapsed the same way |
| `parsed[0]=="/baselist"&&dev&&tempdev` | collapsed the same way |

**The `admin` term is gone from the recovered server's dispatcher**, which
decides who may run an administrative command.

**`bgt libcheck` cannot see any of this**, and says so by not moving: 194
of 196 before and after every attempt below. A collapsed condition still
*contains* its calls, in the right order, with the right literals, which
this file already records about that score -- and the author's own text
for these bodies is in `server.bgt`, the main script, which `--include`
never reaches.

#### The tenth shape, which is what this section ships

`bgt signatures` swept Field Wars and reported **nothing** -- all nine
shapes zero -- while that title's player could not walk:

- `double_assign` wants a name assigned twice **in a row**, and a chain's
  assignments interleave across three slots;
- `tautology` wants `x == x`, and this is `x != 0 && ... && x != 0`.

`collapsed_chain` is a condition with **two or more** short-circuit
operators that tests one slot more than once. Two operators, because a
chain needs three terms before the compiler has to recycle a destination:
with one merge there is one destination and nothing to overwrite. The
condition is bracket-matched rather than patterned, for the reason
`same_argument` already records -- `(me.x < float(maxpos))` has a level of
nesting in it, and a pattern that cannot see one under-reports the very
baseline it is meant to measure.

Swept over every title in the corpus:

| title | `collapsed_chain` |
|---|---|
| Field Wars | **9** |
| cs server | **9** |
| Crazy Party | **3** |
| Super Egg Hunt, The Gate, BTH, rage room, cs client, constant velocity, Manamon 1 | 0 |

**And `empty_arm` was widened**, because it could only see an empty `if`
arm: `_empty_else` was consulted only to upgrade an already-empty arm to
`two_empty_arms`, so an empty `else` under a non-empty arm was invisible
-- which is exactly what a collapsed fold leaves when the arm that folded
away is the second one. It now reports either arm, once per construct.
Baseline: Crazy Party 85, Field Wars and The Gate 10, Manamon 1 8, cs
client 6, cs server 4, Egg Hunt 3, rage room 1, BTH and constant velocity
0.

#### Six attempts, and the cause the sixth one finally named

Every one of these was measured and every one rejected.

| attempt | Field Wars | what it broke |
|---|---|---|
| 1. `_stale_fold` exempts `merge_operands \| merge_chain_links`, a chain link being any destination some merge tests | 9 -> 0 | the server's nested ternary: `" (AFK)"` and `" (active)"` gone, `get_player_index_from` 32 -> 30 |
| 2. ...with chain links derived by ADJACENCY -- a link's own merge-label load is the next merge's test | 9 -> 0 | the same ternary; adjacency alone does not undo it |
| 3. ...and `_stale_fold` narrowed to the chain links only | 9 -> 0 | the ternary comes back and `/godmode` breaks -- see below |
| 4. ...keyed on the bind position, then on the read position | **9 -> 9** | nothing, because the promoting read is somewhere else entirely and the fix is simply undone |
| 5. `_stale_fold` exempts the whole short-circuit set, mirroring `_diamond_bind`, minus the ternaries `_begin_bool_merge`'s own test finds | 9 -> 0 | `/godmode` again: that test finds **none** of this body's ternaries, because theirs is a shape it never looks at |
| 6. ...with ternary destinations found by the FALL-THROUGH arm's shape instead | **9 -> 11** | `/godmode` is right at last, and the detection over-reaches -- 14 of netloop's 23 short-circuit slots -- so the chains collapse again and Field Wars gets worse |

**The cause is structural, and attempt 4 is what proves it.** Promoting a
slot gives it a NAME, and a name belongs to the slot for the whole body,
while staleness is a property of one VALUE. Field Wars' `game` is 5,733
instructions, and slots 14, 22 and 24 are each promoted by exactly one
read -- 7485, 7860 and 3876, which are `inac` and `me.x` and one more,
every one of them a global read going stale through a call, every one of
them correct. Each promotion then collapses every chain in the function
that shares the slot, 2,000 instructions away. No exemption keyed on a
position can help, because by the time the chain is reached the slot is
already named; only refusing to promote the slot at all does, which is
what attempts 1, 2, 3 and 5 do.

**And a ternary needs exactly the same thing for the opposite reason.**
`_begin_value_merge` rejects a named destination just as
`_begin_bool_merge` does, so a ternary also needs its slot foldable --
and its two arms are the only thing carrying its two values, where a
short-circuit that loses the fold merely reads a name instead of an
expression. `cs`'s `netloop` uses slot 57 for both: a real short-circuit
destination in one place and

```
players[index].godmode = (players[index].godmode == true ? false : true);
```

in another. One slot, one name, two incompatible requirements.

**So the fix is not a fold rule.** It is to give a merged value its own
identity instead of borrowing the slot's -- `_begin_bool_merge` already
records the whole `(A op B)`, and what it reads for `A` is the slot's
current atom rather than the atom the arm stored. Recording that atom per
merge and reading it back there would make the chain independent of
whether the slot ever gets a name. The one thing to get right is the
assignment the promotion emits: a chain link has exactly one consumer,
its own merge -- that is the adjacency property above -- so once the
merge uses the recorded atom the assignment is dead and has to go, or the
expression runs twice and a duplication is traded for a collapse.

**Attempt 3 is the one that nearly shipped, and `/godmode` is why it did
not.** The author wrote a toggle whose arms are the constants `false` and
`true`:

```
source:    players[index].godmode = (players[index].godmode == true
                                     ? false : true);
at HEAD:   players[local_24].godmode = (local_16 != 0);
attempt 3: players[local_24].godmode = true;
```

A ternary over 0 and 1 matches the short-circuit shape exactly -- this
file already records that hazard for `_begin_bool_merge` -- and its
destination slot is **also** a destination in the four-term `&&` that
guards the command, so exempting by slot folded its arms away. Godmode
could be switched on and never off. Trading a visible failure for a
silent wrong program is the one trade this file refuses, so attempt 3
came out.

**The widened `empty_arm` is what caught it**, which is the argument for
shipping the instruments on their own: `if (godmode) { } else { }` with
both arms gone, in a shape the sweep could not see an hour earlier.

#### The problem has a NAME, and two decompilers have met it

Searched for rather than re-derived, and the answer reframes everything
above: **this is the standard hard problem of decompilation, and the best
commercial tool punts it to a human.**

- **Hex-Rays.** Its own documentation says a compiler "can actually reuse
  the *same stack location* for different variables active at different
  times", and what IDA offers is a manual `Split variable` (Shift-S) that
  "introduce[s] a new variable for the same stack location" -- adding that
  "the decompiler does not perform any checks". So the industry-leading
  decompiler does not solve this automatically; it gives the user a knife
  and no guard.
- **angr solved the narrow version, and had this exact bug.** Pull request
  #7479 is titled "Consider variable liveness ranges when recognizing stack
  variables from SSA VVars", and its commit message is "split a seeded stack
  region among vvars whose live ranges interfere". What it fixed: `h += f()`
  on 386, where the old `h` and the call's result shared a slot and were both
  live at the concatenation, **rendered as `v0 + v0`**.

`v0 + v0` is `(local_14 != 0) && (local_14 != 0)` under another name. The
same bug, in a mainstream decompiler, fixed by adding an interference check.

- **There is no other AngelScript decompiler to borrow from.** The search
  turned up one disassembler (`asumagic/angelscript-disassembler`, a modified
  `asbuild` that prints bytecode) and the SDK's own compiler-side sample. The
  only general-purpose AngelScript *decompiler* it found is this one.

#### `slot_webs`, which is the machinery that fix needs

So the fix is not a fold rule, and `_promote_temp`'s own docstring already
says why one is not enough: *"The slot gets one name, not a name per
promotion"*, because a fresh name per promotion split `dynamic_menu`'s
joystick edge flag in two and "pressing up disarmed down". That failure and
the collapsed chain are **the same question asked from both ends**, and
neither can be answered without knowing whether two definitions of a slot
INTERFERE.

`FuncDecompiler.slot_webs(slot)` answers it: reaching definitions over the
instruction-level CFG, then union the definitions that share a use. A web is
one source variable; two webs in one slot are two variables the compiler gave
one slot.

**Validated against three cases whose answer is known independently**, two of
which pull in opposite directions:

| case | must | answer |
|---|---|---|
| `dynamic_menu::run_extended` slot 20, the joystick flag | **not** split | 4 writes, 2 reads -> **1 web** |
| Field Wars `game` slots 14 / 22 / 24 | split | 163/136/67 writes -> **140/110/57 webs** |
| `cs` `netloop` slot 57, chain and `/godmode` ternary | split | separated |

and on the same body it leaves alone what should be left alone: slots 9 and
13 of `run_extended` are 2 writes and 8 reads each and come out as **one**
web, while its genuine temporaries (76 writes, 74 reads) come out as 74.

**The worklist has to start from every instruction.** Seeded from the entry
alone it ran exactly ONE round and stopped -- the entry's state is empty,
propagating an empty set changes nothing, and a node is re-queued only when
its state changes, so no definition was ever reached. Every write then came
out as its own web, *including the joystick flag's four*, and the analysis
looked like it was working: 163 writes, 163 webs, which is a plausible number
for a slot that really does carry 163 temporaries. The tell was the flag
reporting 4 and 4 when the right answer is 1.

**It went in as analysis only and is spent now** -- see below, where
`is_named_here` asks it per web. A body over `WEB_ANALYSIS_LIMIT` declines
rather than spending a fixpoint on Crazy Party's 1,074,460-instruction
generated function, and declining means no split, which is the conservative
answer and what this file did everywhere before.

#### Attempt seven: `is_named`, asked of the VALUE

The step this section prescribed was taken: make `is_named` web-local. It
fixes **all four reported defects at once**, and `bgt oracle` rejected it.
Both halves are worth having.

**The audit of its fifteen call sites is reusable**, and the split is clean:

| asked of | sites | why |
|---|---|---|
| the **value** | 12 -- `_bind`, the merge fold, `FREE`, `STOREOBJ`, the `?&out` argument, the receiver test, the constructor and destructor handlers, both ternary checks | every one runs at a position and wants to know what is in the slot THERE |
| the **slot** | 2 -- `_stale_fold`'s behaviour-write narrowing, the declaration hoisting | one asks whether the source ever named the slot at all; the other is about names |

`is_named_here` answers for the web containing the current position, and
falls back to the old answer for a slot with one web -- so nothing moves for
a slot that really is one variable.

**What makes a web a variable is having more than one definition**: two paths
write it and one read sees both, which is what a declared local looks like
once the compiler has laid it out. The exception is a short-circuit's own
destination, which has two definitions as well -- the `SetV dest, 0|1` and
the arm's store -- and must still fold or the structurer loses the condition;
`sc_defs` records those positions while the merges are found, so the
exception is exact rather than another shape guess.

#### It fixed all four, and the numbers were good

| | before | after |
|---|---|---|
| Field Wars' movement conditions | the timer term parked and overwritten | **every term tested** |
| the `cs` server's `admin` check | the term gone | **restored** |
| `/godmode` | `godmode = true`, on and never off | **the toggle** |
| the AFK marker in `/adminlist` | both literals gone | **both back** |

`collapsed_chain` **0 on every title**; `empty_arm` down (`cs` server 6 -> 1,
Field Wars 10 -> 9); residual gotos, dangling gotos, dangling `else`,
unbalanced files, passthrough and bodies given up on **0 everywhere before
and after**; every split verified. Lines fell on six of eight titles and the
call count **rose on four and fell on none** -- Super Egg Hunt 1,607 ->
1,623, The Gate 8,665 -> 8,679, Field Wars 3,001 -> 3,005, the `cs` server
3,032 -> 3,060.

Against the games that came with their source: rage room 291/292 and
constant velocity 94/95 unchanged, the `cs` server 194/196 unchanged, and the
`cs` client 218/218 -> 216/218. Those two are `position_sound_custom_2d` and
`_3d`, and both are the ordering approximation this file records for
`control::focus`: the author writes the rotation x-then-y and the recovery
computed y-then-x, both from the old coordinates, both assigned correctly,
with `sine` and `cosine` pure -- so unobservable, and the new rendering was
tighter besides.

#### `bgt oracle` said no first, and what it was saying

**`counter` went 13 -> 12**, which is that fixture's whole purpose -- it
counts the impure calls a recovery makes, so one fewer is one call lost.
Four shapes moved and named it exactly:

| shape | expected | got |
|---|---|---|
| `declared_reassigned` | 7 | **6** |
| `declared_as_loop_bound` | 36 | **28** |
| `pre_and_post` | 757 | **777** |
| `counter` | 13 | **12** |

`declared_reassigned` is `int v = bump(); v = bump(); return v;`. The first
store is dead -- overwritten before any read -- and webs prove it, where
the old reading could not. Dropping a dead store is right; dropping it
**with its call** is not, and `bump()` is impure by construction.

It vindicated the fixture: every text sweep, every audit, both
ground-truth games and the whole corpus said the change was good, and the
only instrument that caught a lost call was the one that runs the program.

#### Taken, once the census could count

Two things had to be true first, and both are now:

- **The lost-call census counts CALL INSTRUCTIONS**, so
  `int v = bump(); v = bump();` is two calls where one rendering used to
  vouch for both. That is what catches the dead store's call and puts it
  back. See **Taken, and a BIND is not a CALL**.
- **`pre_and_post` needed a write nothing recorded**, which is below.

With those, `bgt oracle` is **52/52** and its `counter` is 13.

##### `is_named_here`, and the audit of where to ask it

`is_named_here(off)` answers for the web containing the current position
and falls back to the whole-body answer wherever there is nothing to split
-- one web, a single write, or a body over `WEB_ANALYSIS_LIMIT` -- so
nothing moves for a slot that really is one variable.

Which way each call site asks was audited rather than guessed, and the
split is clean:

| asked of | sites |
|---|---|
| the **value** | `_bind`, the merge fold, `STOREOBJ`, `FREE`, the `?&out` argument, the receiver test, both constructor branches, the destructor, the member-array branch, both ternary checks -- **twelve**, each running at a position |
| the **slot** | `_stale_fold`'s behaviour-write narrowing (does the source name it *at all*?) and the declaration hoisting (which is about names) -- **two** |

**What makes a web a variable is having more than one definition**: two
paths write it and one read sees both, which is what a declared local looks
like once the compiler has laid it out. The exception is a short-circuit's
own destination, which has two as well -- the `SetV dest,0|1` and the arm's
store -- and must still fold or the structurer loses the condition. So
`sc_defs` records those positions while the merges are found, and only the
merge's **own** definitions are excluded: Psycho Strike's
`find_likely_request` is `int local_1 = -1;` in a slot that is also a
merge's destination, and excluding by slot folded its arms away and remade
the `|| true` defect from a new direction.

##### A slot written THROUGH THE REFERENCE REGISTER is written

The third place in this file where a write cannot be seen by the record
built to hold every write, after a behaviour's pushed address and `ALLOC`'s
stacked destination. `a++` compiles to `LDV 1 ; INCi`, so the increment's
operands name nothing at all and `slot_writes` was blind to it.

`pre_and_post` is the shape, and the oracle is what reported it:

```
int a = 5;
int b = a++;        // b = 5, a = 6
int c = ++a;        // a = 7, c = 7
return a*100 + b*10 + c;                    // 757

SetV4 1 5 ; LDV 1 ; RDR4 2 ; INCi ; CpyVtoV4 3 2
          ; LDV 1 ; INCi ; RDR4 2 ; CpyVtoV4 4 2
```

Slot 2 is the compiler's scratch, so a value taken out of it folds -- and
the value is `local_1`, read after `INCi` has changed slot 1. Nothing could
see that, so the recovery returned **777 for 757**.

`_ref_register_writes` walks each `LDV n` forward to the writes through the
register and records them in `slot_writes`, because that record already
answers the question they belong to: has this slot been written since? A
jump in between makes the write conditional and it is recorded anyway --
the consumer asks whether anything MAY have changed the slot, so a write
that might not happen is the safe direction.

It is one function rather than a loop inside the pre-pass, because the test
for it was written as a copy of the walk first. That is the trap this file
records about building an inverse from the same table: it would have agreed
with a wrong one.

##### ...and promoting one slot TWICE assigns it to itself

`_promote_temp` ends by putting the slot's own name into `temps[off]`, so a
second promotion of the same offset emits `local_4 = local_4;` -- at the
first one's bind position, which is how it was found: one `CpyVtoV4 4 3`
emitting three statements.

It takes two reads in different parts of a body to reach, so it only
appears once `is_named_here` can answer differently at two positions of one
slot. **630 of them across eight titles, 459 on the `cs` server alone**,
and the sweep is what said so: `self_identical` 0 -> 459 is the signature
this file keeps for a collapsed snapshot, reporting something else.

The guard is that there is nothing left to assign. The original's own
`arg0 = arg0;` is **not** this and is still emitted: that one is a real
`string::opAssign` in the bytecode, rendered at its own instruction through
the call path.

#### What it fixed, and what it cost

Four defects reported from playing these games, all one cause:

| | before | after |
|---|---|---|
| Field Wars' walking and held keys | the timer term parked and overwritten | **every term tested** |
| the `cs` server's command dispatcher | the `admin` check gone | **restored** |
| `/godmode` | `godmode = true`, on and never off | **the toggle** |
| the AFK marker in `/adminlist` | both literals gone | **both back** |

Field Wars is the one a user reported twice, as *"none of the timers work
when it comes to walking"*. Its movement condition now reads

```
if (key_down(KEY_LEFT) && flytimer.get_elapsed() > double(flytime)
    && inac && me.x > 0.0 && key_up(KEY_LSHIFT) && key_up(KEY_RSHIFT))
```

where the recovery used to compute the timer into a slot, overwrite it, and
test what was left. **And `bgt drive` confirms it from the other side**:
all three of its canned scenarios pass on the fixed recovery, and
`k_ctrl(1)` reads 0 before the fix and 1 after.

| title | lines | calls read back | goto | split |
|---|---|---|---|---|
| Super Egg Hunt | 5,302 -> **5,239** | 1,607 -> **1,623** | 0 | verified |
| The Gate | 34,944 -> **33,995** | 8,666 -> **8,680** | 0 | verified |
| Battle of the Hunter | 4,373 -> **4,269** | 1,334 | 0 | verified |
| Field Wars | 9,021 -> **7,942** | 3,001 -> **3,005** | 0 | verified |
| rage room | 8,683 -> **8,484** | 2,369 | 0 | verified |
| cs server | 10,130 -> **9,691** | 3,033 -> **3,060** | 0 | verified |
| cs client | 8,178 -> **7,963** | 2,858 | 0 | verified |
| constant velocity | 3,883 -> **3,805** | 1,767 | 0 | verified |

**Calls up on four titles and down on none**, which this file counts as the
result rather than a side effect: a call read back is a call the program
makes. Residual gotos, dangling gotos, dangling `else`, unbalanced files,
passthrough and bodies given up on are **0 everywhere before and after**,
every split verifies, and `bgt oracle` is 52/52.

The sweeps, which is where the diagnosis shows:

| title | `collapsed_chain` | `double_assign` | `empty_arm` | `self_identical` |
|---|---|---|---|---|
| Field Wars | **9 -> 0** | 1 | 1 | 0 |
| cs server | **9 -> 0** | 21 -> **11** | 4 -> **1** | 0 |
| The Gate | 0 | 3 -> **0** | 6 | 0 |
| cs client | 0 | 1 -> **0** | 6 | 0 |
| the other four | 0 | 0 | unchanged | 0 |

Not one shape gets worse on any title.

**And the ground truth holds**, which is the measurement that decides it:
rage room **291 of 292** with 0 differing, the `cs` server **194 of 196**,
constant velocity **94 of 95** -- all exactly as before. The `cs` client
goes 218 to 216, and both rows are the ordering approximation this file
records for `control::focus`: `position_sound_custom_2d` and `_3d` compute
the rotated y into a temp before overwriting x, which is what the bytecode
does and reads the same old coordinates either way, with `sine` and
`cosine` pure.

The bytecode audits are identical on Field Wars and Super Egg Hunt, the
`cs` server's literal row **clears** (1 -> 0), and The Gate gains two
constant rows -- `find_good_weapon`'s `-100` and `moving_levels`' `-1`,
both sentinel stores overwritten before any read. Those are the shape this
file already triages as the original's own dead locals, and webs can
**prove** them dead where a linear reading cannot, which is why they are
now dropped.

#### What IS kept from the rejected attempt: the two walks are memoised

`_slot_io` and `_successors` are pure functions of the body and were rebuilt
once per slot, which made `slot_webs` quadratic in a way that showed on
Manamon 1. Memoised per instance, Super Egg Hunt's whole recovery takes
twelve seconds with the analysis present.

#### Two bugs in the analysis, and neither was caught by a count

- **The worklist started from the entry alone**, so it ran exactly ONE round
  and stopped: the entry's state is empty, propagating an empty set changes
  nothing, and a node is re-queued only when its state changes. Every write
  came out as its own web -- a plausible 163 writes, 163 webs -- and the tell
  was `dynamic_menu`'s joystick flag reporting 4 and 4 when the answer is 1.
- **The named-web answer was cached once for all slots**, from a `_webs`
  dict that fills in lazily, so the cache was built from whichever slots the
  simulation happened to ask about first. `cs`'s slot 57 was not among them,
  so `/godmode` came out unnamed while a standalone probe of the same body
  said the web WAS named. It is cached per slot now.

And two more in the wiring, both of which failed **loudly**, which is the
good case:

- **A web holds instruction POSITIONS, not indices.** `slot_webs` converts
  before returning, so indexing `instrs` with a member is out of range: ten
  oracle bodies came out as `// [decompiler error: IndexError(...)]`.
- **The pre-pass loop continues past `construct_sites`**, so a sort inserted
  after that line landed in the middle of the loop and swallowed the
  `assigned_slots` block. `callee` was then unbound and every body raised,
  in all 52 shapes at once.

#### What it exposed: four places that rendered a type from the wrong thing

None of these is the webs analysis. Each is a place that needed a type and
took the nearest one to hand, and each only showed once a slot could be a
variable in one part of a body and scratch in another. **`bgt drive` found
three of the four**, by compiling and running each recovery -- which is what
it is for, and the first time a new instrument here has paid for itself the
same night.

##### A conversion's result type is known exactly, and was not recorded

`dTOi 19 9` makes an `int`, and the handler built `Atom("call", "int(...)")`
with **no `data_type` at all** -- so everything downstream that asks what the
value is got nothing. `PRIMITIVE_TOKENS` is the inverse of the reader's own
`PRIMITIVE_NAMES` rather than a second table, because two spellings of one
fact is what the `$beh0`/`_beh_0_` lesson in this file cost. A negation
carries its operand's type, for the same reason it carries the origin.

##### ...so a hold was typed from the slot it was INVALIDATING

That is a different variable by construction -- the whole reason a hold
exists -- and `cs`'s server is what said so:

```
ALLOC string -> slot 14               ; parts[?]
VAR 14 ; CALL stn ; CpyRtoV8 9 ; NEGd 9 ; dTOi 19 9
PshV4 19                              ; push int(-stn(local_14))
PSF 14 ; ... opIndex ; ALLOC string   ; slot 14 REBUILT
VAR 14                                ; push the new string
CALLINTF player::give
```

so the held value is an **int** that reads slot 14, and it came out

```
string __nvgt_held_14_24133 = int(-(stn(local_14)));
players[local_32].give(local_14, __nvgt_held_14_24133);
No matching signatures to 'player::give(string, string)'
Candidates are: void player::give(string arg0, int arg1)
```

Eight of those on that server and three on its client, so **neither project
compiled at all** -- which is worse than the stale read the hold was fixing.

**Dropping the fallback alone is the wrong fix, and was measured as one.**
With no type the hold is refused, which is what the docstring already
promised -- and the refusal brings the stale read back:
`give(local_14, int(-(stn(local_14))))` reads slot 14 at the call, by which
time it holds the next string, and the client's `spawn_player` came out with
one slot read three times. That is a visible failure traded for a silent
wrong program, which is the one trade this file refuses. Typing the
conversion is what makes the hold right rather than absent.

##### A promotion writes its own statement, so it has to convert too

`_promote_temp` already notices a bool going into a numeric slot -- it adds
the offset to `mixed_boolean_slots`, whose contract this file states as *"the
slot keeps the numeric type, the store writes 1/0, and reads convert back
with `!= 0`"* -- and then emitted a store that writes the bool.
`_emit_assign` is the half that honours the contract.

The Gate's `load()` is the case, and the position is why it was easy to
misplace: the statement lands at pos **103**, the `SetV1 4` bind, while the
`?&out` local it names is created at pos 248. Adding the offset to the set at
the call site -- the first attempt -- changes nothing, because nothing on
that path reads it.

##### A negative constant stored into an unsigned local needs the cast

`Implicit conversion changed sign of value` is a warning, and a warning stops
an unattended compile on BGT's modal dialog. The Gate's `find_attack_point`
is the one site in the corpus:

```
uint local_9;
local_9 = (0 - 1);          // the engine warns
...
if (local_18 >= local_9)    // CMPu -- the slot really IS unsigned
```

The declaration is right -- the comparison that reads it is `CMPu` -- so the
bits are 0xFFFFFFFF either way and only the spelling draws the warning.
`uint(0 - 1)` and `4294967295` were both put to the compiler, and both give
4294967295. Keyed on a **compile-time negative constant**, because that is
what the engine can see and warns about: an unsigned local assigned a
non-negative int draws nothing. Swept across all eight titles, before and
after: one site in one title, and none at all in the baseline, where the
value folded into its use.

##### What they cost

| title | lines | calls | goto | split |
|---|---|---|---|---|
| Super Egg Hunt | 5,239 | 1,623 | 0 | verified |
| The Gate | 33,995 | 8,680 -> **8,681** | 0 | verified |
| Battle of the Hunter | 4,269 | 1,334 | 0 | verified |
| Field Wars | 7,942 | 3,005 | 0 | verified |
| rage room | 8,484 | 2,369 | 0 | verified |
| cs server | 9,691 | 3,060 | 0 | verified |
| cs client | 7,963 | 2,858 | 0 | verified |
| constant velocity | 3,805 | 1,767 | 0 | verified |

Six titles **byte-identical**; The Gate moves by the two lines these fix and
one call, which is `bgt apicheck` reading `uint(` as the call it
syntactically is; the `cs` server by two more of the same shape. Every
ground-truth score, every signature and every audit is exactly as the
section above records them, and `bgt oracle` is 52/52.

**And the recoveries RUN.** `bgt drive` reaches its table on Super Egg Hunt,
Battle of the Hunter, rage room, constant velocity, Field Wars and -- for the
first time -- the `cs` **client**, which is 7,963 lines of a networked game
compiling and starting from recovered source. Each of those is a stronger
claim than a clean compile, because a global initialiser that throws stops
the program and `-c` never runs one.

##### ...and a generated global initialiser declares nothing

The one error left on the `cs` server after all of that, and it was in the
baseline too. `Structurer.render()` emits statements; the declaration
hoisting that gives an ordinary function its locals lives in `_body`, and a
global's initialiser never goes through it -- so the helper declared the
global and nothing else:

```
string __nvgt_global_init_64() {
    string changes;
    local_1 = (("\r\nnew in " + version) + "...");   // never declared
    changes = string();
    changes = local_1;
    return changes;
}
```

`_initialiser_declarations` supplies them, with the same scalar test `_body`
applies and for the same reason: an object local is constructed where the
bytecode constructs it. Two things it will not do. A name one of the
statements already declares is skipped, because a second declaration is an
error of its own -- and that is exactly what the generated `__nvgt_out_*` and
`__nvgt_held_*` locals are, since they carry their type on the statement. And
a name that occurs only inside a string literal is still declared,
deliberately: an unused declaration compiles and a missing one does not, so
where the two cannot be told apart this takes the harmless side.

**With it, the `cs` server compiles and runs.** `bgt drive` reaches its table
on seven of the eight titles that can be built here -- Super Egg Hunt, Battle
of the Hunter, rage room, constant velocity, Field Wars, the `cs` client and
the `cs` server -- which for a 9,700-line networked game recovered from a
stripped module is the strongest end-to-end result in this file.

The eighth is The Gate, and it is not this work's: it **needs `elias`**, which
no stock BGT registers, so `elias theme;` fails and every `theme.x()` after it
is `Illegal operation on 'int&'`. One missing engine type and a cascade, the
same shape as Manamon 2's `protected`.

#### ...and `duplicated_call` was counting CONVERSIONS

The same correction one shape over. This one is a correctness number --
running a call once per read runs it once per read -- and a numeric
conversion is not a call in that sense: re-evaluating `int(local_10)`
costs nothing and changes nothing. **All six of Paladin's rows were
that**, `int(local_10)` three times in one condition and
`bag[int(pocket_cursor)]` twice, and so was Manamon 1's one.

| title | before | after |
|---|---|---|
| Paladin of the Sky | 6 | **0** |
| Manamon 1 | 1 | **0** |
| Crazy Party | 16 | 16 |
| cs server | 1 | 1 |
| Super Egg Hunt, Psycho Strike | 0 | 0 |

Crazy Party's sixteen stay and are right to: they are real calls --
`arg0.length() >= 3 && arg0.length() <= 20 && ...` -- one getter per
operand of a chain, which is the author's own code and exactly what this
shape claims to report.

**Four of the nine shapes have now been read end to end** -- every empty
arm, every identity cast, the hundred `double_assign` rows and these --
and the pattern across all four is the same: a text-only sweep
over-reports in a way that is obvious once a row is read, and the
narrowing is always a question the text can answer (is this the
destination? is this a conversion? is the slot ever read? is there
anything between the branch and its target?). What is left after all
four is **three real defects**, all of one class -- and all three are
fixed, which is the sweep doing the job it was built for: nine text
shapes, read end to end, pointing at one defect class that four earlier
attempts had been aimed at from the wrong end.

And the instrument needed its own correction, which is the usual one:
asked of `jump_target == 0` it answered **0 for every title**,
including two bodies whose branch over nothing had already been read by
hand. `dw_arg` is the offset in instructions and `jump_target` is the
resolved one -- a zero from the wrong field.

Two narrownesses, both deliberate and both pinned by a test. A comparison
is only seen **parenthesised**, which is what the renderer emits, so a
comparison a person wrote as a bare argument is not swept. And the
duplication check is **per statement**, so `file_menu`'s four reads across
four statements are not its business -- that is the call-sequence
comparison in `bgt libcheck`, and the two are complementary.

#### What it found that nothing was looking for

Three of Manamon 1's four surviving tautologies are **one defect, and a
new one**: a string copied by `opAssign` keeps the *text* of the slot it
was copied from, and that text goes stale when the source slot is written
again. `skill::will_fail` is the clearest:

```
CALLINTF character::special_immunity    ; fills slot 1, the &out reason
PSF 3 ; PSF 1 ; CALLSYS string::opAssign          ; slot1 = slot3
STR "" ; $str ; PSF 3 ; CALLSYS string::$beh0     ; slot3 = ""
PSF 3 ; PSF 1 ; CALLSYS string::opEquals          ; slot1 == slot3
```

-- `if (reason != "") { arg1 = reason; arg2 = ""; }`, which recovered as
`local_3 = ""; if (local_3 != local_3) {`. **The slot-write test cannot
see the write**, because slot 3 is filled by a *behaviour* (`string::$beh0`
through a pushed address) and not by an opcode that names it, and
`slot_writes` is built from opcodes. This file already records that
"an object slot is written by a behaviour, not by an opcode" -- for
`_short_circuit_slots`, one place over. Two places answering one question,
again, and this is the one that was never told.

The cost is a skill's failure message: `will_fail`'s guard is always false,
so `arg1` and `arg2` keep the generic "The move failed!" instead of the
reason, and `unknown_gift::give` takes its `else` branch -- "You can't
obtain this gift yet." -- whatever the real reason was. Not fixed here; it
needs `slot_writes` to count a construction through a behaviour, which is a
fold-safety change and wants its own five-title measurement.

**And Paladin's `battle` really does compare a thing with itself.** The
last surviving tautology there is
`player.strikes[local_47].name != player.strikes[local_47].name`, inside
the `only_hit_by_scroll` guard, and the bytecode copy-constructs the left
operand out of the same member it then compares against -- same array, same
index slot, nothing in between. The author meant
`!= arg0.only_hit_by_scroll` and wrote the left operand twice, so in the
shipped game that guard is dead and any scroll hits a scroll-locked enemy.
That is the third finding of this kind, after `generate_maze`'s discarded
comparison and `load()`'s empty guard: the recovery is faithful, and the
bug is the original's.

### A base class's method, called through `this`, recurses forever

The worst one yet, because it is a *crash* and the project reports nothing:
0 residual gotos, a verified split, `compiled cleanly`, an executable that
starts -- and then

```
BGT Runtime Error: A runtime error occurred.
In function: void person::reset()
Description: Stack overflow
```

with 10,000 identical frames of `person::reset` under it. The stack's base
names the path in: `main` -> `handle_file_menu` -> `init_game` ->
`create_passengers` -> `create_room_passengers` -> `person()`, so it died
building the first passenger of a new game.

Paladin's `class person : interact` opens its override the way source has to:

```
void reset()
{
    interact::reset();          // the base's, then this class's own fields
    type = 3;
    sound_file = "person";
}
```

and that came out as `this.reset();`. A method's `Function.name` in the IR is
the **bare** one, so splitting it on `::` yields no class and the owner has to
come from `fr.object_type` instead -- read off the name, this never found a
base at all. With the owner in hand, `_calls_a_base_method` qualifies the call
when that owner is a strict ancestor of the class the body belongs to and that
class declares the name as well. Where it does not, the unqualified call
already reaches the base's one and saying so adds nothing.

**What makes it safe is the chain that is walked, not the opcode.** Only
`derived_from` is followed, and an interface's methods are reached through
`interfaces`, so an interface dispatch can never match and can never be
pinned to a base by mistake. Gating on the opcode as well was tried and
rejected on measurement: it kept `person::reset` qualified while letting
`clock::reset` fall back to `this.reset()` -- still unbounded recursion --
even though both sites disassemble to a plain `CALL` of `interact::reset`.
Why the two differed was not established, and the honest conclusion is the
narrow one: the opcode is the wrong field to read here, and the ancestor walk
does not need it. `base::method()` was put to BGT 1.3 before being emitted,
and it compiles.

Paladin had **62** of these, in one base class's descendants: `reset`, `init`,
`act`, `make_noise`, `pause`, `resume`, `is_inside`. Only the same-name ones
recurse; the others quietly ran the derived override where the source asked
for the base, which compiles and is simply a different program. Crazy Party,
with 530 derived classes, had **167**.

**The sweep that counts them has to compare arity, not just the name.** A
method forwarding to its own overload -- `focus()` calling
`focus(a, b, c)` -- is ordinary delegation, and Crazy Party has 18 of those;
a name-only sweep reports 184 self-recursive calls there and means nothing by
it. What cannot terminate is the same name with the same number of arguments.

| title | same-arity self-calls | after |
|---|---|---|
| Paladin | 62 | **2** |
| Crazy Party | 167 | **15** |
| Super Egg Hunt | 0 | 0 -- it declares no base class |

Fixing it took two of Crazy Party's compiler warnings away. **It did not
make that title compile**, and this claimed it did: see the standings, where
its 14 residual gotos are 14 errors, and where two warnings of the same
message remain from a different pattern — `null == handle`, which the
language spells `is`.

**And verifying that found the driver claiming a game had started when none
had.** Compiling emits its own `Compilation Result` window on success, which
carries no diagnostics and no "error" in its name -- and the rule for "the
script itself drew a window" was *any* window that is not an error report. So
`bgt compile` on Crazy Party answered `compiled cleanly, and ran: it opened a
window of its own titled 'Compilation Result'`. Nothing ran; the engine had
just said it wrote the executable. Only run mode may draw that conclusion
now, and only from the driver's own `$ran`. Claiming a game started when it
did not is the one thing this driver exists to get right, and it is exactly
the shape of everything else in this section: a confident report of something
that never happened.

Every survivor reads as real recursion. Paladin's two are `interact::act()`
calling itself, guarded, after `add_mode(1)` has advanced the state, in a
class with no base to be confused with. Crazy Party's are flood fills and
accumulators that change an argument (`brule(arg0 - 1, arg1)`,
`att(5, arg1)`). One is worth another look and is recorded rather than
claimed fixed: `Equipe::opCmp(x)` returns `this.opCmp(x)` unchanged.

### A declaration list with no declaration order

The rule above decides whether a slot is *foldable*. A separate one decides
whether it is a **variable at all**, and it reads something BGT does not have.

The newer engine writes one declaration per local in the order the builder
declared them, and that order is information: the source's own locals come
first, and where the offset steps *backwards* the compiler's scratch begins.
`FuncDecompiler` uses exactly that -- the prefix before the first backward
step is forced to stay an lvalue.

BGT records no scalar local at all (see **What the module does not record**),
so `bgt_asir` synthesises the list: object slots from `objVariableTypes` in
record order, then every scalar appended the first time a typed opcode happens
to mention it. That is **bytecode order, with no scope in it** -- and read as
declaration order it finds a backward step wherever the bytecode later touches
a lower slot. `use_screen_reader` is four synthesised entries at offsets
1, 3, 3, 2, and the 2 ends the prefix, so slots 1 and 3 were declared
variables in a function whose source has no locals whatsoever.

What that costs is a whole condition. `screen_reader && voice.reader > -2 &&
voice.sapi_only == false` compiles to two short-circuit merges over three
scratch slots, and the compiler **reuses** them -- slot 3 carries
`screen_reader` and then `sapi_only`, slot 1 carries `reader > -2` and then a
literal. Forced to be variables, each arm's computation is emitted as an
*unconditional* statement, so every term is overwritten before the `if` reads
it:

```
local_3 = (screen_reader ? 1 : 0);          // then clobbered by sapi_only
local_1 = ((voice.reader > -2) ? 1 : 0);    // then clobbered by a literal
...
if (((local_3 != 0) && (local_1 != 0)) && (local_1 != 0))   // == !sapi_only
```

It returned **true where the source returns false**, so every `speak` went to
`screen_reader_speak_interrupt(-1, ...)`, which fails. `run_extended` returns
-1 when it cannot speak its intro, `file_menu` turns that into `""`, and
Paladin's main loop reads that as "no TTS" and reopens the voice selector.
Selecting a voice fixed nothing, because the selector's own
`speak_sapi_only()` is what made speech work while it was open -- so it asked
again, forever, which is how it was reported.

`f.synthetic_variables` marks the list, so nothing mistakes it for the real
thing. The fix is **not** to drop the order rule, and measuring says so
loudly: without it Crazy Party went from 0 residual gotos to **44**, which is
44 compiler errors, because the rule is load-bearing for the mutable scalars
it was written for. Instead `_short_circuit_slots()` finds the slots a merge
carries its value through, from the bytecode alone, and those are excluded:

* `dest`, which the merge's value arrives in on both paths;
* every slot the **arm** writes, which holds part of the right-hand operand;
* every **object** slot the arm constructs or destroys, which no opcode in
  that first list mentions at all -- see below.

**The slot the jump tested is deliberately not one of them**, and that is the
whole difference between this working and doing harm. The left-hand operand is
usually an ordinary local -- `int d = get_total_distance(a, b); if (d > limit
&& ...)` -- so excluding it unforces a real variable and the value folds into
each of its reads instead. Taking it cost Super Egg Hunt three duplicated
calls: `sound_pool` ran `get_total_distance` twice, a menu ran its item
callback twice, and the "erase all data" confirmation asked **twice** while
the branch choosing the other wording of the prompt vanished.

With both, all three titles hold at 0 residual gotos and a verified split, and
`bgt libcheck --decompiler` scores identically before and after on every one
of them -- 39/47 call sequences on Paladin, 43/47 on Super Egg Hunt, 129/153
on Crazy Party -- which is the check that says no call was duplicated.

#### An object slot is written by a behaviour, not by an opcode

"Every slot the arm writes" means the slots named by an opcode that assigns
to them, and a string is not one of those. It is filled by pushing its
address and calling the constructor -- `PSF n` then `CALLSYS $beh0` -- and
emptied by `$beh2`, so nothing that names slot `n` appears in the arm. A slot
constructed *or* destroyed inside an arm belongs to that arm, by scope: one
declared outside is built and torn down outside.

Paladin's `item_type_to_function` is what that costs:

```
if (arg0 == "healing potion" || arg0 == "medical miracle"
    || arg0 == "levelup erb" || arg0 == "perfect healing") return 0;
```

over one reused string slot. Forced to be a variable, the four assignments
hoisted out ahead of the `if` and every comparison read the last of them --

```
local_2 = "healing potion";
local_2 = "medical miracle";
local_2 = "levelup erb";
local_2 = "perfect healing";
if ((((arg0 == local_2) || (arg0 == local_2)) || ...
```

-- so three of the four healing items were classified as something else. It
compiles, it runs, and the only way to notice is to use a potion.

**And a behaviour has two spellings**, which is the delegate factory's
`%delegate_factory` / `$dlgte` all over again. The disassembler prints
`string::_beh_0_`, which is what a reader sees and reaches for; the name the
module stores and the IR carries is `$beh0`. Matching only the pretty one
matched nothing, silently, and the output did not change by a single line.

With it, Paladin recovers 83 lines shorter and `get_active_reader` -- whose
four `return`s used to collapse into one `return WINDOW_EYES;` -- comes back
as the accumulator the source wrote, from the same pass.

**The clamp that this file listed as the one case left is not open, and had
not been for some time.** A **computed** value bound on one path and read
past the join -- `sound_pool`'s `true_y`, written
`int true_y = listener_y; if (listener_y < delta_backward) true_y =
delta_backward; else if (...) ...` -- recovers exactly as the source wrote
it, including the `else if`. Checked as a shape in `bgt oracle`, and checked
at the previous commit too, so it was not the declaration rule above that
fixed it: the item had simply outlived its fix and stayed written down.

A stale open question costs what a stale number costs. It had been quoted as
the reason not to promote computed values, with "Promoting computed values
the same way took Paladin from 0 compiler errors to 16" as the evidence --
and that measurement was itself superseded by the one-name-per-slot fix,
which this file records two sections earlier. The signature it names is
still worth grepping for: an `if` with two empty arms is a condition that
has lost its value.

#### A handle borrowed for one expression is not a statement

`find_walls` walks outward from the player looking for walls, and its loops
are

```
while (true) {
    i += 1;
    if (arg2.length() <= i || arg2[i].length() <= j
            || arg2[i][j] == 0 || play_wall_tone(i, j)) { ...; break; }
}
```

The third operand needs `arg2[i]` in a slot, and the bytecode puts it there
with `RefCpyV 11 ; CALLSYS opIndex ; RDR4 ; FREE 11` -- inside the arm,
after the bounds check that guards it. **`objVariableTypes` names every
object slot**, so that handle copy is emitted as a *statement*, and an event
sorts by its own bytecode position while the branch sorts by the end of the
chain. So it lands ahead of the whole `if`:

```
local_10 += 1;
@local_11 = arg2[int(local_10)];        // indexes HERE
if (((arg2.get_length() <= int(local_10)) || ...
```

The index therefore runs before the test that protects it, so **entering**
any map throws `Index out of bounds` -- `find_walls` always scans out to a
wall or the edge, and the westward and southward loops reach `-1` before
testing `< 0`. The stack reports
`map::map_setup` -> `find_walls()` -> `find_walls(int16, int16, int[][]@)`.
A statement cannot be conditional on the operand before it, so the only
correct rendering folds the handle into the expression.

**What works is local to the instruction stream.** `RefCpyV` *peeks* the
stack rather than popping, so the next instruction reads that copy and the
slot is never looked at: `_borrowed_handle` asks whether a `FREE` of the
same slot follows within four instructions with nothing naming the slot
and no jump in between, and such a bind goes to `temps` instead of being
emitted. Paladin 28,264 -> 27,199 lines, **0 residual gotos, split
verified, `compiled cleanly`**; Super Egg Hunt `compiled cleanly`;
`libcheck` unchanged at 144/149 and 148/149. The 1,065 lines are the
compiler's own handle aliases -- `@local_4 = interacts;` -- which the
source never wrote, and what is left reads better for it: `if (arg0 is
local_3)` becomes `if (arg0 is global_interacts[analytics_battle_1])`,
and one `while` with a trailing `local_4++` comes back as the `for` it
was. **It costs Psycho Strike 2 residual gotos** in
`home::reset_rebels`, which no window size avoids; that title already
cannot compile here for 33 engine absences, and the trade was taken
because the alternative is every map entry throwing.

**Classifying the slot instead was tried twice and is much worse.** Measured
over all 926 of Paladin's bodies, by line count and by how many bare
`expr[i];` statements the output carries:

| `_short_circuit_slots` takes arm handles | `_bind` folds a named SC slot | `RefCpyV` marks its slot used | lines | bare index | fixed |
|---|---|---|---|---|---|
| -- | -- | -- | +0 | 2 | no |
| -- | -- | yes | +38 | 0 | no |
| -- | yes | -- | -44 | 2 | no |
| yes | -- | -- | **-477** | **49** | no |
| yes | yes | yes | **-530** | 0 | **yes** |

Only the full set fixes it, and the first column is what does the damage on
its own. Adding every handle written in a short-circuit arm catches real
variables, not just temps: `load_event_flags` came out with its call
duplicated, the wrong dictionary key read, and `bool` assigned to an `int`
--

```
local_4 = arg0.exists("quest_text");        // int = bool
arg0.get("tutorial_text", local_4);
tutorial_text = arg0.exists("quest_text");  // wrong key
```

Narrowing it to a handle whose `FREE` is in the same arm -- a temp's whole
lifetime is inside the arm where a real variable's is not -- moved -477 to
-447 and changed nothing else. That is not the separating condition.

##### ...and the window was hiding 353 dead assignments in one title

The window is the right *mechanism* and it is not the whole rule, and the
round trip is what found that. `sound_pool::verify_slot` is the case, and
BGT ships the source for it, so there is no arguing about what it should
say:

```
sound_pool_item[]@ local_2;
@local_2 = items;                      // three times, read NEVER
if (items[arg0].persistent) { return true; }
```

The alias was emitted as a statement while the index expression re-read
`items` anyway, so the local is written three times and read nowhere.
The `FREE` is eight instructions past the bind, so the four-instruction
window declined -- and a `FREE` that far away is the normal case, not an
exotic one.

**A slot NOTHING reads is not a variable**, and that is stronger evidence
than any distance. `objVariableTypes` names every object slot, so the
decompiler has a declaration for each one, and the engine's record cannot
say which slots the source NAMED -- the gap this whole file keeps working
around. A slot read nowhere answers it outright. So that is asked first,
and the window still decides every bind whose slot IS read somewhere,
because slots are reused and the whole-body question says no about those.

Two details make it a reading rather than a guess:

- **`FREE` is a write, not a read.** Releasing a slot is not a use of its
  value, so a slot only ever bound and freed is read nowhere -- which is
  the entire rule. Counted the other way, which its operand being the
  slot makes tempting, the rule would never fire at all and nothing would
  say so. `_read_slots` takes this from **AngelScript's own operand
  naming** rather than from a list of opcodes: `asBCTYPE_wW_rW_DW_ARG`
  spells the shape out -- a written slot, a read slot, a dword constant
  -- and a bare `W` is a plain word (a count, a stack offset) and not a
  slot at all, so `asBCTYPE_wW_W_ARG` names one slot and not two. Every
  `bc_type` of the **663,023** instructions in the four titles that can be
  checked here parses -- 17 distinct shapes, none undescribed -- and each
  opcode it is relied on for was read out of the build's own table: `PSF`,
  `VAR`,
  `PshVPtr`, `LOADOBJ`, `WRTV*` and `CmpPtr` read, while `RefCpyV`,
  `FREE`, `ClrVPtr` and `STOREOBJ` write.
- **A `FREE` of the slot must exist somewhere**, because a handle the
  compiler materialised is always released. A slot with none is not one
  of these. It changes no output on the four titles it was checked against
  -- every recovered tree byte-identical with and without it -- so it is a
  condition rather than a fix, kept because a rule that did not ask would
  claim the wrong thing the first time a title had one.

**And folding one RESTORES the original's object lifetime rather than
changing it.** `FREE` runs the destructor, and for a `sound` that is
observable, so this is only safe because the compiler then materialises
its own handle for the same expression -- which is what the original did.
A declared local holds the object to the end of the function, and that is
the behaviour that was wrong.

| title | lines | goto | split | calls read back |
|---|---|---|---|---|
| Super Egg Hunt | 6,240 -> **5,780** | 0 | verified | 1,608 |
| Paladin of the Sky | 27,257 -> **25,942** | 0 | verified | 6,958 -> 6,952 |
| Psycho Strike | 27,498 -> **25,870** | 2 | verified | 6,406 |
| Crazy Party | 192,765 -> **190,735** | **14** | verified | 90,145 |
| Manamon 1 | 90,925 -> **89,712** | 0 | verified | 26,481 |

**Not one residual goto moves**, every split still verifies, passthrough,
body errors, unbalanced files and dangling `else` stay 0 everywhere, and
`bgt oracle` is 51/51. All three `bgt audit` comparisons are identical
before and after on every title -- Paladin 25 call rows, Psycho Strike 41,
Manamon 1 697, Egg Hunt 0, each with the same declined count -- which is
the check that says no call was lost. `bgt libcheck --decompiler` holds at
39/46, 43/46 and 144/148.

**Paladin's six fewer calls are six fewer DUPLICATED calls**, which is the
direction this file counts as the result. The bytecode audit is unchanged,
so nothing went missing; what went is `@local_5 = bag;` and friends, and
with them gone the structurer can see a loop it could not before:

```
-        local_4 = 0;
-        while (local_4 < bag[local_3].items.get_length()) {
-            @local_5 = bag;
-            @local_6 = bag[local_3].items;
+        for (local_4 = 0; local_4 < bag[local_3].items.get_length(); local_4++) {
```

-- the dead statements after the increment were what stopped the `for`
header being recognised.

**Swept as the output rather than counted as lines**: a declared local
that is assigned and never read, per title, before and after.

| title | dead assignments | after | such locals |
|---|---:|---:|---:|
| Super Egg Hunt | 353 | **2** | 108 -> 2 |
| Paladin of the Sky | 1,193 | **217** | 525 -> 188 |
| Psycho Strike | 1,376 | **115** | 427 -> 74 |
| Manamon 1 | 2,295 | **1,479** | 852 -> 457 |

**3,404 of 5,217 gone**, and the residue is named rather than waved at.
Manamon 1 keeps most of it, and it is three different shapes: about 250
more handle aliases, in slots the body DOES read somewhere else -- so the
whole-body rule correctly declines and the window still cannot reach
them, which is the next thing a per-bind version of this would get; 99
`bool` locals, a scalar shape this rule does not touch at all and which
may well be the original's own dead stores; and 92 `__nvgt_ret_N`, the
generated holder for a call with an out argument, where nothing reads the
return value. That last group is the cheap one: the call is the
initialiser, so dropping the assignment leaves `d.get(k, out);` and loses
nothing.

Crazy Party is the row that matters, because it is the title every
over-broad fold change in this file was caught by: **14 residual gotos
before and after**, the same fourteen labels, with 90,145 calls
unchanged. 14 -> 30 rejected a call-text threshold, 14 -> 44 dropping
the declaration-order rule, 14 -> 90 forcing on the copy idiom.

##### The hazard, scanned rather than argued -- and one real gap

`RefCpyV` *peeks*, so the instruction after it reads the stack copy and
the folded expression is rendered into whatever consumes it. That is the
argument for folding being safe, and it is checkable: at each of the
**2,903** binds this newly folds across four titles, what is the next
instruction?

| title | `RefCpyV` | newly folded | next instruction |
|---|---:|---:|---|
| Super Egg Hunt | 493 | 395 | a call, every one |
| Paladin of the Sky | 2,019 | 1,174 | a call, bar **2** `PopPtr` |
| Psycho Strike | 605 | 350 | a call, every one |
| Manamon 1 | 3,807 | 984 | a call, bar **1** `FREE` |

So 2,899 of 2,903 are consumed by a call, which renders them. The three
exceptions were read, and two of them are a defect in the test rather
than in the fold:

- **`CallPtr` is the one opcode whose operands are not where its
  `bc_type` says.** BGT's generation gives it a single word operand, and
  `asreader` normalises that into `w_arg2` with `w_arg` zeroed so one
  rule downstream reads both engine generations -- which is right, and
  leaves the shape disagreeing with the name. Parsed generically,
  `_read_slots` marked slot 0 as read (usually `this`, so harmless) and
  **missed the funcdef-holding slot**, which is the half that matters: a
  bind to it looks unread and folds. Paladin's `final_heaven_scene` and
  `father_hologram` are the two sites, both `@slot = character.affect`
  feeding a `CallPtr`.

  **The output was right anyway, and that is the part worth recording.**
  Both bodies render `local_9.affect(local_8);` with the fold and
  without it, so the guard was wrong while the result was correct for a
  reason nothing had checked. Fixed, **all five recovered trees are
  byte-identical with it and without it**, Crazy Party included -- so the
  fix is a condition rather than a change, and it is in because relying on
  that accident is how the next title pays for it.
- **Manamon 1's `store_manamon` is a dead handle copy and folding it is
  right.** `@local_23 = local_9;` with nothing reading `local_23`; the
  object is `manamon_storage.lists[n].manamon_list`, which the container
  holds, and `local_9` is still a function-scope handle in the recovery.
  So nothing is released early -- the lifetime question this rule raises
  does not bite here, and it was checked rather than assumed.

The three dropped lines in that body are `@local_24 = manamon_storage.lists;`
three times and that copy, and the diff of the whole function is those
four lines and the two declarations. That is what a correctly scoped
fold change looks like at the level of one body.

**And libcheck did not see any of it**, which is the part worth keeping.
`bgt libcheck --decompiler` scored **144/149 call sequences and 148/149
literals -- unchanged -- while the output was badly wrong**, because it
compares only the functions BGT ships source for: 149 of 926. Every
regression above was in the game's own code. The two checks that caught it
cost one command each: the **line count**, which moved by 530, and
`bgt recover --compile`, which named the file and the line. A passing
oracle is evidence about what it covers and nothing else.

### The compiler, read -- every statement's emitted shape

`CompileSwitchStatement` was found through a literal and read on its own.
The other nine statement compilers came out of **one** query, and the
method is worth more than the addresses: `FUN_00426050` is
`CompileStatement`, a bare dispatch on `node->nodeType`, and **its branch
order is AngelScript's own source order** -- the
`snExpressionStatement || firstChild` guard at the top, the `*hasReturn = 1`
that only the last branch performs. So the dispatch names its own cases.

| function | address |
|---|---|
| `CompileStatement` | `FUN_00426050` |
| `CompileStatementBlock` | `FUN_0041E540` |
| `CompileIfStatement` | `FUN_00428310` |
| `CompileForStatement` | `FUN_00428B50` |
| `CompileWhileStatement` | `FUN_00429630` |
| `CompileDoWhileStatement` | `FUN_00429C60` |
| `CompileExpressionStatement` | `FUN_0042A5E0` |
| `CompileBreakStatement` | `FUN_0042A360` |
| `CompileContinueStatement` | `FUN_0042A4A0` |
| `CompileSwitchStatement` | `FUN_00426160` |
| `CompileReturnStatement` | `FUN_0042A9D0` |
| `CompileCase` | `FUN_00428060` |
| `CompileFunction` | `FUN_0041D110` |

**One mechanical obstacle stands in front of all of it**, and it is the
reason a reading of this file is harder than a reading of `asCReader`: the
emitter wrappers take the opcode **in EAX**, so the decompiler drops it
and every emit site reads as `Instr(this)` with no indication of what is
emitted. The constant is only in the instruction bytes. `FUN_0041A070` is
`Instr(op)`, `FUN_0041A490` `InstrDWORD(op, arg)`, `FUN_0041A4F0`
`InstrSHORT(op, arg)`, `FUN_0041A440` `InstrINT(JMP, label)` with the
opcode baked in, `FUN_00419790` `AddCode`, `FUN_00419A00` `Line`,
`FUN_00419BE0` `DeleteInstruction`. The way through is to scan `.text`
for every `rel32` call to a wrapper and read the immediate pushed at each
site, which turns "what emits `CpyVtoV4`?" into a complete enumeration
rather than a search.

What each statement emits:

```
while     L_cond: <c> CpyVtoR4 ClrHi JZ brk ; SUSPEND JitEntry ;
                  <body> ; JMP cond ; L_brk
do-while  L_top: <body> ; L_cont: SUSPEND JitEntry ;
                  <c> CpyVtoR4 ClrHi JNZ top ; L_brk
for       <init> ; JMP cond ; L_inside: SUSPEND JitEntry ; <body> ;
                  L_cont: <incr> ; L_cond: <c> CpyVtoR4 ClrHi JNZ inside ;
                  L_brk
if        <c> CpyVtoR4 ClrHi JZ after ; <then> ; [JMP end] ; L_after ;
                  <else> ; [L_end]
break     Block(true) ; <dtors> ; Block(false) ; JMP brk
continue  Block(true) ; <dtors> ; Block(false) ; JMP cont
return    JMP 0          -- label 0 is the function's single exit
```

#### A `for` is bottom-tested, so it shares a CFG shape with `do-while`

This is a correction. A `for` is **not** a head-tested loop: the compiler
emits an unconditional forward `JMP` to the condition label, puts the
condition **last** (after the increment), and closes with a *conditional*
`JNZ` back edge to a label above the body. So `for` and `do-while` have
the same shape, and "a header that is also the latch" cannot separate
them. Three things can:

| | entry jump to the condition | `SUSPEND` sits | labels |
|---|---|---|---|
| `while` | no | after the condition | 2 |
| `do-while` | no | between body and condition | 3 |
| `for` | **yes** | at the top of the body | 4 |

#### ...and the increment is already outside the body

`continueLabels` holds the label **before** the increment, so a `continue`
in a `for` runs it -- which is what the language says and what the
emission does. This file's rule was that a `for` header "may not hoist
the increment when something jumps straight to the condition", on the
grounds that such a jump is a `continue` whose increment is part of the
body. **The only thing that jumps straight to a `for`'s condition is the
entry jump from the init**, which every `for` has. Read that way the rule
refuses to hoist on every genuine `for` it meets.

The shape it was written to protect -- a `while` with a trailing
increment -- is separable on much stronger evidence: in a `while` the
continue label *is* the top condition label, and the back edge is an
unconditional `JMP`.

#### The latch is the instruction before `LABEL brk`

In all three loop forms, and this is the useful positive result: `brk` is
both the loop's exit and every `break`'s target, and the latch is the
instruction **immediately preceding** it. **Any other backward jump to the
header is a `continue`.** That is cheaper and stronger than
`plain_latches[-1]`, and it is exactly the distinction Paladin's
`register_software` needed -- a `while` pushes its header label onto
`continueLabels`, so a mid-body `continue` is a *second* backward `JMP` to
the same label, which is precisely what `plain_latches[-1]` claimed as the
loop's tail.

#### `break` really can be `JMP 0`, and now there is a mechanism

`ResolveJumps` (`FUN_00419B40`) resolves a jump whose label is the next
instruction to offset **0** and keeps it. The global peephole
(`FUN_00418CE0`, gated on `engine->ep[0xEFD]`) then deletes it:
`curr->op == JMP && next->op == LABEL && curr->arg == next->wArg[0]`
removes the `JMP`. So such a jump is normally gone, and survives **only
when something zero-sized intervenes** -- another `LABEL`, or a `Block`,
`ObjInfo` or `VarDecl` marker. `break` emits `Block(false)` immediately
before its `JMP`, which is exactly such a marker. The operational rule
this file already records stands and is now explained: a surviving
offset-0 `JMP` is a real edge and must not be dropped as a fallthrough.

#### What the switch emission actually looks like

Four corrections and one confirmation, all in BGT 1.3:

- **Tables never interleave with arms, within one `switch`.** All of a
  switch's guards and tables go into one buffer, then every arm in source
  order, then the break label. The only things that can sit between two
  tables are the `nextRange` label and the next range's guard instructions
  (`SetV4`, `CMPi`, `JS`, `JP`) -- never arm code. So the
  `type_effectiveness` diagnosis below, "the chain's tables and arms
  interleave", cannot describe one switch.

  **What does produce `table, arms, table, arms` is N consecutive source
  `switch` statements**, each emitting its own tables and then its own
  arms -- and a type chart written as several switches in a row is the
  natural shape for the function that shows it. That gives a discriminator
  the bytecode can answer today: from a table's end, look at what precedes
  the next table. Guards and a label only, and it is the same switch, so
  merge; any statement-shaped code -- a call, a store, a jump to the
  function exit -- and the next table belongs to a *different* switch, so
  the chain-merger must stop rather than grow `cursor` across it. If that
  is what is happening, the `entries[0] <= instrs[cursor - 1].pos` guard is
  firing because the merge over-reached, and the fix belongs in the merge.
- **Each table has two guards going to different places.** The low bound is
  `CMPi ; JS default` and the high bound `CMPi ; JP nextRange`, plus one
  whole-switch prologue guard against the overall maximum, to the default.
  **Only the high guard sends values on to the next table** -- which is what
  the merge-and-drop-the-guard rule depends on.
- **With no `default:`, the default label *is* the break label.** So those
  edges already leave the switch.
- **The compare chain is "fewer than three values", not "a single
  value".** A two-value range emits *two* `SetV4 ; CMPi ; JZ` triples, and
  there is no `JMP` per compare: one `JMP default` is emitted once after
  all the ranges. The `JMP exit` after Super Egg Hunt's `case 27` is that
  end-of-chain jump.
- **An arm can leave to four places**: `break` to the break label, `return`
  as `JMP 0`, `continue` to the enclosing loop (a switch scope sets
  `isBreakScope` and clears `isContinueScope`), or fall through into the
  next arm.

And two things that confirm what is already here: the compiler **errors**
if `default` is not last, so `_default_last` is needed for BGT too; and it
deletes unreachable code itself (`FUN_00419DA0`), so `_drop_unreachable`
is correctly a source-level pass rather than a model of the engine.

`SUSPEND` is **not** a loop marker, which is worth knowing before reading
one as a landmark: `Line()` emits `LINE` + `JitEntry` at every statement
boundary, `LINE` is given size 1 so `ExtractLineNumbers` can rewrite it to
`SUSPEND` offset-neutrally, and the peephole then collapses consecutive
`SUSPEND`s -- merging a loop's explicit one with its body's first.

### The allocator, read -- why one slot serves several source locals

`AllocateVariableNotIn` is `FUN_0042B450`, and the whole of what
distinguishes a declared variable from a temporary is **one flag**:
`CompileDeclaration` (`FUN_00423570`) calls it with `isTemporary = 0` and
all fifty-eight other call sites pass 1. There is one offset space --
`GetVariableOffset` (`FUN_0042B740`) is a running sum from 1 over every
prior slot, declared and temporary interleaved in allocation order -- and
the flag lives in a `char` array at `this+0x9C`, which the free-list match
consults alongside the type and the on-heap flag. Within one body an
offset is therefore either always a declared variable or always a
temporary, never both.

**And the allocator erases the type on purpose.** Before matching the free
list it rewrites any one-dword primitive's token to `ttInt` and any
two-dword one to `ttDouble`, so `bool`, `int8`, `int`, `uint`, `float` and
every enum share a single free-list class. That is the compiler-side root
of what this file records as "a slot serves several source locals": it is
deliberate reuse of one offset across unrelated declared types, not an
accident of ordering, and it is why `clear_pathway`'s slot 1 is a `bool`
through a `bool&out` and an `int` on the way out.

The compiler also emits **`VarDecl`** (opcode 251) for every declared
variable, carrying its index into the function's variable list -- which is
exactly the fact `noDebugInfo` discards, and the reason no amount of
reading the bytecode can recover it.

#### The `CpyVtoV4` idiom holds, and the OPTIMIZER is the missing half

This is the most useful correction of the two readings, because it
reconciles two measurements this file records as contradictory.

`CpyVtoV4` / `CpyVtoV8` are emitted from **exactly three sites in the
whole binary**, by enumeration rather than by search:

1. `PerformAssignment` at `0x0042C313`, gated on `isVariable`
   (`test byte [edi+0x10], 8`) -- the destination being a variable is what
   selects the copy over a `WRTV*` through the reference register. That is
   the idiom's rule, exactly as recorded.
2. `CompileBooleanOperator` at `0x00441A30` -- the `&&` / `||` merge.
3. `ConvertToTempVariable` at `0x0043E22D`, which copies a declared
   variable *into* a fresh temporary. **This exception was not recorded**,
   and it has 32 call sites.

The optimizer (`FUN_00417BF0`) then changes the shape of the answer, and
every one of its fusions is gated on `IsTemporary(slot)` (`FUN_00418150`).
Two rules matter: `SetV4 t,K ; CpyVtoV4 d,t` becomes `SetV4 d,K`, and
**any three-operand arithmetic op** (`asBCType` 8 or 13) followed by
`CpyVtoV4 d,t` is rewritten to target `d` directly. So:

> **A declared variable initialised from an arithmetic expression leaves
> no `CpyVtoV4` at all**, and from a constant leaves only `SetV4 v,K`. The
> copy survives only when the producer is `asBCType` 3 -- `CpyRtoV4`, a
> call return, or `RDR*`, a dereferenced read -- or when the source was
> never a temporary.

Which says two things at once. The idiom is **sound where it is used**:
`copy_binds` lowers the duplicate-fold threshold for values that arrived
through a copy, and those are exactly the call-return and dereferenced-read
shapes the optimizer leaves alone. And the converse is **false**: "no
`CpyVtoV4`, therefore not declared" is wrong for most declared variables
in a BGT module, which is why forcing a variable on every copy destination
was measured at 14 -> 90 residual gotos on Crazy Party and why no amount of
tuning that lever would have worked. The engine supplies no decidable test
for "did the source name this slot?"; it supplies an asymmetry, and the
asymmetry is already what is being used.

#### The short-circuit merge, and the ternary correction

`&&` and `||` (`0x00441942`-`0x00441A40`) allocate the destination as a
**temporary**, open with `CpyVtoR4 lhs ; ClrHi ; JNZ|JZ L1`, and store the
short-circuit result **asymmetrically**: `&&` emits `SetV4 dest, 0` and
`||` emits `SetV1 dest, 1`. The arm's store is `CpyVtoV4 dest, rhs`.
`^^` is not short-circuit at all. `_short_circuit_slots` accepts
`SetV1`/`SetV2`/`SetV4` with a constant of 0 or 1, so it sees both halves;
a test written for one store would have missed every merge of the other
operator, silently.

**The left operand is released before the destination is allocated**, so a
merge's destination may legitimately reuse the left operand's slot. That is
`use_screen_reader` seen from the compiler's side, and it is why that
function's four synthesised entries sit at offsets 1, 3, 3, 2.

**The ternary does not work the way this file assumed.** It was recorded
that both arms `SetV4` straight into the destination and that
`CpyVtoV4` is not used. `CompileCondition` (`FUN_00432B30`) allocates its
destination as a temporary and both arms store through `PerformAssignment`,
i.e. `CpyVtoV4`; the bare `SetV4` that was observed is the *optimizer*
collapsing `SetV4 t,K ; CpyVtoV4 d,t`, which only happens because both arms
were constants. **With a non-constant arm the `CpyVtoV4` survives, into a
temporary** -- so a ternary can look exactly like a declared variable's
initialisation to a rule that reads the copy alone.

#### Argument order, and the fix it specifies

`MakeFunctionCall` (`FUN_0043D9A0`) moves the receiver's bytecode out of
the context into a local, compiles every argument into the now-empty
context, then re-appends the receiver. `PrepareFunctionCall`
(`FUN_00420700`) walks the arguments **descending**
(`n = len - 1; while (-1 < n)`). So the stream is

```
[a(N-1)] [a(N-2)] ... [a0] [receiver] <call>
```

which is the call frame this file already derived from the bytecode, now
confirmed from the emission -- arguments pushed last to first, receiver
last of all.

It also **specifies the fix for the concatenation defect** recorded under
`bgt oracle`, where `"" + bump() + "," + bump() + "," + bump()` answers
`3,2,1` from the engine and `2,3,1` from the recovery. Each operand
occupies a contiguous ordered span immediately before its call, so a folded
call's statement can be placed by **the span it belongs to** rather than by
the `opAdd` that consumes it -- and for a left-nested chain the textual
order is exactly the reverse of the bytecode order. No new evidence is
needed for that change, only the work.

#### The initialiser list, confirmed, and why reading the slot is safe

`CompileInitList` (`FUN_00424CB0`) emits `AllocMem`;
`CompileInitListElement` (`FUN_004253A0`) emits `SetListSize`, every
`PshListElmnt` and the single `PopRPtr`, and they are the only emitters of
those opcodes in the binary. `PshListElmnt` carries the buffer variable and
a **byte offset**, four-byte aligned per element. For a **scalar** element
the `PopRPtr` is emitted and the element's lvalue is marked a reference with
`isVariable` clear, so `PerformAssignment` takes its `WRTV*` branch --
giving the `SetV4 t,K ; PshListElmnt buf,N ; PopRPtr ; WRTV4 t` this file
records. For an **object** element there is no `PopRPtr`: construction goes
through the address in the reference register.

And the part worth having: **no peephole rule fuses `SetV4` with
`PshListElmnt`**, so reading a scalar element's constant back out of the
frame slot is provably safe rather than merely observed to work.

#### A `?&` argument's `TYPEID` cannot disagree with what is passed

`PrepareArgument` (`FUN_0041F460`) is the only emitter of `TYPEID`, at two
sites, and the id comes from `GetTypeIdFromDataType(&ctx->type.dataType)`
-- the argument expression's own type at that site, which is the same
expression that is then passed. They cannot disagree.

So **the `TYPEID` operand is authoritative for that slot's type at that
call**, and where it conflicts with the decompiler's idea of the slot's
type, the `TYPEID` is right and the slot type is wrong. Paladin's six lost
`bool` save flags were therefore a mis-typing on this side and never a
mismatch the compiler could produce -- the fix recorded above is confirmed
from the engine, not merely measured.

**And the token number is 59 and 60, in two numberings, both correct.**
`ttQuestion` is `0x3B` = **59** in BGT's own `eTokenType`, settled from two
independent sites in the binary. The IR converts a legacy token with
`t + (t >= 36) + (t >= 64)`, so 59 becomes **60**, which is what
`decompile.py` gates on. This file quotes both numbers in different
sections and neither is wrong; what was missing is which numbering each
belongs to. Changing the code to 59 would break every `?&` argument.

### Reading the compiler, not only the reader

This document's first rule is to read `asCReader` rather than infer the
format. The same rule applies one level up and had never been used: the
*shapes* the structurer matches are emitted by `asCCompiler`, which is in
the same binary. `CompileSwitchStatement` is at `FUN_00426160`, found
through `Switch expressions must be integral numbers`.

**The first thing it said killed a hypothesis, cheaply.** The compiler emits
a range guard as `SetV4 tmp,K ; CMPi var,tmp` and the normalisation as
`SetV4 tmp,min ; SUBi var,tmp` -- never the immediate forms. `_begin_switch`
accepts only `CMPIi`/`SUBIi`, so it looked as though an unfused table would
slip past every matcher and explain the bodies given up on. It does not:
the peephole pass fuses every one. All **82** computed jumps in the four
titles carry the fused form. Worth ten minutes to find out, and worth
writing down so nobody pays for it twice.

**The second thing it said is a constant worth having.** After sorting the
case values the compiler starts a new table whenever

    values[n-1] + 5 < values[n]

so a gap of up to five is absorbed into the current table, filled with
entries pointing at the default, and a gap of six or more splits. That makes
a prediction the bytecode can refuse: **no table can hold a run of more than
four default entries.** Measured across all 82 tables -- Paladin 3, Psycho
Strike 4, Manamon 2 4, Super Egg Hunt 3. Reached twice, never exceeded,
which is the same saturating-maximum argument that settled the operand
tables.

#### The entry the gaps share is not always the default

`_dense_table` identified the default by counting: the most common target in
the table, on the argument that the gaps all carry the default label. The
constant above says how far that argument reaches, and it is not far enough.
Several case labels stacked on one body,

```
case 1: case 2: case 3: speak("..."); break;
```

put that arm in the table as many times, and nothing stops a real case
outnumbering the gaps.

Where a switch is a *single* table there is no next range to be sent to, so
every guard jumps to the same place -- and that place is the default, said
outright rather than counted. Checked against every single-table switch in
the corpus, the two answers agree 25 times and **disagree twice**, both in
Manamon 2. `ms_davidson`'s table is `[38, 45, 45, 52, 59, 66, 144]` with the
default at `0x95`, which is not in the table at all: counted, the default
became the arm that `case 2` and `case 3` share, so both labels vanished
from the output and a `break` landed in the wrong arm.
`get_madam_boveels_table_text_seulee` is the same shape. Both are dialogue
functions, so the symptom is an NPC answering the wrong line -- it compiles,
it runs, and nothing reports it.

Counting still answers where the guards disagree, which is a link in a chain:
its own high bound sends larger values on to the next range, so the guards
differ and the gaps are the only evidence left.

`get_madam_boveels_table_text_seulee` lost a whole arm the same way --
`case 20: case 22:` and the line of dialogue they return.

**Which switches this can touch is exhaustive, not sampled.** The new
branch fires only when every guard agrees; there, a table with no repeated
entry already took `guards[0]`, which *is* that agreed target, so nothing
moves. What moves is a table with a repeated entry whose count disagrees
with the guards -- and every single-table switch in the corpus was
enumerated for exactly that: 2 in Manamon 2, 0 in the other three.

Paladin, Psycho Strike and Super Egg Hunt render **byte-identical** before
and after, which is what a correctly scoped structurer change looks like.

#### The tables nothing claims, and what each one really is

These bodies have been "claimed by neither switch matcher" for as long as
the message has existed, which is a symptom and not a cause.
`_dense_table` reads all of them perfectly; it is
`_dense_switch_pattern`'s checks *after* it that decline, and they decline
for **different reasons**.

**And they are not Manamon 2's alone.** Manamon 1 gives up on exactly two
bodies, and they are `number_key_pressed` and `type_effectiveness` -- the
same two functions, by name, in a title four years older by a developer
whose source grew into the other. So these are two *shapes* across two
titles, and a fix to either pays twice. Which guard declines each was read
by tracing the real `_dense_switch_pattern` and reporting the line it
returned None from, so no matcher logic was duplicated to find out:

| body | instructions | tables | declines at |
|---|---|---|---|
| `number_key_pressed` | 168 | 1 | `len(set(joins)) != 1` |
| `type_effectiveness` | 984 | 23 | `entries[0] <= instrs[cursor - 1].pos` |

**Both of the diagnoses this file used to give for them were wrong**, and
both were wrong the same way: they were read off the output rather than out
of the compiler, and each invented a strange layout where the truth is an
ordinary one being mis-measured.

- **`number_key_pressed` has ONE exit, and the second "join" is a
  `return`.** The old reading was that the arms leave to two places, 0x12C
  and 0x12F, both in the epilogue. They do not. Read out of Manamon 1's
  bytecode, the switch has ten case arms at 0x20 .. 0x113 and a default at
  **0x12C** -- and with no `default:` in the source the default label *is*
  the break label, which the compiler reading above confirms. `joins` is
  built over `zip(entries, entries[1:])`, so the default's position closes
  the **last arm's** span, and that arm is 0x113 .. 0x12B:

```
0x113  (case 9's body)
0x11F  CALLSYS f
0x121  CpyRtoV4 1
0x122  CpyVtoV4 3, 1
0x124  CpyVtoR4 3
0x125  JLowZ      -> 0x12C
0x127  SetV1 2, 1            ; true
0x129  CpyVtoR4 2
0x12A  JMP        -> 0x12F   ; <- counted as a second join
0x12C  SetV1 3, 0            ; false -- the default, and the exit
0x12E  CpyVtoR4 3
0x12F  RET
```

  0x12A is the `else`-skip of an `if` **inside** case 9, and it is counted
  only because the test is `_jump_target(body[-1]) >= entries[-1]` while
  `entries[-1]` is the default, so any jump past the default qualifies. The
  compiler says what that jump is: a `return` emits `JMP 0`, to the
  function's single exit. `SetV1 ; CpyVtoR4 ; JMP -> RET` is therefore a
  `return true;`, which this file already knows how to place -- "a register
  load that flows only through cleanup to `RET` now emits `return x;` on the
  spot". A join whose target is reached only by cleanup to `RET` is a
  return, not a second exit, and dropping it from the join set leaves the
  one join the matcher asks for. So the fix is narrow, where "allow a
  switch two exits" would have been the dangerous shape.
- **`type_effectiveness` is TWENTY SWITCHES, not one with an odd layout.**
  The old reading was that its tables and arms interleave and that the
  backward-entry guard fires on an ordinary layout. The compiler refutes the
  premise: within one switch, only the next range's guards and a label can
  sit between two tables -- never arm code. So the interleaving is real and
  it is *between* switches.

  Measured on Manamon 1's 23 tables, by asking what lies in each gap:
  **19 of the 22 gaps hold arm code** (`CpyVtoR8`, which is this
  `double`-returning function's `return`), and only 3 hold guards alone.
  Those 3 are genuine two-table chains; the other 19 are boundaries. The
  function is a type chart written as twenty consecutive `switch`
  statements, which is the natural way to write one.

  So the guard was doing its job and the **merge** over-reached: it follows
  `next_range` into whatever JMPP it finds within twelve instructions, and
  at a switch boundary that is the *next switch's* table, after which
  `cursor` grows to instruction 622 of 984 and the entries it is compared
  against still sit at 0x42 .. 0x486. The stop condition is the
  discriminator above, and it is the same principle `_equality_chain`
  already applies -- "the chain must begin exactly where the table's
  entries ended", because extending a span to something not adjacent
  swallows whatever lies between.
- **`artisoul_tutor`** -- the same guard, failing by one: the span ends at
  exactly 0x263 and the first arm begins at exactly 0x263, and the
  comparison is `<=`. Not re-derived, because Manamon 2 is not on this
  machine any more; it may well be the same over-reach one step smaller.

#### Both are fixed, and the join set was computed in THREE places

Neither relaxation is the broad kind this file records as expensive --
"generalising the existing do-while handler took Crazy Party from 17 gotos
to 55" -- because the compiler says exactly where each boundary is:

- **A jump to the function's `RET` is a `return`, not a join.** Every
  `return` is emitted as a jump to the single function exit.
- **A switch whose every arm returns has no join, and its end is the
  default** -- because with no `default:` written, the compiler emits the
  default label and the break label as one. Where the source *does* write
  a `default:`, that label is an arm and the case is refused instead.
- **The chain-merger stops at a switch boundary.** One switch's tables are
  separated by the next range's guard and nothing else, so anything
  statement-shaped in the gap means the next table is a different switch.

**And finding that exposed the real problem: the join set was computed in
three places** -- the sparse matcher, the dense pattern and the jump-table
matcher -- identically, and the first of those rules went into one of them.
Two places answering one question is the failure this document keeps
recording; three is the same failure with more copies. `_switch_join` is
the one answer now, and all three matchers ask it.

A fourth change came out of the same reading, and it is the one that
touches every title: **an arm with no statements under `default:` is a
label the source never wrote.** Where the default label is the break
label, the default's position is the end of the switch and its span is
empty, so the code that looked like its body belongs after the switch.
`day_to_word` is the case -- `case 1 .. case 31` and then
`return number_to_words(arg0, false) + "th";` -- and it had been
recovering with that fallback inside a `default:` arm.

| title | lines | goto | split | bodies given up | calls |
|---|---|---|---|---|---|
| Super Egg Hunt | 6,247 -> 6,240 | 0 | verified | 0 | 1,608 |
| Paladin of the Sky | 27,343 -> 27,335 | 0 | verified | 0 | 7,110 |
| Psycho Strike | 27,469 -> 27,446 | 2 | verified | 0 | 6,443 |
| Crazy Party | 192,603 -> 192,584 | 14 | verified | 0 | 90,118 |
| Manamon 1 | 90,314 -> 90,848 | 0 | verified | **2 -> 0** | 26,548 -> 26,568 |

**Not one goto count moved**, every split still verifies, passthrough and
unbalanced files stay 0, and `bgt oracle` is 50/50. The four titles lose a
few lines each -- the empty `default:` labels -- and Manamon 1 gains 534
for the two bodies it no longer gives up on, whose calls are now read back
as well.

#### What the symptom actually was, which is not what it looked like

Worth recording, because it decides how hard to look for the next one.
Two oracle shapes were written for these rules and **both turned out
inert**: a switch whose every arm returns is claimed either way, and two
consecutive switches on one selector, merged, come out with the second
*nested in the first's `default:` arm* -- which is reached under exactly
the condition "nothing matched", so it computes the same answers. A
statement placed between the two switches does not change that: it lands
in the default arm and still runs.

So **the merge over-reach was never a silent wrong answer.** At small
scale it produces structure that is wrong and equivalent; at twenty-three
tables it makes the matcher decline, and a decline is *counted*. That is
the opposite of most of what this file records, and it is why the shapes
were written and then removed rather than kept: padding `bgt oracle` from
50 to 56 with six shapes that cannot fail would make that number mean
less, and a metric that cannot fail is the trap this document is
organised around. The evidence here is `body_errors` going 2 -> 0 and the
structural diff, not a value.

`artisoul_tutor` is still counted, in Manamon 2, and still not
re-derived -- that title is not on this machine. It may well be the same
over-reach one step smaller.

### Typing the promoted local took three tries, and the declaration wins

Promotion gives a slot a name, and then the name has to have a type. Measured,
on Paladin:

- **The value's type, overriding the slot's: 377 errors.** A scratch slot
  carries a bool here and an int there, so declaring it from one value's type
  makes every other use of it an error. `Can't implicitly convert from 'int'
  to 'bool'`, hundreds of times.
- **A fresh local per promotion: the flag comes apart.** Egg Hunt's joystick
  edge flag became `__nvgt_hold_20_403 = 0` with the up arm reading it and
  *writing* `__nvgt_hold_20_1152 = 1`, which only the down arm read — so
  pressing up disarmed down. **One slot carries one source variable, so it
  gets one name.**
- **The slot's own type, value's as fallback: right.** Plus two coercions,
  because a promoted name outlives the atom that described it:
  - dropping a comparison against a bool literal leaves the operand *as* the
    condition, so a numeric one needs `(x != 0)`. `x == false` became `!x` on
    an `int`, which is "Illegal operation on this datatype" — and the same
    operand reached through the value register converted correctly, which is
    what made the gap findable.
  - the bool→numeric wrap must not fire on a bare name that is *declared*
    numeric: `local_24 = (local_3 ? 1 : 0);` with `int local_3` is "Expression
    must be of boolean type". The atom claimed bool because that was the last
    value the slot held. **A declaration outranks an atom that outlived its
    value.**

### And a condition dropped on the floor

Fixing the fold left the right shape and the wrong condition:
`... || (local_20 == 0)`, preceded by `if (stick.get_y() >= -100) { } else { }`
-- an `if` with two empty arms, which is a condition that has lost its value.
The `&&` inside the `||` chain was declining to merge, so half the expression
was emitted as a statement that does nothing and the other half stayed in the
condition. **An `if` whose both arms are empty is the signature of this class
of bug**, and worth grepping for.

It declined on a **type**. `_begin_bool_merge` required the slot the merge
stores into to be declared `bool`, and this one is a compiler scratch slot
that `slot_types` had typed from widths -- `SetV4` is as true of an int as of
a bool. The bytecode says it outright instead: the stored value is loaded and
tested with `JLowZ`, and `JLow*` follows no compare at all, it tests the low
byte of the value register, which is the bool protocol and nothing else.
Taking that as evidence recovers

```
if (key_pressed(KEY_UP) || key_pressed(KEY_I) || (stick.get_y() < -100 && local_20 == 0))
```

which is the menu the game shipped. **Read the protocol, not the inferred
type**: on a generated slot the inference is the weaker witness, and it was
the one being trusted.

The general lesson is the one this file keeps relearning, in both directions.
**A clean compile measured nothing here** -- all three bugs compiled -- and
neither did the diagnostic count on the two rejected fixes. Running the result
found the bugs; a *different* metric, the goto count, rejected the cures.

# A residual `goto` is a DANGLING goto, in every title

This file has carried Crazy Party's 14 and Psycho Strike's 2 as flow the
structurer labels rather than forcing into a shape it does not have.
**There are no labels.** Asked of all four files that hold them --
`CarteCombat` 4, `part_6` 6, `Jeu` 2, `CombattantSauvage` 2 -- not one
`L....:` is emitted, and the same is true of Psycho Strike's two in
`home::reset_rebels`.

It is true by construction, which is why it is worth stating: the
structurer has **two** sites that write `goto L{t:04x};` and **none**
that writes a label. Its `label` event is skipped with `i += 1`.

So the sixteen are not labelled flow; they are jumps left pointing at
nothing, and the block holding each target was structured away. Both
kinds are one compiler error per line -- AngelScript has no `goto` -- so
an error count never told them apart, and nothing here asked.
`bgt recover` asks now: `dangling goto` sits beside `dangling else` in
the report and in `recovery.json`, scoped per file because that is how
the structurer names and emits labels.

**The sixteen were first counted by inspection**, and the check now
reports the same: every `goto` target in all four Crazy Party files and
both Psycho Strike ones was compared against every label those files
emit, and there are none. Run on the committed tree, Crazy Party comes
back `gotos 14` and `dangling_goto 14` -- the two numbers equal, which is
the statement that none of them is labelled.
### Fixed: the shape, and the attempt that was worse than the goto

Both titles' gotos are the compiler's **bottom-tested loop**, which this
file already documents: an unconditional forward `JMP` to the condition,
the condition last, and a conditional back edge above the body.
`home::reset_rebels` is the clearest:

```
local_1 = 0;
goto L0044;                       // the entry jump to the condition
...body...
local_1++;
local_2 = rebels.get_length();    // the condition's own materialisation
goto L0004;                       // the conditional back edge
```

`_find_latch` declines it, and the reason is one line: a statement in the
condition block is accepted only if it has no `(` in it, *"anything that
calls something is not [the materialisation], and still rules the loop
out"*. But `for (i = 0; i < rebels.length(); i++)` **calls `length()`
every iteration**, and the compiler parks the result in a slot there.

Narrowing that to "a call there is the condition's own if the CONDITION
READS WHAT IT ASSIGNS" does recognise the loop, and Psycho Strike goes
**2 residual gotos -> 0**. It was still reverted, because the loop it
writes is wrong:

```
local_1 = 0;
for (; local_1 < local_2; local_1++) {      // local_2 is the BOUND
    local_2 = (arg0 ? 1 : 0);               // ...and the body's flag
```

The `local_2 = rebels.get_length();` that set the bound is gone, and slot
2 serves both the bound and the condition flags, so `local_2` starts at 0
and **the loop never runs**. That trades a visible failure for a silent
wrong program, which is the one trade this file refuses -- *"half-emitting
a construct is worse than refusing it, because the damage lands somewhere
else"*.

**The shape that works was named rather than guessed at**: keep the
condition block inside the loop and break out of it,

```
while (true) {
    local_2 = rebels.get_length();
    if (!(local_1 < local_2)) break;
    ...body...
    local_1++;
}
```

which loses nothing and needs no slot to serve two purposes -- and that
is what it emits now, verbatim:

```
local_1 = 0;
while (true) {
    local_2 = rebels.get_length();
    if (local_1 >= local_2) {
        break;
    }
    ...body...
    local_1++;
}
```

The bound's assignment is present, the test is the latch's condition
negated, and the increment is where the bytecode put it. The decision is
`_find_latch`'s third return value: a condition block of **call-free**
assignments keeps the existing `while (cond)` emission, which leaves the
block at the end of the body where a loop-invariant handle alias is
harmless, and a block that **calls** something gets the form above,
because the entry jump lands on it -- so it runs before the first test
and cannot sit at the end of anything.

Two things are still refused, and the second is the one that keeps this
narrow. A statement that is not an assignment means an if/else merge
block rather than a condition, which is why the original guard existed.
And a working block whose values **the test does not read** is not a
condition either -- without that, any run of assignments before a
backward branch would be claimed as a loop.

#### What it cost, measured on all five titles and the ground truth

| title | lines | goto | dangling | split | calls |
|---|---|---|---|---|---|
| Super Egg Hunt | 5,294 | 0 | 0 | verified | 1,608 |
| Paladin of the Sky | 23,440 | 0 | 0 | verified | 6,952 |
| Psycho Strike | 24,428 -> **24,431** | **2 -> 0** | **2 -> 0** | verified | 6,406 |
| Crazy Party | **174,686** | **14 -> 0** | **14 -> 0** | verified | 90,148 |
| Manamon 1 | 83,363 | 0 | 0 | verified | 26,482 |
| rage room | 8,673 -> **8,679** | **4 -> 0** | **4 -> 0** | verified | 2,376 -> **2,377** |

**Crazy Party is PAID, and it is the row that mattered most.** Its
fourteen are what caught every over-broad structurer change this file
records -- 14 -> 30 for a call-text threshold, 14 -> 44 for dropping the
declaration-order rule, 14 -> 90 for forcing on the copy idiom -- and the
run that would have given it was stopped by the host for system memory
twice in one session, so it went in unquoted with an undertaking
attached. Run since, on a quiet machine: **14 residual gotos -> 0, and
14 dangling -> 0**, with the split verified, 90,148 calls read back, 0
unmodelled opcodes and 0 bodies given up on. So this change takes the
last residual goto out of the whole corpus.

What can be said without it is narrower than a measurement and is not
nothing: the new branch fires only where `_find_latch` previously
returned None, and None there emits a `goto`. A body with no goto cannot
reach the new code at all, so at most Crazy Party's four goto-bearing
files can differ and its other 554 cannot. Egg Hunt, Paladin and Manamon
1 are the evidence for that rather than the argument: identical line
counts, 0 gotos before and after.

Egg Hunt, Paladin and Manamon 1 do not move at all, and they cannot: the
new branch fires only where a loop was previously unrecognised, and an
unrecognised loop is a `goto`. A title at 0 gotos has none to find.

Nothing else moves either. `bgt libcheck --decompiler` holds at 44/47,
39/47 and 147/149 with the lifter at 153/155; Psycho Strike's `bgt audit`
is **41 call rows and 2 constant rows**, the figures this file already
records; the split verifies everywhere and passthrough, body errors,
unbalanced files and dangling `else` stay 0.

**And the ground truth says it is right rather than merely quiet.** rage
room's `count_total_items` was the last row that differed from its own
source, and the two now have the same structure:

```
source:     for (uint i = 0; i < inv.get_keys().length(); i++)

recovered:  while (true) {
                @local_4 = inv.get_keys();
                if (local_3 >= local_4.length()) { break; }
                ...
            }
```

so that title is **290 of 292 identical and 0 differing**, and the two
remaining rows are an ordering difference on one `close` rather than a
lost call. The whole progression on it, one measured step at a time:
272 -> 272 -> 284 -> 289 -> **290**.

**The call count rising is the result.** A residual goto had only ever
been a line that cannot compile; here the loop's own test went with it,
so `inv.get_keys().length()` was absent from the body entirely. That is
the first time one of these has been shown to cost a CALL.

### Found beside it: a call returning a VALUE TYPE is invisible to the
### lost-call census

Diagnosed exactly and **not fixed**, because one change at a time is what
made this section's own regression visible.

rage room's `mainmenu` loses an `input_box` and its three literals, which
the bytecode audit reports and `bgt libcheck` confirms against the real
source. The source is the dead-store shape this file already records:

```
string name = input_box("type your name", "type your name here");
name = "name";                 // overwritten on the next line
mainmenu();
```

so the store is correctly dropped -- and `input_box` **prompts the
player**, so the call must not go with it. In the shipped game choosing
"change name" asks you to type one (and throws the answer away, which is
the author's own bug); in the recovery it does nothing at all.

`_lost_calls` exists for exactly this and cannot see it. Instrumented,
`_bind` IS reached twice with the right text on unnamed slots -- so the
path is right -- and `self.invocations` never holds that text. The reason
is one branch, in two of the three call sites:

```python
if has_out and pop_out is not None and pop_out.is_ptr \
        and pop_out.offset is not None:
    self._bind(pop_out.offset, Atom("call", calltxt))   # no _record_call
elif ret is not None and ret.format() != "void":
    ...
    self._record_call(ins, calltxt, fr, ret)            # recorded ONLY here
```

A registered function returning a value type **by value** uses the stack
return-address protocol -- `PSF dest` pushed deepest, before the call --
so it lands straight in the caller's slot and never enters
`invocations`. Only the value-register branch records. `string` is the
commonest such type in these games, so this is not a corner: every
`input_box`, `string_replace` or `get_item_name` whose result the
original discards is a call the census cannot report.

That makes **three** known blind spots with one shape between them, and
this file already names the other two: `coin::act`'s `update_sound_2d`,
whose result a `Cast` overwrites in the value register without flushing,
and `pause_menu`'s seventh `menu_add_item`, masked by six identical
siblings. The wider signal -- call SITES against text occurrences, per
body -- covers all three, and carries the hazard it always did: a call
the renderer spells as syntax would never match its own text.

And `reset_rebels` has a second defect that the goto was hiding, worth
recording because it is this file's own signature: its condition reads
`if ((local_2 != 0) && (local_2 != 0))` -- one reused slot carrying both
operands of a short-circuit chain, which is the `use_screen_reader`
collapse. Structuring the loop does not fix that, and fixing that does
not structure the loop.

# A body given up on may be a TYPO, not a shape

`bodies that failed` counts the bodies the decompiler gave up on, and
every entry this file has ever explained was a *construct*: a jump
table neither matcher claimed, a switch chain that over-reached. So the
count reads as "the structurer cannot shape this one" -- and one of
them was a field that does not exist:

```python
return Atom(atom.kind, atom.text, atom.stack_size, data_type=dt)
```

`Atom` has `dw_size`. There is no `stack_size`, so that line raised
`AttributeError` **every time it was reached** -- and `_body` catches
everything so one bad body costs only itself, which turned a traceback
into a count. The recovered file carried
`// [decompiler error: AttributeError(...)]` where the body should be.

The branch is the one that stops a bool atom which has outlived its
value being wrapped as `(local_3 ? 1 : 0)` where `local_3` is declared
`int` -- this file's own *"a declaration outranks an atom that outlived
its value"* -- so it has been in since the Paladin menu work and had
never once run.

**What it cost is a whole feature of a whole game.** On `cs`'s server
the body was `netloop`, the network dispatcher: every command a client
can send, 119 distinct callees, 218 `send` calls, 102 `length` calls.
The recovered server compiled, started, and did nothing at all when
spoken to.

| that server's recovery | before | after |
|---|---|---|
| lines | 6,695 | **10,787** |
| calls read back | 1,875 | **3,018** |
| `bgt audit --calls` | 2 bodies, **119** values | 1 body, 3 values |
| `bgt audit --constants` | 1 body, **11** values | 0 bodies, 0 values |

The three calls left are the `player` constructor's generated member
construction, which this file already lists as benign, and the
constant audit is clean.

Two things worth keeping, and the second is the one that generalises:

- **An audit found it, not a diagnostic.** `bgt audit --calls` reported
  119 lost callees in one body, and 119 from one body is not a fold
  defect, it is a missing body. No line count, goto count or compiler
  diagnostic said anything: the project recovered with 0 residual
  gotos, a verified split and one counted body error.
- **A count that aggregates two causes hides the rarer one.** A body
  given up on for a SHAPE is a documented limitation; a body given up
  on because the decompiler raised is a bug in this repository. They
  were one number. `body_crashes` tells them apart now -- the summary
  says `bodies that failed 1  (1 a DECOMPILER CRASH)` and the crash is
  a *problem* in `recovery.json` rather than a statistic -- and the
  suite pins that no field name this file reads is absent from `Atom`.

# A debug build keeps the names, and one shipped game is one

This file says in two places that a game's own file names and its local
variable names are "stripped and unrecoverable", on the grounds that
"BGT compiles with `noDebugInfo = 1`". **That is true of `-C` and false
of `-c`**, and the installer registers both: `compile_release` passes
`-C` and `compile_debug` passes `-c`.

Checked by compiling a script of my own both ways -- the module's first
byte is `noDebugInfo`, and a `-c` build writes 0 there. So the question
was never whether BGT can keep debug information; it is which switch the
author used.

**`screamingStrike_en.exe` (Nyanchan, 2013) was shipped `-c`.** A 790 KB
executable, stock seed, 394 registered names -- a BGT between 1.0's 240
and 1.3's 432, so a new version for this corpus as well. Its module
holds:

```
D:\My Documents\screamingSstrike\screamingStrike_en.bgt   the source path
i, temp, point, lostLife                                    LOCAL names
itemComingTime, killedCount, lives, enemyCount              globals
```

**Why that is worth more than another test title.** The question this
toolkit cannot answer is *did the source NAME this slot, or is it the
compiler's scratch?* -- `_reused_object_slot` counts construction sites
for it, `copy_binds` watches for a copy idiom, the declaration-order rule
reads a synthesised list, and `slot_types` infers a type from the opcodes
that touch a slot. Every one of those is a guess at something a debug
module records outright. A `-c` build of a script written here is a
known-answer fixture for all of them, and a shipped `-c` game is the
same thing on code nobody here wrote.

## What it took to get a debug module to parse, and where it stops

Two things, and the first was my own shortcut coming back.

**`detect` could not identify a module with no classes.** Its confidence
comes from the class section landing whole, and this game is a
single-file 2013 game: 0 enums, **0 classes**, 0 funcdefs, 51 globals. Its
head reads perfectly by hand and `detect` refused it outright. I had met
this hole earlier the same day building an oracle fixture and the note I
wrote says *"a probe module of only an enum plus global functions fails
dialect detection -- fixed by giving the probe a class"*. I worked around
it instead of fixing it, and a shipped game walked into it.

The fallback is the format's own strongest check, which `summarize`
already ranks by one level up: parse the whole module and see whether the
tail lands **exactly** on EOF. It fires only when no candidate found a
single class, so no title that was already being identified can be
re-described by it.

**And the first version of that fallback could never have worked**, which
is worth recording: `_walk` only attempts the tail when it has an opcode
table, because a class block holds bytecode, and the fallback passed
`None`. It reported "no candidate lands on EOF" for every module by
construction. `detect` takes the table now.

**Then the function record needs its debug block.** It goes exactly where
this reader carried the comment `# debug info follows only when
noDebugInfo == 0, and BGT always strips it` -- between `objInfo` and the
trailing traits byte. The order is the one `nvgt/asreader.py` already
reads for the newer generation, which was written from AngelScript's
published source: line numbers, then the script sections as alternating
index and string, then the variables with a name each, then the script
section, the declaration position and the parameter names.

Parameters are variables there, which a known-answer fixture shows at
once: `int add_two(int left, int right)` with locals `total` and
`doubled` writes **four** names in one list, in that order.

**It is not finished.** Both debug modules get further and neither lands
on EOF yet:

| module | stops at | saying |
|---|---|---|
| my 744-byte probe | 0x2D5 | `implausible count 33554433` |
| `screamingStrike_en` | 0x1A | `bad string tag 0x01` |

The probe is the one to finish on, because its source is known: it reads
both globals and both functions and stops near the end, so the remaining
error is in one of the last fields rather than in the shape.

**Its head decodes by hand, and confirms the shape this reader has.**
`int enemy_max = 50;` is the probe's first global, byte for byte:

```
00        noDebugInfo = 0
00        enums     = 0
00        classes   = 0
00        funcdefs  = 0
00        typedefs  = 0
02        2 global properties
6e 09     'enemy_max'
00        namespace: the empty string
00        datatype: v = 0, so a new one follows
40 44     eu = 68 -- `int` in the legacy token numbering, which the
          IR converts with `t + (t>=36) + (t>=64)` to the newer 70
00        the datatype's one flags byte
66 ...    'f', the initialisation function
```

So the record really is `str(name) str(ns) datatype ReadFunction` with
the saved-datatypes back-reference, and the error at 0x2D5 is in one of
the debug block's last fields rather than anywhere above it.

**Screaming Strike's 0x1A is not inside a function**, which is what
this said and is worth correcting, because it points somewhere else
entirely. Read byte by byte, 0x1A is the boundary of the FIRST global
property's record:

```
00        noDebugInfo = 0
00        enums     = 0
00        classes   = 0
00        funcdefs  = 0
33        51 global properties        <- and the game has 51
6e 0e     'itemComingTime'            <- tagged: new string, 14 bytes
00        the empty string
40 42     eu = 66
00 00
01        <- the reader wants a function tag here
66 ...    <- and `f`, a function record, begins at 0x1B
```

So the record holds **exactly one byte more** before its initialisation
function than this reader expects, and the `f` at 0x1B is what says
where that function really starts -- a much narrower question than "the
debug block is wrong".

**And it has one leading count FEWER than the probe**, which the two
dumps side by side give away: the probe spends five zero bytes on
enums, classes, funcdefs and typedefs before its global count, and this
module spends four. 51 is the number of globals the game has and the
string after it is a global's name, so the 0x33 is the global count and
**this build writes no typedef section at all** -- a per-build field
like every other one here, in a 2013 BGT with 394 registrations,
between 1.0's 240 and 1.3's 432.

Trialled against the EOF landing, as every per-build field here is:
no typedef section, no namespace in a property record, and a datatype
with no back-reference takes the walk from **0x1B to 0x53E** of
0x5D33, stopping on the second property's name tag.

**That is not evidence, and saying so is the point.** 1,300 bytes for
the initialiser of an `int` is implausible, so that read is
over-running and swallowing records -- and this file's own history is a
signature model that *"parsed at 92.5% while being wrong about three
separate fields, because in the common case two counts were zero and
the layout happened to coincide"*. A trial that walks further is not a
trial that walks correctly. The datatype candidate is refuted outright
by the probe above: `00 40 44 00` is v=0, then token 68, then flags, so
dropping the back-reference would read that `00` as a token of 0.

So the next step is the one this file opens with rather than another
trial: `asCReader::ReadGlobalProperty` and `ReadDataType` out of
**this** build. The Ghidra import died with `OutOfMemoryError` at the
4G heap, and the fix for that is already recorded here -- **import the
PE stub, not the executable**, since half the file is the encrypted
overlay and the string and switch analyzers grind through it for
nothing. `bgtlib.read_trailer` gives the split.

Two things about the tooling that cost time here, both worth knowing
before the next attempt:

- **`as_module.py` takes the executable from `BGT_EXE`, not argv.**
  Passed as a second path it is parsed as a module, and the tool
  reports `neither dialect parses a coherent module head` -- which
  reads as a verdict about the game rather than about the PE file it
  was handed.
- **Without an opcode table there is no tail walk at all**, so this
  module "parses" with 0 enums, 0 classes and no error. The refusal is
  only visible with the table, and that asymmetry is what made the
  stopping point look like a detection failure.

**Nothing here changes a release build.** The debug block returns
immediately when `noDebugInfo` is 1, the `detect` fallback needs a module
with no classes at all, and Super Egg Hunt recovers to the same 5,294
lines, 0 residual gotos, verified split and 1,608 calls read back as
before.

**And Ghidra was tried first and did not help**, as it did not on Crazy
Party. This build has no `LoadByteCode` literal to anchor on; it does have
`_builtin_function_`, so that was the anchor, and the import died with
`OutOfMemoryError: Java heap space` in `X86Analyzer` at the 4G this file
records as sufficient for `bgt.exe` -- on a machine that had already
stopped a measurement for memory that session. What made progress instead
was the thing this file keeps coming back to: a fixture whose answer is
known, and the exact-EOF landing to judge it.

# A whole game WITH its source, which is the strongest oracle yet

`bgt libcheck` scores a recovery against BGT's shipped `include/*.bgt` --
source nobody here wrote -- and reaches 47 to 155 functions of a title's
hundreds. `bgt oracle` writes 52 shapes whose answer is known. Neither is
a whole game, and the gap between them is where every bug reported from
playing these games has lived.

A game handed over **with its source** closes it. `rage room` is one: 48
`.bgt` files, BGT 1.3, written by hand by a beginner, so its idiom is
nobody's house style and nothing in this toolkit was tuned against it.
`bgt libcheck --decompiler --include <its source>` compares every
function that appears once on both sides:

| | |
|---|---|
| functions compared | **292** |
| call sequence identical | **290** |
| call sequence close (>= 80%) | 2 |
| call sequence differs | **0** |
| string literals identical | **279** |

and the recovery itself: 31 classes, 265 functions, 418 globals, 840
bodies, **8,679 lines**, 0 unmodelled opcodes, 0 bodies given up on, 0
unbalanced files, 0 dangling `else`, a verified split, and **2,377 calls
read back** against the game's own runtime, with **0 residual gotos**.

It arrived with 4, all 4 dangling -- the new check from the section above,
on a title it had never seen -- and all 4 were one shape that this file
already had written down from two other titles. Fixing it is the section
**Fixed: the shape, and the attempt that was worse than the goto**, and it
is where the 290th row and the 2,377th call come from.

## The ground truth found the bug in the CHECKER, not in the recovery

All 14 differences were one shape, and it was mine:

```
source:     bullet b1(x, y, dm, sp, r, hs, di);   <- a DECLARATION
            bullets.insert_last(b1);
recovered:  bullets.insert_last(bullet(arg0, arg1, ...));
```

`_CALL` matches an identifier that a `(` opens against, so `b1(` reads as
a call to `b1`. **`bgt_apicheck` already refuses exactly that** -- *"a
declaration is not a call ... what tells them apart is the token before
the name: a declaration has a *type* there"* -- and this checker never got
the rule. Two places answering one question with one of them weaker, which
is the shape this file keeps recording; here the weaker one is the
instrument, so it was **under-reporting its own blindness as a difference**
in all twelve of that game's `spawn_*` helpers.

On this title `bgt apicheck` declines **377** declarations by that rule,
which is the measure of how much of one game's text the shape is.

**And the first fix was too eager, which only the ground truth could
say.** This author writes AngelScript's word operators:

```
if(key_down(KEY_LCONTROL) or key_down(KEY_RCONTROL)) return true;
```

The prefix before the second call ends `) or `, so `or` sat where the type
goes and the call was **suppressed** -- on both sides, which is the
dangerous direction for a checker: a call it cannot see is a call it cannot
report as missing. `control_down`, `dlg_wait`, `dlg` and `mainmenu` each
lost one that way, and the score went **272 -> 268**. The corpus could not
have caught it: BGT's own library writes `||` throughout, so all three
titles held at their exact figures while the rule was wrong.
`and`, `or`, `not`, `xor`, `is`, `in`, `out`, `inout` and the three
literals are in the exclusion now.

**A deferral was paid rather than kept.** A test pinned the old behaviour
deliberately, saying changing it *"would move the scores for a second
reason and neither side of the comparison could then be read"*. Measured,
it moves nothing: `bgt libcheck --decompiler` is **43/47, 39/47 and
144/149** before and after, the lifter path **153/155** with 155/155
literals, and the whole suite passes. The reason to defer was real and it
expired, which is worth as much as the fix.

## The other half: a constructor is syntax on one side and a call on the other

With the declaration fix alone, all 14 rows rose from 0.50 to **0.67** and
every one differed for one reason only:

```
  0.67  <global>::spawn_bullet     insert  source []  recovered ['bullet']
  0.67  <global>::stun             insert  source []  recovered ['timer']
```

The source writes `timer stuntimer;` and the recovery writes
`@local_1 = timer();` -- one construction, two spellings. `_noise` is meant
to drop exactly this; it implements it as `name in TYPE_NAMES`, and that
set holds the engine's **value** types and not a game's own classes.

**The module answers it with no new source of truth**: every `owner::` of a
function label IS a script class, so `script_types` derives the set and
`compare` passes it to `calls`. Derived rather than listed, deliberately --
a name in that set is dropped from BOTH sides, so a hand-written set would
make the comparison weaker by however much it was wrong.

| | before | after |
|---|---|---|
| rage room, identical | 272 | **284** |
| rage room, differs | 14 | **2** |
| Super Egg Hunt | 43 / 47 | 43 / 47 |
| Paladin of the Sky | 39 / 47 | 39 / 47 |
| Psycho Strike | 144 / 149 | 144 / 149 |
| Psycho Strike, lifter | 153 / 155 | 153 / 155 |

**And this is the deferral the test had locked**, with the stated reason
that it *"would move the scores for a second reason"*. It moves no corpus
score at all, which is why it was taken in a second step rather than
argued about: one change at a time is what made the `or` regression
visible, and it is what says this one is free.

### ...and the same shape one level out: the ENGINE's reference types

`timer`, `file` and `sound` are BGT's, not a game's, so they own no method
in the module and `script_types` is blind to them by construction.
`bgt_api.registered_types(exe)` names them -- the registration strings in
the game's own runtime, the oracle `bgt api --exe` and both gap checks
already use. 32 types in BGT 1.3, and exactly one collides with a
registered *function* name: `pathfinder_callback`, the engine's one
funcdef, which a call position makes a delegate rather than a call and
which `bgt_apicheck` already refuses. So the collision wants dropping too.

| | script types only | ...plus engine types |
|---|---|---|
| rage room | 284 / 292, 2 differ | **289 / 292, 1 differ** |
| Super Egg Hunt | 43 / 47, 3 differ | **44 / 47**, 3 differ |
| Paladin of the Sky | 39 / 47, 5 differ | 39 / 47, **4 differ** |
| Psycho Strike | 144 / 149, 1 differ | **147 / 149, 0 differ** |
| Psycho Strike, lifter | 153 / 155 | 153 / 155 |

**This one DOES move the corpus, so every row was read before it was
kept.** A checker that sees fewer calls scores higher for being blinder,
which makes a rise the suspicious direction -- so all ten rows across the
three titles were listed, and every one drops exactly one engine-type
construction from the recovered side and nothing from the source side:
`sound` five times, `timer` twice, `file` three times, `tts_voice` twice.
Not one real call anywhere.

And the source says they are declarations, in BGT's own code and in the
game's alike:

```
sound_pool::reserve_slot      sound temp; @current.handle=temp;
audio_form::set_tts_object    tts_voice temp_voice; @ui_speech=temp_voice;
rage room                     timer speedtimer;   file f, c, mainprojectfile;
```

**It closes a row this file had been explaining away by hand.** The note
above about the fold fixes ends *"Only `reserve_slot` itself is left, and
that one is a shape difference rather than a defect"* -- which was the
right reading and had to be re-made by a person every time the report was
read. It is 1.00 on both titles now, mechanically, and **Psycho Strike's
decompiler path reaches 0 differences across all 149 functions.**

The refusal is what the test pins rather than the set: with no executable
-- a `--opcodes` run legitimately has none -- the set is empty, so the
comparison gets **stricter** rather than quietly weaker. An unreadable or
non-PE file answers the same way instead of raising.

## All four of its dangling gotos are the ONE shape this file already names

The strongest corroboration in the run, and it was free. This file records
Psycho Strike's two residual gotos and Crazy Party's fourteen as the
compiler's **bottom-tested loop**, declined by `_find_latch` because *"a
statement in the condition block is accepted only if it has no `(` in
it"* -- and a `for` whose bound is a call puts one there.

rage room has four, and `count_total_items` is the same thing written by a
different person in a different decade:

```
source:   for (uint i = 0; i < inv.get_keys().length(); i++)

recovered:  local_3 = 0;
            goto L002a;                     // the entry jump to the condition
            ...body...
            local_3++;
            @local_4 = inv.get_keys();      // the materialisation -- A CALL
            goto L0006;                     // the conditional back edge
```

So three unrelated titles, three authors, **one** structurer gap. The
`while (true)` + explicit `break` emission this file names as the next
attempt would close all sixteen of the corpus's and all four of these.

**And one of the two remaining libcheck differences is a consequence of
it**: the source's condition calls `.length()` and the recovered body has
`@local_4 = inv.get_keys();` with no compare at all, because the condition
never became one. That is the first time a residual goto has been shown to
cost a *call* rather than only a compiler error -- the goto is the visible
failure and the lost condition is the quiet one underneath it.

### The audits, run where the source can settle every row

`bgt audit` compares a body's callees, literals and numeric constants
against the bytecode's, and this file's whole account of how to read it
is *"a row is a lead and not a verdict"* -- four benign kinds recur, and
triage means reading the disassembly. On the four games that came with
their own source there is a third thing to read, so a row can be settled
outright:

| | bodies paired | calls | literals | constants |
|---|---|---|---|---|
| cs client | 265 / 437 | 0 | 0 | 0 |
| cs server | 249 / 345 | 0 | 0 | 0 |
| constant velocity | 112 / 157 | 0 | 0 | 0 |
| rage room | 387 / 840 | 1 | 1 | **24** |

Three of the four are clean on all three comparisons, which is the
cross-validation: these are whole games' own code, not library files,
and nothing was lost from any body the audit could pair.

**And rage room's 24 are the original's own dead stores**, which the
source proves rather than suggests. The shape is one function repeated:

```
source:     dictionary d = engine.call("int get_ver1();");
            int e = -1;                       <- the audit's row
            d.get("0", e);
            return e + "." + f + "." + ...;

bytecode:   SetV4 14 -1                       <- `int e = -1;`
            VAR 17 ; ... ; dictionary::get    <- the out arg is a
                                                 CONVERTED temp, slot 17
            i64TOi 18 17 ; CpyVtoV4 14 18     <- ...and slot 14 is
                                                 overwritten, every path
```

`dictionary::get` takes an `int64`, so the compiler passes a temp and
converts it back **unconditionally** -- so the `-1` is overwritten on the
next line whatever `get` returned. The author wrote it as the fallback
for a lookup that misses, and this engine's `get` leaves its argument
untouched on a miss, so the fallback that should have worked is defeated
by the conversion the compiler inserts. It never worked in the shipped
game, and dropping a store nothing can read is faithful -- the
`find_best_weapon` and `sleep_in_bed` shape, found in a third game by a
different instrument with the source in hand to confirm the reading.

24 functions of its plugin layer are that one line: `game_engine_version`,
`export_map`, every `ftp_*`, `reg_exp_*`, `zip_get_files`. The one call
and one literal row are the `input_box` this file already records as the
lost-call census's value-type-return blind spot.

### A reserved word in call position, and the last two client rows

`cs`'s client stood at 216 of 218 with **0 differing**, the other two
being "close" -- and both were one name: `or`.

```
source:     if(key_down(KEY_LCONTROL) or key_down(KEY_RCONTROL)) return true;
reported:   delete  source ['or']  recovered []
```

`_CALL` matches the identifier a `(` opens against, which is right --
*adjacency to the `(` is what identifies a call* -- and `or (` is an
identifier followed by a paren. So the word operator went into the
SOURCE's sequence and nowhere into the recovery's, which renders `||`.

**This file already held the list.** `_TYPE_BEFORE_NAME` lists the word
operators to keep one out of the *type* position -- that is the
narrowing this document records as the fix for `or` SUPPRESSING a call
-- and the same list was never applied to the callee position. One
question answered in two places with one of them blind, for the
umpteenth time here; `RESERVED` is the one set now and both read it.

**Widening `_noise` normally makes the comparison weaker**, because a
name in it is dropped from both sides, which is why `OPERATOR_METHODS`
is widened one measured occurrence at a time. That argument does not
reach a reserved word: the language forbids it as a function name, so
nothing real can ever be dropped. Taken from the language, not from a
measurement.

| | before | after |
|---|---|---|
| cs client | 216 / 218, 2 close | **218 / 218, 0 close** |
| cs server | 194 / 196 | 194 / 196 |
| rage room | 291 / 292 | 291 / 292 |
| constant velocity | 94 / 95 | 94 / 95 |
| Super Egg Hunt | 44 / 47 | 44 / 47 |
| Paladin of the Sky | 39 / 47 | 39 / 47 |
| Psycho Strike | 147 / 149 | 147 / 149 |

**The corpus cannot move and that is checked rather than asserted**:
BGT's own `include/*.bgt` is written with `||` and `&&` throughout, so
there is nothing in it for this to reach. Only a game whose author
writes the word operators moves, and `cs` is the one in hand.

So **a whole game's own code matches its author's source in every
function this can compare** -- 218 of 218, which is a first here.

And the escape trap was paid again on the way: `\b` written through a
shell heredoc arrived as a literal **backspace**, so the new pattern's
word boundary was a control character and the exclusion matched any
name *starting* with a reserved word. The byte check this file
prescribes is what caught it, and the fix is to write such a patch with
a tool rather than a heredoc.

## A second one, and it needed no executable at all

`constant velocity` is the same author's, two years later, and it arrived
as **source with no executable** -- 3,456 lines across `game.bgt` and 16
includes. That is not a smaller version of the rage room exercise, it is a
different one: the module has to be *made* before it can be recovered, so
the chain is the toolkit's own end to end.

```bash
bgt compile game.bgt --build release      # 938,878 bytes, compiled cleanly
bgt recover game.exe -o recovered/
bgt libcheck recovered/game_bytecode.bin game.exe --decompiler \
             --include <the real includes>
```

| | |
|---|---|
| functions compared | 95 |
| call sequence identical | **94** |
| call sequence close (>= 80%) | 1 |
| call sequence differs | **0** |
| string literals identical | **95** |

and the recovery: 11 classes, 45 functions, 32 globals, 157 bodies, 3,883
lines, 0 unmodelled opcodes, 0 bodies given up on, 0 residual gotos, 0
unbalanced files, a verified split and **1,771 calls read back**.

**Nothing in it is a decompiler defect**, and both rows that were not
identical were worth running down rather than assuming:

- `dynamic_menu_pro::run_extended` calls the menu callback. The source
  writes `callback_handle(this, callback_data)` and the recovery writes
  `local_30(local_32, callback_data)` -- the compiler's own alias of the
  member, which it loads into a slot twice, once for the null test and
  once for the call. **This looked like a serious bug for about ten
  minutes**, because a `grep -B4` window showed `local_30` being read by
  `if (local_30 !is local_31)` and assigned only *after* it, which would
  make the test `null !is null` and mean the callback never fires. The
  assignment is there, four lines further back than the window reached.
  A narrow window is not a reading, and the fix for that is to widen it
  before writing anything down.
- `<global>::main` scored **0.00**, and that one was the checker's.

### A source file that declares `main()` is a PROGRAM, not a library

`bgt libcheck` reads every `*.bgt` in the folders it is given and pairs by
`owner::name`. Against BGT's own `include/` that is exactly right. Against
a **game's** source folder it is not, because that is where authors keep
their tools: `constant velocity` ships `matcher.bgt`, a standalone
brace-and-quote counter the game never includes, and it has a `main()`.
So the tool's `main` paired against the GAME's `main` and the report
showed a 0.00 row whose two sides are unrelated programs:

```
source:    input_box, open, read, string_split, length, string_contains, alert, ...
recovered: show_game_window, mainmenu
```

The whole **file** is skipped now, not just its `main`. A tool declares
helpers too, and a helper of a different program is no more this game's
library code than its entry point is. `cs` keeps four such files
(`pack_creator`, `pack_extracter`, `!releaser`,
`!copy_pack_to_clipboard`), so this is the normal case and not a quirk of
one title.

| | before | after |
|---|---|---|
| constant velocity | 94 / 96, **1 differs** | 94 / 95, **0 differ** |
| rage room | 290 / 292, 0 differ | 290 / 292, 0 differ |
| Super Egg Hunt | 44 / 47 | 44 / 47 |
| Paladin of the Sky | 39 / 47 | 39 / 47 |
| Psycho Strike | 147 / 149 | 147 / 149 |

The corpus cannot move and that is checked rather than assumed: **BGT's
`include/` declares no `main` in any file**, so the rule has nothing to
skip there. rage room does not move either, because its own `matcher.bgt`
sits beside the game rather than inside `includes/`.

**Both ground-truth titles now report 0 differing functions**, which is
the first time this project has been able to say that about a whole game's
own code.

## And a recovery is not the game's source, which is the real headline

272 of 292 is the first number in this project that compares a recovery
against a **whole game's own code** rather than against a library, a
fixture or itself. What the remaining distance is made of is now a
question with a known answer available in one command, on a title whose
every line can be read side by side -- which is what `bgt roundtrip` has
been approximating with a rebuild. The two should agree, and checking that
they do is the cheapest validation of the round trip there is.

# Porting to NVGT, which can be compiled on every run

The two engines share a language and almost nothing else, so this is a
smaller job than it sounds and a **measurable** one:

```bash
bgt tonvgt recovered/ -o ported/
```

**Why this can be honest where the BGT side cannot.** `bgt compile` drives a
GUI program and puts a modal dialog on somebody's screen, which is why this
file keeps calling a whole-title compile a thing to spend deliberately.
NVGT's compiler is a **console program** -- `nvgt -c script.nvgt`, exit codes,
warnings on request -- so a conversion is compiled on every run and the report
is what the compiler said rather than what it hoped.

Measured on every title that can be measured here:

| title | `nvgt -c` | and what it is |
|---|---|---|
| Battle of the Hunter | **compiled cleanly** | |
| constant velocity | **compiled cleanly** | |
| Super Egg Hunt | 1 error | `Illegal operation on this datatype` |
| Manamon 1 | **1 error**, in 82,099 lines | `Name conflict. 'sleep' is a global function` -- the game declares a class NVGT has as a function |
| The Gate | 3 errors | the `log` name conflict, and `elias` again -- NVGT has no such type either |
| cs server | 14 -> **5 errors** | the `const network_event@` the converter reports rather than rewrites, and `get_length` on a receiver whose type is not written down |
| cs client | 17 -> **14 errors** | `get_MOUSE_X` and friends: BGT constants NVGT spells differently |
| rage room | 212 errors | `library::call` returning `var@`, in a title that is a BASS wrapper |

**Two of those moved because the decompiler did**, not the converter: the
`cs` server went 14 errors to 5 and its client 17 to 14 across the fold and
type work above. Every error left is an engine difference the converter
reports rather than guesses at, which is what it is for.

Four mechanical steps and three reports. The steps: every `.bgt` becomes a
`.nvgt`, every `#include` is repointed, the entry script gains
`#include "bgt_compat.nvgt"` -- NVGT's own BGT compatibility layer, and the
reason this is a small job -- and the names the two engines spell differently
are renamed.

## A rename has to know what it is renaming on

`get_length` is the one that makes the point, and the engine was asked rather
than a registration read:

```
string[] a;   a.length()        compiles
              a.get_length()    "No matching symbol 'get_length'"
sound s;      s.get_length()    compiles -- `uint64 get_length() property`
```

So a blanket rename breaks every sound. The receiver's **declared type**
decides, and the project's own text is where that is written down -- with one
wrinkle this file has met before: a recovered local is called `local_16` in
every function that has one, so a project-wide map drops it for disagreeing
with itself. The nearest declaration above the use is the answer, which is
what a reader does and what the hoisting in these files makes exact --
`bgt signatures` resolves an unsigned comparison the same way.

**`string[]@` ends in `@`, not in `]`.** The first version declined every
handle-to-array in the corpus, which is why Battle of the Hunter sat at three
errors instead of none. And `lstrip("const")` is not how a prefix comes off:
it strips those five *characters*, so it turned `string[]@` into `ring[]@`.

**Some accessors are a plain PROPERTY there**, so the brackets come off as
well as the prefix. NVGT registers `network_event`'s members with
`RegisterObjectProperty`, so `e.get_peer_id()` is `e.peer_id` -- 10 sites on
the cs client, and its error count fell 55 -> 17 with those and `get_length`
together.

## What it will not do

Guess at a difference in **meaning**. Three are named with every site, and
each is reported rather than rewritten:

| | |
|---|---|
| `library::call` | returns `var@` in NVGT and `dictionary@` in BGT, so the result is not read with `.get(...)`. **All 212 of rage room's errors**, that title being a BASS wrapper |
| `downloader`'s progress | a `float` in NVGT where BGT's `get_progress()` is used as a truth value -- written straight across, `!d.get_progress()` compiles and polls forever |
| `network::request` | returns a `const network_event@`, so the handle it is assigned to has to be `const` too |

A rewrite there would produce source that compiles and does something else,
which this repository treats as the worst outcome available.

## A name the GAME declares that NVGT already has

The last class, and the only one that is the port's problem rather than the
converter's. Manamon 1 declares `class sleep` and NVGT has a global `sleep`;
The Gate declares `log` and NVGT has that too. One compiler error each -- and
Manamon 1's is its **only** one across 83,371 lines.

**The compiler is asked, not the text.** A static scan has to know what is in
*scope*, and one got it wrong in both directions at once: it missed `sleep`,
and it reported `map` and `note`, which NVGT declares in files nobody
included. `Name conflict. 'X' is a global function.` is exact and complete, so
that is what is read -- this file's first rule, applied one engine over.

The cure is a project-wide rename, which is the author's call: a class name
reaches into string literals and saved data, and a tool that renamed it would
be guessing about both.

## Two sets, and they are deliberately different sizes

`Nvgt.known` is every name NVGT's engine registers plus every
`include/*.nvgt` declaration, and it is used to report an **absence**.
`Nvgt.linked` is the engine plus `bgt_compat.nvgt` alone, because a converted
project includes that and nothing else of the library.

The asymmetry is the point and it is this file's own rule: for an absence a
broad set is right, since **a name a check wrongly holds is a gap it will
never report**; for a conflict the opposite holds, since a conflict wrongly
reported is noise. `get_length` is the reminder that a name-only check has a
ceiling either way -- `sound::get_length` exists, so the name is "known"
while the call on an array is not. The compiler closes that, which is why it
is the judge and the reports are a pre-filter.

# Repacking

`bgt_repack.py` runs the chain backwards: compress, wrap in the container header,
encrypt, and reattach as an overlay with a freshly computed trailer.

```bash
python tools/bgt_repack.py game.exe modified_bytecode.bin -o patched.exe
```

The PE stub is copied verbatim, so only the overlay changes. The trailer's offset
field is **recomputed** from the stub length — never copy the old one.

**Correctness is checked by round-trip, not by inspection.** The CLI repacks, unpacks
its own output, and requires the module back byte for byte before writing anything;
`--no-verify` skips that and is not recommended. This has been exercised on a real
509 KB module, including patching a string literal in place and confirming it
survives the rebuild.

## Writing a module back out

`as_write.py` rebuilds a module from a **field trace** the reader emits -- an
ordered record of every primitive it consumed. Duplicating the format in a
separate writer would mean two models to keep in step; replaying the reader's own
trace means there is only one.

The correctness argument is a byte-for-byte round-trip, checked against real
modules rather than asserted, and it is now a stage in `bgt validate`:

| title | module | trace fields | round-trip |
|---|---|---|---|
| Psycho Strike | 509,207 B | 236,348 | byte-exact |
| Paladin of the Sky | 631,015 B | 227,236 | byte-exact |
| Manamon 2 | 4,736,046 B | 2,247,023 | byte-exact |
| Manamon 1 | 2,415,727 B | 1,117,547 | byte-exact |

**This lifts the equal-length restriction.** The format stores no absolute
offsets anywhere -- everything is counted, length-prefixed or index-referenced --
and saved-string back-references are by **index**, so entry N stays entry N and
only the edited record's own encoded length changes:

```bash
bgt asm work/game_bytecode.bin game.exe --replace sounds.dat=my_custom.dat -o mod.bin
bgt repack game.exe mod.bin -o patched.exe
```

Verified end to end: `sounds.dat` → `my_custom_sounds.dat` grows the module by 10
bytes, the edited module still parses to EOF with 68/68 class blocks, the
repacked executable round-trips, and `bgt validate` passes it on every stage.

Three details that make this work rather than merely appear to:

- **The encoder must stop short of the next width's marker.** Each form of the
  encoded integer gives up one more bit to the marker above it, so reading
  `10xxxxxx` as six free bits lets a lead byte reach `0x7F` -- which decodes as
  the eight-byte form, returning an enormous value and leaving the cursor inside
  the next record. The decoder only has to mask; the encoder has to stop.
- **The instruction count is recomputed, not copied.** It counts instructions,
  not dwords, and recomputing it from the instructions actually present is what
  lets one be inserted or removed.
- **The tracer has to re-read under the assumptions `summarize` settled on.**
  `trace_module` calls `summarize` to find out whether the parse reaches EOF,
  and then builds its own `Reader` -- and it was passing only
  `template_namespace` of the per-build fields, so the second read used the
  defaults for the rest. That was latent for as long as the trialled fields
  happened to be the defaults on every title that had been traced, and it
  surfaced the moment one was not: Manamon 1 needs `unguarded_lists` and
  `legacy_body`, and without them the trace raises rather than writing a
  truncated module. Loud, because the tracer refuses a parse that does not
  reach EOF -- but a *third* reading of one format is the shape this file
  keeps warning about, and here two of them disagreed.

What this does **not** do is check that an edit makes sense. Renaming a string is
safe; changing an instruction to one with a different stack effect, or pointing a
`CALL` at an index outside `usedFunctions`, produces a module that loads and then
misbehaves. The round-trip proves the encoding, not the edit.

Two things to expect:

- **Output is not byte-identical to the original.** The LZ77 encoder here is a plain
  greedy matcher and compresses slightly worse than BGT's, so the file grows by a
  percent or two. Nothing downstream cares — every length is declared in the
  container — but do not diff against the original and conclude something broke.
- **Editing a module in place is safest at equal length.** Changing a literal to a
  different length shifts every following offset, and the operand tables are not yet
  rewritten by any tool here.

For asset packs, `bgt_pack.build()` serialises entries and `bgt_pack.replace()`
swaps named ones while copying the rest verbatim — so a single sound can be replaced
without re-encoding the other thousand. Replacing an encrypted entry needs the key,
which is the unsolved part below.

# Asset packs (SFPv1)

`pack_file` / `set_sound_storage`. Format read out of `pack::create` in a BGT binary.

```c
struct pack_header {  char magic[4];  // "SFPv"
                      u32 version;    // 1
                      u32 entry_count;
                      u32 reserved; };

struct pack_entry  {  char magic[4];  // "SFPv" again
                      u32 name_len; u32 flags; u32 data_size;
                      char name[name_len];   // no NUL
                      u8   data[data_size]; };
```

Entry payloads are usually encrypted, marked `SWCR`:

```c
struct swcr {  char magic[4];        // "SWCR"
               u32 plain_size;       // written three times
               u32 plain_size2;
               u32 plain_size3;
               u8  tag[16];
               u8  ciphertext[]; };  // AES-256-ECB
```

`tag` is **not an IV** — that reading is wrong and costs time. It is a
key-verification tag:

```
tag == AES-256-ECB(key, 16 zero bytes)
```

which means a candidate key is checked with one AES block, without touching
ciphertext and without needing to recognise the plaintext. `bgt_pack.Entry.decrypt()`
returns `None` rather than garbage when the key does not verify.

Whether a game uses one global key or a per-file key is visible immediately:
`bgt_pack.tag_index()` returns one entry per distinct key.

---

# Sound-pack decryption - SOLVED

`bgt_kdf.py` implements BGT's password -> key derivation, transcribed instruction by
instruction from the decompiled runtime.

```python
from bgtdecomp import bgt_kdf, bgt_pack
key = bgt_kdf.aes_key(password)          # SHA256(KDF(password))
_, entries = bgt_pack.parse("sounds.dat")
for e in bgt_pack.key_matches(entries, key):
    open(e.name, "wb").write(e.decrypt(key))
```

Verified end to end: on one shipped title it recovers the pack key, which opens
**974 / 974** encrypted entries, every one decrypting to valid Ogg Vorbis. It also
independently reproduces a key captured at runtime with Frida from a second title.

## The derivation

```
seed  = first byte of the password with the high bit set, else '#'
seed  = (seed - 4) * seed                      signed char arithmetic
state = 16 bits: high = seed, low = seed - 1

fill(98 bytes):  c = low byte of state (signed)
                 if c == 0: c = -0x12
                 c = (int)c / (seedInt + c*2 + 8)     C division, truncates to zero
                 if c == 0: c = highByte(state) + 'c'
                 state = (state & 0xff00) | (c & 0xff)

A1 = fill();  A2 = fill()                      ONE generator run twice, state carries
digest = SHA512(A1 || password || A2)          the stock SHA-512 IV
for i in 0..63: if digest[i] == 0:             scrub NULs -> result is a C string
                    c = (-11 * (i+1)) & 0xff
                    digest[i] = c or 0x83
AES key = SHA256(digest)
```

Four details that each silently produce a plausible-but-wrong 64 bytes:

- `char` is **signed**, and the divide is **C integer division** (truncating toward
  zero, not Python's floor).
- The two fill loops read differently in the decompiler - `(c + 4) * 2` versus
  `c * 2 + 8` - but those are the same expression. It is one generator run twice,
  with state carrying across. In practice the generator reaches a **fixed point**
  almost immediately, so the two salts come out identical for 127 of the 129
  reachable seeds (for the default `'#'` seed both are 98 bytes of `0xa0`). Do not
  "fix" the second run into producing different bytes.
- The password goes **between** the two salts, not before or after both.
- The NUL scrub is not cosmetic: the result is consumed as a C string.

The salts depend only on the seed byte, so `bgt_kdf` caches them per seed. That takes
a bulk search from ~8k to ~120k candidates per second.

## Finding the password

The password is whatever the script passed to `set_sound_decryption_key()`, and it is
often **computed rather than stored**. In the title above it was a base64 literal put
through a script function that iterated SHA-512 218 times, reversing the digest at one
point, and returned the iteration whose 64 bytes held the most NUL bytes. Read that
function out of the recovered bytecode rather than guessing - the raw disassembly is
clearer than the lifted output here, because the selection loop lifts poorly.

Note `string_hash(data, algorithm=2, binary)` is **SHA-512**, verified against
the engine along with `string_reverse`, `string_base64_encode` and
`string_mid` -- see **What the documentation does not say, the engine will**.

Titles differ in whether they use one global key or a key per file - `tag_index()`
shows which immediately, and that decides whether one password is enough.

**The common shape is one step, not a loop, and `bgt crack` does it now.**
Super Egg Hunt's is

```
set_sound_decryption_key(string_decrypt(h_key, "af-dc7=rqp+"), true);
```

- not a literal, so a harvest over literals cannot find it, and not computed
far enough to need reading either: both halves are in the module. The
`encrypted` harvester composes them (see **Extracting means decrypting**) and
`bgt recover --extract-data` runs it without being asked. Where that fails,
the recovered **source** is now the place to read the caller - `grep -rn
set_sound_decryption_key` over the project found this one in seconds, where
the disassembly would have taken an afternoon. Recovering first and cracking
second is the better order.

## If you cannot find the password

Capture the key at runtime instead: hook the AES setup and read the 32-byte key as it
is installed. `bgt_pack.key_matches(entries, key)` then confirms a candidate against
the entry tags in one AES block, and `Entry.decrypt(key)` returns the plaintext or
`None`.

# What is still open

Everything below is known and characterised, not merely suspected. Nothing here
blocks reading or rewriting a module.

**Stack balance is complete on the four titles** -- 14,300 / 14,300 bodies --
so it no longer points at anything. The open work was readability, and
`as_lift.fold_temporaries` now does it: it folds a compiler-materialised
temporary back into its single use. Two folds, each with its own safety
argument:

- **A pure value** (a string or numeric literal, or a `string(param)` copy)
  folds into its one by-value use anywhere in the basic block. `v5 = string("");
  v6 = string("&"); v7 = string(a0); v8 = string_replace(v7, v6, v5, v1)` reads
  `string_replace(string(a0), "&", "", v1)`, and `string("x")` collapses to
  `"x"`. A pure value has no side effect, so moving it reorders nothing.
- **A whole-value copy** folds a value-register or variable copy into the
  assignment above it: `ret = f(); v1 = ret` becomes `v1 = f()`, and
  `ret = f(); return ret` becomes `return f()`. This one may move a *call*, so
  it fires only when the use consumes the value whole (`L = var;` or
  `return var;`) and stands immediately after the definition -- no other
  subexpression is evaluated in between, so again nothing reorders.

Both are confined to a basic block and blocked by any reassignment of the
temporary or of what its right-hand side reads; a string literal is masked when
scanning for uses so a name inside it is never taken for one. Because only these
two safe shapes move, the fold is **invisible to `bgt libcheck`**: per function,
the call sequences (153 / 155 on Psycho Strike) and literal multisets (155 /
155) are identical with folding on or off. It removes **18-25% of body lines**
(strike 18.7, paladin 25.4, sbyw 24.3, manamon2 23.1), and all 14,300 bodies
fold without error.

The `!v1 != !v2` bool-test pattern an earlier note listed as remaining work does
not actually occur in any title's lifted output -- the two-part `CMP`-plus-jump
handling already renders those as the comparison they are. `bgt libcheck` is the
check to run for any further readability change: one that alters a call sequence
or a literal is wrong.

**Residual gotos: Crazy Party went from 17 to 0, and every one was a loop
whose body folded into its condition.** They had been the dominant error
source — 17 of that title's 19 compiler errors — and AngelScript has no
`goto`, so each line was an error rather than a blemish.

The shape is a backward branch whose target resolves to **the branch's own
event index**: no *event* lies between the target and the branch, because the
whole body folded into the condition expression. Source like

```
do { y = random(0, h - 1); } while (absolute(centre - y) < 3);
```

arrives as one expression that does the work and one branch that repeats it.
An empty-bodied `while (cond) { }` says exactly that, since the condition is
re-evaluated per iteration either way — and unlike a `goto` it compiles.
Almost all fifteen were a minigame's `placeZone` picking a spot far enough
from something; `DescenteMine::choisisDirection` is the same thing as
`do { v = random(-1, 1); } while (v == 0);`.

**Two wrong attempts came first, and the second is the lesson.** Generalising
the existing do-while handler to "the first backward branch anywhere in the
slice" took Crazy Party from 17 gotos to **55**: claiming the first back edge
claims an *inner* loop before the outer one is recognised, which breaks the
real enclosing loop and turns its `continue`s and `break`s into gotos. A
`loop.is_continue` guard cannot save that, because at a function's top level
there is no enclosing loop context yet. It was reverted. The point is not
that the idea was bad but that **neither attempt matched the actual shape**,
and the only reason that was visible is that each one was measured.

**Measure a structurer change per attempt, and make it cheap enough to.**
Decompiling Crazy Party's 4,601 bodies takes minutes; the sixteen that
contained gotos take about twenty seconds. That difference is what turned
this from guessing into looking, and it is worth rebuilding for the next
shape. Cross-check the titles that are already clean by **diffing their
rendered output**, not just their counts: this fix leaves Super Egg Hunt,
Paladin and Psycho Strike byte-identical, which is what a correctly scoped
structurer change looks like.

**Nothing is left on any title that can be measured here.** All five are
at 0 residual gotos and 0 dangling gotos, Crazy Party's fourteen
included -- that row was owed twice and is paid above. Manamon 2
reported 4 at the commit it was last measured and cannot be
re-measured here, because its own runtime is gone from this machine
and BGT 1.3 does not parse its fork.

And they were never "labelled", which this said for a long time: a
residual `goto` in this corpus has no label anywhere -- see **A
residual `goto` is a DANGLING goto, in every title**, where the
structurer turns out to have two sites that write a `goto` and none
that writes a label.

**No semantic checking on edits.** `bgt asm` proves the *encoding* round-trips,
not that your edit makes sense. Renaming a literal is safe; changing an
instruction's stack effect or pointing a `CALL` outside `usedFunctions` yields a
module that loads and then misbehaves.

**Crazy Party was the sixth title, and the first that did not parse. It was
not a new format.** It is the biggest by a wide margin -- a 9.3 MB module,
`tagged` dialect, 550 classes, 4,486 bodies -- and two *guesses in this
reader* were the entire obstacle. Both are the same mistake in different
clothes: a round number, and one spelling of a name.

- **A sanity guard rejecting real data.** The instruction count was checked
  against `1 << 20`. Crazy Party generates part of its own source, and the
  generated `ajouteLangue` declares **1,074,460** instructions, which walk to
  exactly that count and end on `RET`. The bound is now the bytes remaining,
  since every instruction costs at least its opcode byte. That is exact where
  the constant was a guess, and the constant was the only thing between this
  title and a full parse.
- **The delegate factory has two names.** `usedFunctions[334]` is
  `%delegate_factory`; the reader knew only `$dlgte`. That record is the name
  alone, and nothing in the stream says so, so reading on takes the next
  field as a parameter count — which surfaced 200 entries later as an
  "inOutFlag count 660 > 28 params". Both spellings are known now.

With those two, **every stage passes, byte-exact rewrite included**, and the
module recovers to 190,277 lines across 559 files with 0 unmodelled opcodes
and 0 bodies that failed.

Recovery went from **170 compiler errors to 2, and both are the same single
line** -- the engine funcdef described below. It found five latent decompiler
bugs on the way, none of which any earlier title happened to need:

- **A delegate is not a call to the factory, and naming it takes two
  sources.** The handling existed and was right as far as it went — bind the
  object and method, take the funcdef type from the following `STOREOBJ` —
  but it matched `$dlgte` only, so 43 sites emitted
  `fadeOut(arg0, %delegate_factory(), arg1)`. Matching the other spelling was
  not enough: where the delegate is passed **straight into a call** there is
  no `STOREOBJ`, so no slot to take the type from, and the bare method is
  rejected just as firmly ("Can't pass class method as arg directly"). The
  bound method's own signature names it instead — `Jeu::att(int, bool)`
  against the module's one matching `void CbFade(int, bool)` — and an
  ambiguous match is left unwrapped on purpose, because that fails visibly
  while the wrong funcdef would compile and bind the wrong callback. The
  source form `CbFade(this.att)` was put to BGT 1.3 rather than assumed.
- **`do while` had a second emit site** that never went through `_condition`,
  which is why fixing the first one left `} while (local_4 - local_1) < 1;`
  behind. Two places answering one question is the recurring shape of
  everything in this list.
- **`_condition` asked the wrong question.** It tested
  `startswith("(") and endswith(")")`, which is true of `(0 + 2) < (x)` —
  a string enclosing nothing — so it added no parentheses and emitted
  `while (0 + 2) < (x) {`. 110 errors, in `while` and `do while` alike. The
  file already had `_encloses` for exactly this; the wrapper was not using it.
- **A global function a method shadows needs its scope said out loud.**
  `Case::lanceMenu` calls the *global* 8-parameter `lanceMenu`; unqualified,
  the class's own 6-parameter method shadows it and the compiler reports a
  6-parameter candidate called with 8 arguments, which reads like an arity
  bug in the lifter and is a scoping one. `::lanceMenu(...)` is what source
  would write, and the compiler accepts it. The change alters no output at
  all on the other titles, which is how a fix of this shape should look.

**Crazy Party generates part of its own source**, which is worth knowing
before reading its code and is the one real exception to the note above about
file names. `genereHelp` and `genereAjouteLangue` emit `.bgt` text at runtime --
the module carries literals like `// ce code est généré automatiquement
par la fonction genereAjouteLangue`, `void ajouteLangue() {` and the file
names `help.bgt` and `ajouteLangue.bgt`. Those are real names of the game's
own source files, but they are a *generator's output*, not a record of the
build, so they still do not give the compiler's file list. They do mean a
string search for `.bgt` in this title finds source rather than a sound —
and they explain why one function is a million instructions long.

**One site needs a name the module does not carry, and both sources have it.**
`pathfinder::set_callback_function` takes an *engine* funcdef, and
`objVariableTypes` records every funcdef-typed value under the
`_builtin_function_` placeholder with no signature, so neither the slot nor
the module's own funcdefs can name it. `bgt_asir.name_engine_funcdefs` asks
outside the module: the documentation (`bgt api pathfinder` gives `bool
set_callback_function(pathfinder_callback@ callback)`) and, where BGT is not
installed or does not reach, the registration strings in the game's **own**
runtime -- the one executable always on hand, since it is the input. Crazy
Party's `JoueurTerrain::setPf` now recovers as
`pf.set_callback_function(pathfinder_callback(arg0.callbackPf))`.

**How much surface that has is measured, and it is one name.** A registered
*funcdef* is declared the way a function is, so it appears in `registered()`
under its own name, while a registered *type* never does -- every constructor
and factory is declared under the literal name `f`, with the owner as a
separate string. Asked of six binaries that way, the answer does not move:
BGT 1.3, Paladin, Super Egg Hunt and Crazy Party at 432 registrations, Psycho
Strike's fork at 453 and Manamon 2's at 509, spanning 2010 to 2019, register
**exactly one funcdef** -- `pathfinder_callback`, taken by exactly one method.
Not even the fork that added Crypto++ and a newer AngelScript adds a second
callback type. So this is a complete answer rather than a sample, and the
two sources agree on it.

**What Ghidra contributed here was nothing, and that is worth recording.**
The binary analysed fine (at a 5G heap; 2G runs out on this one), but the
xref search for `LoadByteCode failed` found no referencing function. What
cracked it was the self-verifying criteria the rest of this document is
built on: a declared count that walks to exactly a `RET`, and a tail that
lands exactly on EOF. Read the reader when the format is in question; when
your *own* reader is in question, the checks are what tell you.

**`--string` finds nobody more often than it should, and the fix is four
bytes.** That `LoadByteCode failed` dead end repeated exactly on
`GetProcAddress failed for '%s'`, which *is* referenced -- once, from
`0x0048107a`. This is a 32-bit build, so a literal's address is pushed as an
immediate: compute the string's VA from the section table and search the
file for those four bytes little-endian, then hand the hit to `--at`. That
turned three "no referencing function" answers into the `library`
registration block, the `GetProcAddress` site and the signature parser. Use
`--string` first and this when it comes back empty.

**A fifth title may differ again.** Three builds produced two answers for the
template-namespace field and two for the script-object flag. The fourth (SBYW)
parsed unchanged but used opcodes none of the others did. Run `bgt validate`
before assuming a new title matches, and check the lifter's passthrough count
as well as the stages.

And run `bgt recover` on more than one, for the reason Paladin showed: the
default-argument order was wrong from the start, and Psycho Strike has too few
defaults for it to matter there. A title that recovers well is not evidence.

**What the recovered source still does not compile.** `bgt recover --compile`
is the measure, and the groups it leaves are known rather than mysterious:

**Three of the four groups this list used to name are gone, and the counts
it quoted for them were stale** -- 50 residual gotos in Psycho Strike, 10
`<?>` sites in Paladin and 1 in Psycho Strike, 7 funcdef-typed locals in
Psycho Strike. Re-measured against a fresh run of every title: **0, 0 and
0.** Only Manamon 2 still carries anything, and both of its groups are
named below rather than counted. A number in this file is a measurement
with a date on it, and these three had outlived theirs.

- **Residual `goto`.** The structurer labels flow it cannot shape, and
  AngelScript has no `goto`, so every one of those lines is an error. Four
  remain, all in Manamon 2; Paladin, Psycho Strike, Super Egg Hunt and Crazy
  Party are at zero. Either the shape gets recognised or those bodies need a
  dispatch rewrite; a label is not an option.
- **A body no switch matcher claims.** Three, all in Manamon 2, and they are
  three separate diagnoses rather than one mystery -- see **The three tables
  nothing claims**.
- **A call the simulation could not supply arguments for** printed `<?>`
  rather than inventing values. There is no longer one in any title.
- **A funcdef-typed local** had no name source could use. There is no longer
  a `_builtin_function_` anywhere in any recovered file, and the engine's
  whole funcdef surface turns out to be one name -- see **One site needs a
  name the module does not carry**.
- **A type no stock engine registers** (Psycho Strike's `elias`): reported,
  with the DLL it comes from, and not compilable here at all. This is the
  one that stands.

**The NVGT library corpus is checked for compiling, not meaning.** 40 of 52
library builds recompile -- six modules fail, the same six at HEAD and after
every change here, all on one generated list local that is used but not
declared. NVGT decompiler bugs compile cleanly while computing something
else, so a new construct belongs in a fixture, not only in the corpus.

**And the fixtures that *run* have to be able to run.** `test_roundtrip_behavior`
is the check that catches a decompile which compiles and lies, and in this
environment it was inert: without `NVGT_COMPILER` it skips, and with it every
case died in `subprocess` before the compiler started. So the BGT work changed
`decompile.py` by 774 lines with that check silently not running, and three
regressions got in. Each was found by making it run, and fixed rather than
accommodated:

- **A dense switch's default is not last.** The arms come out in bytecode
  order, and a jump table's default target is the code right after the table
  -- before every case body. AngelScript rejects that ("The default case must
  be the last one"), so three fixtures and the library's `native_form` did not
  compile at all. `_default_last` moves it, but only when it neither falls
  through nor is fallen into: its own statements must end in `return`, `break`
  or `continue`, and so must the arm above it. Otherwise the order stands,
  because a switch that does not compile beats one that runs the wrong arm.
- **A bool-literal comparison stopped simplifying.** Typing a reused slot
  numeric renders a bool operand as `(X ? 1 : 0)`, and the simplification
  matched only a bare `true`/`false`, so `x == false` came back as
  `(!getf(arg0) ? 1 : 0) == (false ? 1 : 0)` -- correct, compiling, and
  saying nothing. `_unwrap_bool` sees through the wrapper; its paren-balance
  check is load-bearing, because `(a ? 1 : 0) + (b ? 1 : 0)` also begins with
  `(` and ends with `)`.
- **A generated local's declaration is hoisted**, which split
  `bool __nvgt_ret_N = d.get(...)` into a declaration and an assignment. That
  is the safer shape -- such a local can be read outside the block whose call
  created it -- so the fixture now pins the intent rather than the old
  spelling.

The lesson is about the harness, not the decompiler: **a check that cannot run
is worse than no check**, because it is counted. Every `subprocess` call in
this repository now passes `stdin=subprocess.DEVNULL`, and that is the reason.

**Two narrow NVGT constructs still decompile wrong** (repros in `docs/nvgt.md`),
both pre-existing and found while fixing the three below: a `? :` over the
constants 0 and 1 *added inside an expression* (`(x>0 ? 1:0) + ...` -- the `0/1`
arms make `_begin_bool_merge` claim it before `_begin_value_merge` can, and its
`ADDi` merge produces an empty `if`), and a guarded increment in a stripped
build (`if (f()) total += 10;` sometimes hoists the `+= 10` out of the `if`).

**Three compiles-and-lies bugs found with the control-flow fixture are fixed:**
a ternary used *inside* a larger expression (`10 + (c ? 3 : 7)` no longer
becomes `10 + 7` -- the value-merge derives the ternary's slot from its arms
when the merge is arithmetic); a `for` variable reused across sibling scopes
(hoisting takes scalar names from every debug variable, not just the last per
slot); and a `&&`/`||` whose result is *stored* in a bool and used later (the
merge folds `(A op B)` into the stored slot at its `CpyVtoV4`, so an `if`, a
ternary or an expression reading it later sees the whole value -- guarded to a
bool destination so a uint ternary still goes to the value-merge).

**NVGT payloads from unverified builds.** Official NVGT releases get fresh
packaging parameters per build, so executables from releases without a verified
profile are reported as unsupported (see `docs/nvgt.md`). That is deliberate. A
profile is added only after it has been verified against real samples.

# Conventions

- **Read the reader, don't guess the format.** Every format detail here came out of a
  game's own `asCReader` / `pack::create` in Ghidra -- or, for NVGT, its published
  source. `bgt.exe` itself is worth opening: it settled the template-stub question
  (`bgt ghidra decompile "<BGT>/bgt.exe" --string factstub`).
- **Compiling is not meaning; run it.** Output that recompiles is valid, not
  equivalent. A dropped `@h.item = b`, an out argument copied before the call
  that fills it, and a `?&in` handle passed as a copy all compiled cleanly.
  Running the result and comparing it with the original caught each one.
- **Make each layer self-verifying.** Exact declared lengths, exact EOF landings,
  identifier-shaped names. A parser that "mostly works" is a parser that is silently
  desynchronised.
- **Validate against something you did not write.** BGT ships the source of several
  standard-library classes under its install directory; a lifter can be checked
  against them objectively rather than by spot-checking output that looks plausible.
- **Cross-validate across titles.** These games share a runtime, so a change that
  improves one title and breaks another is wrong.
- **A metric can be confidently wrong.** A greedy search optimising stack residue once
  adopted eight opcode stack-effect changes and was wrong about seven of them. Read
  `asBCInfo[]` out of the binary instead.
- Keep this folder free of game files and per-title findings. Scratch output goes
  somewhere else and is reproducible in one command.
