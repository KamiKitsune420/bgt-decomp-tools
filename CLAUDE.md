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
need per-title reverse engineering. This has been confirmed against three unrelated
shipped titles spanning 2014–2019 — same trailer, same key, same container magic,
same compression, same pack format, all opened by this toolchain unmodified.

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
| `bgt_api.py` | `bgt api`: the engine's documented API, read out of the installed `bgt.chm` |
| `bgt_compile.py` | `bgt compile`: runs BGT's own compiler and reads back every diagnostic |
| `bgt_project.py` | `bgt recover`: a browsable, compilable project — files, ZIP, report |
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

Or, in one command, the whole thing as a project the compiler judges:

```bash
bgt recover game.exe -o recovered/ --compile
bgt compile recovered/game.bgt            # just the compiler, on any script
```

Extending the reader means reading `asCReader` out of the binary, and the Ghidra
side of that is scripted too — see `docs/ghidra_workflow.md`:

```bash
bgt ghidra status                                    # Ghidra + JDK 21+ present?
bgt ghidra install                                   # fetch it (asks first)
bgt ghidra decompile game.exe --string _builtin_function_ -o readers.c
```

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
| in/out + default-arg lists | written **unconditionally** | only when `paramCount != 0` |
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

### One difference is per-build, not per-dialect

`ReadTypeInfo`'s `'a'` (template) form carries a namespace string after the name
in Psycho Strike and Manamon 2, and does **not** in Paladin of the Sky — same
`tagged` dialect, different record. So `as_module` trials both and keeps the one
whose tail lands exactly on EOF, the same way the dialect itself is detected.
`summarize()` reports which won as `template_namespace`.

Do not assume a third title matches either of these two. Run `bgt validate`.

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

**Global-pointer operands are encoded differently per dialect, and both readings
fail quietly.** In `len2` the operand is `2 * index + tag`: tag 0 selects the
string-constant table, tag 1 the global-property table. 149,656 `PGA` operands in
Manamon 2 are even (literals) and 106 are odd (`player`, `current_map`,
`save_data`); reading them all as literals resolves those 106 to a real string
from the wrong table. In `tagged` there is no tag bit at all — the operand is a
plain `usedGlobalProps` index, `STR` carries literals separately, and Psycho
Strike's `PshG4` saturates at 170 against 171 globals. Applying the `len2` rule
there halves every index and still yields a real global name:
`pack_file::open(retreave, ...)` reads as `pack_file::open(money_wanted, ...)`.

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
  two copies then absorbed the game code in between.
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
**Manamon 2 fails it**, on every run including a clean one in an isolated
worktree, so its project is browsable but its include order is not proven
faithful; the other titles pass. Read the single-file render for that title
until the cause is found, and do not trust its file split.

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

| title | lines | files | goto | unbalanced | split | compiler says |
|---|---|---|---|---|---|---|
| Super Egg Hunt | 6,450 | 15 | 0 | 0 | yes | **0 errors, and it runs** |
| Paladin of the Sky | 27,494 | 60 | 0 | 0 | yes | **0 errors, and it runs** |
| Psycho Strike | 27,563 | 75 | 0 | 0 | yes | 33, every one the engine's |
| Manamon 2 | 171,755 | 1,640 | 25 | 3 | **NO** | 68, five files the engine's |
| Crazy Party | — | — | — | — | — | does not parse yet (see below) |

**Two titles compile clean and run.** `bgt compile --run` on the recovered
project reports `compiled with 1 warning(s), and ran: it opened a window of
its own titled 'Super Egg Hunt Version 1.53'` — which is the title the
original executable shows, checked by launching it. Paladin does the same.
That is the end-to-end check: executable in, source out, source back into the
engine, game on screen. The one warning left is `The script section is empty`,
on the generated entry script, which holds nothing but `#include` lines.

**Psycho Strike's 33 are all the installed engine's.** 32 are uses of
`elias`, a plugin type, and one is `tts_voice::speak_to_sound`, which this
engine does not document and the game's own executable registers. Nothing
there is the recovery's.

**SBYW is absent from this table on purpose.** Its executable is no longer in
the folder it was read from, so its numbers could not be re-measured against
the current code and are not quoted as if they were. Everything above it in
this document that mentions SBYW is a *parse* and *lift* result, which stands
— it is only the recovery table that needs a run.

**Manamon 2 is two different problems, and the brace count tells them apart.**
Five files stop on `protected` or `weakref<T>`, which only its own newer
engine has. Three more — `character.bgt`, `part_27.bgt`, `anagrams.bgt` —
are **structurally broken**: the structurer gave up on a branch, emitted a
`goto`, and emitted the arm anyway, so `cure_all_statuses` contains
`} else {` with no `if`. Those files are 2, 10 and 1 braces short, while the
`protected` file balances at zero. The compiler cannot tell you this: it
blames a declaration hundreds of lines later with "Expected method or
property", the same thing it says for a missing keyword. `bgt recover` now
reports `unbalanced files` and `dangling else` for exactly that reason, and
Manamon 2 is also the one title whose **split does not verify**, so do not
trust its file layout either.

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
tree -- 140 functions and 25 types with 273 methods, from 413 of its 421
pages. Tutorial pages are skipped, because example code is not an API.

Three things it settles that were guesses before:

- **The documented type list is the oracle for the engine gap.** Searching a
  binary for a name is a guess; this is a list. `bgt recover` uses it, and
  falls back to the binary search only when the help file cannot be read.
- **The language has no `goto` and no `protected`.** Neither word appears
  anywhere in the help file. So a residual `goto` can never compile, however
  it is spelled -- and Manamon 2's `protected` really is a newer engine's.
- **The command-line options are documented** (Appendix G), and match what the
  installer's shell verbs do: `-c` debug, `-C` release, `-r` the registration
  manager, no space before a quoted path, and a bare `-c` opens a file dialog.

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
- **It hangs on a module this size.** Asked to build Psycho Strike's or
  Paladin's recovered source into an executable, BGT 1.3's compiler dismisses
  its dialog, holds the output file open and never completes; the partial file
  has no `xproc10` trailer, so it starts and exits without running anything.
  A small script builds fine, so the mechanism works -- the limit is the
  module. Running the script is the route that works today.

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
  it was edited -- `` eaten by a shell -- which matches nothing, so
  `return` and `goto` silently stopped terminating a block while `break;` and
  `continue;` went on working. Output stayed valid and two "Unreachable code"
  warnings per title looked like something the compiler had a right to say.
  Paladin's four are gone, and both the pass and the dialect probe now have
  tests.
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
  fourteen cases the source wrote.
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
names `weakref` and `ecdh`. (`protected` is a keyword rather than a type, so it
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

## Plugins: a type no stock engine has

Psycho Strike uses `elias`, and the installed BGT 1.3 has no such type, no
plugin directive, and no mention of either. The game's own executable has both
`elias.dll` and the registered `elias @f()`, so the build that produced it had
that plugin compiled in. `bgt recover` reports it — a DLL named after a type
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
both sides: **140 have the source's exact call sequence in evaluation order**,
3 more are within 80%, and **148 of 149 have its exact string literals**. The
lifter, measured the same way over 155 functions, gets 153 and 155 -- it is
still the better-validated path for reading one function, and this is the path
that compiles.

That check found the duplication the compiler cannot see:
`sound_pool::play_extended_1d` calls `reserve_slot()` forty-five times where
the source calls it once and keeps the result in a local. The rule that
prevents exactly this for a dereferenced temporary (`_read_temp`) deliberately
does **not** apply to a value pushed from a slot: applied there it promoted so
many slots to variables that the compile went from 93 diagnostics to 400, from
declarations landing in the wrong scope. So the duplication is known, located
and measured rather than fixed -- which is the honest state, and the number to
move next.

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

Two details that make this work rather than merely appear to:

- **The encoder must stop short of the next width's marker.** Each form of the
  encoded integer gives up one more bit to the marker above it, so reading
  `10xxxxxx` as six free bits lets a lead byte reach `0x7F` -- which decodes as
  the eight-byte form, returning an enormous value and leaving the cursor inside
  the next record. The decoder only has to mask; the encoder has to stop.
- **The instruction count is recomputed, not copied.** It counts instructions,
  not dwords, and recomputing it from the instructions actually present is what
  lets one be inserted or removed.

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

Note `string_hash(data, algorithm=2, binary)` is **SHA-512**.

Titles differ in whether they use one global key or a key per file - `tag_index()`
shows which immediately, and that decides whether one password is enough.

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

**0.88% residual gotos.** Irreducible flow, switch tails and multi-entry loops
stay labelled `goto` rather than being forced into a shape they do not have.
Some of this is genuinely irreducible; some is not yet recognised.

**No semantic checking on edits.** `bgt asm` proves the *encoding* round-trips,
not that your edit makes sense. Renaming a literal is safe; changing an
instruction's stack effect or pointing a `CALL` outside `usedFunctions` yields a
module that loads and then misbehaves.

**Crazy Party does not parse, and it is the first title that does not.** It is
the sixth, and the biggest by a wide margin: a 9.3 MB module, `tagged`
dialect, 550 classes. Everything up to the module is unaffected -- stock key
seed, stock container, the overlay decrypts and decompresses -- and so is most
of the module: 11 enums, **550 / 550 class declarations, 550 / 550 class
blocks**, 132 global properties, and **806 of its 883 module functions**, each
decoding to exactly its declared instruction count.

Then one record will not read. `void ajouteLangue()` at `0x2B3177` has a valid
`'f'` tag, name, return type, zero parameters, funcType 1, no owner and an
empty namespace -- and the four bytes where its instruction count belongs,
`70 10 65 1c`, decode to 1,074,460, which is more instructions than the rest
of the file could hold. The other 38 failures are that one desync cascading;
the resynchroniser limps to the end of the section, and the global-function
count after it is garbage, so `tail()` refuses at `0x2EB831`.

What has been ruled out, so a next pass need not redo it: it is not the byte
count (every alignment from `-8` to `+8` was tried, and each fails inside the
body or on the record after it); it is not a missing flags byte, because with
one skipped the object-variable section does not read either; and it is not a
long body misread, because no offset anywhere near the record disassembles a
clean run to a `RET` of the right length. The declaration sections being
exact to the last class block means the desync starts *in this record*.

So this is the case the conventions were written for: **read the reader**.
`asCReader::ReadFunction` is statically linked into `Crazy Party.exe`, and
the branch it takes for a funcType-1 module function in that build is the
answer. `bgt ghidra decompile "Crazy Party.exe" --string _builtin_function_`
is where that starts.

**Crazy Party generates part of its own source**, which is worth knowing
before reading its code and is the one real exception to the note above about
file names. `genereHelp` and `genereAjouteLangue` emit `.bgt` text at runtime --
the module carries literals like `// ce code est généré
automatiquement par la fonction genereAjouteLangue`, `void ajouteLangue() {`
and the file names `help.bgt` and `ajouteLangue.bgt`. Those are real names of
the game's own source files, but they are a *generator's output*, not a record
of the build, so they still do not give the compiler's file list. They do mean
a string search for `.bgt` in this title finds source rather than a sound.

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

- **Residual `goto`.** The structurer labels flow it cannot shape, and
  AngelScript has no `goto`, so every one of those lines is an error -- 50 in
  Psycho Strike, from 9 bodies of 1,102. Either the shape gets recognised or
  those bodies need a dispatch rewrite; a label is not an option.
- **A call the simulation could not supply arguments for** prints `<?>` rather
  than inventing values: 10 sites in Paladin, 1 in Psycho Strike. Marked and
  counted is the right behaviour, but it does not compile.
- **A funcdef-typed local.** `objVariableTypes` names the placeholder type
  `_builtin_function_` with no signature to identify which funcdef it is, so
  the declaration has no name source can use. 7 sites in Psycho Strike.
- **A type no stock engine registers** (Psycho Strike's `elias`): reported,
  with the DLL it comes from, and not compilable here at all.

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
