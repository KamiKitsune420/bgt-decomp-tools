# BGT Games — Decompilation Toolkit

General-purpose tooling for recovering code and assets from games built with **BGT
(BlastBay Gaming Toolkit)**, the 2010 audio-game engine by BlastBay Studios.

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
| `bgt_repack.py` | the chain in reverse — rebuild an executable around a modified module |
| `bgt_crack.py` | harvest candidate passwords from a module and test them against a pack |
| `bgt_validate.py` | run the whole pipeline over several titles and compare, stage by stage |
| `bgt_ghidra.py` | find/install Ghidra + a JDK, install extensions, drive headless decompiles |
| `bgt_kdf.py` | BGT's password → AES-key derivation for encrypted asset packs |
| `bgt_string_crypt.py` | BGT's `string_encrypt` / `string_decrypt`, and the shared key setup |

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
python tests/test_toolkit.py        # or: python -m pytest tests/ -q
```

124 known-answer tests on **synthetic inputs only** — no game files — so they run
anywhere. They deliberately target the things that fail *quietly* rather than loudly:
the encoded-integer boundary at 64, negative lengths rewinding the cursor, overlapping
LZ77 matches, the keygen constant, a pack walk that does not land on EOF, the SWCR
tag rejecting a wrong key, a tail that does not land on EOF, the low-bit table
selector in a global-pointer operand, jump targets counted in instructions, and a
resynchroniser that must refuse rather than run to EOF.

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
| `usedObjectProps` entry | `typeinfo` + property **name** | `typeinfo` + **index** |
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
all three titles this resolves **every operand** — 226,626/226,626 on Manamon 2,
52,889/52,889 on Psycho Strike, 55,338/55,338 on Paladin — with every jump target
landing on an instruction boundary and every `LoadThisR` property belonging to its
enclosing class. Psycho Strike's 6,612 jump targets and 2,352 `LoadThisR` sites
match an independent parser's counts exactly.

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
machine. **Zero passthrough across all 853,190 instructions in the three titles** —
every opcode is modelled — and 153 of 166 methods in BGT's own shipped library
sources come back by name.

```
void <global>::prepare_audio()
{
    ret = get_SCRIPT_COMPILED();
    if (!get_SCRIPT_COMPILED()) goto L0;
    v2 = string("\0\0able to\0\0learn\0...");
    ret = get(&v2);
    ret = set_sound_decryption_key(v3, &v2);
    v2 = string("data.dat");
    ret = set_sound_storage(v3);
L0:
}
```

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

| title | functions ending clean |
|---|---|
| Psycho Strike | 1,080 / 1,102 (98.0%) |
| Paladin of the Sky | 919 / 926 (99.2%) |
| Manamon 2 | 9,510 / 9,924 (95.8%) |

A **`?&in` parameter (token 59)** takes two stack slots for one declared
parameter -- AngelScript's variable-argument type passes the value *and* its type
id. Three functions in this corpus take one; the rule is mechanical and worth 82
balanced bodies.

The one rule here that is **inferred rather than read** is the hidden type id a
template-registered function receives. `TranslateFunction` was checked and does
not settle it -- it gives `TYPEID`'s operand a meaning but says nothing about the
stack, because that is a runtime calling convention rather than a load-time
fixup. Supporting it: `TYPEID` is **51x enriched** in bodies that do not balance,
and removing the rule costs 0.67 points of clean-stack functions and 168 stranded
values while moving the over-pop counter by one. Settling it means reading the
VM's `CallSystemFunction` path.

Residue never corrupts output — it sits *below* the popped arity — but it is the
honest measure of what is still approximate.

**Structuring is real structural analysis**, not pattern-spotting: a CFG,
iterative dominators and post-dominators, natural loops from back edges, then
nested `if` / `else` / `while` / `do-while` with `break` and `continue`.
Residual gotos are **2,676 of 264,309 statements (1.01%)**, and 84-95% of
function bodies come out entirely goto-free.

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

**The hidden type id a template-registered function receives.** The one rule in
`as_lift` that is inferred rather than read. `asCReader::TranslateFunction` was
checked and does not settle it -- it gives `TYPEID`'s operand a meaning but says
nothing about the stack, because that is a runtime calling convention rather than
a load-time fixup. Settling it means reading the VM's `CallSystemFunction` path.
See "Lifting" for the evidence that supports it and the A/B that keeps it.

**~4% of Manamon 2 bodies do not balance their stack** (9,510 / 9,924 clean;
strike 98.0%, paladin 99.2%). Most are off by exactly one value. Residue never
corrupts output -- it sits below the popped arity -- but it is the honest measure
of what is approximate. The template rule above is the largest known contributor.

**1.01% residual gotos.** Irreducible flow, switch tails and multi-entry loops
stay labelled `goto` rather than being forced into a shape they do not have.
Some of this is genuinely irreducible; some is not yet recognised.

**No semantic checking on edits.** `bgt asm` proves the *encoding* round-trips,
not that your edit makes sense. Renaming a literal is safe; changing an
instruction's stack effect or pointing a `CALL` outside `usedFunctions` yields a
module that loads and then misbehaves.

**A fourth title may differ again.** Three builds already produced two answers
for the template-namespace field and two for the script-object flag. Run
`bgt validate` before assuming a new title matches either.

# Conventions

- **Read the reader, don't guess the format.** Every format detail here came out of a
  game's own `asCReader` / `pack::create` in Ghidra.
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
