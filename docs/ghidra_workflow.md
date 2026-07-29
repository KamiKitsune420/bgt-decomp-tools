# Reading a BGT binary in Ghidra

This is for the next person who needs to extend the reader. Every format detail in
this toolkit came out of a game's own `asCReader` / `pack::create`, and the whole
point of the convention **"read the reader, don't guess the format"** is that the
exact record layout for the build in front of you is *in the binary in front of
you*. AngelScript is statically linked into every BGT game, so you never have to
infer a layout from byte patterns — and you should not, because that reliably
produces answers that are confident, plausible and wrong. (A signature model built
that way parsed at 92.5% while being wrong about three separate fields.)

---

## Just use the tool

`bgt_ghidra.py` does the setup and the driving, so most of this document is
background rather than instructions:

```bash
bgt ghidra status                  # is Ghidra + a JDK 21+ present, and where?
bgt ghidra install                 # download the latest release (asks first)
bgt ghidra install-extension <zip> # into the per-user Extensions dir

# the two ways you actually find a reader
bgt ghidra decompile game.exe --string _builtin_function_ -o readers.c
bgt ghidra decompile game.exe --at 0x0041E2A0,0x0041DE20   -o readers.c
```

Ghidra is deliberately **not** bundled — about a gigabyte unpacked, and a new
release every few months would make a vendored copy both large and stale.

Two environment notes that cost time if you hit them cold:

* **Ghidra needs a JDK 21+**, and the `java` on PATH is often an old one kept
  for something else. `status` reports the version it found and where; `--jdk`
  overrides. This machine, for instance, has Java 8 on PATH and a usable JDK 22
  at `C:\Program Files (x86)\Java\jdk-22.0.2`.
* **Extensions do not live in the install directory.** They go under the
  per-user path, which `status` prints:
  `%APPDATA%\ghidra\ghidra_<version>_PUBLIC\Extensions` on Windows,
  `~/.config/ghidra/...` on Linux, `~/Library/ghidra/...` on macOS. Dropping an
  extension into the install's own `Extensions/` folder looks right and does not
  load. And note the MCP servers are **GUI plugins** — they do nothing headless,
  where `-postScript` is the mechanism instead (which is what this tool uses).

## Getting the binary loaded

The GUI runs auto-analysis out of memory on a small machine. Run it headless with
a memory cap into its own project:

```powershell
$env:GHIDRA_HEADLESS_MAXMEM = "2G"
& "...\ghidra_12.1_PUBLIC\support\analyzeHeadless.bat" `
    "<project dir>" <project name> `
    -import "...\game.exe" -processor "x86:LE:32:default"
```

Takes a few minutes. `StackVariableAnalyzer` may still OOM and get skipped — that
degrades stack-variable recovery only; functions, xrefs, strings and the decompiler
are unaffected, and those are what matter here.

The Ghidra MCP server is a **GUI plugin**, so it only answers when the GUI has a
project open. For headless work drive it with `-postScript` GhidraScript `.java`
files parameterised through environment variables. If you do use the GUI, note
that GhidrAssistMCP works on Ghidra 12.1 where the older LaurieWired GhidraMCP
fails.

Apply RTTI if it is offered: it names `asCEnumType::vftable`, `asCTypedefType::vftable`
and friends, which lets you identify a record by the object being constructed
instead of by guessing from the fields.

---

## Finding `asCReader::ReadInner`

Two routes, both reliable:

1. **The error string.** Search for `LoadByteCode failed`. It has exactly one
   caller-side helper, and that helper is called from `ReadInner` dozens of times —
   once after every `ReadEncodedUInt` that could fail. Take xrefs to the string,
   find the small function that formats it, then take xrefs to *that*. The function
   with by far the most calls to it is `ReadInner`.

2. **The `noDebugInfo` string**, if the build carries it.

`ReadInner` is long (~2,000 lines decompiled) and almost entirely sequential, which
is what makes it readable: the section order is just the order the calls appear in.
Skim past the error-handling blocks — they are the repeated
`if ((iVar8 != 0) && (iVar8 != -1)) { ... }` pattern after each read — and write
down the remaining calls in order. That list *is* the file format.

For reference, the order in the Manamon 2 build (`FUN_00427ab0`):

```
eu(noDebugInfo)                        <- ReadEncodedUInt, not ReadData
eu(enumCount)      each: ReadTypeDeclaration(phase 1) then (phase 2)
eu(classCount)     each: ReadTypeDeclaration(phase 1) only
eu(funcdefCount)   each: ReadFunction
                   ReadTypeDeclaration(phase 2) for every INTERFACE
                   ReadTypeDeclaration(phase 2) for every non-interface
                   ReadTypeDeclaration(phase 3) for every non-interface
eu(typedefCount)   each: phase 1 then phase 2 (= eu(tokenType))
eu(globalCount)    each: ReadGlobalProperty
eu(funcCount)      each: ReadFunction          <- module functions, with bodies
eu(count)          each: ReadFunction          <- global functions
eu(count)          each: ReadFunction, ReadString   <- bind/import info
eu(count)          each: ReadTypeInfo          <- usedTypes
                   ReadUsedTypeIds
                   ReadUsedFunctions
                   ReadUsedGlobalProps
                   ReadUsedStringConstants
                   ReadUsedObjectProps         <- must end EXACTLY at EOF
```

The three-pass loop over the class list is the part that is easy to get wrong.
It is not one block per class: interfaces get phase 2 first, then everything else
gets phase 2, then everything else gets phase 3. Walking them interleaved
desynchronises on the first interface, and skipping phase 3 leaves the property
tables in the stream where they read *convincingly* as the next section.

### The helper functions worth naming immediately

Once you have `ReadInner`, rename the handful of routines it calls; everything else
follows from them. In the Manamon 2 build:

| address | function |
|---|---|
| `0x00427ab0` | `asCReader::ReadInner` |
| `0x0042acc0` | `ReadTypeDeclaration(type, phase, &isNew)` |
| `0x0042a2f0` | `ReadFunction` |
| `0x00429da0` | `ReadFunctionSignature` |
| `0x0042d340` | `ReadByteCode` |
| `0x0042c870` | `ReadTypeInfo` |
| `0x0042c640` | `ReadDataType` |
| `0x0042c430` | `ReadGlobalProperty` |
| `0x0042c550` | `ReadObjectProperty` |
| `0x0042c330` | `ReadString` |
| `0x0042c050` | `ReadEncodedUInt` — returns u64, high dword is an error code |
| `0x00427830` | `ReadData(ptr, n)` |

Addresses are per-build; the *shapes* are not. Find them by their call sites in
`ReadInner`, not by these numbers.

---

## Finding `asBCInfo[]` (the opcode table)

`as_opcodes.extract()` already does this automatically, and you should prefer it —
it recovers the table from whatever build you hand it. Do it by hand only when
that fails.

1. Search for a distinctive opcode name: `PshVPtr`, `CALLSYS`, `CALLINTF`, `SUSPEND`.
2. Cross-reference to the pointer that names it. You will land in a **16-byte
   strided** array of `{ const char *name; int bc; int type; short stackInc; }`.
3. Walk backwards to the start of the run — the first entry whose name pointer
   stops resolving to an identifier-shaped string.

Two quirks, both established by reading `asCReader::ReadByteCode` rather than
inferred, and both already handled in `as_opcodes.py`:

* **`name(op) = table[op + 1].name`** — the name field is one entry out of step.
  Without the shift, `PopPtr`, `JMP` and `RET` appear to share a type, which cannot
  be true because they take different operands.
* **`type(op) = table[op].type` and `stackInc(op) = table[op].stackInc`** — these
  are indexed *normally*, not shifted like the name.

`stackInc` is worth reading rather than deriving. A greedy search that optimised
stack residue at `RET` once adopted eight stack-effect changes and was wrong about
seven of them; the binary settled it and the metric did not.

---

## Finding the KDF

1. Search for `set_sound_decryption_key` — it is a registered script function name,
   so the string is present and referenced where the engine registers it.
2. Follow the registration to the native implementation, then into the key setup.
3. The KDF is the `__fastcall` taking ECX = input pointer, EDX = length. In the
   builds seen so far it is `FUN_00458800`.

Around it sit the other three pieces of BGT's one and only encryption arrangement,
which it reuses for the executable overlay, the asset packs and script-level
`string_encrypt` alike:

| role | note |
|---|---|
| the KDF | password -> 64 NUL-free bytes |
| key setup | `SHA256(cstring)` then `makeKey` / `cipherInit` |
| the CBC operation | mode = `(flag != 0) + 1`, so 1 = ECB, 2 = CBC |

Reading the key setup is what tells you the key is taken with **`strlen`** — which
is exactly why the KDF scrubs NULs out of its own output, and why omitting that
scrub silently collapses different passwords onto the same key.

---

## Is BGT's own `bgt.exe` worth opening?

Sometimes — but it is a smaller win than it sounds, and it is worth knowing why
before spending an afternoon on it.

`bgt.exe` (the compiler, in `Program Files (x86)\BGT`) carries the same
statically linked AngelScript as the games it builds. Checked against this
toolkit it recovers a **200-entry `asBCInfo` identical in layout to Psycho
Strike's and Paladin's**, and it contains the same era-marking strings
(`%delegate_factory`, `_builtin_function_`). So it is a **`tagged`-dialect**
build: it is the compiler that produced Psycho Strike and Paladin, and it tells
you nothing new about the newer `len2` builds like Manamon 2.

What it genuinely adds:

* **`asCWriter`** — the serialiser, which the games do not contain. It is the
  exact inverse of `asCReader` and is usually *easier* to read, because the
  writer has none of the reader's error-handling clutter and states the field
  order directly. If you are building an assembler or rewriting a module rather
  than just reading one, read the writer.
* **`include/`** — BGT's shipped standard-library sources (`dynamic_menu.bgt`,
  `sound_pool.bgt`, `form.bgt`, ...). This is the objective validation material
  the conventions call for: a lifter can be checked against source somebody else
  wrote, instead of against output that merely looks plausible.
* **`bgt.chm`** — the documented built-in API, which pins registered function
  signatures and arities.
* **`exec.bin`** — the runtime stub that gets prepended to every game. The same
  stub is already sitting uncompressed in any game executable you have, so this
  is only useful if you have BGT but no games.

What it does not add: the reader for a dialect you do not already have a game
for. All three titles here now parse end to end, so the reading side is done;
`bgt.exe` is for the writing side.

## Finding `pack::create` (the SFPv1 writer)

Search for `SFPv`. It appears in the pack writer and in the entry writer, and the
function containing it lays out the header and per-entry records in order. The
`SWCR` magic is in the payload encryptor next to it.

The one thing to read carefully there is the 16-byte field after the three size
words. It is **not an IV** — that reading costs real time. It is
`AES-256-ECB(key, 16 zero bytes)`, a key-verification tag, which is why a candidate
key can be checked in one AES block without touching ciphertext or knowing what the
plaintext should look like.

---

## How to verify a transcription

Never by inspection. Every layer here has a check that fails loudly, and a
transcription is not finished until one of them passes.

**For a record layout** — parse a real module and require the declared count to
equal the recovered count, and the section to end exactly where the next one's
count begins. `bgt validate` runs this for you:

```bash
bgt validate game.exe another.exe
```

**For the tail sections specifically** — `usedObjectProps` is last, so there is
nothing after it to absorb a mistake: it must finish **exactly at EOF**. That
single constraint transitively validates every field width upstream of it. It is
the strongest check in the whole format; if it passes, the chain is right.

**For the KDF** — derive a key from a known password and compare against a key
captured at runtime with Frida, or against a pack whose entries it should open.
`bgt_pack.key_matches()` confirms a candidate in one AES block.

**For the opcode table** — check that `type` values produce sensible operand
counts: `RET` 0, `CALL` 1, `PshV4` 1, `PshC4` 1. Then check the operands
themselves by **range analysis**: collect every operand a given opcode ever takes
and compare its maximum against each table's size. The right table *saturates* —
`CALL`'s maximum operand is 8179 against a 8,180-entry `usedFunctions`, which makes
an off-by-one impossible in both directions.

**For anything at all** — cross-validate across titles. These games share a
runtime, so a change that improves one and breaks another is wrong, and that is
easy to miss when you are working against a single binary.

---

## Two traps that do not fail loudly

Worth repeating here because both cost real time and neither raises anything:

* **The bytecode length field counts instructions, not dwords.**
* **Jump offsets count instructions, not dwords.** Reading them as dwords still
  lands on a valid instruction boundary whenever the target happens to be one dword
  wide, so a majority of jumps "resolve" while silently pointing at the wrong
  instruction. Instruction-relative took target resolution from 67.3% to 100%.

And one more found while writing `as_disasm.py`: a global-pointer operand
(`PGA`, `PshGPtr`, `LDG`, …) is not a plain index. It is `2 * index + tag`, where
tag 0 selects the string-constant table and tag 1 selects the global-property
table. Reading every one as a literal resolves the tagged minority to a real string
from the wrong table, with nothing to signal it.
