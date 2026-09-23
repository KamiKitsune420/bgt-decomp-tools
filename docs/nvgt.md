# NVGT: formats and recovery

NVGT (NonVisual Gaming Toolkit) is BGT's open-source successor. Scripts look
alike; almost nothing underneath does. This is the NVGT counterpart to the BGT
sections of `CLAUDE.md`. Every format claim below was read out of NVGT's
published source (the file is named each time), not inferred from bytes.

| | BGT | NVGT |
|---|---|---|
| locate the payload | `xproc10` trailer at EOF | end of the last PE section (Windows); u32 stub size at EOF elsewhere |
| payload | `"<n> "` + AES-256-CBC(generated key) + LZ77 | Poco 7-bit pack count, embedded packs, XOR-masked size, encrypted zlib |
| stream | the module | Poco preamble, then the module |
| AngelScript | 2.2x era, 32-bit, two string dialects | 2.37 era, 64-bit, `len2` strings, 64-bit type flags |
| asset packs | SFPv1, AES-ECB per entry, `SWCR` tag | `0xDADFADED` pack, trailing TOC, CRC32, whole-file XChaCha20 |
| debug info | always stripped | kept in debug builds (names, lines, sections) |

---

## The executable (src/nvgt_angelscript.cpp `LoadCompiledExecutable`, src/pack.cpp)

```
[stub]
7-bit            embedded pack count                  load_embedded_packs
per pack:        7-bit length + name                  a Poco std::string
                 u32 LE size
                 size bytes                           a complete NVGT pack
7-bit            payload size XOR NVGT_BYTECODE_NUMBER_XOR
payload          encrypted, see profiles
```

The pack name is a **Poco string**, not a u32-prefixed one. The recovery code
this was merged from read it as a u32, which consumed the name's own bytes as a
length (`sounds.dat` became a length of 1,970,238,218) and lost every
executable that embeds a pack. `extract.read_embedded_packs()` is now the single
walk of this block, and `tests/test_integration.py` pins it.

## The decrypted stream (`SaveCompiledScript`)

```
u16      plugin count, then Poco strings
i32      system-namespace count, then (name, namespace) Poco string pairs
41 x     7-bit engine properties (asEP_LAST_PROPERTY)
i64      build timestamp
u8       app.no_auto_chdir
...      asCWriter module stream
```

## Packaging profiles

The payload's encryption is not fixed. It comes from `nvgt_config.h`, which a
custom build may rewrite and which NVGT's release CI **regenerates with fresh
random parameters for every official build**. So a version string says nothing
about how a payload is protected, and each profile has to be verified against
real samples before it is supported:

| profile | verified against |
|---|---|
| repository default (`nvgt_config.h` as published) | NVGT source; round-trip tests |
| official release of 2026-08-30 | that release's stub |
| pre-versioned fixed-size profile (`legacy_fixed_size_a5b4`) | one shipped game's loader |
| one executable-bound XChaCha20 / AES / HMAC custom profile | one custom build |

An executable from any other build fails with `Cannot identify NVGT payload
size/profile` or `Unsupported or corrupt NVGT payload`. It never produces a
guessed project. That includes the release installed on the machine this merge
was tested on (0.90.0-dev, 2026-09-15), whose profile is not among the verified
ones. Bytecode you already hold, such as a module your own script exported
with `script_get_module(...).get_bytecode()`, decompiles whatever build made it.
Recovery was checked that way against that release: the result compiled with
its `nvgt.exe`.

Embedded packs sit outside the payload, so `bgt nvgt extract --packs` and
`bgt nvgt pack` read them whatever the payload's profile.

## NVGT packs (src/pack.cpp, src/crypto.cpp)

```
header   64 bytes: u32 0xDADFADED, u64 toc_offset, u32 CRC32(TOC), zeros
data     entries back to back, in insertion order
TOC      toc_offset .. EOF: 7-bit name length, name (UTF-8, no controls),
         7-bit size -- offsets are never stored, only rebuilt
```

The reader demands that the TOC walk ends exactly on EOF, that the CRC matches
and that the sizes sum exactly to `toc_offset`. `nvgt_pack.parse` does the same,
so a wrong field width fails rather than producing a plausible table. NVGT's
own reader also rejects a pack with no entries, and so does this one.

With a key, the whole file is `nonce[24] || XChaCha20(BLAKE2b-256(key), nonce)(
0xACEFADED || pack)`. Monocypher's `crypto_chacha20_x` (DJB counter layout)
matches pycryptodome's IETF XChaCha20 for any stream under 256 GiB, because the
high counter word stays zero. The 4-byte magic is only a 32-bit key check, so
the CRC and the landing checks behind it are what settle a key.

`nvgt_pack.build()` reproduces packs written by NVGT 0.90.0-dev **byte for byte**,
plain and encrypted (given the same nonce). That was checked against packs
created by the real `pack_file` API.

## The module reader and decompiler

`asreader` ports `asCReader` for AngelScript 2.37 (64-bit flags, enum underlying
types, template functions, try/catch), with a legacy mode for 32-bit flags and
the older token numbering. The legacy renumbering (`+1` at >= 36, `+1` at >= 64)
maps BGT's token ids onto the current ones. BGT's `?` (59) becomes NVGT's 60,
which is how the two halves' `?&in` rules line up.

`decompile` simulates each body's stack and registers, and structures loops,
`switch`, `try`/`catch`, ternaries and short-circuit logic. A self-assignment
`x = (x + y)` is written `x += y` (and `x = (x + 1)` as `x++`), for a simple
lvalue with no call in it so nothing is evaluated twice. A counted `while` whose
last statement increments the variable its condition tests is then folded back
into a `for` -- `for (i = 0; (i < n); i++)` rather than an `i = 0;` and a
`while` -- but only where that is behaviour-preserving: a loop containing
`continue` is left as a `while`, because `continue` skips the increment in a
`while` and runs it in a `for`. `recover` wraps it into a project, and
`source_evidence.json` separates what the bytecode retained from what was
synthesised.

Both toolkits decode AngelScript's encoded integers independently, from
different builds of `asCReader`. `tests/test_integration.py` requires them to
agree on every width, including the sign flag.

### Checked against NVGT's own library

NVGT ships its standard library as source, so it is the one body of code whose
original is known and which nobody here wrote. `bgt nvgt libcheck` builds a
corpus from it: for every `include/*.nvgt`, a harness has nvgt.exe export the
module twice (`get_bytecode(false)`, with debug information, and
`get_bytecode(true)`, stripped the way a release ships). Each is decompiled
into a project, and the project has to compile with the same nvgt.exe.

```
bgt nvgt libcheck                  # ~3 minutes; nvgt.exe from NVGT_COMPILER or C:\nvgt
50 / 50 library modules recompile after decompilation
  debug  25 / 25
  strip  25 / 25
  decompiler errors 0, unhandled opcodes 0, gotos 0
  not scored (include does not compile as shipped): db_props, int_to_byte, legacy_sound_pool, logger
```

The decompiler started this work at **21 / 50**. The four unscored includes don't
build as shipped against 0.90.0-dev: the missing `sqlite3` and `pack` types, and
`string_reverse` / `string_trim_left`. They are named in the report rather than
counted against the decompiler.

Compiling proves valid AngelScript, not the same meaning. Three of the bugs
below compiled cleanly and computed something else, so
`tests/nvgt/test_roundtrip_behavior.py` goes a step further. It **runs** a
decompiled program and compares its result with the original's. Its fixtures,
`fixtures/decompiler_patterns.nvgt` and `fixtures/control_flow_patterns.nvgt`,
hold one instance of each construct -- inheritance, handles and out-arguments in
the first; loops, `switch`, bitwise arithmetic (`>>` vs `>>>`), arrays,
dictionaries and argument order in the second. Each is run in both its debug and
its stripped build and must produce the original's value. Undoing any one of the
three fixes below fails the first fixture.

### Three constructs still decompiled wrong

Writing the second fixture surfaced three bugs, each of the "compiles and lies"
kind, so the fixture is written to avoid them and they are recorded here for a
fix rather than shipped in a failing test. Each has a one-line repro.

- **A ternary inside a larger expression** (*fixed*). `return c ? 3 : 7;` was
  correct, but `return 10 + (c ? 3 : 7);` decompiled to an empty `if (c) {} else
  {}` and `return (10 + 7);` -- the branch collapsed to its false arm. The
  value-merge fired only when the merged value was consumed by a push or a
  return, not when the diamond's slot is read straight into an arithmetic
  operand (`ADDi slot = 10 + <ternary slot>`). It now derives that slot from the
  arms (the one slot both wrote) whenever the merge is an arithmetic or
  comparison op, and the op reads the folded ternary. `fixtures/ternary_
  expression.nvgt` guards it. (Restricted to arithmetic/comparison merges on
  purpose: a diamond producing a handle or a short-circuit bool is an ordinary
  branch, and folding those as a value ternary put a `bool` where a handle or
  double was wanted -- it briefly cut the corpus to 35/52 before the guard.)
- **A stored short-circuit result** (*fixed*). `bool b = (x > 0) && (x < 10);
  return b ? 100 : 200;` decompiled to an empty `if (x <= 0) {}` and `return ((x
  < 10) ? 100 : 200);` -- the first operand lost, only the second surviving. The
  `&&`/`||` value was recovered (`_begin_bool_merge`) only where the merge loads
  the result straight into the value register (`CpyVtoR4`), a return or a
  condition. When it is stored into a slot (`CpyVtoV4` into `b`) and read later,
  it was not. The merge now folds `(A op B)` into the stored slot at that
  `CpyVtoV4`, so every later read -- in an `if`, a ternary or an expression,
  however far away -- sees the whole value; the `CpyVtoR4` and `CpyVtoV4`
  handlers share one consumption path. Restricted to a **bool** destination:
  the same shape storing a uint is a ternary over values (`_begin_value_merge`
  handles it), and folding it as `A op uint` gave "No conversion from 'uint' to
  'bool'" and cut the corpus to 28/52 before the guard. With it the corpus is
  52/52, and `bool b = A && B` used in a ternary, an `if` and an expression all
  round-trip. `fixtures/short_circuit.nvgt` guards it.
- **A loop variable reused in sibling scopes** (*fixed*). `for (int i ...) {}
  for (uint i ...) {}` is legal -- two scopes -- and the compiler reuses each
  counter's slot for a later local (`i` then `total`, `i` then `v`). The
  hoisting that emits one declaration per scalar name read the names from the
  post-run frame, which keeps only a slot's *last* name, so a transient `i` was
  never hoisted and its two typed declarations landed at one scope: "`i` is
  already declared". Hoisting now takes the scalar names from every debug
  variable, not just the survivors. `fixtures/reused_loop_variable.nvgt` guards
  it: its debug build must recompile and declare the counter once.

All three found with the control-flow fixture are now fixed. Two narrower,
pre-existing cousins surfaced while testing them and stay open (they are value
recovery, not reading -- the bytecode is understood, the shape around it is
wrong):

- **A `? :` over the constants 0 and 1, added inside an expression.** `(x > 0 ?
  1 : 0) + (x > 5 ? 1 : 0) * 10` decompiles with the first term as an empty
  `if` and `0 +` in its place. The `0/1` arms make `_begin_bool_merge` claim it
  before `_begin_value_merge` can, but the merge is an `ADDi`, not a register
  load, so it produces nothing. (`(x > 5 ? 1 : 0) * 10`, whose merge is `MULi`,
  is fine.)
- **A guarded increment in a stripped build.** `if (f()) total += 10;`
  sometimes decompiles with the `total += 10` hoisted out of the `if` and run
  unconditionally. The guard's diamond is mis-structured when the body is a
  single compound assignment.

What had to change, grouped by what it broke:

**Classes and inheritance.**
- A derived class's vftable lists the inherited methods it does not override.
  Methods are now paired with their bodies by signature, not by name alone
  (name, parameter types, in/out flags, `const`). Inherited methods are not
  re-emitted, since a re-emitted copy is a redefinition.
- Inherited properties are written `this.x`. A private inherited member is
  reachable that way and not by its bare name (checked against nvgt.exe).
- A call to the base-class constructor is `super(...)`.
- Constructors of namespaced classes use the qualified name (`spec::path`).
- A `const` method calling a non-const method on `this` uses the bare name.
  Through `this.` it is "No matching signatures" (touch.nvgt's
  `get_available() const`).

**Handles.**
- **`@h.item = b` was dropped.** `REFCPY` through a member address had no case.
  It now emits the assignment, but only for members *declared* as handles. A
  by-value member of a reference type (`mixer music_mixer;`) is REFCPY'd too,
  by the constructor's generated initialisation, which the source never wrote.
- **`?&in` arguments keep their `@`.** The hidden TYPEID says what the source
  passed. A handle type id means `d.set("k", @b)`. Written as `d.set("k", b)`,
  it stores a *copy*, and later changes through `b` no longer show.
- Reassigning a handle variable is `@x = y`. Without the `@` it is a value
  copy into the object, which most types refuse.
- `CmpPtr` conditions read `is` / `!is`.
- `cast<T@>` recognises the compiler's null-safe cast sequence. `SwapPtr` is
  modelled.
- A `?&out` receiving a reference type declares `T@ tmp` and passes `@tmp`.
  Declared by value, it needs a default constructor the type may not have.

**Evaluation order.**
- **An out argument is read after the call that writes it.** A call whose value
  feeds a later condition is deferred into that condition, but its out argument
  is copied into place straight after the call. In
  `if (!d.get("k", @fetched))` that copy printed *before* the call. The call is
  now declared into a `__nvgt_ret_N` local as soon as a statement reads its
  output.
- Assignment operators leave their receiver in the value register, and
  by-value results are bound to their slots.

**Types.**
- An integer constant meeting a by-value enum or application type is written
  `Type(value)`.
- Ternary arms are normalised to the target type.
- `opConv` renders as `target(obj)`. Called by name, it is ambiguous when a
  type converts to several things.
- Enums keep `shared` / `external`.
- **Slots shared between `bool` and a number.** In a stripped build one frame
  slot can hold `bool inside` in one scope and `float d` in another. Nothing
  says where the switch happens. The slot takes the numeric type (int, uint,
  double, then float). A bool is stored as `(b ? 1 : 0)` and tested as
  `x != 0`. This last fix covered `float` and `double` too, which took
  touch.nvgt's stripped build (`bool in_bounds` / `float dist_sq_start`) from
  failing to passing.
- In debug builds a variable is redeclared at each `declared_at` its
  information records. Hoisted declarations are deduplicated by name, with
  `const` stripped.

**Conditions.** Negation works on the whole expression, splitting at depth-0
comparisons and flipping the operator (including `is`/`!is`), instead of
prefixing `!` to text that may not be one term.

---

### File names in stripped builds

A release build strips the script sections, and with them every file name.
`recover` then names include files after the classes they hold. `bgt files
game.exe` recovers what is left: which shipped `include/*.nvgt` files the game
used, by name, and where its own code splits between them. Scored against debug
builds of the library corpus, it gets 439 / 439 declarations right (see "Source
file names" in `CLAUDE.md`).

## Changes in the merged toolkit

Relative to nvgt-source-recovery at `eaa176b`:

- **Embedded packs:** names are Poco strings (see above). Fixed in
  `get_payload`, `package_owned_module` and the new `read_embedded_packs()`;
  `embedded_packs()` and `extract --packs` expose them.
- **New `nvgt_pack`:** NVGT's asset packs, plain and encrypted, read and write,
  CLI `bgt nvgt pack list|extract|create`, including packs inside an
  executable (`--embedded`).
- **Arithmetic right shift:** `BSRA`/`BSRA64` render as `>>>`. AngelScript's
  `>>` is the *logical* shift (NVGT evaluates `-8 >> 1` to 2147483644 and
  `-8 >>> 1` to -4), so rendering `BSRA` as `>>` changed the meaning of every
  negative shift.
- Package layout: modules live in `bgtdecomp.nvgt`, use the repository's
  "relative import, else flat" convention, and still run as scripts.
  `keyscan` and `native_probe` gained `main()`, `gen_opcodes` writes beside
  itself, and `refine_source_archive` moved into the package, where its tests
  import it.
- Tests run under the shared pytest suite. Fixtures moved to
  `tests/nvgt/fixtures/`, and the `bcdump` host builds into
  `tests/nvgt/fixtures/build/`.

## Usage

```bash
bgt identify game.exe
bgt nvgt recover game.exe -o game-source.zip [--check-with nvgt.exe]
bgt nvgt decompile game.exe -o game.nvgt
bgt nvgt disasm game.exe -o game.asm
bgt nvgt extract game.exe game.bin --packs packs/
bgt nvgt inspect game.exe --output report.json
bgt nvgt pack list packs/sounds.dat --key "..."
bgt nvgt library game.exe --compiler nvgt.exe --include-root include [--auto]
```

Recovery never runs the target. `--check-with`, `library` and `probe` run the
NVGT *compiler* or an owned harness in a disposable folder, and say so in their
reports.

### Reusing the standard library, detected automatically

`bgt nvgt library` replaces a shipped library file the game was built with by an
`#include`, once it has confirmed **every one of that file's declarations by
exact bytecode** against a freshly compiled reference (a name match is never
enough; a changed copy is rejected). `--include` used to be mandatory. With no
`--include` it now auto-detects them with the same logic as `bgt files`, so

```bash
bgt nvgt library game.exe --compiler C:/nvgt/nvgt.exe --include-root C:/nvgt/include \
    --build-dir work/build --output work/recovered.nvgt --reference-mode runtime
```

finds which library files a stripped module used, confirms them, and emits
`#include` lines for the ones that verify. On the installed 0.90.0-dev, whose
payload profile is unverified, use `--reference-mode runtime` (the reference is
exported with `get_bytecode`, sidestepping the payload format).

**A false negative that hid for a while.** The exact-bytecode comparison
resolves operands to names so that two builds of the same source match despite
different function/type tables. Five opcodes were missed: `LoadThisR`,
`LoadRObjR`, `LoadVObjR`, `ADDSi` and `ADDProp` carry the accessed property's
type as a `usedTypeIds` index in `dw_arg`, and `RefCpyV` carries the assigned
handle's type as a `usedTypes` index in `qw_arg`. Left raw, those indices differ
between any two independent builds, so **every class with a `this`-property load,
a member access or a handle assignment was rejected** -- almost all of them.
`asreader` now resolves each to its type (the decompiler reads none of these
fields, so its output is unchanged and the corpus still recompiles 52/52), and
the comparison normalizes them. A form-including module now reuses `form.nvgt`
and recompiles to identical behaviour.
