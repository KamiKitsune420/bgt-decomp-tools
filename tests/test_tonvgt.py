"""Known-answer tests for `bgt tonvgt`.

The converter's own judge is NVGT's compiler, which is a console program and
so can be asked on every run -- the thing the BGT side cannot do. These tests
cover the parts that decide WHAT is handed to it, and they need no NVGT: the
extractor that reads NVGT's registrations, the type lookup that makes a rename
safe, and the two reports that are deliberately not rewrites.

Every rename in this tool was put to NVGT's compiler before being believed:

    string[] a;  a.length()      compiles
                 a.get_length()  "No matching symbol 'get_length'"
    sound s;     s.get_length()  compiles -- `uint64 get_length() property`

which is why the rename is type-guarded and not global.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "tools"))

import bgt_to_nvgt                                           # noqa: E402


class EngineNameTests(unittest.TestCase):
    """NVGT wraps every registered string in its own `_O(...)` macro.

    The first version demanded the type and the declaration be adjacent --
    `",\\s*"` -- and NVGT writes

        RegisterObjectMethod(_O("timer"), _O("void restart()"), ...)

    so it matched none of them, and `timer::restart` was reported as a name
    NVGT does not have. Every quoted string in the call is read instead,
    which cannot care how they are wrapped.
    """

    def _src(self, text):
        import tempfile
        folder = tempfile.mkdtemp()
        with open(os.path.join(folder, "x.cpp"), "w", encoding="utf-8") as fh:
            fh.write(text)
        return folder

    def test_a_wrapped_method_registration_is_read(self):
        found = bgt_to_nvgt.engine_names(self._src(
            'engine->RegisterObjectMethod(_O("timer"), _O("void restart()"),'
            ' asMETHOD(timer, restart), asCALL_THISCALL);\n'))
        self.assertIn("restart", found)

    def test_a_property_registration_is_read_by_its_last_word(self):
        found = bgt_to_nvgt.engine_names(self._src(
            'engine->RegisterObjectProperty(_O("network_event"),'
            ' _O("const uint64 peer_id"), asOFFSET(network_event, peer_id));\n'))
        self.assertIn("peer_id", found)

    def test_a_global_function_is_read(self):
        found = bgt_to_nvgt.engine_names(self._src(
            'engine->RegisterGlobalFunction(_O("void nanosleep(uint64 ns)"),'
            ' asFUNCTION(SDL_DelayNS), asCALL_CDECL);\n'))
        self.assertIn("nanosleep", found)


class ReceiverKindTests(unittest.TestCase):
    """What a declared type IS, for naming a method on it.

    A handle to a thing takes the thing's methods, so the markers come off
    first -- and `string[]@` ends in `@`, not in `]`, which is why the first
    version declined every handle-to-array in the corpus and left Battle of
    the Hunter at three errors instead of none.
    """

    def test_a_handle_to_an_array_is_an_array(self):
        for kind in ("string[]", "string[]@", "weapon@[]", "animals@[]"):
            self.assertEqual(bgt_to_nvgt._receiver_kind(kind), "array", kind)

    def test_a_string_is_a_string_however_it_is_qualified(self):
        for kind in ("string", "const string", "const string&", "string@"):
            self.assertEqual(bgt_to_nvgt._receiver_kind(kind), "string", kind)

    def test_lstrip_is_not_how_a_prefix_comes_off(self):
        """`lstrip("const")` strips those five CHARACTERS, not the word.

        It turned `string[]@` into `ring[]@`, which matched nothing -- the
        same trap in a different costume each time it is met.
        """
        self.assertEqual("string[]@".lstrip("const"), "ring[]@")
        self.assertEqual(bgt_to_nvgt._receiver_kind("string[]@"), "array")

    def test_another_type_keeps_its_own_name(self):
        self.assertEqual(bgt_to_nvgt._receiver_kind("sound@"), "sound")
        self.assertEqual(bgt_to_nvgt._receiver_kind("network_event@"),
                         "network_event")


class NearestDeclarationTests(unittest.TestCase):
    """A recovered local's type is the nearest declaration above its use.

    `local_16` is the name of a different thing in every body that has one,
    so a project-wide map drops it for disagreeing with itself -- correctly.
    What a reader does is look up, and the hoisting in these files makes that
    exact: every local is declared at the top of its own function.
    """

    TEXT = ("void a() {\n"
            "    sound local_16;\n"
            "    local_16.load(\"x.ogg\");\n"
            "}\n"
            "void b() {\n"
            "    string[]@ local_16;\n"
            "    if (local_16.get_length() > 1) { }\n"
            "}\n")

    def test_each_use_gets_its_own_function_s_declaration(self):
        text = self.TEXT
        first = text.index("local_16.load")
        second = text.index("local_16.get_length")
        self.assertEqual(bgt_to_nvgt.nearest_type(text, "local_16", first),
                         "sound")
        self.assertEqual(bgt_to_nvgt.nearest_type(text, "local_16", second),
                         "string[]@")

    def test_the_rename_follows_the_nearest_declaration(self):
        out, notes = bgt_to_nvgt.apply_typed_renames(self.TEXT, {})
        self.assertIn("local_16.length()", out)
        self.assertNotIn("get_length", out)
        self.assertTrue(any("get_length -> length" in n for n in notes), notes)

    def test_a_sound_keeps_get_length(self):
        """NVGT registers `uint64 get_length() property` on `sound`, so the
        blanket rename would have broken every one."""
        text = "void a() {\n    sound s;\n    int n = s.get_length();\n}\n"
        out, _notes = bgt_to_nvgt.apply_typed_renames(text, {})
        self.assertIn("s.get_length()", out)


class DeclaredTypeTests(unittest.TestCase):
    def test_a_name_declared_two_ways_is_dropped(self):
        """Renaming on a disagreement is how a correct `sound.get_length()`
        becomes a broken `sound.length()`."""
        scripts = [("a.nvgt", "sound thing;\n"),
                   ("b.nvgt", "string[] thing;\n")]
        self.assertNotIn("thing", bgt_to_nvgt.declared_types(scripts))

    def test_a_name_declared_one_way_is_kept(self):
        scripts = [("a.nvgt", "string[] names;\n"),
                   ("b.nvgt", "void f() { names.length(); }\n")]
        self.assertEqual(bgt_to_nvgt.declared_types(scripts).get("names"),
                         "string[]")


class ConvertTextTests(unittest.TestCase):
    def test_every_include_is_repointed(self):
        text = '#include "includes/types.bgt"\n#include "other.bgt"\n'
        out, _notes = bgt_to_nvgt.convert_text(text, {})
        self.assertIn('#include "includes/types.nvgt"', out)
        self.assertIn('#include "other.nvgt"', out)
        self.assertNotIn(".bgt", out)

    def test_a_rename_applies_only_where_the_name_is_CALLED(self):
        """A local or member that happens to share the spelling is left."""
        text = ("void f() {\n"
                "    int load_from_memory = 3;\n"
                "    s.load_from_memory(data);\n"
                "}\n")
        out, notes = bgt_to_nvgt.convert_text(
            text, {"load_from_memory": "load_memory"})
        self.assertIn("int load_from_memory = 3;", out)
        self.assertIn("s.load_memory(data)", out)
        self.assertEqual(notes, ["load_from_memory -> load_memory (1 call)"])


class AccessorToPropertyTests(unittest.TestCase):
    """NVGT registers `network_event`'s members with
    `RegisterObjectProperty`, so the brackets come off as well as the prefix.
    """

    def test_a_registered_property_loses_its_call_brackets(self):
        text = ("void f() {\n"
                "    network_event@ e;\n"
                "    if (e.get_type() == 1) { dis(e.get_message()); }\n"
                "}\n")
        out, notes = bgt_to_nvgt.apply_typed_renames(text, {})
        self.assertIn("e.type ==", out)
        self.assertIn("dis(e.message)", out)
        self.assertTrue(any("property" in n for n in notes), notes)

    def test_an_unknown_receiver_is_left_alone(self):
        text = "void f() {\n    if (thing.get_type() == 1) { }\n}\n"
        out, _notes = bgt_to_nvgt.apply_typed_renames(text, {})
        self.assertIn("thing.get_type()", out)


class CallDetectionTests(unittest.TestCase):
    def test_a_declaration_is_not_a_call(self):
        names = [n for _line, n in
                 bgt_to_nvgt.calls_in("string serialize(dictionary@ d) { }\n")]
        self.assertNotIn("serialize", names)

    def test_a_method_call_is_a_call(self):
        names = [n for _line, n in
                 bgt_to_nvgt.calls_in("void f() { a.restart(); }\n")]
        self.assertIn("restart", names)

    def test_a_url_in_a_string_does_not_eat_the_file(self):
        """Comments and literals are blanked in ONE pass, because each can
        contain the other's opener -- `bgt_apicheck` records paying for this
        with a one-argument call reported as taking ten."""
        text = ('void f() {\n'
                '    url_get("http://host/x.txt");\n'
                '    key_pressed(KEY_UP);\n'
                '}\n')
        names = [n for _line, n in bgt_to_nvgt.calls_in(text)]
        self.assertIn("url_get", names)
        self.assertIn("key_pressed", names)


class SemanticDifferenceTests(unittest.TestCase):
    """A difference in MEANING is reported, never rewritten.

    `library::call` returns `var@` in NVGT and `dictionary@` in BGT;
    `downloader`'s progress is a `float` where BGT's is used as a truth
    value. Written straight across, the second compiles and polls forever,
    which is the outcome this repository treats as the worst available.
    """

    def test_both_are_named_with_what_differs(self):
        for name in ("call", "request",
                     "generate_computer_id", "string_compress",
                     "string_decompress", "serialize", "deserialize"):
            self.assertIn(name, bgt_to_nvgt.SEMANTIC)
            self.assertTrue(len(bgt_to_nvgt.SEMANTIC[name]) > 40)

    def test_the_save_path_differences_are_all_reported(self):
        """A recovered title's save path is `serialize` into `string_compress`
        into `string_encrypt`, and `bgt_compat.nvgt` shims the first two with
        a different format each. Both are the quiet kind: the port compiles,
        runs, and cannot read what the original wrote -- so each has to be
        reported with its sites rather than rewritten."""
        for name in ("serialize", "deserialize", "string_compress",
                     "string_decompress", "generate_computer_id"):
            why = bgt_to_nvgt.SEMANTIC[name]
            self.assertIn("BGT", why)

    def test_an_nvgt_that_answers_exactly_is_asked_rather_than_assumed(self):
        """A fork can carry BGT's own compression, dictionary format and
        computer id, and then the difference is resolved there while it is
        still real of every other build. So the question is put to the
        `bgt_compat.nvgt` in hand, and a build that routes the shim to the
        exact implementation is reported as answering rather than differing --
        which stops a person being sent to fix what is already fixed."""
        import tempfile

        scratch = tempfile.mkdtemp(prefix="tonvgt_shims_")
        include = os.path.join(scratch, "include")
        os.makedirs(include)
        compat = os.path.join(include, "bgt_compat.nvgt")

        with open(compat, "w") as handle:
            handle.write("string string_compress(string s) "
                         "{ return string_deflate(s, 9); }\n")
        nvgt = bgt_to_nvgt.Nvgt(os.path.join(scratch, "nvgt.exe"), include, None)
        self.assertEqual(bgt_to_nvgt.exact_shims(nvgt), set())

        #: Every symbol any entry asks for, so the set comes back whole --
        #: written from the table rather than listed, because a hand-written
        #: list goes stale the moment a sixth format is read.
        with open(compat, "w") as handle:
            for symbols in bgt_to_nvgt.EXACT_SHIMS.values():
                for symbol in symbols:
                    handle.write("// routes to %s\n" % symbol)
        self.assertEqual(bgt_to_nvgt.exact_shims(nvgt),
                         set(bgt_to_nvgt.EXACT_SHIMS))

    def test_with_no_nvgt_nothing_is_claimed_as_answered(self):
        """The stricter direction: an absent or unreadable compiler means the
        difference is reported, not quietly suppressed."""
        self.assertEqual(bgt_to_nvgt.exact_shims(None), set())

    def test_every_exact_shim_is_a_semantic_difference(self):
        """Otherwise the suppression would be keyed on a name nothing reports."""
        for name in bgt_to_nvgt.EXACT_SHIMS:
            self.assertIn(name, bgt_to_nvgt.SEMANTIC)

    def test_get_progress_moved_out_of_here_and_into_a_typed_rename(self):
        """It was listed as a difference in MEANING and it is a RENAME.

            BGT   bool  http::get_progress() const
            NVGT  float http::get_progress() property
            NVGT  bool  http::get_running()  property

        BGT's answers "is it still going?", which is what the loop using it
        says; NVGT spells that `running` and keeps `progress` for the
        fraction. Both are on a type called `http` in both engines, so the
        receiver guard has something to match and nothing else has to move.
        """
        self.assertNotIn("get_progress", bgt_to_nvgt.SEMANTIC)
        self.assertIn("get_progress", bgt_to_nvgt.TYPED_RENAMES)
        spelling, kinds = bgt_to_nvgt.TYPED_RENAMES["get_progress"]
        self.assertEqual(spelling, "get_running")
        self.assertIn("http", kinds)

    def test_a_typed_semantic_note_is_not_reported_for_another_type(self):
        """`SEMANTIC` is keyed by the bare call name, so a note about one type
        fired on every type sharing a method name: Super Egg Hunt reads a
        download in chunks with `h.request()` on an `http` and got the note
        for `network::request`. A report that cannot be acted on is worse than
        no report, because the next one is read with less attention.

        A receiver whose type cannot be read still reports, which is the safe
        direction -- this narrows a false alarm, it does not hide a
        difference.
        """
        for name, kinds in bgt_to_nvgt.SEMANTIC_TYPES.items():
            self.assertIn(name, bgt_to_nvgt.SEMANTIC)
            self.assertTrue(kinds)

        scrubbed = bgt_to_nvgt._scrub("    h.request();")
        self.assertEqual(
            bgt_to_nvgt._semantic_receiver(scrubbed, {"h": "http"},
                                           "request", 1), "http")
        self.assertEqual(
            bgt_to_nvgt._semantic_receiver(scrubbed, {}, "request", 1), None)

    def test_none_of_them_is_also_a_rename(self):
        """A name cannot be both rewritten and left to a person."""
        for name in bgt_to_nvgt.SEMANTIC:
            self.assertNotIn(name, bgt_to_nvgt.RENAMES)
            self.assertNotIn(name, bgt_to_nvgt.TYPED_RENAMES)
            self.assertNotIn(name, bgt_to_nvgt.PROPERTY_RENAMES)


if __name__ == "__main__":
    unittest.main()


class ScrubLengthTests(unittest.TestCase):
    """`_scrub` must be LENGTH-PRESERVING, because it is searched by offset.

    It blanks comments and string literals so a pattern cannot match inside
    one, and every caller then takes an offset from the result and uses it
    against the real text. It was short by one for each backslash escape, and
    long by one or two for an unterminated literal or block comment at end of
    file -- so from the first escape in a file onward `nearest_type` looked in
    the wrong place, and a rewrite that sliced the real text at a scrubbed
    offset truncated the file: `Unexpected end of file`, from a rename that
    was otherwise correct.
    """

    CASES = (
        'a = "x";',
        'a = "x\\ty";',
        'a = "\\\\";',
        '"\\\\\\\\"',
        'f("a\\"b");',
        "'\\''",
        '// comment',
        'a // comment',
        '/* block */ f();',
        '/*unterminated',
        '"unterminated',
        "'",
        '"',
        '\\',
        '',
        'f(1);',
    )

    def test_every_hand_case_keeps_its_length(self):
        for case in self.CASES:
            with self.subTest(case=case):
                self.assertEqual(len(bgt_to_nvgt._scrub(case)), len(case))

    def test_fuzzed_over_the_characters_that_matter(self):
        """A quote, an escape, a newline and both comment openers, which is
        where every drift came from."""
        import random
        random.seed(7)
        alphabet = ''.join((chr(34), chr(39), chr(92), 'abc', chr(10), '/*; '))
        for _ in range(20000):
            text = ''.join(random.choice(alphabet)
                           for _ in range(random.randint(0, 28)))
            if len(bgt_to_nvgt._scrub(text)) != len(text):
                self.fail('drifted on %r' % text)

    def test_it_still_blanks_what_it_is_for(self):
        """Length alone would be satisfied by returning the input unchanged."""
        source = 'f(' + chr(34) + 'sleep(' + chr(34) + ');  // sleep('
        scrubbed = bgt_to_nvgt._scrub(source)
        self.assertNotIn('sleep(', scrubbed)
        self.assertIn('f(', scrubbed)


class ChainResolutionTests(unittest.TestCase):
    """A method on an ELEMENT or a MEMBER, which is most of a real project.

    `bgt libcheck`-style name-only renaming cannot answer
    `world[i].interacts.get_length()`, and declining it was 67 of Paladin's
    72 compiler errors. Each link is taken from the project's own
    declarations, and the chain declines at the first one that is not
    written down -- so this gets stricter, never looser, where the project
    says nothing.
    """

    SCRIPTS = (
        ("globals.nvgt", "map[] world;\nsound effect;\n"),
        ("map.nvgt",
         "class map {\n"
         "    string filename;\n"
         "    int[][] world;\n"
         "    interact@[] interacts;\n"
         "    void go() { int[] world; }\n"
         "}\n"),
        #: a class whose whole body is on ONE line, which is how Paladin
        #: writes `class character`
        ("character.nvgt", "class character { dragonstrike[] strikes; }"),
    )

    def setUp(self):
        self.members = bgt_to_nvgt.class_members(self.SCRIPTS)
        self.types = bgt_to_nvgt.declared_types(self.SCRIPTS)

    def test_a_class_member_is_not_a_global(self):
        """The flat map is keyed by bare name, so class `map`'s member
        `int[][] world` collided with the global `map[] world` and the name
        was dropped as disagreeing -- after which nothing knew what
        `world.get_length()` was called on."""
        self.assertEqual(self.types.get("world"), "map[]")
        self.assertEqual(self.members["map"]["world"], "int[][]")

    def test_a_one_line_class_body_still_has_members(self):
        """A `;` terminates as well as a newline. Without that, a class
        written on one line reported no members at all, the chain through it
        declined, and the rename declined with it."""
        self.assertEqual(self.members["character"]["strikes"],
                         "dragonstrike[]")

    def test_a_method_body_declares_locals_not_members(self):
        """`map::go`'s `int[] world` is a local at brace depth 2 and belongs
        to nobody but the method."""
        self.assertEqual(self.members["map"]["world"], "int[][]")

    def test_each_link_of_a_chain(self):
        for middle, want in (("", "map[]"),
                             ("[i]", "map"),
                             ("[i].interacts", "interact@[]"),
                             ("[i].world", "int[][]"),
                             ("[i].world[j]", "int[]")):
            with self.subTest(middle=middle):
                self.assertEqual(
                    bgt_to_nvgt.resolve_chain("map[]", middle, self.members),
                    want)

    def test_it_declines_rather_than_guesses(self):
        for middle in ("[i].nope",          # no such member
                       "[i][j]",            # `map` is not an array
                       ".interacts",        # a member of an ARRAY
                       "[i].interacts.x"):  # a member of a registered type
            with self.subTest(middle=middle):
                self.assertIsNone(
                    bgt_to_nvgt.resolve_chain("map[]", middle, self.members))

    def test_the_rename_follows_a_chain_and_leaves_a_sound_alone(self):
        source = ("void f() {\n"
                  "    character[] party;\n"
                  "    int a = world[i].interacts.get_length();\n"
                  "    int b = party[n].strikes.get_length();\n"
                  "    double c = effect.get_length();\n"
                  "}\n")
        out, _notes = bgt_to_nvgt.apply_typed_renames(
            source, self.types, self.members)
        self.assertIn("world[i].interacts.length()", out)
        self.assertIn("party[n].strikes.length()", out)
        #: NVGT really does register `uint64 get_length() property` on a
        #: sound, so renaming this one would break it
        self.assertIn("effect.get_length()", out)

    def test_with_no_members_a_chain_declines(self):
        """Passing no member table must not make the rename looser."""
        source = "void f() { int a = world[i].interacts.get_length(); }\n"
        out, _notes = bgt_to_nvgt.apply_typed_renames(source, self.types, {})
        self.assertIn("get_length()", out)


class SignatureParameterTests(unittest.TestCase):
    """A PARAMETER is declared in the signature, not as a statement.

    `_DECLARED` is anchored at the start of a line, so on

        vector[] remove_vector(vector[] arg0, vector arg1, bool arg2 = true)

    it captures `remove_vector` as a name of type `vector[]` and never sees
    `arg0`. Every receiver in a recovered body is a local or a parameter, so
    half of them had no type at all: the last 10 of Paladin's errors.
    """

    def test_every_parameter_is_read_with_its_type(self):
        text = ("vector[] remove_vector(vector[] arg0, vector arg1, "
                "bool arg2 = true)\n{\n}\n")
        self.assertEqual(
            bgt_to_nvgt.signature_parameters(text),
            [(0, "arg0", "vector[]"), (0, "arg1", "vector"),
             (0, "arg2", "bool")])

    def test_a_default_argument_may_hold_a_comma(self):
        """A plain `split(',')` would cut a parameter in half and leave the
        half looking like a declaration of something else."""
        q = chr(34)
        text = ('void f(string arg0 = string(' + q + 'a,b' + q + '), '
                'int arg1)\n{\n}\n')
        self.assertEqual(
            [(n, k) for _p, n, k in bgt_to_nvgt.signature_parameters(text)],
            [("arg0", "string"), ("arg1", "int")])

    def test_a_call_is_not_a_signature(self):
        """The line must END at the closing paren, which is what tells a
        signature from a call or from a constructor-form declaration."""
        for line in ("    f(a, b);\n", "    sound_pool p(500);\n",
                     "    int n = g(x);\n"):
            with self.subTest(line=line):
                self.assertEqual(bgt_to_nvgt.signature_parameters(line), [])

    def test_a_parameter_resolves_a_receiver(self):
        text = ("void walk(int[][] arg2, sound arg1)\n{\n"
                "    if (arg2.get_length() <= 1) { return; }\n"
                "    double d = arg1.get_length();\n"
                "}\n")
        out, _notes = bgt_to_nvgt.apply_typed_renames(text, {}, {})
        self.assertIn("arg2.length()", out)
        self.assertIn("arg1.get_length()", out)


class CopyConstructorTests(unittest.TestCase):
    """BGT registers `void f(const vector &in)` and NVGT does not.

    NVGT registers the type `asOBJ_POD`, so AngelScript gives it a bitwise
    copy for free -- `vector b = a;` and `c = a;` were both put to `nvgt -c`
    before either was emitted. Only where the argument's own type is the same
    type: BGT's other constructor takes floats with defaults, so `vector(1.0)`
    is a legal one-argument call that means something else.
    """

    SOURCE = ("void f(vector arg0)\n{\n"
              "    vector local_24;\n"
              "    vector local_27;\n"
              "    vector local_28(local_27);\n"
              "    local_28 = vector(local_24);\n"
              "    local_28 = vector(arg0);\n"
              "    local_28 = vector(1.0);\n"
              "    local_28 = vector(local_24.x);\n"
              "    local_28 = vector(1, 2, 3);\n"
              "}\n")

    def setUp(self):
        self.out, self.notes = bgt_to_nvgt.apply_copy_constructors(
            self.SOURCE, {}, {})

    def test_a_declaration_keeps_its_value_as_an_initialiser(self):
        """The construction IS the declaration, so dropping it entirely would
        lose the value."""
        self.assertIn("vector local_28 = local_27;", self.out)

    def test_a_copy_in_expression_position_becomes_the_value(self):
        self.assertIn("local_28 = local_24;", self.out)
        self.assertIn("local_28 = arg0;", self.out)

    def test_the_float_constructor_is_left_alone(self):
        """`vector(1.0)` and `vector(v.x)` are BGT's OTHER constructor, with
        its defaults -- a different call that means something else."""
        self.assertIn("vector(1.0)", self.out)
        self.assertIn("vector(local_24.x)", self.out)
        self.assertIn("vector(1, 2, 3)", self.out)

    def test_it_says_how_many_it_moved(self):
        self.assertTrue(any("vector" in n for n in self.notes))


class ConstHandleTests(unittest.TestCase):
    """NVGT registers `const network_event@ network::request()`.

    BGT's is not const, so a recovered local that receives one is declared
    `network_event@` and *"Can't implicitly convert from 'const
    network_event@' to 'network_event@'"* -- on every BGT game that reads its
    network. One word on the declaration fixes it, and it was put to
    `nvgt -c` on a real recovery before it was emitted.
    """

    SOURCE = ("network host;\n"
              "void loop()\n{\n"
              "    network_event@ local_4;\n"
              "    network_event@ local_7;\n"
              "    @local_4 = host.request();\n"
              "    @local_7 = network_event();\n"
              "}\n")

    def setUp(self):
        self.types = bgt_to_nvgt.declared_types(
            [("g.nvgt", self.SOURCE)])
        self.out, self.notes = bgt_to_nvgt.apply_const_handles(
            self.SOURCE, self.types, {})

    def test_the_receiving_local_is_declared_const(self):
        self.assertIn("const network_event@ local_4;", self.out)

    def test_a_local_filled_from_elsewhere_is_left_alone(self):
        """`network_event()` is not const, and a non-const handle assigns INTO
        a const one anyway -- so widening this would be safe and pointless,
        while leaving it alone keeps the output nearest the original."""
        self.assertIn("    network_event@ local_7;", self.out)

    def test_it_declines_when_the_receiver_is_not_a_network(self):
        source = ("http client;\n"
                  "void f()\n{\n"
                  "    network_event@ local_4;\n"
                  "    @local_4 = client.request();\n"
                  "}\n")
        types = bgt_to_nvgt.declared_types([("g.nvgt", source)])
        out, _notes = bgt_to_nvgt.apply_const_handles(source, types, {})
        self.assertIn("    network_event@ local_4;", out)

    def test_it_says_what_it_did(self):
        self.assertTrue(any("const network_event@" in n for n in self.notes))


class GlobalVariableConflictTests(unittest.TestCase):
    """A global VARIABLE whose name NVGT has as a function.

    Aliens Attack declares `sound power;` and `sound exp2;` at file scope,
    and NVGT has a global function of each name -- which BGT allowed and NVGT
    does not, so two sounds stopped the whole title compiling.

    Renaming a variable is safe whatever BGT has, which is the difference
    from `renameable`: a variable's name is READ, never called, so moving it
    cannot change which function runs. The engine's own function stays
    reachable wherever the text calls it.
    """

    def test_a_global_variable_is_found_with_its_type(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as out:
            inc = os.path.join(out, "includes")
            os.makedirs(inc)
            with open(os.path.join(inc, "globals.nvgt"), "w",
                      encoding="utf-8") as handle:
                handle.write("int fish;\nsound power;\n"
                             "void f() { sound local_1; }\n")
            where = bgt_to_nvgt.global_variable(out, "power")
            self.assertIsNotNone(where)
            self.assertEqual(where[1], 2)
            self.assertEqual(where[2], "sound")
            #: a LOCAL of that name is not a global
            self.assertIsNone(bgt_to_nvgt.global_variable(out, "local_1"))
            #: and neither is a function
            self.assertIsNone(bgt_to_nvgt.global_variable(out, "f"))

    def test_a_class_is_not_offered(self):
        """This file declines renaming a class all along: a class name
        reaches into string literals and saved data. The Gate declares
        `class log` and Manamon 1 `class sleep`, and both are reported
        rather than renamed."""
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as out:
            with open(os.path.join(out, "a.nvgt"), "w",
                      encoding="utf-8") as handle:
                handle.write("class log {\n    int n;\n}\n")
            self.assertIsNone(bgt_to_nvgt.global_variable(out, "log"))


class StringifiedNumberTests(unittest.TestCase):
    """BGT takes a tone_synth FREQUENCY as text and NVGT takes the number.

        BGT    bool freq_ms(string& in, double& in)
        NVGT   bool freq_ms(double freq, int ms)

    Both engines take a note NAME as a string, so it is the `freq*` family
    alone -- BGT's own API is inconsistent here and NVGT fixed it. A game
    therefore writes `freq_ms(("" + freq), 40.0)`, stringifying a double it
    already had, and unwrapping that is exact. The `ms` argument needs
    nothing: AngelScript converts the double with no warning, which was
    measured on the real `cs` server rather than assumed.
    """

    SOURCE = ("void f()\n{\n"
              "    tone_synth synth;\n"
              "    double freq;\n"
              "    string name;\n"
              '    synth.freq_ms(("" + freq), 40.0);\n'
              '    synth.freq(("" + 440), 1.0);\n'
              '    synth.freq_ms(("" + name), 40.0);\n'
              "    synth.freq_ms(name, 40.0);\n"
              "    synth.freq(880, 1.0);\n"
              '    synth.note_ms("C4", 40.0);\n'
              "}\n")

    def setUp(self):
        types = bgt_to_nvgt.declared_types([("g.nvgt", self.SOURCE)])
        self.out, self.notes = bgt_to_nvgt.apply_stringified_numbers(
            self.SOURCE, types, {})

    def test_a_stringified_number_is_unwrapped(self):
        self.assertIn("synth.freq_ms(freq, 40.0);", self.out)
        self.assertIn("synth.freq(440, 1.0);", self.out)

    def test_a_stringified_STRING_is_left_alone_and_reported(self):
        """`"" + x` is only a stringified number when `x` is one. Unwrapping
        a real concatenation would hand the engine the wrong thing."""
        self.assertIn('synth.freq_ms(("" + name), 40.0);', self.out)
        self.assertTrue(any("left alone 2 time" in n for n in self.notes))

    def test_a_note_takes_a_string_in_BOTH_engines(self):
        self.assertIn('synth.note_ms("C4", 40.0);', self.out)

    def test_an_argument_that_is_already_a_number_is_not_reported(self):
        """The scan restarts after each rewrite, so without this a site the
        pass had just FIXED came back as one it had left alone -- `freq_ms`
        reported 3 left alone where 2 are."""
        self.assertIn("synth.freq(880, 1.0);", self.out)
        self.assertFalse(any("left alone 3 time" in n for n in self.notes))

    def test_the_first_argument_is_bracket_matched(self):
        """An argument may hold a comma of its own."""
        text = '    synth.freq_ms(("" + f(a, b)), 40);\n'
        span = bgt_to_nvgt._first_argument(text, text.index("("))
        self.assertEqual(text[span[0]:span[1]], '("" + f(a, b))')

    def test_a_leading_paren_need_not_wrap_the_whole_expression(self):
        """`(a) + (b)` starts with `(` and ends with `)` and encloses
        nothing -- a mistake this file records costing a title's `while`
        statements."""
        self.assertTrue(bgt_to_nvgt._wraps_whole('("" + freq)'))
        self.assertFalse(bgt_to_nvgt._wraps_whole("(a) + (b)"))
