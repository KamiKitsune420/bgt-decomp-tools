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
        for name in ("call", "get_progress", "request",
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

        with open(compat, "w") as handle:
            for name in ("bgt_string_compress", "bgt_string_decompress",
                         "bgt_serialize", "bgt_generate_computer_id"):
                handle.write("// routes to %s\n" % name)
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

    def test_none_of_them_is_also_a_rename(self):
        """A name cannot be both rewritten and left to a person."""
        for name in bgt_to_nvgt.SEMANTIC:
            self.assertNotIn(name, bgt_to_nvgt.RENAMES)
            self.assertNotIn(name, bgt_to_nvgt.TYPED_RENAMES)
            self.assertNotIn(name, bgt_to_nvgt.PROPERTY_RENAMES)


if __name__ == "__main__":
    unittest.main()
