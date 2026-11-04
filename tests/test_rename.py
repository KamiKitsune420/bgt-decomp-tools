"""Known-answer tests for `bgt rename`.

Every case here is a mistake that was made while writing the pass, kept so
that it cannot be made again.  They run on synthetic projects written into a
temporary directory -- no game file is involved.

The ones worth knowing about:

*   the verifier checked its rename mapping per **file**, and `local_1` in two
    methods of one class is two unrelated slots, so it reported 143 correct
    renames as contradictions;
*   a rule read a name out of the code and picked up a slot that had not been
    renamed yet, so a slot kept a placeholder for a name;
*   the engine's parameter table kept the longest overload of a name, and
    `set` is `calendar::set(year, month, ...)`, so every `x.set(v)` in a
    project named `v` after a year;
*   the collision check ran against the rewritten text with spans recorded
    before the rewrite, which point at the next function once the text has
    changed length;
*   `return x;` matched the declaration pattern, so every getter looked as
    though it declared a local.
"""

import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "tools"))

import bgt_rename as R  # noqa: E402


def write(root, rel, text):
    path = os.path.join(root, rel.replace("/", os.sep))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


class MaskTests(unittest.TestCase):
    def test_a_comment_marker_inside_a_string_is_not_a_comment(self):
        src = 'string a = "http://x";\nint b = 1;\n'
        m = R.mask(src)
        self.assertEqual(len(m), len(src))
        self.assertIn("int b = 1;", m)
        self.assertNotIn("http", m)

    def test_a_quote_inside_a_comment_does_not_open_a_string(self):
        src = '// it is a "thing\nint b = 1;\n'
        m = R.mask(src)
        self.assertIn("int b = 1;", m)

    def test_an_escaped_quote_does_not_end_a_string(self):
        src = 'string a = "x\\"y"; int b = 2;'
        m = R.mask(src)
        self.assertIn("int b = 2;", m)

    def test_newlines_and_length_survive(self):
        src = '/* one\ntwo */\nint x;\n'
        m = R.mask(src)
        self.assertEqual(len(m), len(src))
        self.assertEqual(m.count("\n"), src.count("\n"))


class TokenTests(unittest.TestCase):
    def test_a_string_is_one_token(self):
        self.assertEqual(R.tokens('f("a, b", 1)'),
                         ["f", "(", '"a, b"', ",", "1", ")"])

    def test_positions_point_back_into_the_text(self):
        src = "int local_3;"
        for tok, at in R.tokens_with_pos(src):
            self.assertEqual(src[at:at + len(tok)], tok)


class VerifyScopeTests(unittest.TestCase):
    """A slot's mapping is per function body, never per file."""

    BEFORE = (
        "class A {\n"
        "    void one() { int local_1; local_1 = 1; }\n"
        "    void two() { string local_1; local_1 = \"x\"; }\n"
        "}\n")
    AFTER = (
        "class A {\n"
        "    void one() { int nombre; nombre = 1; }\n"
        "    void two() { string texte; texte = \"x\"; }\n"
        "}\n")

    def _scopes(self, text):
        root = tempfile.mkdtemp()
        try:
            write(root, "a.bgt", text)
            proj = R.Project(root)
            out = {}
            for fn in proj.funcs:
                lo = min([fn.body_start] + [p.start for p in fn.params])
                out.setdefault(fn.path, []).append((lo, fn.body_end))
            return out
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_one_slot_may_become_two_names_in_two_bodies(self):
        scopes = self._scopes(self.BEFORE)
        self.assertEqual(len(scopes["a.bgt"]), 2)
        problems = R.verify({"a.bgt": self.BEFORE}, {"a.bgt": self.AFTER},
                            scopes)
        self.assertEqual(problems, [])

    def test_without_the_scopes_the_same_rename_reads_as_a_contradiction(self):
        problems = R.verify({"a.bgt": self.BEFORE}, {"a.bgt": self.AFTER}, {})
        self.assertTrue(problems)

    def test_two_slots_may_not_collapse_onto_one_name(self):
        before = "void f() { int local_1; int local_2; local_1 = local_2; }\n"
        after = "void f() { int n; int n; n = n; }\n"
        scopes = self._scopes(before)
        self.assertTrue(R.verify({"a.bgt": before}, {"a.bgt": after}, scopes))

    def test_a_changed_non_placeholder_token_is_refused(self):
        before = "void f() { int local_1; local_1 = 1; }\n"
        after = "void f() { int nombre; nombre = 2; }\n"
        scopes = self._scopes(before)
        self.assertTrue(R.verify({"a.bgt": before}, {"a.bgt": after}, scopes))


class OfferTests(unittest.TestCase):
    def test_a_candidate_derived_from_a_placeholder_is_refused(self):
        s = R.Slot("local_1", "local")
        s.offer(R.P_INDEX_READ, "arg0")
        s.offer(R.P_MEMBER_READ, "local_7")
        self.assertEqual(s.cands, [])
        self.assertIsNone(s.best())

    def test_a_tie_keeps_the_evidence_seen_first_not_the_shorter_word(self):
        s = R.Slot("local_1", "local")
        s.offer(R.P_LITERAL_ROLE, "message")
        s.offer(R.P_LITERAL_ROLE, "texte")
        self.assertEqual(s.best(), "message")


class EngineParamTests(unittest.TestCase):
    def test_a_position_two_overloads_disagree_on_has_no_name(self):
        # the shape of `dictionary::set(key, value)` against
        # `calendar::set(year, month, day, hour, minute, second)`
        got = R._unanimous({
            "set": [{"key", "year"}, {"value", "month"}, {"day"}],
        })
        self.assertEqual(got["set"], ["", "", "day"])

    def test_a_position_every_overload_agrees_on_keeps_the_name(self):
        got = R._unanimous({"wait": [{"milliseconds"}]})
        self.assertEqual(got["wait"], ["milliseconds"])

    def test_the_engine_word_table_is_applied(self):
        self.assertEqual(R.engine_word("milliseconds"), "millisecondes")
        self.assertEqual(R.engine_word("replace_all"), "toutRemplacer")


class CollisionTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_a_return_statement_is_not_a_declaration(self):
        write(self.root, "a.bgt",
              "class A {\n"
              "    int numCase;\n"
              "    int getNumCase() { return numCase; }\n"
              "}\n")
        self.assertEqual(R.collisions(R.Project(self.root)), [])

    def test_a_local_that_shadows_a_member_is_reported(self):
        write(self.root, "a.bgt",
              "class A {\n"
              "    int numCase;\n"
              "    void f() { int numCase; numCase = 1; }\n"
              "}\n")
        self.assertTrue(R.collisions(R.Project(self.root)))

    def test_a_local_that_shadows_an_inherited_member_is_reported(self):
        write(self.root, "a.bgt",
              "class Base { int nbPiece; }\n"
              "class A : Base {\n"
              "    void f() { int nbPiece; nbPiece = 1; }\n"
              "}\n")
        self.assertTrue(R.collisions(R.Project(self.root)))


class FunctionNameTests(unittest.TestCase):
    """A method may be called `get`; a property accessor is not a method."""

    def setUp(self):
        self.root = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_a_method_named_get_is_found_and_its_body_renamed(self):
        write(self.root, "a.bgt", "class ChoixCombat {\n    int curseur;\n    int[] get() {\n        int[]@ local_1;\n        @local_1 = array<int>();\n        return local_1;\n    }\n}\n")
        proj = R.Project(self.root)
        self.assertIn("ChoixCombat::get", [f.label for f in proj.funcs])
        report = R.rename_project(self.root, chm=os.devnull)
        text = open(os.path.join(self.root, "a.bgt"), encoding="utf-8").read()
        self.assertNotIn("local_1", text)
        self.assertEqual(report.problems, [])

    def test_a_statement_keyword_is_still_not_a_function(self):
        write(self.root, "a.bgt", "void f() {\n    int local_1;\n    local_1 = 0;\n    if (local_1 == 0) {\n        local_1 = 1;\n    }\n}\n")
        proj = R.Project(self.root)
        self.assertEqual([f.label for f in proj.funcs], ["<global>::f"])


class RenameTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def run_rename(self):
        # no help file: the engine's names are an optional authority, and the
        # pass has to work without them
        return R.rename_project(self.root, chm=os.devnull)

    def test_every_slot_is_named_and_nothing_shadows(self):
        write(self.root, "a.bgt",
              "int g_total = 0;\n"
              "class Joueur {\n"
              "    string pseudo;\n"
              "    int nbPiece;\n"
              "    Joueur(string arg0) { pseudo = arg0; }\n"
              "    void setPseudo(string arg0) { pseudo = arg0; }\n"
              "    int gagne(int arg0) {\n"
              "        int local_1;\n"
              "        nbPiece = nbPiece + arg0;\n"
              "        for (local_1 = 0; local_1 < 3; local_1++) {\n"
              "            g_total = g_total + 1;\n"
              "        }\n"
              "        return arg0;\n"
              "    }\n"
              "}\n")
        report = self.run_rename()
        self.assertEqual(report.problems, [])
        self.assertEqual(report.named, report.slots)
        text = open(os.path.join(self.root, "a.bgt"), encoding="utf-8").read()
        self.assertNotIn("local_", text)
        self.assertNotIn("arg0", text)
        # the constructor's parameter is named for the member it fills, and
        # qualified so that it cannot shadow it
        self.assertIn("pseudoInitial", text)
        self.assertIn("nouveauPseudo", text)
        # a `for` counter is `i`
        self.assertIn("for (i = 0;", text)
        # the delta of a member is named after that member
        self.assertIn("variationNbPiece", text)

    def test_a_name_never_equals_a_global_or_a_member(self):
        write(self.root, "a.bgt",
              "string message;\n"
              "void dis(string arg0, bool arg1) { }\n"
              "void f() {\n"
              "    string local_2;\n"
              "    local_2 = \"hello\";\n"
              "    dis(local_2, true);\n"
              "}\n")
        report = self.run_rename()
        self.assertEqual(report.problems, [])
        text = open(os.path.join(self.root, "a.bgt"), encoding="utf-8").read()
        body = text.split("void f()")[1]
        self.assertNotIn("string message;", body)

    def test_shadowing_the_recovery_already_had_is_not_this_pass_s_problem(self):
        write(self.root, "a.bgt",
              "int musique = 0;\n"
              "void f() { int musique; musique = 1; }\n")
        report = self.run_rename()
        self.assertEqual(report.problems, [])
        self.assertEqual(len(report.inherited), 1)


class MemberListRepairTests(unittest.TestCase):
    """A member's initialiser list, built through one reused buffer slot."""

    SRC = (
        "class Quiz {\n"
        "    string[][] baseQuestion = {local_4, local_4};\n"
        "    Quiz() {\n"
        "        string[]@ local_4;\n"
        "        string[] __nvgt_list_5_1 = {\"a\", \"b\"};\n"
        "        @local_4 = __nvgt_list_5_1;\n"
        "        string[] __nvgt_list_5_2 = {\"c\", \"d\"};\n"
        "        @local_4 = __nvgt_list_5_2;\n"
        "    }\n"
        "}\n")

    def setUp(self):
        self.root = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_the_lists_move_back_onto_the_member(self):
        write(self.root, "a.bgt", self.SRC)
        report = R.Report()
        proj = R.Project(self.root)
        R.repair_member_lists(proj, report)
        self.assertEqual(len(report.repairs), 1)
        out = proj.files["a.bgt"]
        self.assertIn('{"a", "b"}', out)
        self.assertIn('{"c", "d"}', out)
        self.assertNotIn("local_4", out)
        self.assertNotIn("__nvgt_list", out)

    def test_it_is_refused_when_the_slot_is_really_read(self):
        src = self.SRC.replace(
            "        @local_4 = __nvgt_list_5_2;\n",
            "        @local_4 = __nvgt_list_5_2;\n"
            "        baseQuestion.insert_last(local_4);\n")
        write(self.root, "a.bgt", src)
        report = R.Report()
        proj = R.Project(self.root)
        R.repair_member_lists(proj, report)
        self.assertEqual(report.repairs, [])

    def test_it_is_refused_when_the_counts_disagree(self):
        src = self.SRC.replace("{local_4, local_4}",
                               "{local_4, local_4, local_4}")
        write(self.root, "a.bgt", src)
        report = R.Report()
        proj = R.Project(self.root)
        R.repair_member_lists(proj, report)
        self.assertEqual(report.repairs, [])


class RewriteTests(unittest.TestCase):
    """The rewrite assembles the file once, not once per rename."""

    def setUp(self):
        self.root = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_many_renames_in_one_file_all_land(self):
        lines = ["void f() {", "    int local_1;"]
        lines += ["    local_1 = %d;" % n for n in range(400)]
        lines += ["}"]
        write(self.root, "a.bgt", "\n".join(lines) + "\n")
        R.rename_project(self.root, chm=os.devnull)
        text = open(os.path.join(self.root, "a.bgt"), encoding="utf-8").read()
        self.assertNotIn("local_1", text)
        self.assertEqual(text.count("= 399;"), 1)


if __name__ == "__main__":
    unittest.main()
