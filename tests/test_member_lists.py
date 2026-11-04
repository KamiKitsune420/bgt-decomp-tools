"""Known-answer tests for a MEMBER declared with an initialiser list.

`string[] text1 = {"is here", "just came online", ...};` at class scope
compiles to the initialisation-list protocol inside every constructor, and
the store that puts the finished array into the member is the same
eight-instruction idiom the compiler writes for any by-value member:

    AllocMem 7 ; SetListSize 7 0 5 ; <five elements written>
    PshVPtr 7 ; CALL factstub ; STOREOBJ 8
    PshVPtr 8 ; PshVPtr 0 ; ADDSi dogbot::text1 ; REFCPY ; PopPtr ; FREE 8

That span is dropped as generated code -- correctly, since no source
statement produces it -- and the list went with it, so the declaration came
out `string[] text1;` and every read of it was an empty array. Build to
Survive's server reads `text1[random(0, text1.length() - 1)]` in three
classes, so a recovered server threw `Index out of bounds` the moment a
player, a dogbot or an update bot spawned.

Swept across nine artefacts, this shape occurs in exactly one of them --
seven members of that one server -- so these are the tests rather than a
corpus figure. BGT was asked whether a member initialiser list compiles at
all before any of it was emitted, and it does, keeping its values.

Synthetic inputs only.
"""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, os.path.join(ROOT, "tools", "nvgt"))

import bgt_audit                                               # noqa: E402
from nvgt import decompile                                     # noqa: E402
from nvgt.asreader import DataType, Function, Instr, TypeInfo  # noqa: E402


def array_of_string():
    """`string[]` by value, as a property's recorded type."""
    subtype = DataType()
    subtype.primitive_name = "string"
    out = DataType()
    out.obj_type = TypeInfo(name="array")
    out.template_subtypes = [subtype]
    return out


def instr(name, w_arg=0, prop_name=None, func_ref=None):
    return Instr(pos=0, op=0, name=name, bc_type="", size=1, w_arg=w_arg,
                 prop_name=prop_name, func_ref=func_ref)


def factory(by_reference):
    """`factstub`, taking the list buffer by reference or a length by value."""
    parameter = DataType()
    if by_reference:
        parameter.obj_type = TypeInfo(name="int")
        parameter.is_reference = True
    else:
        parameter.primitive_name = "uint"
    out = Function()
    out.name = "factstub"
    out.param_types = [parameter]
    return out


def prologue(member, by_reference=True, buffer_slot=7, temp_slot=8):
    """The member-initialisation idiom, with a factory call in front."""
    return [
        instr("PshVPtr", buffer_slot),
        instr("CALL", func_ref=factory(by_reference)),
        instr("STOREOBJ", temp_slot),
        instr("PshVPtr", temp_slot),
        instr("PshVPtr", 0),
        instr("ADDSi", prop_name="dogbot." + member),
        instr("REFCPY"),
        instr("PopPtr"),
        instr("FREE", temp_slot),
    ]


def skeleton(instrs, properties):
    """A FuncDecompiler holding just what the member-list path reads."""
    owner = TypeInfo(name="dogbot")
    fn = Function()
    fn.name = "dogbot"
    fn.object_type = owner
    fd = object.__new__(decompile.FuncDecompiler)
    fd.fn = fn
    fd.instrs = list(instrs)
    fd.property_types = {"dogbot." + n: dt for n, dt in properties.items()}
    fd.member_list_slots = {}
    fd.member_list_text = {}
    fd.list_values = {}
    fd.list_sizes = {}
    fd.sc_defs = set()
    return fd


def atom(text):
    return decompile.Atom("raw", text)


class MemberInitialiserLists(unittest.TestCase):

    def test_the_dropped_list_reaches_the_declaration(self):
        """Its elements, braced, under the member's own name."""
        fd = skeleton(prologue("text1"), {"text1": array_of_string()})
        skipped = fd._generated_member_initialisers()
        self.assertEqual(fd.member_list_slots, {1: ("text1", 7)},
                         "the call's index, the member, and the buffer slot")
        self.assertTrue(skipped, "the idiom is still dropped")
        fd.list_sizes[7] = 2
        fd.list_values[7] = {0: atom('"is here"'), 1: atom('"just booms in"')}
        fd._snapshot_member_list(1)
        self.assertEqual(fd.member_lists(),
                         {"text1": '{"is here", "just booms in"}'})

    def test_one_buffer_slot_serves_several_members(self):
        """So the list is taken AT the call, not after the run.

        `player` declares four member lists and the compiler reuses one
        buffer slot for all of them -- `AllocMem` resets the elements and
        `SetListSize` overwrites the size, so after the run that slot holds
        only the last list. Read then, all four members came out with it:
        `wepclass`, whose elements are `melee`, `short-range` and
        `long-range`, got a list of chat lines. Writing the wrong values is
        worse than the empty array this was fixing, and no count can see it
        -- the line totals are identical either way.
        """
        instrs = prologue("wepclass") + prologue("text1")
        fd = skeleton(instrs, {"wepclass": array_of_string(),
                               "text1": array_of_string()})
        fd._generated_member_initialisers()
        self.assertEqual(sorted(fd.member_list_slots.values()),
                         [("text1", 7), ("wepclass", 7)],
                         "both members, through the one slot")

        fd.list_sizes[7] = 1
        fd.list_values[7] = {0: atom('"melee"')}
        first, = [k for k, v in fd.member_list_slots.items()
                  if v[0] == "wepclass"]
        fd._snapshot_member_list(first)
        # ...and now the next member's `AllocMem` has replaced the buffer.
        fd.list_values[7] = {0: atom('"is here"')}
        second, = [k for k, v in fd.member_list_slots.items()
                   if v[0] == "text1"]
        fd._snapshot_member_list(second)
        self.assertEqual(fd.member_lists(),
                         {"wepclass": '{"melee"}', "text1": '{"is here"}'})

    def test_a_buffer_not_fully_accounted_for_is_refused(self):
        """A list one element short is worse than one that is empty.

        The empty rendering is at least what this had before the list was
        recovered at all; a short one is a different program that compiles.
        """
        fd = skeleton(prologue("text1"), {"text1": array_of_string()})
        fd._generated_member_initialisers()
        fd.list_sizes[7] = 3                      # the compiler declared three
        fd.list_values[7] = {0: atom('"a"'), 1: atom('"b"')}
        fd._snapshot_member_list(1)
        self.assertEqual(fd.member_lists(), {},
                         "two elements of a declared three is not a list")

    def test_the_length_factory_is_not_a_list(self):
        """`double[] down(256)` takes its length by VALUE, and already works.

        The length survives on the declaration through
        `_member_array_sizes`; recording it here as well would put a
        `{...}` on a declaration that carries `(256)`. Asserted against the
        by-reference form in the same test, because an absence on its own
        is a test that passes on any tree that records nothing at all.
        """
        prop = {"down": array_of_string()}
        length = skeleton(prologue("down", by_reference=False), prop)
        length._generated_member_initialisers()
        buffer = skeleton(prologue("down", by_reference=True), prop)
        buffer._generated_member_initialisers()
        self.assertEqual(buffer.member_list_slots, {1: ("down", 7)},
                         "a by-reference parameter is the list buffer")
        self.assertEqual(length.member_list_slots, {},
                         "a by-value parameter is a length, not a buffer")

    def test_a_handle_member_is_a_real_assignment(self):
        """`@this.member = T();` is source, so neither dropped nor recorded.

        Contrasted with the by-value member in the same test: the handle is
        what makes this the source's own statement, and a test that only
        asserted the absence would pass with the whole rule removed.
        """
        handle = array_of_string()
        handle.is_object_handle = True
        by_handle = skeleton(prologue("text1"), {"text1": handle})
        by_value = skeleton(prologue("text1"), {"text1": array_of_string()})
        self.assertEqual(by_handle._generated_member_initialisers(), set(),
                         "a handle store is the source's own")
        self.assertTrue(by_value._generated_member_initialisers(),
                        "a by-value member's store is generated")
        self.assertEqual(by_handle.member_list_slots, {})
        self.assertEqual(by_value.member_list_slots, {1: ("text1", 7)})

    def test_the_list_is_formatted_in_one_place(self):
        """One reading of the protocol, one formatter, two callers.

        The member path needs the same list as the local one and renders it
        somewhere else -- on a declaration rather than in a statement. Built
        separately, the two would drift, which is the failure this
        repository keeps recording. `test_recovery` pins the formatter; this
        pins that the member path goes through the same function.
        """
        path = os.path.join(ROOT, "tools", "nvgt", "decompile.py")
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        self.assertEqual(source.count("def list_text("), 1)
        self.assertGreaterEqual(source.count("self.list_text("), 2,
                                "the local and the member path both ask")


class ConstructorAudit(unittest.TestCase):
    """`bgt audit` has to look where a member initialiser lands.

    The bytecode attributes those values to the constructor, because that is
    where the compiler builds them; source writes them on the declaration.
    Audited against the constructor's braces alone, every one reads as lost
    -- 59 string literals across three bodies that hold every one of them,
    reported identically before the fix and after it, which is an instrument
    that cannot see its own subject.
    """

    CLASS = (
        "class dogbot {\n"
        '    string[] text1 = {"is here", "just booms in"};\n'
        "    int movetime;\n"
        "    dogbot(int ct) {\n"
        "        movetime = 150;\n"
        "    }\n"
        "    void chat() {\n"
        '        send(0, "a method body, which is NOT a declaration", 2);\n'
        "    }\n"
        "}\n"
    )

    def test_declaration_spans_skip_a_method_body(self):
        scrubbed = bgt_audit.bgt_apicheck.scrub(self.CLASS)
        start = scrubbed.index("{")
        end = bgt_audit._matching(scrubbed, start, "{}")
        spans = bgt_audit.declaration_spans(scrubbed, start, end)
        text = "".join(self.CLASS[a:b] for a, b in spans)
        self.assertIn("text1", text, "a property declaration is included")
        self.assertIn("movetime", text)
        self.assertNotIn("NOT a declaration", text,
                         "a method body would weaken the comparison")
        self.assertNotIn("150", text, "and so would a constructor body")

    def test_a_constructor_carries_its_class_declarations(self):
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            with open(os.path.join(folder, "dogbot.bgt"), "w",
                      encoding="utf-8") as fh:
                fh.write(self.CLASS)
            bodies = bgt_audit.text_bodies(folder)
        ctor, = bodies["dogbot::dogbot"]
        literals = bgt_audit.text_literals(ctor)
        self.assertIn(b"is here", literals,
                      "the member initialiser is part of what the "
                      "constructor is audited against")
        method, = bodies["dogbot::chat"]
        self.assertNotIn(b"is here", bgt_audit.text_literals(method),
                         "an ordinary method gets no such extension")


if __name__ == "__main__":
    unittest.main()
