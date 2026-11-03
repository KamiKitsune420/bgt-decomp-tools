"""Known-answer tests for a body whose slots have REAL names.

Everything that looks for a frame slot in emitted text looked for the
names this decompiler invents -- `local_19`, `tmp3`. A debug build names
every slot, so three rules went blind at once and the recovery of Air Puck
2PE came out with 176 compiler errors across its two halves while every
count this project measures said it was clean: 0 residual gotos, 0
unbalanced files, a verified split.

What the compiler reported, and what each one is:

  * `'parsed' is not declared`, sixty times over --
    `_declare_read_before_written` exists to declare a slot the body reads
    and never assigns, and it found slots by a NAME PATTERN, which matches
    nothing a source ever wrote.
  * `for (success = false; (success ? 1 : 0) < item_count; success++)` --
    one slot carries every declaration the source made in it, and the
    adapter kept the last. `netloop` makes twenty-seven in one slot,
    mixing `int`, `uint` and `bool`.
  * `Can't implicitly convert from 'string' to 'uint'` -- two different
    slots can carry one source name, in different blocks, and a slot's
    declaration is hoisted to the top of the body.

Synthetic inputs only, and each test is a shape the real reports named.
"""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, os.path.join(ROOT, "tools", "nvgt"))

from nvgt import decompile                                    # noqa: E402
from nvgt.asreader import DataType, Function, ScriptVariable   # noqa: E402


def dt(name, token=0):
    """A primitive data type that formats as `name`."""
    out = DataType()
    out.token_type = token
    out.primitive_name = name
    return out


def _formats_as(name):
    out = DataType()
    out.format = lambda: name            # the only thing the rule reads
    return out


def fd_for(variables, param_names=(), object_type=None):
    """A FuncDecompiler holding just what the declaration net reads."""
    fn = Function()
    fn.name = "netloop"
    fn.variables = list(variables)
    fn.param_names = list(param_names)
    fn.param_types = [_formats_as("string") for _ in param_names]
    fn.object_type = object_type
    fd = object.__new__(decompile.FuncDecompiler)
    fd.fn = fn
    fd.var_names = {v.stack_offset: v.name for v in variables if v.name}
    fd.var_names.update(decompile._parameter_layout(fn))
    fd.var_types = {v.stack_offset: v.type for v in variables if v.name}
    fd.parameter_slots = {off for off, _ in decompile._parameter_layout(fn)}
    return fd


class DeclaringARealNameTests(unittest.TestCase):

    def test_a_real_name_read_before_written_is_declared(self):
        """The net looked for `local_19` and found no `parsed`.

        Air Puck's `netloop` assigns `parsed` and never declares it, sixty
        times over in that one body, and the compiler says
        `'parsed' is not declared` once per use.
        """
        fd = fd_for([ScriptVariable(name="parsed", stack_offset=20,
                                    type=_formats_as("string[]"))])
        out = decompile._declare_read_before_written(
            ["    parsed = local_21;", "    local_11 = parsed[0];"], fd, 1)
        self.assertEqual(out[0], "    string[] parsed;")

    def test_a_generated_name_is_still_found(self):
        """The net searched with `(?:local|tmp)_?\\d+`, which matches no real
        name at all -- so widening it to the frame's own names has to keep
        finding the generated ones, which is every release build's whole
        frame."""
        fd = fd_for([ScriptVariable(name="local_21", stack_offset=21,
                                    type=_formats_as("int"))])
        out = decompile._declare_read_before_written(
            ["    local_21 = stn(x);"], fd, 1)
        self.assertEqual(out[0], "    int local_21;")

    def test_a_parameter_is_not_declared_again(self):
        """The signature declares it, and a second declaration shadows it
        with an uninitialised copy -- so the body would read a blank."""
        fd = fd_for([], param_names=["filename"])
        out = decompile._declare_read_before_written(
            ["    speak(filename, true);"], fd, 1)
        self.assertEqual(out, ["    speak(filename, true);"])

    def test_every_name_a_reused_slot_renders_under_is_declared(self):
        """`redeclare` renames a reused slot at each declaration's position,
        so one offset writes `index`, `index2` and `rindex` in the scopes the
        source declared them in. `var_names` holds the one the walk ended
        with, and the other two were the server's last 18 errors."""
        off = 15
        fd = fd_for([
            ScriptVariable(name="index", stack_offset=off,
                           declared_at=10, type=_formats_as("int")),
            ScriptVariable(name="index2", stack_offset=off,
                           declared_at=40, type=_formats_as("int")),
            ScriptVariable(name="rindex", stack_offset=off,
                           declared_at=70, type=_formats_as("int")),
        ])
        # The walk ended on `rindex`, which is what `var_names` holds.
        fd.var_names[off] = "rindex"
        out = decompile._declare_read_before_written(
            ["    index = get_player_index(x);",
             "    index2 = get_player_index(y);",
             "    rindex = get_room_index(z);"], fd, 1)
        declared = [line.strip() for line in out if line.strip().endswith(";")
                    and " " in line.strip().split(";")[0]]
        self.assertIn("int index;", declared)
        self.assertIn("int index2;", declared)
        self.assertIn("int rindex;", declared)

    def test_a_type_source_cannot_name_is_left_alone(self):
        """A slot whose type has no spelling is not declared as something it
        is not -- the pre-existing refusal, which must survive the widening."""
        fd = fd_for([ScriptVariable(name="cb", stack_offset=4,
                                    type=_formats_as("_builtin_function_"))])
        out = decompile._declare_read_before_written(["    cb(1);"], fd, 1)
        self.assertEqual(out, ["    cb(1);"])

    def test_a_name_already_declared_in_the_body_is_not_declared_twice(self):
        fd = fd_for([ScriptVariable(name="parsed", stack_offset=20,
                                    type=_formats_as("string[]"))])
        lines = ["    string[] parsed = array<string>();",
                 "    local_11 = parsed[0];"]
        self.assertEqual(
            decompile._declare_read_before_written(lines, fd, 1), lines)


if __name__ == "__main__":
    unittest.main()
