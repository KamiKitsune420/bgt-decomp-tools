"""Signature recovery checks, including the pinned AngelScript compiler."""
from pathlib import Path
import subprocess
import tempfile
import unittest

from asreader import DataType, Function, TypeInfo, TT_IDENTIFIER, TT_INT, TT_VOID
from signatures import (class_header, format_parameter, format_parameters,
                        funcdef_declaration, function_signature, namespace_block)


ROOT = Path(__file__).resolve().parent / "fixtures"


class SignatureTests(unittest.TestCase):
    def test_reference_directions_and_defaults(self):
        ref = DataType(token_type=TT_INT, is_reference=True)
        for flag, expected in ((1, "int&in"), (2, "int&out"), (3, "int&inout"),
                               (5, "int&in")):
            with self.subTest(flag=flag):
                self.assertEqual(format_parameter(ref, flag), expected)
        self.assertEqual(format_parameter(DataType(token_type=TT_INT), 1), "int")
        f = Function(name="assign", return_type=DataType(token_type=TT_VOID),
                     param_types=[ref, DataType(token_type=TT_INT)],
                     in_out_flags=[2, 0], param_names=["result", "value"],
                     default_args=[None, "7"])
        self.assertEqual(function_signature(f), "void assign(int&out result, int value = 7)")
        self.assertEqual(f.signature(False), "void assign(int&out, int)")

    def test_const_object_and_const_handle_are_distinct(self):
        obj = TypeInfo(name="Item", namespace_="game")
        pointer = DataType(token_type=TT_IDENTIFIER, obj_type=obj, is_object_handle=True)
        self.assertEqual(pointer.format(), "game::Item@")
        pointer.is_handle_to_const = True
        self.assertEqual(pointer.format(), "const game::Item@")
        pointer.is_readonly = True
        self.assertEqual(pointer.format(), "const game::Item@const")
        self.assertEqual(pointer.format("game"), "const Item@const")

    def test_method_attributes_and_overload_identity(self):
        c = TypeInfo(name="Thing", namespace_="game")
        f = Function(name="get_value", return_type=DataType(token_type=TT_INT),
                     object_type=c, flags_byte=1 | 4 | 8 | 16 | 64)
        self.assertEqual(function_signature(f),
                         "protected int get_value() const final override property")
        self.assertEqual(f.signature(False), "int game::Thing::get_value() const")
        f.flags_byte &= ~1
        self.assertEqual(f.signature(False), "int game::Thing::get_value()")
        ctor = Function(name="$beh0", return_type=DataType(token_type=TT_VOID),
                        object_type=c, param_types=[DataType(token_type=TT_INT)],
                        flags_byte=32)
        self.assertEqual(function_signature(ctor, ["value"]), "Thing(int value) explicit")

    def test_class_inheritance_and_scoped_funcdefs(self):
        base = TypeInfo(name="Base", namespace_="outer")
        interface = TypeInfo(name="IValue", namespace_="outer", is_interface=True)
        c = TypeInfo(name="Thing", namespace_="game", derived_from=base,
                     interfaces=[interface, interface])
        callback = TypeInfo(name="Callback", kind="funcdef", parent_class=c)
        self.assertEqual(callback.format_name(), "game::Thing::Callback")
        self.assertEqual(callback.format_name("game"), "Thing::Callback")
        self.assertEqual(class_header(c), "class Thing : outer::Base, outer::IValue")
        self.assertEqual(class_header(interface), "interface IValue")
        c.is_shared = True
        c.flags |= 1 << 23
        self.assertTrue(class_header(c).startswith("shared final class Thing"))
        f = Function(name="Callback", func_type=4, parent_class=c,
                     return_type=DataType(token_type=TT_VOID),
                     param_types=[DataType(token_type=TT_INT, is_reference=True)],
                     in_out_flags=[2])
        self.assertEqual(funcdef_declaration(f, ["value"]),
                         "funcdef void Callback(int&out value);")

    def test_compiler_metadata_and_rendered_declarations(self):
        compiler = ROOT / "build/bcdump.exe"
        if not compiler.exists():
            self.skipTest("pinned AngelScript test compiler unavailable")
        # Properties must retain the property attribute for member syntax to
        # compile, and callbacks declared inside a class must keep that scope.
        original = """
namespace example {
    interface ICount { int get_count() const; }
    class Base { protected int count_value; }
    class Counter : Base, ICount {
        funcdef void Callback(const string&in message, int&out result);
        Callback@ callback;
        Counter(int value) explicit { count_value = value; }
        int get_count() const property { return count_value; }
        void update(int&out value, const string&in text, array<int>&inout items) {
            value = int(items.length());
        }
    }
    void assign(int&out result, int value = 7) { result = value; }
}
"""
        from decompile import load_any
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as folder:
            folder = Path(folder)

            def compile_source(name, source):
                path = folder / (name + ".as")
                path.write_text(source, encoding="utf-8")
                result = subprocess.run([str(compiler), str(path), str(path.with_suffix(".bin"))],
                                        capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return load_any(str(path.with_suffix(".bin")))

            module = compile_source("original", original)
            counter = next(c for c in module.classes if c.name == "Counter")
            interface = next(c for c in module.classes if c.name == "ICount")
            callback = next(f for f in module.funcdefs if f.name == "Callback")
            self.assertEqual([i.name for i in counter.interfaces], ["ICount"])
            self.assertIs(callback.parent_class, counter)
            callback_type = next(dt.obj_type for n, dt, flags in counter.properties if n == "callback")
            self.assertEqual(callback_type.format_name(), "example::Counter::Callback")
            self.assertEqual(class_header(counter), "class Counter : Base, ICount")
            methods = {f.name: f for f in counter.vft if f.object_type is counter}
            self.assertEqual(methods["update"].in_out_flags, [2, 1, 3])
            ctor = next(f for f in counter.constructors if f.param_types)
            assignment = next(f for f in module.global_functions if f.name == "assign")
            declaration = "\n".join([
                class_header(interface) + " {",
                function_signature(interface.methods[0]) + ";", "}",
                "class Base { protected int count_value; }",
                class_header(counter) + " {", funcdef_declaration(callback),
                "Callback@ callback;",
                function_signature(ctor, ["value"]) + " { count_value = value; }",
                function_signature(methods["get_count"]) + " { return count_value; }",
                function_signature(methods["update"], ["value", "text", "items"]) +
                " { value = int(items.length()); }", "}",
                function_signature(assignment, ["result", "value"]) + " { result = value; }",
                "void use() { Counter c(3); int n = c.count; assign(n); }",
            ])
            compile_source("rendered", namespace_block(declaration, "example"))


if __name__ == "__main__":
    unittest.main()
