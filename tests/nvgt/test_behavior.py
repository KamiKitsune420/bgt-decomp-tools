"""Execution checks: python -m unittest -v test_behavior.

Each owned program is compiled with stripped debug metadata, decompiled,
compiled again, and executed. Both executions must match the known result.
The small bcdump host exposes stdout through print(), so failures distinguish
compilable output from source that actually preserves behavior.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest

from decompile import decompile_module, load_any


ROOT = Path(__file__).resolve().parent / "fixtures"
COMPILER = ROOT / "build/bcdump.exe"


@unittest.skipUnless(COMPILER.exists(), "build/bcdump.exe unavailable")
class BehaviorTests(unittest.TestCase):
    def test_namespaces_preserve_overlapping_names_and_cross_namespace_calls(self):
        self.roundtrip('''
namespace left {
    enum Mode { active = 7 }
    typedef int64 Count;
    int value = 3;
    string label = "left";
    funcdef int Mapper(int);
    class Item { int number; Item(int n) { number = n; } }
    int get() { value++; return value; }
}
namespace right {
    int value = 20;
    int get() { return value + left::get(); }
}
void main() {
    left::Item item(5);
    print("" + right::get() + ":" + left::value + ":" + item.number + ":" + left::label);
}
''', "24:4:5:left")

    def test_cross_namespace_callbacks_and_complex_global_initializers(self):
        self.roundtrip('''
namespace left {
    funcdef int Mapper(int);
    int apply(int n) { return n + 3; }
    Mapper@ callback = apply;
    string label = "left::label" + apply(2);
}
namespace right { int apply(int n) { return n + 20; } }
void main() {
    left::Mapper@ callback = left::apply;
    print("" + callback(2) + ":" + right::apply(1) + ":" + left::label);
}
''', "5:21:left::label5")

    def test_destructor_body_preserves_observable_cleanup(self):
        self.roundtrip('''
class Tracked {
    int number;
    Tracked(int n) explicit { number = n; }
    ~Tracked() { print("drop:" + number + ";"); }
    void touch() { number += 1; }
}
void use() { Tracked object(3); object.touch(); print("during;"); }
void main() { use(); print("after;"); }
''', "during;drop:4;after;")

    def test_interleaved_namespaces_preserve_global_initializer_order(self):
        self.roundtrip('''
int trace = 0;
int remember(int n) { trace = trace * 10 + n; return n; }
namespace first { int one = remember(1); }
namespace second { int two = remember(2); }
namespace first { int three = remember(3); }
void main() { print("" + trace + ":" + first::one + second::two + first::three); }
''', "123:123")

    def test_binary_string_literals_preserve_null_and_non_utf8_bytes(self):
        self.roundtrip(r'''
string bytes_value = "\xFF\x00\x01\x7FA";
void main() {
    print("" + bytes_value.length() + ":" + int(bytes_value[0]) + ":"
        + int(bytes_value[1]) + ":" + int(bytes_value[2]) + ":"
        + int(bytes_value[3]) + ":" + int(bytes_value[4]));
}
''', "5:255:0:1:127:65")

    def test_binary_string_literals_preserve_all_256_byte_values(self):
        literal = "".join("\\x" + format(value, "02x") for value in range(256))
        self.roundtrip('string bytes_value = "' + literal + '\";\n' + '''
void main() {
    int total = 0;
    int weighted = 0;
    for (uint i = 0; i < bytes_value.length(); i++) {
        total += int(bytes_value[i]);
        weighted += int(bytes_value[i]) * (int(i) + 1);
    }
    print("" + bytes_value.length() + ":" + total + ":" + weighted);
}
''', "256:32640:5592320")

    def test_saved_plain_scope_restores_destructor_timing(self):
        self.roundtrip('''
class Tracked {
    int number;
    Tracked(int n) { number = n; }
    ~Tracked() { print("drop:" + number + ";"); }
    void tick() { number++; }
}
void main() {
    print("begin;");
    { Tracked object(3); object.tick(); print("during;"); }
    print("after;");
}
''', "begin;during;drop:4;after;")

    def test_handle_value_survives_sibling_null_branch(self):
        self.roundtrip('''
array<int>@ choose(bool present) {
    array<int>@ values;
    if (present) @values = array<int>();
    else @values = null;
    return values;
}
void main() {
    array<int>@ result = choose(true);
    array<int>@ missing = choose(false);
    print("" + result.length() + ":" + (missing is null ? "null" : "bad"));
}
''', "0:null")

    def test_factory_result_survives_earlier_null_return_branch(self):
        self.roundtrip('''
array<int>@ make_values(bool early) {
    if (early) return null;
    array<int>@ values = array<int>();
    values.insertLast(7);
    return values;
}
void main() {
    array<int>@ result = make_values(false);
    print("" + result.length() + ":" + result[0]);
}
''', "1:7")

    def test_uint_counter_and_boolean_share_saved_slot_without_type_loss(self):
        self.roundtrip('''
void main() {
    uint total = 0;
    for (uint index = 0; index < 3; index++) total += index;
    for (uint index = 0; index < 2; index++) total += 3;
    { bool good = false; if (!good) total += 5; }
    print("" + total);
}
''', "14")

    def roundtrip(self, source, expected, strip=True):
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as folder:
            folder = Path(folder)
            original = folder / "original.as"
            original.write_text(source, encoding="utf-8")
            first = self.compile_and_run(original, strip=strip)
            self.assertEqual(first, expected, "original test program result")
            recovered = folder / "recovered.as"
            recovered.write_text(decompile_module(load_any(str(original.with_suffix(".bin")))),
                                 encoding="utf-8")
            second = self.compile_and_run(recovered, strip=strip)
            self.assertEqual(second, expected, recovered.read_text(encoding="utf-8"))

    def compile_and_run(self, path, strip=True):
        result = subprocess.run([str(COMPILER), str(path), str(path.with_suffix(".bin")),
                                 *(["--strip"] if strip else []), "--run"],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0,
                         result.stderr + "\n" + path.read_text(encoding="utf-8"))
        return result.stdout

    def test_debug_parameter_names_do_not_shadow_object_fields(self):
        self.roundtrip('''
class Worker { int n; Worker(int n) { this.n = n; } int sum(int n) { return this.n + n; } }
void main() { Worker w(7); print("" + w.sum(9)); }
''', "16", strip=False)

    def test_parameter_writes_are_assignments_before_return(self):
        self.roundtrip('''
funcdef string Filter(const string&in);
string upper(const string&in text) { return "changed:" + text; }
bool say(string text, Filter@ filter) {
    if (filter != null) text = filter(text);
    print(text + ";"); return true;
}
uint wrap(int n, int step = 1) {
    n += step;
    if (n < 0) return 3;
    if (n > 3) return 0;
    return n;
}
void main() {
    say("hello", upper); say("plain", null);
    print("" + wrap(-2) + ":" + wrap(3) + ":" + wrap(1));
}
''', "changed:hello;plain;3:0:2")

    def test_object_returns_on_early_paths_preserve_later_mutations(self):
        self.roundtrip('''
array<int>@ selections(int mode) {
    array<int> values;
    if (mode < 0) return values;
    if (mode == 0) return values;
    if (mode == 1) { values.insertLast(7); return values; }
    for (int i = 0; i < mode; i++) values.insertLast(i);
    return values;
}
void main() {
    print("" + selections(-1).length() + ":" + selections(0).length()
          + ":" + selections(1)[0] + ":" + selections(3)[2]);
}
''', "0:0:7:2")

    def test_reused_scalar_and_string_slots_in_sibling_scopes(self):
        self.roundtrip('''
string describe(int mode) {
    string result;
    if (mode == 1) {
        int counter = 4; while (counter < 6) counter++;
        bool ok = counter == 6;
        string message = ok ? "yes" : "no";
        result += message;
    }
    if (mode == 2) {
        string message = "second";
        int counter = 0; while (counter < 3) counter++;
        result += message + ":" + counter;
    }
    return result;
}
void main() { print(describe(1) + ";" + describe(2) + ";" + describe(0)); }
''', "yes;second:3;")

    def test_dictionary_callback_mutation_survives_conditional_cleanup(self):
        self.roundtrip('''
funcdef int Event(dictionary@);
int allow(dictionary@ d) { d.set("seen", true); return 0; }
int reject(dictionary@ d) { return 1; }
void handle(Event@ event) {
    dictionary data = {{"key", 82}, {"boundary", true}};
    if (event != null && event(data) == 1) return;
    if (data.exists("seen")) print("seen;");
    if (data.exists("boundary")) print("boundary;");
}
void main() { handle(allow); handle(reject); handle(null); }
''', "seen;boundary;boundary;")

    def test_empty_dictionary_list_factories_reuse_allocated_slots(self):
        self.roundtrip('''
int process(dictionary@ data) { return int(data.getSize()); }
void main() {
    { dictionary one; print("" + process({})); }
    { dictionary two = {{"value", 7}}; print(":" + process(two)); }
    { dictionary three; print(":" + process({})); }
}
''', "0:1:0")

    def test_boolean_ternary_arguments_and_handle_callback_arguments(self):
        self.roundtrip('''
bool setting = true;
enum EventType { FIRST = 1 }
class Form { int value = 7; }
funcdef int Callback(Form@, EventType, dictionary@);
int callback(Form@ f, EventType e, dictionary@ d) { return f.value + int(e); }
bool take(bool value) { return value; }
void show(bool option) {
    Form form;
    Callback@ cb = callback;
    dictionary data;
    print("" + take(option ? true : false) + ":" + take(option ? setting : false)
          + ":" + cb(form, FIRST, data) + ";");
}
void main() { show(true); show(false); }
''', "true:true:8;false:false:8;")

    def test_boolean_short_circuit_side_effects(self):
        self.roundtrip('''
int calls = 0;
bool probe(bool value) { calls++; return value; }
void main() {
    bool a = (false && probe(true)) || probe(true);
    bool b = (true || probe(false)) && probe(false);
    if (a && !b) print("ok:");
    print("" + calls);
}
''', "ok:2")

    def test_anonymous_sort_callback_and_reversed_string_addition(self):
        self.roundtrip('''
void main() {
    array<int> values = {2, 7, 4};
    values.sort(function(a, b) { return a > b; });
    print(values[0] + ":" + values[1] + ":" + values[2]);
}
''', "7:4:2")

    def test_method_delegate_keeps_bound_object(self):
        self.roundtrip('''
funcdef int callback(int);
class Worker { int factor; Worker(int n) { factor = n; } int apply(int n) { return n * factor; } }
void main() { Worker w(7); callback@ f = callback(w.apply); print("" + f(3)); }
''', "21")

    def test_script_handle_list_preserves_each_object(self):
        self.roundtrip('''
class Box { int n; Box(int x) { n = x; } }
void main() {
    array<Box@> items = {Box(9), Box(4), Box(5)};
    items[1].n = 13;
    print("" + items[0].n + ":" + items[1].n + ":" + items[2].n);
}
''', "9:13:5")

    def test_object_handle_returns_and_null_arguments(self):
        self.roundtrip('''
class Box {
    int value;
    Box(int n) { value = n; }
}
Box@ make_box() { return Box(7); }
int read_box(Box@ item) {
    if (item is null) return -1;
    return item.value;
}
void main() {
    Box@ item = make_box();
    print("" + read_box(null) + ":" + read_box(item));
}
''', "-1:7")

    def test_loops_globals_and_discarded_calls(self):
        self.roundtrip('''
int calls = 0;
int bump() { calls++; return calls; }
void main() {
    bump();
    bump();
    int sum = 0;
    int n = 0;
    while (n < 4) { sum += n; n++; }
    print("" + calls + ":" + sum);
}
''', "2:6")

    def test_overloads_and_string_returns(self):
        self.roundtrip('''
string label(int value) { return "int=" + value; }
string label(const string &in value) { return "str=" + value; }
void main() {
    print(label(4) + ";" + label("hello"));
}
''', "int=4;str=hello")

    def test_global_string_array_initializer(self):
        self.roundtrip('''
array<string> names = {"north", "south"};
void main() {
    print(names[0] + ":" + names[1]);
}
''', "north:south")

    def test_nested_conditional_constructor_arguments(self):
        self.roundtrip('''
bool choose = true;
int calls = 0;
string part(string value) { calls++; return value; }
class Item {
    string name;
    int code;
    Item(string value, int n) { name = value; code = n; }
}
Item item(part("pre") + (choose ? part("yes") : part("no")), 37);
void main() {
    print(item.name + ":" + item.code + ":" + calls);
}
''', "preyes:37:2")

    def test_multistatement_global_initializer(self):
        self.roundtrip('''
bool choose = false;
int calls = 0;
int mark(int n) { calls++; return n; }
int value = int(choose ? double(mark(8)) : double(mark(3)));
void main() { print("" + value + ":" + calls); }
''', "3:1")

    def test_nested_array_factory_assignment(self):
        self.roundtrip('''
array<string>@ make_names() {
    array<string> values = {"east", "west"};
    return values;
}
int size_of(array<string>@ values) { return values.length(); }
string describe(array<string>@ values, int n) {
    return values[0] + ":" + n;
}
void main() {
    array<string> names = make_names();
    print(names[1] + ":" + describe(make_names(), size_of(make_names())));
}
''', "west:east:2")

    def test_array_value_return_protocol(self):
        self.roundtrip('''
array<string> revise(array<string> values) {
    values.insertLast("tail");
    return values;
}
void main() {
    array<string> original = {"head"};
    array<string> result = revise(original);
    print(result[1] + ":" + result.length() + ":" + original.length());
}
''', "tail:2:1")

    def test_registered_enum_preserves_outer_arguments(self):
        self.roundtrip('''
string show(int n, bool enabled) { return "" + n + ":" + enabled; }
void main() {
    int n = int(get_host_mode());
    print(show(n == 2 ? 7 : 9, false));
    print(show(int(get_host_mode()) == 2 ? 4 : 6, true));
}
''', "7:false4:true")

    def test_properties_after_reference_array_index(self):
        self.roundtrip('''
class Control { int kind = 5; string text = "ready"; bool enabled = true; }
void main() {
    array<Control@> controls;
    controls.insertLast(Control());
    controls[0].kind = 7;
    print(controls[0].text + ":" + controls[0].kind + ":" + controls[0].enabled);
}
''', "ready:7:true")

    def test_dictionary_list_and_generic_output_arguments(self):
        self.roundtrip('''
void main() {
    dictionary values = {{"enabled", true}, {"count", 3}, {"label", "ready"}};
    bool enabled = false;
    int count = 0;
    string label;
    values.get("enabled", enabled);
    values.get("count", count);
    values.get("label", label);
    print(label + ":" + count + ":" + enabled);
}
''', "ready:3:true")

    def test_explicit_string_comparison_result(self):
        self.roundtrip('''
void main() {
    string a = "north";
    string b = "south";
    int order = a.opCmp(b);
    print("" + (order < 0) + ":" + (a < b) + ":" + (a > b));
}
''', "true:true:false")

    def test_try_catch_and_nested_return_paths(self):
        self.roundtrip('''
int check(bool fail) {
    int result = 3;
    try {
        if (fail) raise_error();
        result += 4;
    } catch { result += 10; }
    return result;
}
int nested() {
    try { raise_error(); return 1; }
    catch {
        try { raise_error(); return 2; }
        catch { return 9; }
    }
}
void main() { print("" + check(false) + ":" + check(true) + ":" + nested()); }
''', "7:13:9")

    def test_dense_switch_string_and_integer_returns(self):
        self.roundtrip('''
string label(int n) {
    switch (n) {
        case 3: return "a";
        case 4: return "b";
        case 5: return "c";
        case 6: return "d";
        default: return "x";
    }
}
int value(int n) {
    switch (n) {
        case 0: return 4;
        case 1: return 7;
        case 2: return 9;
        case 3: return 2;
        default: return -1;
    }
}
void main() {
    for (int n = -1; n < 8; n++) print(label(n) + ":" + value(n) + ";");
}
''', "x:-1;x:4;x:7;x:9;a:2;b:-1;c:-1;d:-1;x:-1;")

    def test_empty_catch_regions_preserve_exception_swallowing(self):
        self.roundtrip('''
int count = 0;
void main() {
    try { count++; raise_error(); count += 100; } catch {}
    try { count += 2; raise_error(); count += 200; } catch {}
    print("" + count);
}
''', "3")

    def test_infinite_loop_with_break_and_continue(self):
        self.roundtrip('''
int visits = 0;
int total = 0;
void main() {
    while (true) {
        visits++;
        if (visits == 4) break;
        if (visits == 2) continue;
        total += visits;
    }
    print("" + visits + ":" + total);
}
''', "4:4")

    def test_scalar_array_reference_writes_and_increments(self):
        self.roundtrip('''
void main() {
    array<int> counts = {2, 5};
    array<bool> flags = {false, false};
    counts[0]++;
    counts[1] = 9;
    --counts[1];
    flags[1] = true;
    print("" + counts[0] + ":" + counts[1] + ":" + flags[0] + ":" + flags[1]);
}
''', "3:8:false:true")

    def test_do_while_nested_branches_and_following_code(self):
        self.roundtrip('''
int count = 0;
int total = 0;
void main() {
    do {
        count++;
        if (count == 2) continue;
        if (count < 3) total += 10;
        else total += 20;
    } while (count < 4 && total < 100);
    print("" + count + ":" + total);
}
''', "4:50")

    def test_method_hidden_string_return_slot(self):
        self.roundtrip('''
class Formatter {
    string format(string text, bool expand) {
        if (text == "!") return "bang";
        if (expand) {
            if (text == "UP") return "prefix:" + text;
        } else {
            if (text == "low") return text;
        }
        return "fallback:" + text;
    }
}
void main() {
    Formatter@ f = Formatter();
    print(f.format("!", true) + ";" + f.format("UP", true) + ";"
        + f.format("low", false) + ";" + f.format("UP", false));
}
''', "bang;prefix:UP;low;fallback:UP")

    def test_scoped_counter_reuse_preserves_handle_across_branches(self):
        self.roundtrip('''
class Item {
    int value;
    Item(int n) { value = n; }
    int number() const { return value; }
}
void main() {
    for (uint i = 0; i < 1; i++) print("start;");
    array<Item@> items;
    items.insertLast(Item(1));
    items.insertLast(Item(2));
    items.insertLast(Item(3));
    for (uint i = 0; i < items.length(); i++) {
        Item@ item = items[i];
        if (item.number() == 1) continue;
        if (item.number() == 2) { print("two;"); continue; }
        print("" + item.number() + ";");
    }
    for (uint i = 0; i < 1; i++) print("end");
}
''', "start;two;3;end")

    def test_sparse_switch_breaks_and_fallthrough(self):
        self.roundtrip('''
int value(int n) {
    int result = 0;
    switch (n) {
        case 0: result += 1; break;
        case 1: result += 2;
        case 100: result += 4; break;
        default: result += 8;
    }
    return result + 10;
}
void main() {
    print("" + value(-1) + ":" + value(0) + ":" + value(1)
        + ":" + value(100) + ":" + value(2));
}
''', "18:11:16:14:18")

    def test_for_increment_with_nested_continue_paths(self):
        self.roundtrip('''
int visits = 0;
int total = 0;
void main() {
    for (int n = 8; n >= 0; n--) {
        visits++;
        if (n > 5) {
            if (n == 7) total += 100;
            else { total += 10; continue; }
        }
        if (n == 4) {
            if (total > 0) { total += 20; continue; }
        }
        total += n;
    }
    print("" + visits + ":" + total);
}
''', "9:158")

    def test_global_reference_read_before_member_writes(self):
        self.roundtrip('''
float facing = 2.5;
int consume(const float&in value) { return int(value); }
class State {
    bool enabled;
    int id;
    State() {
        id = consume(facing);
        enabled = true;
    }
}
void main() {
    State@ value = State();
    print("" + value.id + ":" + value.enabled + ":");
    value.enabled = false;
    value.id = 9;
    facing += 1.0;
    print("" + value.id + ":" + value.enabled + ":" + facing);
}
''', "2:true:9:false:3.5")

    def test_signed_double_and_large_integer_constants(self):
        self.roundtrip('''
double divisor = -1000.0;
double negative = -123.4567;
double tiny = 0.000001;
int64 positive = 0x123456789abcde;
int64 large_negative = -0x123456789abcde;
double divide(double n) { return n / divisor; }
int64 milliseconds(int64 n) { return n / 1000; }
void main() {
    print("" + (divide(2500.0) == -2.5)
        + ":" + (negative > -124.0 && negative < -123.0)
        + ":" + (tiny > 0.0 && tiny < 0.00001)
        + ":" + (positive + large_negative == 0)
        + ":" + (milliseconds(12345000) == 12345));
}
''', "true:true:true:true:true")

    def test_conditional_string_references_in_outer_call(self):
        self.roundtrip('''
string first = "east";
string second = "west";
bool choose = true;
string join(string text, int n, bool enabled) {
    return text + ":" + n + ":" + enabled;
}
void main() {
    print(join("pre:" + (choose ? first : second) + ":post", 27, true));
    choose = false;
    print(join("pre:" + (choose ? first : second) + ":post", 14, false));
}
''', "pre:east:post:27:truepre:west:post:14:false")


if __name__ == "__main__":
    unittest.main()
