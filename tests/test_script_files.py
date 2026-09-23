"""
Tests for script_files: which source files a stripped module was built from.

Synthetic inputs, like the rest of the suite. Each test pins something that
would fail QUIETLY -- a plausible file list that is wrong:

  * a game class that merely shares a library class's name is claimed
  * a derived class, whose method list carries inherited methods, is not
  * two library files declaring the same class resolve by name order
  * a return type written against the name (`pack@open_pack(`) hides a function
  * a game's namespaced copy of library code is taken for the library
  * a compiler-made lambda, positioned after everything, is left unclaimed
  * a file seen in only one pass is merged into the wrong place
  * two passes that disagree are forced together instead of reported

The optional last test builds a real NVGT module that includes a shipped library
file, strips it, and scores the attribution against the debug build's own
record of every declaration's file. Needs NVGT_COMPILER; skips otherwise.

Run:  python -m pytest tests/ -q
"""

import os
import shutil
import sys
import tempfile
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.join(HERE, "..", "tools")
if TOOLS not in sys.path:
    sys.path.insert(0, TOOLS)

import pytest

import cli
import script_files as sf
from script_files import Entity, SourceFile

MENU_SRC = """
#include "speech.bgt"
// class commented_out { void nope() {} }
enum menu_mode { menu_flat, menu_nested }
class menu {
    string title;
    menu(string t) { title = t; }
    ~menu() {}
    void add_item(string text) { if (text == "}") return; }
    int run() const { return 0; }
    bool is_open() { return true; }
}
namespace helpers {
    pack@open_pack(const string&in name) { return null; }
    class tool { void use() {} }
}
string menu_version() { return "1{"; }
"""


# --------------------------------------------------------------------------
# scanning library sources
# --------------------------------------------------------------------------

def test_scan_source_finds_declarations_not_bodies():
    s = sf.scan_source(MENU_SRC, "menu.bgt")
    assert s.classes == {"menu": {"add_item", "run", "is_open"},
                         "helpers::tool": {"use"}}       # constructor/destructor excluded
    assert s.functions == {"menu_version", "helpers::open_pack"}
    assert s.enums == {"menu_mode"}
    assert s.includes == ["speech.bgt"]
    assert s.declarations() == 5


def test_return_type_against_the_name_is_still_a_function():
    # NVGT's bgt_compat.nvgt writes `pack@open_pack(...)`: no space before the
    # name. Requiring one lost the function and cost an attribution.
    assert sf.scan_source("pack@open_pack(const string&in f) { return null; }").functions \
        == {"open_pack"}
    assert sf.scan_source("array<int>@ make_list() { return null; }").functions == {"make_list"}
    # ...and input_forms.nvgt writes `#include"form.nvgt"`, which hid that
    # nothing can sit between the two files
    assert sf.scan_source('#include"form.nvgt"\n#include  "a b.nvgt"').includes \
        == ["form.nvgt", "a b.nvgt"]


# --------------------------------------------------------------------------
# attribution
# --------------------------------------------------------------------------

LIBRARY = [
    SourceFile("menu.bgt", classes={"menu": {"add_item", "run", "is_open"}},
               functions={"menu_version"}),
    SourceFile("speech.bgt", functions={"speak", "stop_speech"}),
]


def test_library_class_and_functions_are_attributed():
    entities = [Entity("class", "player", {"move"}),
                Entity("class", "menu", {"add_item", "run", "is_open"}),
                Entity("function", "main"), Entity("function", "menu_version"),
                Entity("function", "speak"), Entity("function", "stop_speech")]
    a = sf.attribute(entities, LIBRARY)
    assert a.owner == [None, "menu.bgt", None, "menu.bgt", "speech.bgt", "speech.bgt"]
    assert [r[0] for r in a.included] == ["menu.bgt", "speech.bgt"]


def test_game_class_sharing_a_library_name_is_not_claimed():
    # The game's own `menu`, nothing like the library's: a name is not enough.
    # The library file declares nothing else, so coverage alone would be 1/1.
    library = [SourceFile("menu.bgt", classes={"menu": {"add_item", "run", "is_open"}})]
    entities = [Entity("class", "menu", {"draw", "click", "resize"}),
                Entity("function", "main")]
    a = sf.attribute(entities, library)
    assert a.owner == [None, None]
    assert a.included == [] and a.candidates == []


def test_derived_nvgt_class_is_compared_by_its_own_methods():
    # An NVGT class's `methods` include inherited ones, listed under the base.
    # Its own are the vftable entries it owns -- compared in full, every
    # derived class failed to match its source.
    from types import SimpleNamespace as NS
    base = NS(name="text_field")
    cls = NS(name="number_field", namespace_="", enum_values=[], kind="",
             constructors=[], factories=[], methods=[], vft=[])
    cls.vft = [NS(name="fill", object_type=base, script_section="", bytecode=[]),
               NS(name="configure", object_type=base, script_section="", bytecode=[]),
               NS(name="set_value", object_type=cls, script_section="", bytecode=[]),
               NS(name="is_valid", object_type=cls, script_section="", bytecode=[])]
    cls.methods = list(cls.vft)
    module = NS(classes=[cls], script_functions=[], enums=[], globals=[])
    [entity] = sf.nvgt_entities(module)
    assert entity.members == {"set_value", "is_valid"}
    library = [SourceFile("forms.nvgt", classes={"number_field": {"set_value", "is_valid"}})]
    assert sf.attribute([entity], library).owner == ["forms.nvgt"]


def test_namespaced_copy_of_library_code_stays_game_code():
    # Manamon 2 carries `rhythm::position_sound_1d` beside the library's own.
    # Unqualified, the copy matched, and the code between the two copies was
    # then filled in as library code.
    from types import SimpleNamespace as NS
    def fn(name, ns=""):
        return {"owner": None, "name": name, "namespace": ns}
    mod = NS(script_classes=[], info={"enums": []}, tail={},
             functions=[fn("main"), fn("position_1d"), fn("play_noise"),
                        fn("position_1d", "rhythm")])
    entities = sf.bgt_entities(mod)
    assert [e.name for e in entities] == ["main", "position_1d", "play_noise",
                                          "rhythm::position_1d"]
    library = [SourceFile("positioning.bgt", functions={"position_1d"})]
    assert sf.attribute(entities, library).owner == [None, "positioning.bgt", None, None]


def test_partially_present_file_is_a_candidate_not_a_claim():
    library = [SourceFile("big.bgt", functions={"a", "b", "c", "d", "e"})]
    a = sf.attribute([Entity("function", "a"), Entity("function", "main")], library)
    assert a.included == [] and a.candidates == [("big.bgt", 1, 5)]
    assert a.owner == [None, None]


def test_best_method_agreement_wins_a_shared_class_name():
    # NVGT ships sound_pool.nvgt and legacy_sound_pool.nvgt, both declaring
    # `sound_pool`. Alphabetical order picked the legacy one; agreement does not.
    library = [SourceFile("legacy_pool.nvgt", classes={"pool": {"play", "stop"}}),
               SourceFile("pool.nvgt", classes={"pool": {"play", "stop", "pause", "update"}})]
    a = sf.attribute([Entity("class", "pool", {"play", "stop", "pause", "update"})], library)
    assert a.owner == ["pool.nvgt"]


def test_file_with_nothing_of_its_own_is_not_included():
    # NVGT's legacy_sound_pool shares globals and helpers with sound_pool.
    # Its class loses the method comparison, and what is left -- declarations
    # the other file explains just as well -- is no evidence it was included.
    library = [SourceFile("pool.nvgt", classes={"pool": {"play", "stop", "pause"}},
                          functions={"helper"}, globals={"POOL_MAX"}),
               SourceFile("legacy_pool.nvgt", classes={"pool": {"legacy_play"}},
                          functions={"helper"}, globals={"POOL_MAX"})]
    entities = [Entity("class", "pool", {"play", "stop", "pause"}),
                Entity("function", "helper"), Entity("global", "POOL_MAX")]
    a = sf.attribute(entities, library)
    assert [n for n, _, _ in a.included] == ["pool.nvgt"]
    assert a.owner == ["pool.nvgt"] * 3


def test_global_variables_are_declarations_too():
    # sqlite3constants.nvgt declares nothing but constants.
    s = sf.scan_source('int SQLITE_OK = 0; /* ok */\nconst string a = "x,y", b;\n'
                       'sound_pool pool(100);\nfuncdef void cb();\nclass fwd;')
    assert s.globals == {"SQLITE_OK", "a", "b", "pool"}
    assert s.functions == set() and s.classes == {}


def test_unclaimed_run_inside_one_library_file_is_that_files():
    library = [SourceFile("lib.bgt", functions={"f1", "f3"})]
    entities = [Entity("function", "main"), Entity("function", "f1"),
                Entity("function", "missed_by_the_scanner"), Entity("function", "f3"),
                Entity("function", "after")]
    a = sf.attribute(entities, library)
    assert a.owner == [None, "lib.bgt", "lib.bgt", "lib.bgt", None]


def test_lambda_goes_with_the_function_that_creates_it():
    # Lambdas are compiled after every declaration, so they sit at the end of
    # the function pass whatever file they came from.
    library = [SourceFile("stats.nvgt", classes={"stat_set": {"list", "add"}},
                          functions={"helper"})]
    entities = [Entity("function", "main"), Entity("function", "helper"),
                Entity("function", "__nvgt_lambda_1", container=("class", "stat_set")),
                Entity("class", "stat_set", {"list", "add"})]
    a = sf.attribute(entities, library)
    assert a.owner == [None, "stats.nvgt", "stats.nvgt", "stats.nvgt"]
    # ...and stays out of the file-order runs, where it would be a false anchor
    assert [o for o, _ in a.runs({"function"})] == [None, "stats.nvgt"]


def test_accuracy_counts_game_code_as_right_when_unclaimed():
    entities = [Entity("function", "main", truth="game.nvgt"),
                Entity("function", "speak", truth="speech.bgt"),
                Entity("function", "stop_speech", truth="speech.bgt")]
    assert sf.attribute(entities, LIBRARY).accuracy() == (3, 3)


# --------------------------------------------------------------------------
# merging the two passes
# --------------------------------------------------------------------------

POOL_LIBRARY = [
    SourceFile("pool.bgt", classes={"pool": {"play"}}, includes=["positioning.bgt"]),
    SourceFile("positioning.bgt", functions={"position_1d"}),
    SourceFile("menu.bgt", classes={"menu": {"run"}}),
]


def _pool_game():
    return [Entity("class", "player", {"move"}), Entity("class", "pool", {"play"}),
            Entity("class", "enemy", {"hit"}), Entity("class", "menu", {"run"}),
            Entity("class", "shop", {"buy"}),
            Entity("function", "main"), Entity("function", "setup"),
            Entity("function", "position_1d"), Entity("function", "late_helper")]


def test_file_seen_in_one_pass_follows_its_includer():
    a = sf.attribute(_pool_game(), POOL_LIBRARY)
    segments, problems = sf.file_order(a, POOL_LIBRARY)
    assert problems == []
    assert [s.file for s in segments] == [None, "pool.bgt", "positioning.bgt", None,
                                          "menu.bgt", None]
    assert segments[2].note == "included by pool.bgt"


def test_main_file_functions_are_placed_exactly():
    # Nothing can sit between pool.bgt and the positioning.bgt it includes, so
    # the functions before position_1d belong to the first segment -- exactly.
    a = sf.attribute(_pool_game(), POOL_LIBRARY)
    segments, _ = sf.file_order(a, POOL_LIBRARY)
    first = segments[0]
    assert [e.name for e in first.classes] == ["player"]
    assert [e.name for e in first.functions] == ["main", "setup"]
    assert first.note == ""
    # the functions after it could be in either later game run: said, not guessed
    after = next(s for s in segments if any(e.name == "late_helper" for e in s.functions))
    assert "somewhere from here to the end" in after.note


def test_passes_that_disagree_are_reported_not_forced():
    library = [SourceFile("a.bgt", classes={"ca": set()}, functions={"fa"}),
               SourceFile("b.bgt", classes={"cb": set()}, functions={"fb"})]
    entities = [Entity("class", "ca"), Entity("class", "cb"),
                Entity("function", "fb"), Entity("function", "fa")]
    _, problems = sf.file_order(sf.attribute(entities, library), library)
    assert problems and "order the library files differently" in problems[0]


def test_report_lists_only_top_level_includes():
    a = sf.attribute(_pool_game(), POOL_LIBRARY)
    text = sf.report(a, POOL_LIBRARY)
    assert '#include "pool.bgt"' in text and '#include "menu.bgt"' in text
    assert '#include "positioning.bgt"' not in text      # comes in through pool.bgt
    assert "declares main()" in text


def test_cli_dispatches_files_and_rejects_bgt_without_exe(tmp_path, capsys):
    module = tmp_path / "module.bin"
    module.write_bytes(b"\0" * 16)
    # a lone .bin is read as NVGT; with no include folder that is a usage error
    assert cli.main(["files", str(module), "--include", str(tmp_path / "none")]) == 2
    assert "library source folder" in capsys.readouterr().err


# --------------------------------------------------------------------------
# against a real NVGT, scored by its own debug information
# --------------------------------------------------------------------------

COMPILER = Path(os.environ["NVGT_COMPILER"]) if os.environ.get("NVGT_COMPILER") else None

GAME_SCRIPT = """#include "form.nvgt"
class player { int hp; void hurt(int n) { hp -= n; } }
int score(int a) { return a * 2; }
void main() {
\tplayer p; p.hurt(1);
\tfile_put_contents("debug.bin", script_get_module("nvgt_game", 0).get_bytecode(false));
\tfile_put_contents("strip.bin", script_get_module("nvgt_game", 0).get_bytecode(true));
}
"""


@pytest.mark.skipif(not (COMPILER and COMPILER.exists()),
                    reason="set NVGT_COMPILER to an nvgt.exe for the ground-truth check")
def test_stripped_nvgt_attribution_matches_debug_information():
    import subprocess
    from nvgt import decompile

    include = Path(os.environ.get("NVGT_INCLUDE") or COMPILER.parent / "include")
    work = Path(tempfile.mkdtemp(prefix="script_files_"))
    try:
        (work / "game.nvgt").write_text(GAME_SCRIPT, encoding="utf-8")
        subprocess.run([str(COMPILER), "game.nvgt"], cwd=work, capture_output=True,
                       timeout=90, check=False)
        assert (work / "strip.bin").exists(), "the harness did not export its module"
        library = sf.library_index([str(include)], ("*.nvgt",))
        truth = sf.nvgt_entities(decompile.load_any(str(work / "debug.bin")))
        stripped = sf.nvgt_entities(decompile.load_any(str(work / "strip.bin")))
        assert [e.name for e in truth] == [e.name for e in stripped]
        assert all(e.truth is None for e in stripped)       # really stripped
        for e, t in zip(stripped, truth):
            e.truth = t.truth
        a = sf.attribute(stripped, library)
        right, known = a.accuracy()
        assert right == known, sf.report(a, library)
        assert "form.nvgt" in [n for n, _, _ in a.included]
        segments, problems = sf.file_order(a, library)
        assert problems == []
        assert any(e.name == "main" for e in segments[0].functions)
    finally:
        shutil.rmtree(work, ignore_errors=True)
