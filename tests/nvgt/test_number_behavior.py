"""Blind Number Quest checks: reconstructed owned_traceic, deterministic owned IO.

No original game source or executable is run. Requires the optional challenge
input and installed NVGT. Full UI/speech-library behavior remains unverified.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
import zipfile

from decompile import load_any, ModuleDecompiler
from recover import generate_project

ROOT = Path(__file__).resolve().parent / "fixtures"
TARGET = Path(os.environ["NVGT_NUMBER_EXE"]) if os.environ.get("NVGT_NUMBER_EXE") else None
COMPILER = Path(os.environ["NVGT_COMPILER"]) if os.environ.get("NVGT_COMPILER") else None
HARNESS = r'''
int secret = 0, attempts = 0, best_score = 0;
bool tts_default_interrupt = true;
funcdef string text_processing_callback(const string&in);
text_processing_callback@ tts_default_text_processing_callback;
string[] inputs;
uint cursor = 0;
string owned_trace;
int owned_random(int low, int high) { return 42; }
string owned_input(string title, string message, string initial, int flags) {
    if (cursor >= inputs.length()) return "";
    return inputs[cursor++];
}
bool owned_speak(string message, bool interrupt, text_processing_callback@ cb, bool braille) {
    owned_trace += "speech|" + message + "\n"; return true;
}
void state(string name) {
    owned_trace += "case|" + name + "|" + secret + "|" + attempts + "|" + best_score + "\n";
}
void main() {
    inputs = {""}; cursor = 0; play_round(); state("giveup");
    inputs = {"abc", "0", "101", "1", "100", "42"}; cursor = 0;
    play_round(); state("bounds-low-high-win");
    inputs = {"42"}; cursor = 0; play_round(); state("better-score");
    inputs = {"1", "2", "3", "42"}; cursor = 0; play_round(); state("slower-score");
    inputs = {"Y", "yes", ""}; cursor = 0;
    bool a = play_again(), b = play_again(), c = play_again();
    owned_trace += "again|" + (a ? "yes" : "no") + "|" + (b ? "yes" : "no")
           + "|" + (c ? "yes" : "no") + "\n";
    file output; output.open("REPORT_PATH", "w"); output.write(owned_trace); output.close();
}
'''


@unittest.skipUnless(TARGET and COMPILER and TARGET.exists() and COMPILER.exists(),
                     "set NVGT_NUMBER_EXE and NVGT_COMPILER for optional challenge checks")
class NumberBehaviorTests(unittest.TestCase):
    def test_complete_project_compiles_to_valid_release_package(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as work:
            folder = Path(work)
            manifest = generate_project(TARGET, folder / "project")
            self.assertEqual(manifest["packaging_profile"], "custom_pe_bound_xchacha_aes_20260820")
            self.assertEqual((manifest["classes"], manifest["script_functions"], manifest["globals"]), (6, 21, 19))
            environment = os.environ.copy()
            environment["TEMP"] = environment["TMP"] = str(folder)
            result = subprocess.run([str(COMPILER), "-c", str(folder / "project/main.nvgt")],
                                    env=environment, capture_output=True, text=True, timeout=50)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(all(value == 0 for value in manifest["diagnostics"].values()))
            with zipfile.ZipFile(folder / "project/main.zip") as package:
                self.assertIsNone(package.testzip())
                self.assertTrue(any(name.endswith(".exe") and package.getinfo(name).file_size > 0
                                    for name in package.namelist()))

    def test_guessing_and_scores_with_owned_io(self):
        module = load_any(str(TARGET))
        renderer = ModuleDecompiler(module)
        for name in ("new_round", "play_again", "play_round", "report_win"):
            renderer._render_function(next(f for f in module.script_functions if f.name == name))
        body = "\n".join(renderer.lines)
        # Rename only call identifiers; preserve recovered message strings.
        for native, owned in (("random", "owned_random"), ("input_box", "owned_input"),
                              ("speak", "owned_speak")):
            body = re.sub(r"\b" + native + r"(?=\s*\()", owned, body)
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as work:
            folder = Path(work)
            report = folder / "report.txt"
            source = folder / "owned_io.nvgt"
            source.write_text(HARNESS.replace("REPORT_PATH", report.as_posix()) + body, encoding="utf-8")
            environment = os.environ.copy()
            environment["TEMP"] = environment["TMP"] = str(folder)
            result = subprocess.run([str(COMPILER), "-Q", str(source)], env=environment,
                                    capture_output=True, text=True, timeout=25)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            owned_trace = report.read_text(encoding="utf-8").splitlines()
        states = [line for line in owned_trace if line.startswith(("case|", "again|"))]
        self.assertEqual(states, ["case|giveup|42|0|0", "case|bounds-low-high-win|42|3|3",
                                 "case|better-score|42|1|1", "case|slower-score|42|4|1",
                                 "again|yes|no|no"])
        self.assertIn("speech|That is not a whole number. Try again.", owned_trace)
        self.assertEqual(owned_trace.count("speech|Stay between 1 and 100. Try again."), 2)
        self.assertIn("speech|Too low. Guess number 1.", owned_trace)
        self.assertIn("speech|Too high. Guess number 2.", owned_trace)
        self.assertIn("speech|Correct! You found 42 in 3 guesses.", owned_trace)
        self.assertEqual(owned_trace.count("speech|That is a new best score!"), 2)
        self.assertIn("speech|Your best is still 1 guesses.", owned_trace)


if __name__ == "__main__":
    unittest.main()
