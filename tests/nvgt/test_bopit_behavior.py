"""Compare recovered game logic with the available original using deterministic IO.

The game is run against small test doubles, so tests do not open windows, play
audio, wait in real time, or require keyboard interaction.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from decompile import load_any, ModuleDecompiler

ROOT = Path(__file__).resolve().parent / "fixtures"
ORIGINAL = Path(os.environ["NVGT_BOPIT_SOURCE"]) if os.environ.get("NVGT_BOPIT_SOURCE") else None
TARGET = Path(os.environ["NVGT_BOPIT_EXE"]) if os.environ.get("NVGT_BOPIT_EXE") else None
HARNESS = r'''
int mode = 0;
int round_number = 0;
int high_score = 0;
string[] actions = {"Bop It!", "Pull It!", "Twist It!", "Flick It!", "Spin It!"};
const int KEY_ESCAPE=41, KEY_SPACE=44, KEY_UP=82, KEY_LEFT=80, KEY_RIGHT=79,
          KEY_F=9, KEY_S=22;
class pack_interface {}
class sound_pool {
    int play_stationary(string path, bool loop, bool persistent=false) {
        print("sound:"+path+"\n"); return 1;
    }
    int play_3d(string path, pack_interface@ p, float lx, float ly, float lz,
                float sx, float sy, float sz, double rotation, bool loop,
                bool persistent=false) {
        print("spatial:"+sx+","+sy+","+sz+"\n"); return 1;
    }
}
sound_pool s_pool;
class timer {
    timer() { round_number++; }
    uint64 get_elapsed() property { return mode==1 ? 3000 : 0; }
}
void wait(int milliseconds) { print("wait:"+milliseconds+"\n"); }
bool screen_reader_speak(const string&in text, bool interrupt) {
    print("speech:"+text+":"+(interrupt ? "1" : "0")+"\n"); return true;
}
int random(int low, int high) { return 0; }
bool key_pressed(int key) {
    if (mode==0) return key==KEY_ESCAPE;
    if (mode==2 || round_number>21) return key==KEY_F;
    return key==KEY_SPACE;
}
int[] keys_pressed() { return {}; }
void main() {
    for (mode=0; mode<4; mode++) {
        print("scenario:"+mode+"\n");
        round_number=0;
        play_bop_it();
        print("high_score:"+high_score+"\n");
    }
}
'''


class BopItBehaviorTests(unittest.TestCase):
    def test_recovered_game_matches_original_with_deterministic_io(self):
        if ORIGINAL is None or TARGET is None or not ORIGINAL.exists() or not TARGET.exists():
            self.skipTest("optional original BopIt source is unavailable")
        compiler = ROOT / "build/bcdump.exe"
        if not compiler.exists():
            self.skipTest("bcdump test compiler is unavailable")
        original = ORIGINAL.read_text(encoding="utf-8")
        original = original[original.index("void play_bop_it() {"):]
        module = load_any(str(TARGET))
        renderer = ModuleDecompiler(module)
        renderer._render_function(next(f for f in module.script_functions
                                       if f.name == "play_bop_it"))
        recovered = "\n".join(renderer.lines)
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as folder:
            results = []
            for name, body in (("original", original), ("recovered", recovered)):
                source = Path(folder) / (name + ".as")
                source.write_text(HARNESS + body, encoding="utf-8")
                result = subprocess.run(
                    [str(compiler), str(source), str(source.with_suffix(".bin")), "--run"],
                    capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                results.append(result.stdout)
            self.assertEqual(results[1], results[0])
            self.assertEqual(results[0].count("speech:Speeding up!:0"), 1)
            self.assertIn("high_score:21", results[0])


if __name__ == "__main__":
    unittest.main()
