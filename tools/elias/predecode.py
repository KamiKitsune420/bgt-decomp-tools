r"""Decode one theme's stems to raw 16-bit PCM for the elias harness.

The harness is C# and cannot decode Ogg Vorbis, and the whole theme will not
fit in a 32-bit process anyway -- 91 stems of 93 seconds is about 1.5 GB. The
source protocol streams (op 2 rewinds, op 1 reads N samples), so the harness
reads from disk on demand and only needs these files to exist.

Interleaved s16le, which is what elias asks for: its own shortfall padding
advances by two bytes per sample.
"""
import os
import sys
import numpy as np
import soundfile as sf

HERE = os.path.dirname(os.path.abspath(__file__))
theme = sys.argv[1] if len(sys.argv) > 1 else "boss"
SRC = os.path.join(HERE, "playable", "assets", "sounds", "sounds",
                   "music", "elias", theme, "audio")
DST = os.path.join(HERE, "pcm", theme)
os.makedirs(DST, exist_ok=True)

names = sorted(os.listdir(SRC))
print("%s: %d stems" % (theme, len(names)))
total = 0
for i, name in enumerate(names):
    out = os.path.join(DST, os.path.splitext(name)[0] + ".pcm")
    if os.path.isfile(out):
        total += os.path.getsize(out)
        continue
    data, rate = sf.read(os.path.join(SRC, name), dtype="int16", always_2d=True)
    if data.shape[1] == 1:                     # mono -> duplicate to stereo
        data = np.repeat(data, 2, axis=1)
    data.astype("<i2").tofile(out)
    total += os.path.getsize(out)
    if i < 3 or i == len(names) - 1:
        print("   %-16s %d frames, %d ch, %d Hz -> %.1f MB"
              % (name, data.shape[0], data.shape[1], rate,
                 os.path.getsize(out) / 1e6))

print("%d files, %.2f GB in %s" % (len(names), total / 1e9, DST))
