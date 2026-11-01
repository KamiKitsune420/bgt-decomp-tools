// Render a real elias theme at a chosen intensity, by driving the game's own
// elias.dll and streaming the game's own stems into it.
//
// Everything the harness does was read out of gate.exe rather than guessed:
//
//   elias_theme_start(theme, source_cb, 0, 0, level, max, 0, 0, 0)
//       nine arguments -- `add esp,0x24` at 0x0046C890 -- of which the five
//       the game fills from its wrapper object all tolerate zero.
//
//   source_cb(op, elias_source, arg3, arg4)
//       op 3 prepare, op 1 read arg4 samples into arg3, op 2 rewind,
//       op 4 finish. The host's own handle is at elias_source+0x1c, which is
//       where gate.exe reads it (`mov esi,[eax+0x1c]`).
//
//   samples are interleaved 16-bit: elias pads a shortfall itself with
//       `lea edi,[edi+eax*2]`, and arg4 of 22050 is 250 ms of stereo at
//       44.1 kHz -- exactly the processing period that was set.
//
// Streaming is not an optimisation: 82 stems of 93 seconds is 0.92 GB, which
// a 32-bit process cannot hold, and the protocol is built for it.
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

static class Render {
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate IntPtr AllocFn(uint size);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate void FreeFn(IntPtr p);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate void SetAllocator(IntPtr a, IntPtr f);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int CreateFromXml(out IntPtr t, byte[] xml, byte[] err, int n, IntPtr z);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int SourceResolve(IntPtr src, IntPtr outHandle, IntPtr user);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int Enumerate(IntPtr t, IntPtr cb, IntPtr user);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int TwoInts(IntPtr t, int a);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int GetOut(IntPtr t, out int v);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int Start9(IntPtr t, IntPtr cb, int a3, int a4, int level,
                        int max, int a7, int a8, int a9);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int SetLevel7(IntPtr t, int a, int b, int c, int d, int key, int flag);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int ReadSamples(IntPtr t, IntPtr buf, ref int count);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int Destroy(IntPtr t);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int SourceOp(int op, IntPtr src, IntPtr arg3, int arg4);

    [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
    static extern IntPtr LoadLibraryA(string n);
    [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
    static extern IntPtr GetProcAddress(IntPtr m, string n);

    static IntPtr mod;
    static T Fn<T>(string n) where T : class {
        IntPtr p = GetProcAddress(mod, n);
        return p == IntPtr.Zero ? null
             : Marshal.GetDelegateForFunctionPointer(p, typeof(T)) as T;
    }

    static AllocFn keepAlloc; static FreeFn keepFree;
    static SourceResolve keepResolve; static SourceOp keepOp;

    class Src {
        public string name, path;
        public FileStream fs;
        public byte[] scratch = new byte[0];
        public long reads;
    }
    static readonly List<Src> all = new List<Src>();
    static readonly Dictionary<int, Src> byId = new Dictionary<int, Src>();
    static string pcmDir;
    static int missing;

    static int Resolve(IntPtr src, IntPtr outHandle, IntPtr user) {
        string name = Marshal.PtrToStringAnsi(Marshal.ReadIntPtr(src, 0x14));
        string bare = Path.GetFileNameWithoutExtension(name ?? "");
        Src s = new Src();
        s.name = name;
        s.path = Path.Combine(pcmDir, bare + ".pcm");
        if (!File.Exists(s.path)) { missing++; s.path = null; }
        all.Add(s);
        IntPtr h = Marshal.AllocHGlobal(4);
        Marshal.WriteInt32(h, all.Count);
        byId[all.Count] = s;
        Marshal.WriteIntPtr(outHandle, h);
        return 1;                     // every source must resolve or we get 15
    }

    static int Op(int op, IntPtr src, IntPtr arg3, int arg4) {
        Src s = null;
        if (src != IntPtr.Zero) {
            IntPtr mine = Marshal.ReadIntPtr(src, 0x1C);
            if (mine != IntPtr.Zero) byId.TryGetValue(Marshal.ReadInt32(mine), out s);
        }
        if (s == null) return 0;
        switch (op) {
            case 3:
                if (s.path != null && s.fs == null)
                    s.fs = new FileStream(s.path, FileMode.Open, FileAccess.Read,
                                          FileShare.Read, 1 << 16);
                return 1;
            case 2:
                if (s.fs != null) s.fs.Position = 0;
                return 1;
            case 4:
                if (s.fs != null) { s.fs.Dispose(); s.fs = null; }
                return 1;
            case 1: {
                int want = arg4 * 2;                     // bytes for arg4 int16
                if (s.scratch.Length < want) s.scratch = new byte[want];
                int got = 0;
                if (s.fs != null) {
                    while (got < want) {
                        int n = s.fs.Read(s.scratch, got, want - got);
                        if (n <= 0) break;
                        got += n;
                    }
                }
                for (int i = got; i < want; i++) s.scratch[i] = 0;   // pad
                Marshal.Copy(s.scratch, 0, arg3, want);
                s.reads++;
                return 1;
            }
            default: return 1;
        }
    }

    static int Main(string[] argv) {
        if (argv.Length < 5) {
            Console.WriteLine("usage: render <elias.dll> <theme.epro> <pcmdir> <out.wav> <level> [seconds]");
            return 2;
        }
        pcmDir = argv[2];
        int level = int.Parse(argv[4]);
        double seconds = argv.Length > 5 ? double.Parse(argv[5]) : 30.0;

        mod = LoadLibraryA(argv[0]);
        keepAlloc = delegate(uint z) { return Marshal.AllocHGlobal((int)z); };
        keepFree = delegate(IntPtr p) { if (p != IntPtr.Zero) Marshal.FreeHGlobal(p); };
        keepResolve = Resolve;
        keepOp = Op;
        Fn<SetAllocator>("elias_set_memory_allocator")(
            Marshal.GetFunctionPointerForDelegate(keepAlloc),
            Marshal.GetFunctionPointerForDelegate(keepFree));

        byte[] xml = File.ReadAllBytes(argv[1]);
        byte[] cstr = new byte[xml.Length + 1];
        Array.Copy(xml, cstr, xml.Length);
        byte[] err = new byte[1088];
        IntPtr theme;
        int rc = Fn<CreateFromXml>("elias_theme_create_from_xml")(
            out theme, cstr, err, 1024, IntPtr.Zero);
        if (rc != 0) {
            Console.WriteLine("create_from_xml -> {0}: {1}", rc,
                              Encoding.ASCII.GetString(err).TrimEnd('\0'));
            return 1;
        }
        int rate, channels;
        Fn<GetOut>("elias_theme_get_source_count")(theme, out rate);
        Console.WriteLine("theme loaded, {0} sources", rate);
        int rc2 = Fn<Enumerate>("elias_theme_enumerate_sources")(
            theme, Marshal.GetFunctionPointerForDelegate(keepResolve), IntPtr.Zero);
        Console.WriteLine("enumerate -> {0}; {1} resolved, {2} with no pcm file",
                          rc2, all.Count, missing);

        Fn<TwoInts>("elias_theme_set_prebuffer_length_in_milliseconds")(theme, 500);
        Fn<TwoInts>("elias_theme_set_processing_period_in_milliseconds")(theme, 250);
        Fn<TwoInts>("elias_theme_set_suggested_thread_count")(theme, 2);
        int greatest;
        Fn<GetOut>("elias_theme_get_greatest_trigger")(theme, out greatest);
        Console.WriteLine("greatest trigger (max intensity): {0}; rendering at {1}",
                          greatest, level);

        int rcs = Fn<Start9>("elias_theme_start")(
            theme, Marshal.GetFunctionPointerForDelegate(keepOp),
            0, 0, level, greatest, 0, 0, 0);
        Console.WriteLine("start -> {0}", rcs);
        if (rcs != 0) { Fn<Destroy>("elias_theme_destroy")(theme); return 1; }

        int chunk = 4096;
        IntPtr buf = Marshal.AllocHGlobal(chunk * 2 * 2);
        long wantValues = (long)(seconds * 44100) * 2;
        MemoryStream outPcm = new MemoryStream();
        int quiet = 0;
        while (outPcm.Length / 2 < wantValues && quiet < 200) {
            int count = chunk;
            if (Fn<ReadSamples>("elias_theme_read_samples")(theme, buf, ref count) != 0) break;
            if (count <= 0) { quiet++; System.Threading.Thread.Sleep(5); continue; }
            quiet = 0;
            byte[] got = new byte[count * 2];
            Marshal.Copy(buf, got, 0, got.Length);
            outPcm.Write(got, 0, got.Length);
        }

        byte[] pcm = outPcm.ToArray();
        long nonzero = 0; int peak = 0;
        for (int i = 0; i + 1 < pcm.Length; i += 2) {
            short v = (short)(pcm[i] | (pcm[i + 1] << 8));
            if (v != 0) nonzero++;
            if (Math.Abs((int)v) > peak) peak = Math.Abs((int)v);
        }
        Console.WriteLine("rendered {0:F1} s: {1} of {2} int16 non-zero, peak {3}",
                          pcm.Length / 4.0 / 44100.0, nonzero, pcm.Length / 2, peak);

        int served = 0;
        foreach (Src s in all) if (s.reads > 0) served++;
        Console.WriteLine("stems actually played: {0} of {1}", served, all.Count);
        foreach (Src s in all)
            if (s.reads > 0) Console.WriteLine("    {0}  ({1} reads)", s.name, s.reads);

        using (BinaryWriter w = new BinaryWriter(File.Create(argv[3]))) {
            w.Write(Encoding.ASCII.GetBytes("RIFF")); w.Write(36 + pcm.Length);
            w.Write(Encoding.ASCII.GetBytes("WAVEfmt ")); w.Write(16);
            w.Write((short)1); w.Write((short)2); w.Write(44100);
            w.Write(44100 * 2 * 2); w.Write((short)4); w.Write((short)16);
            w.Write(Encoding.ASCII.GetBytes("data")); w.Write(pcm.Length); w.Write(pcm);
        }
        Console.WriteLine("wrote {0}", argv[3]);
        Fn<Destroy>("elias_theme_destroy")(theme);
        return 0;
    }
}
