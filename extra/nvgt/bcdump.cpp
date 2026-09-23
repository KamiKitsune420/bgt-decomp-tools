// bcdump.cpp - compile an AngelScript source file and dump the raw module bytecode.
//
// This is the testing side of the decompiler: it uses the exact pinned
// AngelScript engine NVGT is built with to turn .as/.nvgt source into the
// same serialized module stream that NVGT embeds in compiled executables.
//
// Usage: bcdump <input.nvgt> <output.bc> [--strip] [--run]
//
// Output layout (our own container, NOT the NVGT executable format):
//   magic   "ASBC" (4 bytes)
//   version u32 (1)
//   size    u32 (bytecode length)
//   payload (raw asCWriter stream, exactly what SaveByteCode produces)
//
// Build: see tools/build_bcdump.bat

#include <angelscript.h>
#include <scriptbuilder/scriptbuilder.h>
#include <scriptstdstring/scriptstdstring.h>
#include <scriptarray/scriptarray.h>
#include <scriptdictionary/scriptdictionary.h>
#include <scripthandle/scripthandle.h>
#include <scriptany/scriptany.h>
#include <scriptmath/scriptmath.h>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>

static void print_impl(const std::string &s) { std::cout << s; }
static int get_host_mode() { return 2; }
static void raise_error() { asGetActiveContext()->SetException("owned test exception"); }

static void print_help() {
    std::cout << "usage: bcdump <input.nvgt> <output.bc> [--strip] [--run]\n"
                 "  --strip  save bytecode without debug info (release mode)\n"
                 "  --run    execute void main() after saving; script output goes to stdout\n";
}

static void message_callback(const asSMessageInfo *msg, void *) {
    const char *type = "ERROR";
    if (msg->type == asMSGTYPE_WARNING) type = "WARN";
    else if (msg->type == asMSGTYPE_INFORMATION) type = "INFO";
    std::cerr << msg->section << ":" << msg->row << " " << type << ": " << msg->message << "\n";
}

// Minimal string factory so script strings have somewhere to live
// (the SDK's RegisterStdString already registers the type; the engine
// just needs the factory callbacks wired to the same std::string type).
static void register_string_factory(asIScriptEngine *engine) {
    (void)engine; // RegisterStdString installs its own factory via the addon;
                  // nothing extra needed here. Kept as an extension point.
}

// In-memory asIBinaryStream used to capture SaveByteCode output.
class MemBytecodeStream : public asIBinaryStream {
public:
    std::string buffer;
    mutable size_t readPos = 0;

    int Write(const void *ptr, asUINT size) override {
        buffer.append(static_cast<const char *>(ptr), size);
        return 0;
    }
    int Read(void *ptr, asUINT size) override {
        if (readPos + size > buffer.size()) return -1;
        memcpy(ptr, buffer.data() + readPos, size);
        readPos += size;
        return 0;
    }
};

int main(int argc, char **argv) {
    if (argc < 3) { print_help(); return 1; }
    std::string input = argv[1], output = argv[2];
    bool strip = false, run = false;
    for (int i = 3; i < argc; i++) {
        if (!strcmp(argv[i], "--strip")) strip = true;
        else if (!strcmp(argv[i], "--run")) run = true;
        else { print_help(); return 1; }
    }

    asIScriptEngine *engine = asCreateScriptEngine(ANGELSCRIPT_VERSION);
    engine->SetMessageCallback(asFUNCTION(message_callback), 0, asCALL_CDECL);

    RegisterStdString(engine);
    RegisterScriptArray(engine, true);
    RegisterScriptDictionary(engine);
    RegisterScriptHandle(engine);
    RegisterScriptAny(engine);
    RegisterScriptMath(engine);
    register_string_factory(engine);
    engine->RegisterEnum("host_mode");
    engine->RegisterEnumValue("host_mode", "HOST_MODE_ACTIVE", 2);
    engine->RegisterGlobalFunction("host_mode get_host_mode()",
                                   asFUNCTION(get_host_mode), asCALL_CDECL);
    engine->RegisterGlobalFunction("void raise_error()", asFUNCTION(raise_error), asCALL_CDECL);

    // A few NVGT-style globals scripts commonly use (kept minimal: the
    // decompiler only needs call targets to resolve names).
    engine->RegisterGlobalFunction("void print(const string &in)",
                                   asFUNCTION(print_impl), asCALL_CDECL);
    engine->RegisterGlobalFunction("void println(const string &in)",
                                   asFUNCTION(print_impl), asCALL_CDECL);

    // Engine properties matching NVGT's compiler defaults for bytecode
    // compatibility (see src/nvgt_angelscript.cpp ConfigureEngine).
    engine->SetEngineProperty(asEP_OPTIMIZE_BYTECODE, true);

    CScriptBuilder builder;
    if (builder.StartNewModule(engine, "nvgt_game") < 0) {
        std::cerr << "StartNewModule failed\n";
        return 1;
    }
    if (builder.AddSectionFromFile(input.c_str()) < 0) {
        std::cerr << "failed to add section " << input << "\n";
        return 1;
    }
    if (builder.BuildModule() < 0) {
        std::cerr << "build failed\n";
        return 1;
    }

    asIScriptModule *mod = engine->GetModule("nvgt_game");
    if (!mod) { std::cerr << "module missing\n"; return 1; }

    MemBytecodeStream stream;
    if (mod->SaveByteCode(&stream, strip) < 0) {
        std::cerr << "SaveByteCode failed\n";
        return 1;
    }

    std::ofstream out(output, std::ios::binary);
    const char magic[4] = {'A', 'S', 'B', 'C'};
    unsigned int version = 1;
    unsigned int size = (unsigned int)stream.buffer.size();
    out.write(magic, 4);
    out.write((char *)&version, 4);
    out.write((char *)&size, 4);
    out.write(stream.buffer.data(), size);
    out.close();
    if (!out) {
        std::cerr << "failed to write " << output << "\n";
        engine->ShutDownAndRelease();
        return 1;
    }
    (run ? std::cerr : std::cout) << "wrote " << output << " (" << size << " bytes)\n";

    int result = 0;
    if (run) {
        asIScriptFunction *entry = mod->GetFunctionByDecl("void main()");
        if (!entry) {
            std::cerr << "--run requires void main()\n";
            result = 1;
        } else {
            asIScriptContext *ctx = engine->CreateContext();
            int status = ctx->Prepare(entry);
            if (status >= 0) status = ctx->Execute();
            if (status != asEXECUTION_FINISHED) {
                std::cerr << "script execution failed (status " << status << ")";
                if (status == asEXECUTION_EXCEPTION)
                    std::cerr << ": " << ctx->GetExceptionString();
                std::cerr << "\n";
                result = 1;
            }
            ctx->Release();
        }
    }

    engine->ShutDownAndRelease();
    return result;
}
