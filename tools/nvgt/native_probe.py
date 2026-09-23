"""Compile recovered text in a copied native stub using an owned harness.

The original target bytecode is discarded. The harness only compiles text and
writes diagnostics; it never executes recovered functions or initializers.
Supports targets whose encryption is already verified by extract.py.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

try:                      # installed as a package
    from .asreader import read_module
    from . import extract
except ImportError:       # run directly from a checkout
    from asreader import read_module
    import extract


def probe(target, compiler, source, output):
    target, compiler, source, output = map(lambda path: Path(path).resolve(),
                                         (target, compiler, source, output))
    original = target.read_bytes()
    original_hash = hashlib.sha256(original).hexdigest()
    info, old_stream = extract.extract(target)
    # NVGT preconfiguration disables initialization after Build. Assert that
    # the target's serialized properties retain that setting (property 9).
    if len(info.engine_properties) <= 9 or info.engine_properties[9] != 0:
        raise ValueError("This probe requires INIT_GLOBAL_VARS_AFTER_BUILD=false")
    if output.exists() and any(output.iterdir()):
        raise FileExistsError("Choose an empty output folder for the owned probe")
    source_text = source.read_text(encoding="utf-8")
    if any(line.lstrip().startswith("#include") for line in source_text.splitlines()):
        raise ValueError("Native probe expects a single flattened source file; includes are unsupported")
    output.mkdir(parents=True, exist_ok=True)
    temp = output / "temp"
    temp.mkdir(exist_ok=True)
    code = output / "compile_input.nvgt"
    code.write_text("\n".join(line for line in source_text.splitlines()
                              if not line.lstrip().startswith("#pragma")), encoding="utf-8")
    harness = output / "owned_harness.nvgt"
    bytecode = harness.with_suffix(".bin")
    log = output / "native_compile.log"
    harness_source = ("\n".join(f"#pragma plugin {plugin}" for plugin in info.plugins)
        + "\n" + "\n".join(f"#pragma namespace {name} {namespace}" for name, namespace in info.namespaces)
        + '\nvoid main() {\n'
        + '    if (!SCRIPT_COMPILED) {\n'
        + '        file_put_contents(' + json.dumps(bytecode.as_posix())
        + ', script_get_module("nvgt_game", 0).get_bytecode(false));\n        return;\n    }\n'
        + '    script_module@ module = script_get_module("owned_recovery_compile_probe", 2);\n'
        + '    module.set_access_mask(0xffffffff);\n'
        + '    module.add_section("recovered", file_get_contents(' + json.dumps(code.as_posix()) + '));\n'
        + '    array<string> errors;\n    int status = -1000;\n'
        + '    try { status = module.build(errors); } catch {}\n'
        + '    string message = "compile_status=" + status + "\\n";\n'
        + '    for (uint i = 0; i < errors.length(); i++) message += errors[i] + "\\n";\n'
        + '    file_put_contents(' + json.dumps(log.as_posix()) + ', message);\n}\n')
    harness.write_text(harness_source, encoding="utf-8")
    env = dict(os.environ, TEMP=str(temp), TMP=str(temp))
    bytecode.unlink(missing_ok=True)
    reference = subprocess.run([str(compiler), str(harness)], cwd=output,
                               capture_output=True, timeout=45, env=env)
    (output / "reference.log").write_bytes(reference.stdout + reference.stderr)
    if reference.returncode or not bytecode.exists():
        raise RuntimeError("Owned harness did not export bytecode; see reference.log")
    owned = bytecode.read_bytes()
    module = read_module(owned)
    if len(module.script_functions) != 1 or module.script_functions[0].name != "main" or module.globals:
        raise ValueError("Expected one owned main function and no global initializers")
    prefix = old_stream[:-len(info.bytecode)]
    packaged = extract.package_owned_module(original, prefix + owned)
    verified, _ = extract.extract_data(packaged)
    if verified.bytecode != owned or verified.engine_properties[9] != 0:
        raise ValueError("Owned package verification failed")
    executable = output / "owned_native_compile_probe.exe"
    executable.write_bytes(packaged)
    libraries = output / "lib"
    libraries.mkdir(exist_ok=True)
    for dll in (target.parent / "lib").glob("*.dll"):
        shutil.copyfile(dll, libraries / dll.name)
    log.unlink(missing_ok=True)
    result = subprocess.run([str(executable)], cwd=output, capture_output=True, timeout=45, env=env)
    (output / "process.log").write_bytes(result.stdout + result.stderr)
    if hashlib.sha256(target.read_bytes()).hexdigest() != original_hash:
        raise ValueError("Target changed during experiment")
    report = {"target_sha256": original_hash, "target_unchanged": True,
              "original_game_bytecode_executed": False, "recovered_code_executed": False,
              "owned_script_functions": 1, "global_initialization_after_build": False,
              "process_exit": result.returncode, "diagnostics_written": log.exists(),
              "native_diagnostics": str(log)}
    (output / "experiment.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    if not log.exists():
        raise RuntimeError("Copied native stub produced no diagnostics; see process.log")
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target")
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True)
    arguments = parser.parse_args(argv)
    try:
        print(json.dumps(probe(arguments.target, arguments.compiler, arguments.source, arguments.output), indent=2))
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        parser.exit(1, str(error) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
