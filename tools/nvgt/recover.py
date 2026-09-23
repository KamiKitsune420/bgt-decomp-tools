"""Recover a browsable NVGT project: python recover.py game.exe -o recovered_game."""
from __future__ import annotations

import argparse
import hashlib
import html
import json
from pathlib import Path
import re
import zipfile
import tempfile
import os
import errno
import shutil
import subprocess

try:                      # installed as a package
    from .decompile import ModuleDecompiler, load_any
    from .inspect_exe import identity
    from .source_evidence import recovery_evidence
except ImportError:       # run directly from a checkout
    from decompile import ModuleDecompiler, load_any
    from inspect_exe import identity
    from source_evidence import recovery_evidence


class ProjectDecompiler(ModuleDecompiler):
    def __init__(self, module):
        super().__init__(module)
        self.sections = []
        self.section_order = []

    def capture(self, kind, name, operation, origin="", declared_at=0):
        start = len(self.lines)
        operation()
        content = "\n".join(self.lines[start:]).strip() + "\n"
        del self.lines[start:]
        if content.strip():
            self.sections.append((kind, name, content, origin))
            self.section_order.append((declared_at & 0xfffff, declared_at >> 20) if declared_at else (1 << 20, 0))

    def _render_class(self, cls):
        members = cls.methods + cls.constructors + cls.vft + ([cls.destructor] if cls.destructor else [])
        origins = {f.script_section for f in members if f.script_section}
        first = min((f.declared_at for f in members if f.declared_at),
                    key=lambda value: (value & 0xfffff, value >> 20), default=0)
        self.capture("classes", cls.name, lambda: super(ProjectDecompiler, self)._render_class(cls),
                     next(iter(origins)) if len(origins) == 1 else "", first)

    def _render_globals(self):
        self.capture("globals", "globals", lambda: super(ProjectDecompiler, self)._render_globals())

    def _render_function(self, function):
        self.capture("functions", function.name,
                     lambda: super(ProjectDecompiler, self)._render_function(function), function.script_section, function.declared_at)


def declaration_units(text):
    """Split emitted declarations, keeping strings and nested bodies intact."""
    depth = 0
    quote = None
    block_comment = False
    escaped = False
    pending = []
    for line in text.splitlines(keepends=True):
        pending.append(line)
        cursor = 0
        while cursor < len(line):
            char = line[cursor]
            pair = line[cursor:cursor + 2]
            if block_comment:
                if pair == "*/":
                    block_comment = False
                    cursor += 2
                    continue
            elif quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
            elif pair == "//":
                break
            elif pair == "/*":
                block_comment = True
                cursor += 2
                continue
            elif char in ('"', "'"):
                quote = char
            elif char in "{([":
                depth += 1
            elif char in "})]":
                depth -= 1
            cursor += 1
        if depth == 0 and not quote and not block_comment and line.rstrip().endswith((";", "}")):
            yield "".join(pending)
            pending = []
    if "".join(pending).strip():
        yield "".join(pending)


def grouped(units, target_lines):
    chunk, size = [], 0
    for unit in units:
        lines = len(unit.splitlines())
        if chunk and size + lines > target_lines:
            yield "\n".join(chunk)
            chunk, size = [], 0
        chunk.append(unit)
        size += lines
    if chunk:
        yield "\n".join(chunk)


def source_name(name, used):
    """Readable filenames, safe on Windows and on case-insensitive filesystems."""
    stem = re.sub(r"[^a-z0-9-]", "", name.lower())[:90] or "unnamed"
    if stem in {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)),
                *(f"lpt{i}" for i in range(1, 10))}:
        stem += "_source"
    candidate, suffix = stem, 2
    while candidate.casefold() in used:
        candidate = f"{stem}_{suffix}"
        suffix += 1
    used.add(candidate.casefold())
    return candidate


def browser(files, title):
    payload = json.dumps(files, ensure_ascii=True).replace("<", "\\u003c")
    return '''<!doctype html><html lang="en"><meta charset="utf-8">
<title>Recovered source browser</title>
<style>body{font:17px system-ui;margin:24px;background:#15191f;color:#edf1f7}
input,select,button{font:inherit;padding:8px;margin:4px;color:inherit;background:#242d38;border:1px solid #8290a1}
select{max-width:100%}pre{padding:16px;border:1px solid #596779;overflow:auto;line-height:1.5}
button:focus,input:focus,select:focus{outline:3px solid #79beff}label{display:inline-block}</style>
<h1>''' + html.escape(title) + '''</h1>
<p>Generated file layout. Original include boundaries are not verified. Working game verification is pending.</p>
<label>Find file <input id="filter" type="search"></label>
<label>Source file <select id="files"></select></label><br>
<label>Jump to function <select id="members"></select></label><br>
<label>Find text <input id="query" type="search"></label><button id="find">Find next</button><br>
<button id="previous">Previous 500 lines</button><button id="next">Next 500 lines</button>
<p id="status" role="status" aria-live="polite"></p><pre id="source" tabindex="0"></pre>
<script>
const data = ''' + payload + r''';
const select = document.getElementById('files');
const members = document.getElementById('members');
let page = 0, match = -1;
const lines = () => (data[select.value] || '').split('\n');
function show() {
  const text = lines(), start = page * 500;
  document.getElementById('source').textContent = text.slice(start,start+500)
    .map((line,index) => String(start+index+1).padStart(5)+'  '+line).join('\n');
  document.getElementById('status').textContent = select.value
    + ' — lines ' + (start+1) + '–' + Math.min(start+500,text.length) + ' of ' + text.length;
  document.getElementById('previous').disabled = page === 0;
  document.getElementById('next').disabled = start+500 >= text.length;
}
function listMembers() {
  members.replaceChildren();
  const first=document.createElement('option');first.value='0';first.textContent='Start of file';members.append(first);
  const text=lines();
  text.forEach((line,index)=>{
    const match=line.match(/^\s*(?:(?:shared|private|protected|final|explicit)\s+)*(?:[\w:@<>,\[\]&]+\s+)?([A-Za-z_]\w*)\s*\(/);
    if(!match || ['if','while','for','switch','catch'].includes(match[1]))return;
    if(!line.trimEnd().endsWith('{') && (text[index+1]||'').trim()!=='{')return;
    const option=document.createElement('option');option.value=String(index);
    option.textContent=match[1]+' — line '+(index+1);members.append(option);
  });
}
function populate() {
  const current = select.value, query = document.getElementById('filter').value.toLowerCase();
  select.replaceChildren();
  Object.keys(data).filter(name=>name.toLowerCase().includes(query)).forEach(name=>{
    const option=document.createElement('option');option.value=name;option.textContent=name;select.append(option);
  });
  if (Object.hasOwn(data,current) && Array.from(select.options).some(o=>o.value===current)) select.value=current;
  page=0;match=-1;listMembers();show();
}
select.onchange=()=>{page=0;match=-1;listMembers();show();};
members.onchange=()=>{match=Number(members.value);page=Math.floor(match/500);show();
  document.getElementById('status').textContent += ' — declaration at line '+(match+1);};
document.getElementById('filter').oninput=populate;
document.getElementById('query').oninput=()=>{match=-1;};
document.getElementById('previous').onclick=()=>{page--;show();};
document.getElementById('next').onclick=()=>{page++;show();};
function find() {
  const query=document.getElementById('query').value.toLowerCase(),text=lines();
  if(!query)return;
  for(let step=1;step<=text.length;step++) {
    const index=(match+step)%text.length;
    if(text[index].toLowerCase().includes(query)){match=index;page=Math.floor(index/500);show();
      document.getElementById('status').textContent += ' — match at line '+(index+1);return;}
  }
  document.getElementById('status').textContent='No match in this file.';
}
document.getElementById('find').onclick=find;
document.getElementById('query').onkeydown=event=>{if(event.key==='Enter')find();};
populate();
</script></html>'''


def check_compilation(sources, compiler, timeout=90):
    """Compile only generated source in a disposable folder; never run the game."""
    if isinstance(compiler, (str, os.PathLike)):
        compiler_path = Path(compiler).resolve()
        if not compiler_path.is_file():
            raise FileNotFoundError(f"NVGT compiler not found: {compiler_path}")
        command = [str(compiler_path)]
    else:
        command = [str(part) for part in compiler]
        if not command:
            raise ValueError("compiler command is empty")
    with tempfile.TemporaryDirectory(prefix="nvgt_compile_") as scratch:
        root = Path(scratch)
        for name, content in sources.items():
            destination = root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(content, encoding="utf-8", newline="\n")
        try:
            result = subprocess.run(command + ["-c", str(root / "main.nvgt")],
                                    cwd=root, capture_output=True, text=True,
                                    errors="replace", timeout=timeout)
            output = result.stdout + result.stderr
            status = "passed" if result.returncode == 0 else "failed"
            exit_code = result.returncode
        except subprocess.TimeoutExpired as error:
            def decoded(chunk):
                return chunk.decode("utf-8", errors="replace") if isinstance(chunk, bytes) else (chunk or "")
            output = decoded(error.stdout) + decoded(error.stderr)
            status, exit_code = "timeout", None
        output = output.replace(str(root), "<temporary-project>")
        output = output.replace(root.as_posix(), "<temporary-project>")
        summary = {"status": status, "compiler": Path(command[0]).name,
                   "exit_code": exit_code, "error_lines": len(re.findall(r"\bERROR:", output)),
                   "report_file": "compile-report.txt"}
        report = (f"Compilation: {status}\nCompiler: {summary['compiler']}\n"
                  f"Exit code: {exit_code}\n\n" + output)
        return summary, report


def generate_project(input_path, output, target_lines=800, progress=lambda message: None, validation=None, compiler=None):
    input_path, output = Path(input_path).resolve(), Path(output).resolve()
    progress("Reading executable and bytecode")
    raw = input_path.read_bytes()
    module = load_any(str(input_path))
    progress("Recovering declarations and control flow")
    renderer = ProjectDecompiler(module)
    header = renderer.render().strip() + "\n"
    sources, includes, used_names = {}, [], set()
    globals_text, functions, section_paths, debug_units = [], [], {}, {}
    for (kind, name, content, origin), declaration_order in zip(renderer.sections, renderer.section_order):
        if origin and kind != "globals" and module.debug_info:
            if origin not in section_paths:
                basename = Path(origin.replace("\\", "/")).stem
                stem = re.sub(r"[^A-Za-z0-9_-]", "_", basename)[:90] or "unnamed"
                # Retain the original spelling when safe, including underscores.
                if stem.casefold() in {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1,10)),
                                      *(f"lpt{i}" for i in range(1,10))}:
                    stem += "_source"
                candidate, suffix = stem, 2
                while candidate.casefold() in used_names:
                    candidate = f"{stem}_{suffix}"
                    suffix += 1
                used_names.add(candidate.casefold())
                section_paths[origin] = f"includes/{candidate}.nvgt"
            path = section_paths[origin]
            if path not in sources:
                sources[path] = ""
                includes.append(path)
            debug_units.setdefault(path, []).append((declaration_order, content))
            continue
        if kind == "classes":
            candidate = source_name(name, used_names)
            path = f"includes/{candidate}.nvgt"
            sources[path] = content
            includes.append(path)
        elif kind == "globals":
            globals_text.extend(declaration_units(content))
        else:
            functions.append(content)
    for path, units in debug_units.items():
        sources[path] = "\n".join(content for order, content in sorted(units, key=lambda unit: unit[0]))
    for kind, units in (("globals", globals_text), ("functions", functions)):
        for index, content in enumerate(grouped(units, target_lines), 1):
            if kind == "functions":
                match = re.search(r"\b([A-Za-z_][A-Za-z_0-9]*)\s*\(", content)
                filename = source_name(match.group(1) if match else f"functions{index}", used_names)
            else:
                filename = f"globals_{index:03}"
            path = f"includes/{kind}/{filename}.nvgt"
            sources[path] = content
            includes.append(path)
    sources["main.nvgt"] = header + "\n" + "\n".join(f'#include "{path}"' for path in includes) + "\n"
    compile_summary = compile_report = None
    if compiler is not None:
        progress("Compiling generated source with the supplied NVGT compiler")
        compile_summary, compile_report = check_compilation(sources, compiler)
    combined = "\n".join(sources.values())
    manifest = {
        "format_version": 1,
        "input": input_path.name, "input_sha256": hashlib.sha256(raw).hexdigest(),
        "engine_identity_evidence": identity(raw) if raw[:2] == b"MZ" else None,
        "layout_origin": "generated from recovered declarations",
        "bytecode_profile": getattr(module, "bytecode_profile", None),
        "packaging_profile": getattr(getattr(module, "nvgt_info", None), "packaging_profile", "current_preamble"),
        "debug_info": module.debug_info,
        "script_section_paths": [{"original": origin, "recovered": path}
                                 for origin, path in section_paths.items()],
        "verified_original_includes": [], "working_game_verified": False,
        "source_compilation": compile_summary["status"] if compile_summary else "not_checked",
        "compile_check": compile_summary,
        "validation": validation,
        "classes": len(module.classes), "script_functions": len(module.script_functions),
        "globals": len(module.globals),
        "diagnostics": {"unstructured_gotos": len(re.findall(r"\bgoto\s+L", combined)),
                        "unknown_markers": len(re.findall(r"<\?[^>]*>", combined)),
                        "decompiler_errors": combined.count("[decompiler error:"),
                        "unsupported_targets": combined.count("(unsupported target)"),
                        "unhandled_opcodes": combined.count("(unhandled)"),
                        "unresolved_types": len(re.findall(r"\b(?:tok\d+|type#\d+)\b", combined)),
                        "temporary_references": len(re.findall(r"\btmp\d+\b", combined))},
        "source_files": [{"path": path, "lines": len(content.splitlines()),
                          "sha256": hashlib.sha256(content.encode()).hexdigest()}
                         for path, content in sources.items()]
    }
    evidence = recovery_evidence(module)
    manifest["source_evidence"] = {"file": "source_evidence.json", **evidence["summary"]}
    files = dict(sources)
    files["source_evidence.json"] = json.dumps(evidence, indent=2, ensure_ascii=True) + "\n"
    files["browse.html"] = browser(sources, input_path.stem + " recovered source")
    if compile_report is not None:
        files["compile-report.txt"] = compile_report
    compile_note = ("Compilation was not checked by this export." if compile_summary is None else
                    f"Compilation check: {compile_summary['status']} with {compile_summary['compiler']}. "
                    "See [compile-report.txt](compile-report.txt). This does not verify behavior.")
    index = ["# Recovered source project", "", "Open [browse.html](browse.html) to search files and read 500 lines at a time.",
             "", "Entry file: [main.nvgt](main.nvgt). Debug section filenames are retained when available. Remaining boundaries are generated; comments, include directives and exact original contents are not restored.",
             "", "[source_evidence.json](source_evidence.json) lists saved names, source coordinates, declaration order and lifetime markers. Synthesized source is not original text.",
             "", compile_note, "Working game verification is pending. Zero decompiler diagnostics does not mean the source compiles.",
             "", "Source files:", ""]
    index += [f"- [{path}]({path}) ({len(content.splitlines())} lines)" for path, content in sources.items()]
    files["README.md"] = "\n".join(index) + "\n"
    manifest["generated_file_hashes"] = {path: hashlib.sha256(content.encode()).hexdigest()
                                        for path, content in files.items()}
    files["manifest.json"] = json.dumps(manifest, indent=2) + "\n"
    files["manifest.sha256"] = hashlib.sha256(files["manifest.json"].encode()).hexdigest() + "\n"
    previous_hashes = {}
    prior_manifest = output / "manifest.json"
    prior_digest = output / "manifest.sha256"
    if prior_manifest.exists() and prior_digest.exists():
        previous_bytes = prior_manifest.read_bytes()
        if prior_digest.read_text().strip() == hashlib.sha256(previous_bytes).hexdigest():
            previous = json.loads(previous_bytes)
            if previous.get("format_version") == 1:
                previous_hashes = previous.get("generated_file_hashes", {})
                previous_hashes["manifest.json"] = hashlib.sha256(previous_bytes).hexdigest()
                previous_hashes["manifest.sha256"] = hashlib.sha256(prior_digest.read_bytes()).hexdigest()
    # Re-running recovery must not silently replace hand-edited source.
    for path, content in files.items():
        destination = output / path
        if destination.exists() and destination.read_text(encoding="utf-8") != content:
            if previous_hashes.get(path) != hashlib.sha256(destination.read_bytes()).hexdigest():
                raise FileExistsError(f"Output contains a different file: {destination}. Choose a new output folder.")
    # A later export without --check-with must not leave a stale generated
    # report suggesting that the new source was compiled. Preserve hand edits.
    old_report = output / "compile-report.txt"
    if (compile_report is None and old_report.exists()
            and previous_hashes.get("compile-report.txt") == hashlib.sha256(old_report.read_bytes()).hexdigest()):
        old_report.unlink()
    progress("Writing source folder and offline browser")
    output.mkdir(parents=True, exist_ok=True)
    for path, content in files.items():
        destination = output / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8", newline="\n")
    with zipfile.ZipFile(output / "source.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        for path, content in files.items():
            archive.writestr(path, content.encode("utf-8"))
    progress(f"Recovered {len(sources)} source files. Compilation: {manifest['source_compilation']}; working game verification pending.")
    return manifest


def generate_archive(input_path, archive_path, target_lines=800, progress=lambda message: None, validation=None, compiler=None):
    """Retain only the source ZIP; temporary source files are always removed."""
    archive_path = Path(archive_path).resolve()
    if archive_path.exists():
        raise FileExistsError(f"Archive already exists: {archive_path}. Choose a new output folder or archive name.")
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="nvgt_recovery_", dir=archive_path.parent) as scratch:
        manifest = generate_project(input_path, scratch, target_lines, progress, validation, compiler)
        generated = Path(scratch) / "source.zip"
        # Publish the complete ZIP atomically without replacing a competing
        # writer's file. Scratch and destination are on the same filesystem.
        try:
            os.link(generated, archive_path)
        except OSError as error:
            # FAT and some network filesystems do not provide hard links.
            if error.errno not in (errno.EPERM, errno.EXDEV, errno.ENOSYS, errno.EOPNOTSUPP):
                raise
            with archive_path.open("xb") as destination:
                try:
                    with generated.open("rb") as source:
                        shutil.copyfileobj(source, destination)
                except BaseException:
                    destination.close()
                    archive_path.unlink()
                    raise
    progress(f"Saved source ZIP: {archive_path}")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input")
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("--file-lines", type=int, default=800,
                        help="Target size for declaration groups; whole functions remain intact")
    parser.add_argument("--zip-only", action="store_true", help="Keep only the ZIP; --output is an archive filename")
    parser.add_argument("--check-with", metavar="NVGT_EXE",
                        help="Compile recovered source with this NVGT compiler in a disposable folder; does not run the game")
    args = parser.parse_args()
    if args.file_lines < 50:
        parser.error("--file-lines must be at least 50")
    try:
        exporter = generate_archive if args.zip_only or Path(args.output).suffix.lower() == ".zip" else generate_project
        manifest = exporter(args.input, args.output, args.file_lines, print, compiler=args.check_with)
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(1, f"Recovery failed: {error}\n")
    print(json.dumps(manifest["diagnostics"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
