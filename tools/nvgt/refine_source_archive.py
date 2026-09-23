"""Rename an existing generated project ZIP without its original executable."""
from pathlib import Path
import hashlib
import json
import re
import sys
import zipfile

try:                      # installed as a package
    from .recover import browser, source_name
except ImportError:       # run directly from a checkout
    from recover import browser, source_name


def refine(source, destination):
    destination = Path(destination)
    if destination.exists():
        raise FileExistsError(destination)
    with zipfile.ZipFile(source) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError("Archive contains duplicate filenames")
        files = {name: archive.read(name).decode("utf-8") for name in names}
    manifest = json.loads(files["manifest.json"])
    if hashlib.sha256(files["manifest.json"].encode()).hexdigest() != files["manifest.sha256"].strip():
        raise ValueError("Archive manifest digest mismatch")
    sources = {}
    for entry in manifest["source_files"]:
        content = files[entry["path"]]
        if hashlib.sha256(content.encode()).hexdigest() != entry["sha256"]:
            raise ValueError(f"Modified source: {entry['path']}")
        sources[entry["path"]] = content
    renamed = {path for path in sources if path.startswith(("includes/classes/class_", "includes/functions/functions_"))}
    used = {Path(path).stem.casefold() for path in sources if path not in renamed}
    mapping = {}
    for path, content in sources.items():
        if path.startswith("includes/classes/class_"):
            mapping[path] = "includes/" + source_name(Path(path).stem[6:], used) + ".nvgt"
        elif path.startswith("includes/functions/functions_"):
            match = re.search(r"\b([A-Za-z_][A-Za-z_0-9]*)\s*\(", content)
            mapping[path] = "includes/functions/" + source_name(match.group(1) if match else Path(path).stem, used) + ".nvgt"
        else:
            mapping[path] = path
    if len({path.casefold() for path in mapping.values()}) != len(mapping):
        raise ValueError("Refined filenames collide")
    for old, new in mapping.items():
        sources["main.nvgt"] = sources["main.nvgt"].replace(f'"{old}"', f'"{new}"')
        files["README.md"] = files["README.md"].replace(old, new)
    sources = {mapping[path]: content for path, content in sources.items()}
    for path in manifest["source_files"]:
        files.pop(path["path"])
    files.update(sources)
    files["browse.html"] = browser(sources, Path(source).stem + " recovered source")
    manifest["source_files"] = [{"path": path, "lines": len(content.splitlines()),
                                  "sha256": hashlib.sha256(content.encode()).hexdigest()}
                                 for path, content in sources.items()]
    manifest["generated_file_hashes"] = {path: hashlib.sha256(content.encode()).hexdigest()
                                         for path, content in files.items()
                                         if path not in ("manifest.json", "manifest.sha256")}
    files["manifest.json"] = json.dumps(manifest, indent=2) + "\n"
    files["manifest.sha256"] = hashlib.sha256(files["manifest.json"].encode()).hexdigest() + "\n"
    for entry in manifest.get("script_section_paths", []):
        entry["recovered"] = mapping.get(entry["recovered"], entry["recovered"])
    files["manifest.json"] = json.dumps(manifest, indent=2) + "\n"
    files["manifest.sha256"] = hashlib.sha256(files["manifest.json"].encode()).hexdigest() + "\n"
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "x", zipfile.ZIP_DEFLATED) as archive:
        for path, content in files.items():
            archive.writestr(path, content.encode())


if __name__ == "__main__":
    refine(*sys.argv[1:])
