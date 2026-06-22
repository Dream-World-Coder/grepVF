"""
Lockfile Parser — extracts (package_name, version, ecosystem) tuples from
dependency manifests so the CVE checker can query OSV.dev.

Deliberately parses lockfiles (package-lock.json, poetry.lock) over plain
manifests (package.json, pyproject.toml) when both are present, because
manifests often specify version *ranges* ("^4.17.1") while OSV needs an
*exact resolved version* to give an accurate answer. Falling back to the
manifest only happens when no lockfile exists.
"""

import json
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str
    ecosystem: str  # OSV ecosystem identifier: "PyPI", "npm", "Go", etc.
    source_file: str
    transitive: bool = False


def parse_requirements_txt(path: Path, rel_path: str) -> list[Dependency]:
    """
    Parses requirements.txt-style files. Only handles pinned exact versions
    (`pkg==1.2.3`); ranges (`pkg>=1.0`) and unpinned lines are skipped since
    we can't know the resolved version without an actual install, and a
    wrong guess would produce false CVE results.
    """
    deps: list[Dependency] = []
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return deps

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # strip inline comments and environment markers
        line = line.split("#", 1)[0].strip()
        line = line.split(";", 1)[0].strip()

        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)$", line)
        if m:
            name, version = m.group(1), m.group(2)
            deps.append(
                Dependency(
                    name=name, version=version, ecosystem="PyPI", source_file=rel_path
                )
            )
    return deps


def parse_package_lock_json(path: Path, rel_path: str) -> list[Dependency]:
    """
    Parses npm's package-lock.json. Supports both lockfile v2/v3 ("packages"
    keyed by node_modules path) and the older v1 format ("dependencies",
    recursively nested for transitive deps).
    """
    deps: list[Dependency] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError):
        return deps

    if "packages" in data:  # lockfile v2/v3
        for pkg_path, meta in data["packages"].items():
            if not pkg_path or pkg_path == "":
                continue  # root package entry
            name = meta.get("name") or _name_from_node_modules_path(pkg_path)
            version = meta.get("version")
            if name and version:
                is_transitive = pkg_path.count("node_modules/") > 1
                deps.append(
                    Dependency(
                        name=name,
                        version=version,
                        ecosystem="npm",
                        source_file=rel_path,
                        transitive=is_transitive,
                    )
                )
    elif "dependencies" in data:  # lockfile v1, recursive

        def _walk(dep_dict: dict, transitive: bool):
            for name, meta in dep_dict.items():
                version = meta.get("version")
                if version:
                    deps.append(
                        Dependency(
                            name=name,
                            version=version,
                            ecosystem="npm",
                            source_file=rel_path,
                            transitive=transitive,
                        )
                    )
                if "dependencies" in meta:
                    _walk(meta["dependencies"], transitive=True)

        _walk(data["dependencies"], transitive=False)

    return deps


def _name_from_node_modules_path(pkg_path: str) -> str | None:
    """node_modules/foo/node_modules/@scope/bar -> '@scope/bar'"""
    parts = pkg_path.split("node_modules/")
    return parts[-1] if parts else None


def parse_poetry_lock(path: Path, rel_path: str) -> list[Dependency]:
    """
    Minimal TOML parser for poetry.lock's [[package]] tables. Avoids a hard
    dependency on `tomllib`/`toml` for just this one structured-enough
    format — poetry.lock's [[package]] blocks are simple key="value" pairs.
    """
    deps: list[Dependency] = []
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return deps

    blocks = re.split(r"\n\[\[package\]\]\n", content)
    for block in blocks[1:]:  # skip preamble before first [[package]]
        name_m = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
        version_m = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
        if name_m and version_m:
            deps.append(
                Dependency(
                    name=name_m.group(1),
                    version=version_m.group(1),
                    ecosystem="PyPI",
                    source_file=rel_path,
                )
            )
    return deps


def parse_go_sum(path: Path, rel_path: str) -> list[Dependency]:
    """
    go.sum lines look like:
        github.com/pkg/errors v0.9.1 h1:...
        github.com/pkg/errors v0.9.1/go.mod h1:...
    Each module+version appears twice (once for the module zip, once for
    go.mod); dedup by (name, version).
    """
    deps: dict[tuple[str, str], Dependency] = {}
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    for line in content.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        name, version = parts[0], parts[1]
        version = version.split("/")[0]  # strip "/go.mod" suffix if present
        if version.startswith("v"):
            version = version[1:]
        deps[(name, version)] = Dependency(
            name=name, version=version, ecosystem="Go", source_file=rel_path
        )

    return list(deps.values())


# Dispatch table: filename pattern -> parser function
_PARSERS = [
    (re.compile(r"requirements.*\.txt$"), parse_requirements_txt),
    (re.compile(r"package-lock\.json$"), parse_package_lock_json),
    (re.compile(r"poetry\.lock$"), parse_poetry_lock),
    (re.compile(r"go\.sum$"), parse_go_sum),
]


def parse_manifest(repo_root: str, rel_path: str) -> list[Dependency]:
    """Dispatches to the right parser based on filename, returns [] if unsupported."""
    abs_path = Path(repo_root) / rel_path
    filename = Path(rel_path).name

    for pattern, parser_fn in _PARSERS:
        if pattern.search(filename):
            return parser_fn(abs_path, rel_path)

    return []  # manifest type not yet supported (e.g. Gemfile.lock, Cargo.lock)


def parse_all_manifests(repo_root: str, manifest_paths: list[str]) -> list[Dependency]:
    """
    Parses every manifest in the queue and deduplicates by (name, version,
    ecosystem) — the same package can legitimately appear in multiple lock
    files (e.g. a monorepo with several package-lock.json files), and we
    only want to query OSV once per unique (name, version) pair.
    """
    seen: dict[tuple[str, str, str], Dependency] = {}
    for rel_path in manifest_paths:
        for dep in parse_manifest(repo_root, rel_path):
            key = (dep.name, dep.version, dep.ecosystem)
            if key not in seen:
                seen[key] = dep
    return list(seen.values())
