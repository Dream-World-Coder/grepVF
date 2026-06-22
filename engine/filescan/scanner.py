import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path

from .configs import configs


# return type
# ============
@dataclass
class RoutedFiles:
    secrets: list[str] = field(default_factory=list)
    manifests: list[str] = field(default_factory=list)
    code: list[str] = field(default_factory=list)
    skipped_binary: list[str] = field(default_factory=list)
    skipped_too_large: list[str] = field(default_factory=list)

    @property
    def total_routed(self) -> int:
        return len(self.secrets) + len(self.manifests) + len(self.code)


def _matches_any(filename: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(filename, pat) for pat in patterns)


def _probably_binary(path: Path, sniff_bytes: int = 1024) -> bool:
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(sniff_bytes)
        return b"\x00" in chunk
    except OSError:
        return True  # unreadable -> treat as skip-worthy


# main
# =====
def scan_files(
    root_path: str,
    max_file_size_bytes: int = configs.DEFAULT_MAX_FILE_SIZE_BYTES,
    extra_skip_dirs: set[str] | None = None,
) -> RoutedFiles:

    skip_dirs = configs.SKIP_DIRS | (extra_skip_dirs or set())
    routed = RoutedFiles()
    repo_root = Path(root_path).resolve()

    for dirpath, dirnames, filenames in os.walk(repo_root):
        # prune skip-dirs in place so os.walk doesn't descend into them
        dirnames[:] = [
            d for d in dirnames if d not in skip_dirs and not d.startswith(".git")
        ]

        for filename in filenames:
            abs_path = Path(dirpath) / filename
            rel_path = str(abs_path.relative_to(repo_root))

            try:
                size = abs_path.stat().st_size
            except OSError:
                continue

            if size > max_file_size_bytes:
                routed.skipped_too_large.append(rel_path)
                continue

            if size == 0:
                continue  # empty files carry no findings, skip silently

            is_dedicated_secret = _matches_any(
                filename, configs.DEDICATED_SECRET_PATTERNS
            )
            is_manifest = _matches_any(filename, configs.MANIFEST_PATTERNS)
            ext = abs_path.suffix.lower()
            is_code_ext = (
                ext in configs.CODE_EXTS
                or filename in configs.CODE_FILES
                or filename.startswith("Dockerfile.")
            )

            if not (is_dedicated_secret or is_manifest or is_code_ext):
                continue  # unknown file type, e.g. .md, .png -- nothing to scan

            if _probably_binary(abs_path):
                routed.skipped_binary.append(rel_path)
                continue

            if is_dedicated_secret:
                routed.secrets.append(rel_path)

            if is_manifest:
                routed.manifests.append(rel_path)

            # Source code files go to BOTH code and secrets queues -- see
            # module docstring for why this is intentional, not an oversight.
            if is_code_ext:
                routed.code.append(rel_path)
                if not is_dedicated_secret:
                    routed.secrets.append(rel_path)

    return routed
