# File Router / scan_files

partitions a repository into three typed queues so each
downstream scanner only ever sees the files it knows how to reason about.

Important: queues are NOT mutually exclusive. A `.py` file can legitimately
contain a hardcoded secret AND a code-logic vulnerability, so source files
are routed to both the "code" queue (for semantic/AST analysis) and the
"secrets" queue (for entropy/regex scanning). Treating routing as a strict
partition is a common mistake that causes hardcoded secrets inside .py/.js
files to be silently missed.

---

configs{}

`DEDICATED_SECRET_PATTERNS`:
Files that are always secret-queue candidates regardless of extension.

`MANIFEST_PATTERNS`:
Dependency manifests / lockfiles routed to the CVE checker.

`CODE_EXTS`:
Extensions that get full semantic (Semgrep/AST) & secret-scan treatment.

`SKIP_DIRS`:
Files/dirs to always skip — vendored code, build artifacts, VCS internals.

`CODE_FILES`:
Files with no extension but a well-known name that still need semantic
scanning (Semgrep has dedicated grammars for several of these).

`DEFAULT_MAX_FILE_SIZE_BYTES`:
Hard cap so a single absurdly large generated file doesn't stall the scan.


---

```py
def scan_files(
    root_path: str,
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
    extra_skip_dirs: set[str] | None = None,
) -> RoutedFiles:
```


Walk `root_path` and classify every file into one or more queues.

Returns a `RoutedFiles` object. Paths are relative to `root_path` so that
findings produced downstream can be reported with repo-relative paths
(matches what SARIF/GitHub expects for inline PR annotations).

---
