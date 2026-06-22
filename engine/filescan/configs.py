from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True)
class Config:
    DEDICATED_SECRET_PATTERNS: list[str]
    MANIFEST_PATTERNS: list[str]
    CODE_EXTS: set[str]
    SKIP_DIRS: set[str]
    CODE_FILES: set[str]
    DEFAULT_MAX_FILE_SIZE_BYTES: int


# configs
# ========
configs: Final = Config(
    DEDICATED_SECRET_PATTERNS=[
        ".env",
        ".env.*",
        "*.env",
        "*.pem",
        "*.key",
        "*.pfx",
        "*.p12",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "*credentials*.json",
        "*.credentials",
        ".npmrc",
        ".pypirc",
        ".netrc",
    ],
    MANIFEST_PATTERNS=[
        "requirements.txt",
        "requirements-*.txt",
        "Pipfile",
        "Pipfile.lock",
        "poetry.lock",
        "pyproject.toml",
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "go.mod",
        "go.sum",
        "Gemfile",
        "Gemfile.lock",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "composer.json",
        "composer.lock",
        "Cargo.toml",
        "Cargo.lock",
    ],
    CODE_EXTS={
        ".py",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".go",
        ".java",
        ".rb",
        ".php",
        ".c",
        ".cpp",
        ".h",
        ".hpp",
        ".cs",
        ".sh",
        ".bash",
        ".yml",
        ".yaml",
        ".tf",
        ".dockerfile",
    },
    SKIP_DIRS={
        ".git",
        "node_modules",
        "vendor",
        "__pycache__",
        ".venv",
        "venv",
        "dist",
        "build",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "target",
        ".idea",
        ".vscode",
        "coverage",
        ".next",
        ".nuxt",
    },
    CODE_FILES={
        "Dockerfile",
        "Makefile",
        "Jenkinsfile",
        "Vagrantfile",
    },
    DEFAULT_MAX_FILE_SIZE_BYTES=5 * 1024 * 1024,
)
