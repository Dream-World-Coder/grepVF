"""
conftest.py — pytest fixtures shared across the entire test suite.

Fixtures here are automatically available in every test file without imports.
"""

import textwrap
from pathlib import Path

import pytest


def _write(root: Path, rel: str, content: str) -> Path:
    """Helper: write a file at root/rel, creating parent dirs as needed."""
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(textwrap.dedent(content))
    return target


@pytest.fixture()
def tmp_repo(tmp_path: Path) -> Path:
    """Minimal empty repository root (just the directory)."""
    return tmp_path


@pytest.fixture()
def repo_with_secrets(tmp_path: Path) -> Path:
    """Repo containing files that trigger entropy & regex secret detectors."""
    _write(
        tmp_path,
        ".env",
        """\
        AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
        AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
        DATABASE_URL=postgres://admin:SuperS3cr3t@db.internal:5432/prod
    """,
    )
    _write(
        tmp_path,
        "config.py",
        """\
        SECRET_KEY = "hardcoded-django-secret-value-should-not-be-here"
        DEBUG = True
    """,
    )
    return tmp_path


@pytest.fixture()
def repo_with_weak_crypto(tmp_path: Path) -> Path:
    """Repo containing weak cryptography patterns."""
    _write(
        tmp_path,
        "crypto_utils.py",
        """\
        import hashlib

        def get_checksum(data: bytes) -> str:
            return hashlib.md5(data).hexdigest()

        def get_sig(data: bytes) -> str:
            return hashlib.sha1(data).hexdigest()
    """,
    )
    return tmp_path


@pytest.fixture()
def repo_with_tls_issues(tmp_path: Path) -> Path:
    """Repo containing disabled TLS verification."""
    _write(
        tmp_path,
        "src/api/client.py",
        """\
        import requests

        def fetch(url):
            return requests.get(url, verify=False)
    """,
    )
    return tmp_path


@pytest.fixture()
def repo_with_injection(tmp_path: Path) -> Path:
    """Repo containing SQL injection and shell injection patterns."""
    _write(
        tmp_path,
        "db.py",
        """\
        import sqlite3
        import subprocess

        def get_user(username):
            conn = sqlite3.connect("app.db")
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE name = '" + username + "'")
            return cur.fetchall()

        def run_cmd(user_input):
            subprocess.run(user_input, shell=True)
    """,
    )
    return tmp_path


@pytest.fixture()
def repo_with_requirements(tmp_path: Path) -> Path:
    """Repo with a requirements.txt containing pinned packages."""
    _write(
        tmp_path,
        "requirements.txt",
        """\
        requests==2.25.0
        flask==1.0.0
        django==2.0.0
    """,
    )
    return tmp_path


@pytest.fixture()
def repo_with_package_lock(tmp_path: Path) -> Path:
    """Repo with a minimal package-lock.json (npm lockfile v2)."""
    import json

    lock = {
        "name": "test-app",
        "version": "1.0.0",
        "lockfileVersion": 2,
        "packages": {
            "node_modules/lodash": {
                "version": "4.17.4",
                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.4.tgz",
            },
        },
    }
    _write(tmp_path, "package-lock.json", json.dumps(lock, indent=2))
    return tmp_path


@pytest.fixture()
def repo_with_dockerfile(tmp_path: Path) -> Path:
    """Repo with a Dockerfile missing a USER directive."""
    _write(
        tmp_path,
        "Dockerfile",
        """\
        FROM python:3.11-slim
        WORKDIR /app
        COPY . .
        RUN pip install -r requirements.txt
        CMD ["python", "main.py"]
    """,
    )
    return tmp_path


@pytest.fixture()
def repo_clean(tmp_path: Path) -> Path:
    """Repo with no known vulnerabilities — used to assert zero false positives."""
    _write(
        tmp_path,
        "safe.py",
        """\
        import hashlib
        import secrets
        import os

        def get_checksum(data: bytes) -> str:
            return hashlib.sha256(data).hexdigest()

        def generate_token() -> str:
            return secrets.token_hex(32)

        DEBUG = os.environ.get("DJANGO_DEBUG", "False") == "True"
    """,
    )
    return tmp_path


@pytest.fixture()
def repo_mixed(tmp_path: Path) -> Path:
    """Repo mixing multiple vulnerability classes for integration tests."""
    _write(tmp_path, ".env", "STRIPE_SECRET=sk_live_abcdef1234567890abcd\n")
    _write(tmp_path, "requirements.txt", "flask==1.0.0\nrequests==2.25.0\n")
    _write(
        tmp_path,
        "app.py",
        """\
        import hashlib
        import requests
        import subprocess

        DEBUG = True

        def checksum(data):
            return hashlib.md5(data).hexdigest()

        def fetch(url):
            return requests.get(url, verify=False)

        def run(cmd):
            subprocess.run(cmd, shell=True)
    """,
    )
    return tmp_path
