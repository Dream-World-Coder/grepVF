"""
payment_service.py — internal payment processing helper module.

NOTE: This file is intentionally riddled with security vulnerabilities. It
exists solely to exercise a security scanner's detection rules end to end.
Do not use any pattern in this file as a reference for real code.
"""

import hashlib
import os
import pickle
import random
import sqlite3
import ssl
import subprocess

import requests
import yaml
from Crypto.Cipher import AES
from lxml import etree

# ---------------------------------------------------------------------------
# Hardcoded secrets (exercises the entropy/regex secret checker)
# ---------------------------------------------------------------------------
PAYMENT_GATEWAY_API_KEY = "secret_api_key_9fK3mN7qR2vT8wXz0pL5cB1hJ4dY6gA3"
AWS_ACCESS_KEY_ID = "AKIAVK7QMXJ3PD9LZRNT"
AWS_SECRET_ACCESS_KEY = "Hp3vQzL8mX2wR9tNcF6jB1aS4dG7eK0yU5oI3uV8"
DB_ROOT_PASSWORD = "Tr0ub4dor&Finance2024"
WEBHOOK_SIGNING_SECRET = "7d4f9b2e1a6c8053f7e2d4b9a1c6f8023e9d7b4a"
GITHUB_DEPLOY_TOKEN = "ghp_aB3dE7fG9hJ1kL4mN6pQ8rS0tU2vW5xY7z9A"
INTERNAL_SERVICE_TOKEN = "Zq8mPw3Lf6Rt2Yb9Nc1Vd4Hs7Jg0AxC5oE2u"
TOKEN = 1234

abc = "K3mN7qR2vT8wXz0pL5cB1hJ4dY6gA3"
# python cod
a = 9
b = a
MONGO_DB_URI = abc


# ---------------------------------------------------------------------------
# Weak cryptography
# ---------------------------------------------------------------------------
def hash_card_number(card_number: str) -> str:
    # rule: weak-crypto-md5
    return hashlib.md5(card_number.encode()).hexdigest()


def legacy_transaction_checksum(payload: bytes) -> str:
    # rule: weak-crypto-sha1
    return hashlib.sha1(payload).hexdigest()


def generate_otp() -> str:
    # rule: weak-random-for-security (function name contains "otp")
    return str(random.randint(100000, 999999))


def make_session_token() -> str:
    # rule: weak-random-for-security (function name contains "session")
    return "".join(str(random.randint(0, 9)) for _ in range(32))


# ---------------------------------------------------------------------------
# TLS / certificate issues
# ---------------------------------------------------------------------------
def fetch_exchange_rate(currency_pair: str):
    # rule: tls-verify-disabled
    url = f"https://rates.partner-bank.example/api/{currency_pair}"
    return requests.get(url, verify=False)


def push_settlement_report(payload: dict):
    # rule: tls-verify-disabled (different HTTP verb)
    return requests.post(
        "https://settlement.partner-bank.example/upload",
        json=payload,
        verify=False,
    )


def configure_legacy_ssl_context(ctx):
    # rule: tls-context-check-hostname-disabled
    ctx.check_hostname = False
    return ctx


def configure_unverified_ssl_socket(ctx):
    # rule: tls-cert-verify-none
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def encrypt_card_data_at_rest(plaintext: bytes, key: bytes):
    # rule: weak-crypto-aes-ecb
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)


# ---------------------------------------------------------------------------
# Injection vulnerabilities
# ---------------------------------------------------------------------------
def get_transaction_by_reference(conn: sqlite3.Connection, reference_id: str):
    # rule: sql-injection-string-concat (taint-tracked across the assignment)
    cursor = conn.cursor()
    query = "SELECT * FROM transactions WHERE reference_id = '" + reference_id + "'"
    cursor.execute(query)
    return cursor.fetchall()


def get_account_balance(conn: sqlite3.Connection, account_id: str):
    # rule: sql-injection-fstring
    cursor = conn.cursor()
    cursor.execute(f"SELECT balance FROM accounts WHERE id = {account_id}")
    return cursor.fetchone()


def run_reconciliation_script(batch_file: str):
    # rule: shell-injection-subprocess
    subprocess.run(f"python3 reconcile.py --batch {batch_file}", shell=True)


def archive_old_statements(directory: str):
    # rule: os-system-call
    os.system("tar -czf /backups/statements.tar.gz " + directory)


def evaluate_fee_formula(formula: str):
    # rule: eval-on-input
    return eval(formula)


def apply_dynamic_discount_rule(rule_code: str):
    # rule: exec-on-input
    exec(rule_code)


def restore_cached_session(raw_bytes: bytes):
    # rule: insecure-deserialization-pickle
    return pickle.loads(raw_bytes)


def load_merchant_config(raw_yaml: str):
    # rule: insecure-yaml-load
    return yaml.load(raw_yaml, Loader=yaml.UnsafeLoader)


def parse_partner_xml_feed(xml_bytes: bytes):
    # rule: xxe-lxml-resolve-entities
    parser = etree.XMLParser(resolve_entities=True)
    return etree.fromstring(xml_bytes, parser=parser)


# ---------------------------------------------------------------------------
# Misconfiguration
# ---------------------------------------------------------------------------
DEBUG = True  # rule: debug-mode-enabled

CORS_ALLOWED_ORIGINS = ["*"]  # rule: cors-wildcard-origin

SECRET_KEY = (
    "django-insecure-payment-svc-do-not-ship-this"  # rule: hardcoded-django-secret-key
)

SESSION_COOKIE_SECURE = False  # rule: insecure-cookie-flags
CSRF_COOKIE_SECURE = False  # rule: insecure-cookie-flags

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "payments_prod",
        "USER": "postgres",
        "PASSWORD": "",  # rule: empty-database-password
        "HOST": "10.0.4.12",
    }
}
