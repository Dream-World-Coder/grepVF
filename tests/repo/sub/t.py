import hashlib
import sqlite3
import subprocess

import requests
from flask import Flask, request

app = Flask(__name__)

# =====================================================================
# PART 1: Targeting Entropy & Regex Scanners
# =====================================================================

# 1. Hardcoded Secrets
# Entropy Checker will flag this high-entropy string
api_key = "secret_api_key_51HJG1287SHBAjsg87123gasd"


# 2. Weak Cryptography
def generate_hash(data):
    # The rule registry should flag md5() as deprecated.
    return hashlib.md5(data.encode()).hexdigest()


# 3. Insecure Configuration (TLS)
def fetch_data(url):
    # This disables TLS verification, allowing MITM attacks.
    return requests.get(url, verify=False)


# =====================================================================
# PART 2: Targeting Semgrep / AST Scanners
# =====================================================================


# 4. SQL Injection (Taint Tracking Required)
@app.route("/user")
def get_user():
    # Source: User input
    user_id = request.args.get("id")
    conn = sqlite3.connect("bank_users.db")
    cursor = conn.cursor()

    # AST analysis must trace 'user_id' into the formatted 'query' variable
    query = f"SELECT * FROM accounts WHERE id = {user_id}"

    # Sink: Execution of the tainted query
    cursor.execute(query)
    return str(cursor.fetchall())


# 5. Command Injection (Taint Tracking Required)
@app.route("/ping")
def ping_host():
    # Source: User input
    target_host = request.args.get("host")

    # AST analysis must track the concatenation
    command = "ping -c 1 " + target_host

    # Sink: Execution with shell=True
    result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    return result.stdout.read()


if __name__ == "__main__":
    # 6. Insecure Defaults
    app.run(debug=True)
