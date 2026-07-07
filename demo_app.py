import sqlite3

def get_user_data(username):
    """
    Simulates a database lookup that is vulnerable to SQL Injection.
    This should be caught by both the Semantics Checker (Semgrep) 
    and the new ZoneScan layer!
    """
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # [VULNERABILITY: SQL Injection via string concatenation]
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    
    return cursor.fetchall()


def connect_to_aws():
    """
    Simulates a hardcoded credential.
    This should be caught by the Entropy Checker.
    """
    # [VULNERABILITY: Hardcoded AWS Access Key]
    aws_access_key = "AKIAIOSFODNN7EXAMPLE"
    aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    
    return aws_access_key, aws_secret_key
