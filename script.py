# This file is intentionally vulnerable to test AI classification.

# === GITLEAKS & YARA ===
AWS_SECRET_ACCESS_KEY = "AKIA1234567890TESTKEY"
eval("print('danger')")
import subprocess
subprocess.call("ls", shell=True)


# === SEMGREP (Hardcoded credential + command injection) ===
def login():
    password = "hunter2"  # Hardcoded password

def run_shell():
    import subprocess
    user_input = input("Enter a command: ")
    subprocess.call(user_input, shell=True)  # Vulnerable to shell injection
