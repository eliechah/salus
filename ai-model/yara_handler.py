import subprocess
import os
from ai_filter import is_threat

YARA_RULE_PATH = "/rules/test_secrets.yar"
SCAN_PATH = "/app/scanner"

def run_yara():
    """Runs YARA and returns matches as a list of (rule, filepath)"""
    try:
        result = subprocess.run(
            ["yara", "-r", YARA_RULE_PATH, SCAN_PATH],
            capture_output=True,
            text=True,
            check=True
        )
        matches = []
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            try:
                rule, filepath = line.strip().split(" ", 1)
                matches.append((rule.strip(), filepath.strip()))
            except ValueError:
                continue
        return matches
    except subprocess.CalledProcessError as e:
        print("[!] YARA scan failed:", e.stderr)
        return []

def extract_line(filepath):
    """Returns first non-empty line from file for classification"""
    try:
        with open(f"scanner/{os.path.basename(filepath)}", "r") as f:
            for line in f:
                if line.strip():
                    return line.strip()
    except Exception as e:
        print(f"[DEBUG] Failed to read {local_path}: {e}")
        return ""
    return ""


def classify_yara_matches(matches):
    for i, (rule, filepath) in enumerate(matches, 1):
        code = extract_line(filepath.replace("/scan", "scanner"))  # adjust path to local mount
        if not code:
            print(f"[{i}] ⚠️ Could not read code from {filepath}")
            continue
        result = is_threat(code)
        verdict = "THREAT ✅" if result else "False Positive ❌"
        print(f"[{i}] {verdict} — matched {rule} in {filepath.split('/')[-1]}")
        print(f"     Code: {code}")

if __name__ == "__main__":
    print("[*] Running YARA scan and AI classification...")
    matches = run_yara()
    if not matches:
        print("[✓] No YARA matches found.")
    else:
        classify_yara_matches(matches)
