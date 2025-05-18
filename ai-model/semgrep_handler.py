import json
import os
from ai_filter import is_threat

SEMGREP_REPORT = "scanner/semgrep.json"

def load_semgrep_findings():
    if not os.path.exists(SEMGREP_REPORT):
        print(f"[!] Semgrep report not found: {SEMGREP_REPORT}")
        return []

    with open(SEMGREP_REPORT, "r") as f:
        try:
            data = json.load(f)
            return data.get("results", [])
        except json.JSONDecodeError:
            print("[!] Invalid Semgrep JSON.")
            return []

def extract_code_snippets(findings):
    snippets = []
    for item in findings:
        # Fallback in case Semgrep omits the line (some OSS rules do)
        line = item.get("extra", {}).get("lines", "")
        if not line or "requires login" in line:
            # Load full file and try extracting the line manually
            try:
                filepath = item.get("path", "")
                if filepath.startswith("/scan/"):
                    filepath = filepath.replace("/scan/", "scanner/")
                with open(filepath, "r") as f:
                    lines = f.readlines()
                    line_number = item["start"]["line"]
                    code_line = lines[line_number - 1].strip()
                    snippets.append(code_line)
            except Exception as e:
                print(f"[DEBUG] Could not extract fallback line: {e}")
        else:
            snippets.append(line.strip())
    return snippets

def classify_snippets(snippets):
    for i, code in enumerate(snippets, 1):
        result = is_threat(code)
        verdict = "THREAT ✅" if result else "False Positive ❌"
        print(f"[{i}] {verdict} — {code}")

if __name__ == "__main__":
    print("[*] Running Semgrep + KDNN classification...")
    findings = load_semgrep_findings()
    if not findings:
        print("No findings to classify.")
    else:
        code_snippets = extract_code_snippets(findings)
        classify_snippets(code_snippets)
