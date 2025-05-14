import json
import os
from ai_filter import is_threat

GITLEAKS_REPORT = "scanner/gitleaks.json"

print("[*] Looking for:", GITLEAKS_REPORT)

def load_gitleaks_findings(path):
    if not os.path.exists(path):
        print("[!] File not found:", path)
        return []

    with open(path, "r") as f:
        try:
            data = json.load(f)
            print(f"[✓] Loaded {len(data)} findings.")
            return data
        except json.JSONDecodeError:
            print("[!] Invalid JSON in gitleaks.json")
            return []

def extract_code_snippets(findings):
    return [item.get("Match") for item in findings if "Match" in item]

def classify_snippets(snippets):
    for i, snippet in enumerate(snippets, 1):
        result = is_threat(snippet)
        verdict = "THREAT ✅" if result else "False Positive ❌"
        print(f"[{i}] {verdict} — {snippet.strip()}")

if __name__ == "__main__":
    findings = load_gitleaks_findings(GITLEAKS_REPORT)
    if findings:
        snippets = extract_code_snippets(findings)
        classify_snippets(snippets)
    else:
        print("[!] No findings to classify.")
