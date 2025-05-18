import json
import os
from ai_filter import is_threat

# === Paths ===
GITLEAKS_REPORT = "scanner/gitleaks-report.json"
SEMGREP_REPORT = "scanner/semgrep-report.json"
YARA_TARGET_DIR = "scanner"
YARA_RULES_PATH = "/rules/test_secrets.yar"

# === GITLEAKS ===
def handle_gitleaks():
    print("\n[🔍] Gitleaks Results:")
    if not os.path.exists(GITLEAKS_REPORT):
        print("[!] Gitleaks report not found.")
        return []
    with open(GITLEAKS_REPORT, "r") as f:
        try:
            findings = json.load(f)
            threats = []
            for item in findings:
                code = item.get("line", "").strip()
                if code:
                    result = is_threat(code)
                    verdict = "THREAT ✅" if result else "False Positive ❌"
                    print(f"  → {verdict} — {code}")
                    threats.append((verdict, code))
            return threats
        except json.JSONDecodeError:
            print("[!] Invalid Gitleaks JSON.")
            return []

# === YARA ===
def handle_yara():
    print("\n[🔍] YARA Results:")
    try:
        from subprocess import run, PIPE
        result = run(
            ["yara", "-r", YARA_RULES_PATH, YARA_TARGET_DIR],
            stdout=PIPE,
            stderr=PIPE,
            text=True,
        )
        output = result.stdout.strip().splitlines()
        threats = []
        for line in output:
            if line:
                parts = line.strip().split()
                matched_file = parts[-1]
                with open(matched_file, "r") as f:
                    first_line = next((l.strip() for l in f if l.strip()), "")
                    if first_line:
                        result = is_threat(first_line)
                        verdict = "THREAT ✅" if result else "False Positive ❌"
                        print(f"  → {verdict} — {matched_file} → {first_line}")
                        threats.append((verdict, first_line))
        if not threats:
            print("  → No YARA matches found.")
        return threats
    except Exception as e:
        print(f"[!] YARA error: {e}")
        return []

# === SEMGREP ===
def handle_semgrep():
    print("\n[🔍] Semgrep Results:")
    if not os.path.exists(SEMGREP_REPORT):
        print("[!] Semgrep report not found.")
        return []
    with open(SEMGREP_REPORT, "r") as f:
        try:
            data = json.load(f)
            findings = data.get("results", [])
            threats = []
            for item in findings:
                line = item.get("extra", {}).get("lines", "")
                if not line or "requires login" in line:
                    # fallback
                    try:
                        filepath = item.get("path", "")
                        if filepath.startswith("/scan/"):
                            filepath = filepath.replace("/scan/", "scanner/")
                        with open(filepath, "r") as f_in:
                            lines = f_in.readlines()
                            line_number = item["start"]["line"]
                            line = lines[line_number - 1].strip()
                    except Exception:
                        line = ""
                if line:
                    result = is_threat(line)
                    verdict = "THREAT ✅" if result else "False Positive ❌"
                    print(f"  → {verdict} — {line}")
                    threats.append((verdict, line))
            return threats
        except json.JSONDecodeError:
            print("[!] Invalid Semgrep JSON.")
            return []

# === COMBINED RUN ===
if __name__ == "__main__":
    print("📦 Running all handlers through KDNN classifier...\n")
    report = {
        "gitleaks": handle_gitleaks(),
        "yara": handle_yara(),
        "semgrep": handle_semgrep(),
    }
    print("\n✅ Unified Threat Report Complete.")
