import json
import os
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"  # 0 = all, 1 = filter INFO, 2 = filter WARNING
from ai_filter import is_threat

# === Paths ===
GITLEAKS_REPORT = "outputs/gitleaks-report.json"
SEMGREP_REPORT = "outputs/semgrep-report.json"
YARA_TARGET_DIR = "/app/code"
YARA_EXCLUDE = ["outputs/gitleaks-report.json", "outputs/semgrep-report.json"]
YARA_RULES_PATH = "/rules/test_secrets.yar"

print("[DEBUG] Files inside /app/code:")
for root, dirs, files in os.walk("/app/code"):
    for file in files:
        print("  →", os.path.join(root, file))

# === GITLEAKS ===
def run_gitleaks():
    print("[⚙️] Running Gitleaks...")
    print("[DEBUG] Gitleaks scan target contents:")
    for root, dirs, files in os.walk("/app/code"):
        for file in files:
            print("  →", os.path.join(root, file))

    from subprocess import run
    cmd = [
        "gitleaks", "detect",
        "--no-git",
        "--source=/app/code",
        "--config=/gitleaks.toml",
        "--report-path=/app/outputs/gitleaks-report.json"
    ]
    result = run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[!] Gitleaks scan error:\n{result.stderr}")


def handle_gitleaks():
    print("\n[🔍] Gitleaks Results:")
    print(f"[DEBUG] Checking if Gitleaks report exists at {GITLEAKS_REPORT}: {os.path.exists(GITLEAKS_REPORT)}")

    if not os.path.exists(GITLEAKS_REPORT):
        print("[!] Gitleaks report not found.")
        return []

    with open(GITLEAKS_REPORT, "r") as f:
        try:
            findings = json.load(f)
            print(f"[DEBUG] Raw Gitleaks JSON: {findings}")

            threats = []
            for item in findings:
                code = item.get("Match", "").strip()
                print(f"[DEBUG] Gitleaks finding Match field: {code}")
                if code:
                    result = is_threat(code)
                    verdict = "THREAT ✅" if result else "False Positive ❌"
                    print(f"  → {verdict} — {code}")
                    threats.append((verdict, code))

            if not threats:
                print("  → No Gitleaks threats detected.")
            return threats

        except json.JSONDecodeError:
            print("[!] Invalid Gitleaks JSON.")
            return []


# === YARA ===
def handle_yara():
    print("\n[🔍] YARA Results:")
    try:
        from subprocess import run, PIPE

        find_cmd = (
            f"find {YARA_TARGET_DIR} -type f \\( -name '*.py' -o -name '*.txt' -o -name '*.js' \\) "
            "! -name 'gitleaks-report.json' ! -name 'semgrep-report.json' "
            f"-exec yara -r {YARA_RULES_PATH} {{}} +"
        )
        
        print(f"[DEBUG] YARA find command: {find_cmd}")

        print("[DEBUG] Files targeted by YARA:")
        for root, dirs, files in os.walk(YARA_TARGET_DIR):
            for file in files:
                if file.endswith(".py") or file.endswith(".txt") or file.endswith(".js"):
                    print("  →", os.path.join(root, file))

        
        result = run(find_cmd, shell=True, stdout=PIPE, stderr=PIPE, text=True)
        output = result.stdout.strip().splitlines()
        threats = []

        for line in output:
            # Output line format: RuleName filename
            parts = line.strip().split()
            if len(parts) >= 2:
                rule_name = parts[0]
                matched_file = " ".join(parts[1:])  # In case file path has spaces

                # Just grab the first non-empty line for display
                try:
                    with open(matched_file, "r") as f:
                        first_line = next((l.strip() for l in f if l.strip()), "")
                except Exception as e:
                    first_line = "[Could not read file]"

                result = is_threat(rule_name)  # Classify using rule name
                verdict = "THREAT ✅" if result else "False Positive ❌"
                print(f"  → {verdict} — {rule_name} matched in {matched_file} → {first_line}")
                threats.append((verdict, rule_name))

        if not threats:
            print("  → No YARA matches found.")
        return threats

    except Exception as e:
        print(f"[!] YARA error: {e}")
        return []

def run_semgrep():
    print("[⚙️] Running Semgrep...")

    # Print what files Semgrep is expected to scan
    print("[DEBUG] Running Semgrep on /app/code, files to be scanned:")
    for root, dirs, files in os.walk("/app/code"):
        for file in files:
            if file.endswith(".py") or file.endswith(".js") or file.endswith(".txt"):
                print("  →", os.path.join(root, file))

    # Then run the scan
    from subprocess import run
    cmd = [
        "semgrep", "scan",
        "--config=p/ci",
        "--metrics=on",
        "--verbose", "--debug",
        "--json",
        "--output=/app/outputs/semgrep-report.json",
        "/app/code"
    ]
    
    with open("/app/code/script.py") as f:
        print("[DEBUG] Contents of script.py:")
        print(f.read())

    result = run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[!] Semgrep scan error:\n{result.stderr}")


def handle_semgrep():
    print("\n[🔍] Semgrep Results:")
    print(f"[DEBUG] Checking if Semgrep report exists at {SEMGREP_REPORT}: {os.path.exists(SEMGREP_REPORT)}")

    if not os.path.exists(SEMGREP_REPORT):
        print("[!] Semgrep report not found.")
        return []

    known_threats = {
        "python.lang.security.deserialization.pickle.avoid-pickle": True,
        "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true": True,
    }

    with open(SEMGREP_REPORT, "r") as f:
        try:
            data = json.load(f)
            print("[DEBUG] Raw Semgrep JSON:", data)

            findings = data.get("results", [])
            threats = []

            for item in findings:
                check_id = item.get("check_id", "")
                full_path = item.get("path", "")
                message = item.get("extra", {}).get("message", "").strip()

                print(f"[DEBUG] Semgrep file path: {full_path}")
                print(f"[DEBUG] Semgrep rule ID: {check_id}")
                print(f"[DEBUG] Semgrep message: {message}")

                if message:
                    verdict = "THREAT ✅" if known_threats.get(check_id, False) else "False Positive ❌"
                    print(f"  → {verdict} — {message}")
                    threats.append((verdict, message))
                else:
                    print("  → No message provided by Semgrep.")

            if not threats:
                print("  → No Semgrep threats detected.")
            return threats

        except json.JSONDecodeError:
            print("[!] Invalid Semgrep JSON.")
            return []

        

# === COMBINED RUN ===
if __name__ == "__main__":
    print("📦 Running all handlers through KDNN classifier...\n")

    run_gitleaks()
    run_semgrep()

    report = {
        "gitleaks": handle_gitleaks(),
        "semgrep": handle_semgrep(),
        "yara": handle_yara()
    }

    print("\n✅ Unified Threat Report Complete.")

