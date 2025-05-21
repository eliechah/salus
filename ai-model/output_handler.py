import json
import os
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"  # 0 = all, 1 = filter INFO, 2 = filter WARNING
from ai_filter import is_threat

# === Paths ===
GITLEAKS_REPORT = "outputs/gitleaks-report.json"
SEMGREP_REPORT = "outputs/semgrep-report.json"
YARA_TARGET_DIR = "/app/code"
YARA_EXCLUDE = ["outputs/gitleaks-report.json", "outputs/semgrep-report.json"]
YARA_RULES_PATH = "/app/configs/yara_rules/test_secrets.yar"

os.makedirs("outputs", exist_ok=True)


# === GITLEAKS ===
def run_gitleaks():
    print("[⚙️] Running Gitleaks...")

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


# === SUMGREP ===
def run_semgrep():
    print("[⚙️] Running Semgrep...")

    # Then run the scan
    from subprocess import run
    cmd = [
        "semgrep", "scan",
        "--config=p/python",
        "--no-git-ignore",
        "--json",
        "--output=/app/outputs/semgrep-report.json",
        "/app/code"
    ]

    result = run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[!] Semgrep scan error:\n{result.stderr}")


def handle_semgrep():
    print("\n[🔍] Semgrep Results:")
    print(f"[DEBUG] Checking if Semgrep report exists at {SEMGREP_REPORT}: {os.path.exists(SEMGREP_REPORT)}")

    if not os.path.exists(SEMGREP_REPORT):
        print("[!] Semgrep report not found.")
        return []

    with open(SEMGREP_REPORT, "r") as f:
        try:
            data = json.load(f)

            findings = data.get("results", [])
            threats = []

            for item in findings:
                message = item.get("extra", {}).get("message", "").strip()
                if not message:
                    continue

                print(f"[DEBUG] Semgrep finding message: {message}")
                result = is_threat(message)
                verdict = "THREAT ✅" if result else "False Positive ❌"
                print(f"  → {verdict} — {message}")
                threats.append((verdict, message))

            if not threats:
                print("  → No Semgrep threats detected.")
            return threats

        except json.JSONDecodeError:
            print("[!] Invalid Semgrep JSON.")
            return []


# === YARA ===
def handle_yara():
    print("\n[🔍] YARA Results:")
    try:
        from subprocess import run, PIPE

        find_cmd = (
            f"find {YARA_TARGET_DIR} -type f "
            f"\\( -name '*.py' -o -name '*.txt' -o -name '*.js' \\) "
            f"! -name '/app/ai-model/ai_filter.py' "
            f"-exec yara {YARA_RULES_PATH} {{}} \\;"
        )
        
        print(f"[DEBUG] YARA find command: {find_cmd}")
        
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

    # Count total threats
    total_threats = sum(1 for tool_results in report.values() for verdict, _ in tool_results if "THREAT" in verdict)

    if total_threats > 0:
        print(f"\n❌ Detected {total_threats} threat(s). Failing the pipeline.")
        exit(1)
    else:
        print("\n✅ No threats detected. Proceeding safely.")
