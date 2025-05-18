# Git Repository Security Scanner (SALUS)

**SALUS** is a full-stack GitHub repository security pipeline that integrates CI/CD scanning tools with AI-driven threat classification. It continuously analyzes code for hardcoded secrets, misconfigurations, and vulnerabilities using **Gitleaks**, **YARA**, and **Semgrep**, then classifies findings with a **Keras deep learning model** to minimize false positives and automate secure deployments.

---

## Features

* **Gitleaks Integration**: Scans commits for secrets like API keys and tokens
* **YARA Integration**: Detects low-level patterns and applies custom rules in source files
* **Semgrep Integration**: Performs semantic static analysis to identify code vulnerabilities and misconfigurations
* **AI-Based Threat Classification**: Keras DNN model filters false positives from scan outputs
* **Jenkins/GitHub Actions Integration**: Secure CI/CD flow with automated block/pass decision-making
* **Dockerized Deployment**: All services managed with Docker Compose for ease of setup

---

## Folder Structure

```bash
.
├── ai-model/              # KDNN model, tokenizer, and classification logic
├── scanner/               # Scan inputs and outputs (e.g. leaks.py, gitleaks-report.json)
├── configs/
│   ├── gitleaks.toml      # Gitleaks configuration
│   └── yara_rules/        # YARA rules (custom_rules.yar, test_secrets.yar, etc.)
├── docker-compose.yml     # Runs all tools together
├── Jenkinsfile            # CI pipeline (optional)
├── README.md
```

---

## Getting Started

### Prerequisites

* Docker & Docker Compose
* Git
* Optional: Jenkins / GitHub Actions runner

### Installation

```bash
git clone https://github.com/your-username/salus.git
cd salus
docker compose build
```

---

## Usage

### 1. Run Full Scan

```bash
docker compose run --rm gitleaks
docker compose run --rm semgrep
```

YARA is executed inside the AI handler.

### 2. Classify Findings with AI

```bash
docker compose run --rm ai_model python3 output_handler.py
```

### 3. Block/Allow via CI/CD (Optional)

* Jenkins will halt deployments if real threats are detected.
* GitHub Actions workflow (`.github/workflows/security-scan.yml`) can be added in Day 4.

---

## Model Details

| Model            | Accuracy | Use Case                   |
| ---------------- | -------- | -------------------------- |
| Keras DNN (KDNN) | 97%      | General classification     |
| Random Forest    | 95%      | Safe commit detection      |
| Decision Tree    | 94%      | Vulnerability recall focus |

---

## Roadmap

### Day 1 – AI Model Finalization

* [x] Train KDNN
* [x] Save `.keras` + `tokenizer.pkl`
* [x] Create classification scripts

### Day 2 – Tool Integration

* [x] Dockerize Gitleaks, YARA, Semgrep
* [x] Compose file setup

### Day 3 – Handlers and Reporting

* [x] Create `github_scan_handler.py`, `yara_handler.py`, and `semgrep_handler.py`
* [x] Generate unified scan report (`output_handler.py`)

### Day 4 – CI/CD Integration

* [ ] Build GitHub Actions or Jenkinsfile
* [ ] Test end-to-end blocking behavior

---

## License

[MIT](LICENSE)