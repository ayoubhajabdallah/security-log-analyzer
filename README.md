# Security Log Analyzer

![Tests](https://github.com/ayoubhajabdallah/security-log-analyzer/actions/workflows/tests.yml/badge.svg)

A Python security application that analyzes authentication logs and detects suspicious login activity using configurable security rules and machine-learning anomaly detection.
![Security Log Analyzer Dashboard](docs/dashboard.png)
The project provides:

- A command-line interface
- A REST API built with FastAPI
- A browser dashboard
- Rule-based brute-force detection
- Isolation Forest anomaly detection
- Automated tests with GitHub Actions
- Docker support

## Features

### Rule-based detection

The analyzer detects:

- IP addresses with many failed login attempts
- IP addresses targeting multiple usernames
- Repeated failures within a configurable time window

### Machine-learning anomaly detection

The project uses scikit-learn's `IsolationForest` to identify IP addresses whose behavior differs significantly from other IP addresses.

The model considers:

- Total login attempts
- Failed login attempts
- Number of unique targeted users
- Failed-login ratio

Machine-learning results are treated as additional investigation signals, not definitive proof of malicious activity.

### Interfaces

The same analysis logic is available through:

- A Python command-line interface
- A FastAPI REST endpoint
- An interactive browser dashboard
- JSON output for automation and integration

## Technology Stack

- Python 3.14
- FastAPI
- Uvicorn
- scikit-learn
- HTML, CSS and JavaScript
- Docker
- GitHub Actions
- Python `unittest`

## Project Structure

```text
security-log-analyzer/
├── .github/
│   └── workflows/
│       └── tests.yml
├── data/
│   └── sample_auth.log
├── src/
│   ├── analyzer.py
│   ├── api.py
│   ├── dashboard.py
│   ├── main.py
│   ├── ml_analyzer.py
│   ├── parser.py
│   └── report.py
├── tests/
│   ├── test_analyzer.py
│   ├── test_api.py
│   ├── test_ml_analyzer.py
│   ├── test_parser.py
│   └── test_report.py
├── .dockerignore
├── .gitignore
├── Dockerfile
├── README.md
└── requirements.txt