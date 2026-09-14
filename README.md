# aws-iam-analyzer

Static analyzer for dangerous IAM permissions: wildcard admin, iam:PassRole, inline policies, and destructive S3 access.

## Rules

| ID | Severity | Description |
|----|----------|-------------|
| IAM-001 | CRITICAL | Wildcard admin policy attached (Action:* on Resource:*) |
| IAM-002 | HIGH | Full IAM access granted (iam:*) |
| IAM-003 | HIGH | iam:PassRole allowed on all resources |
| IAM-004 | MEDIUM | Inline policy attached to IAM user |
| IAM-005 | MEDIUM | Destructive S3 action allowed on all buckets |

## Install

```bash
pip install rich
```

## Usage

```bash
# Analyze from JSON file
python main.py entities.json

# Analyze from stdin
cat entities.json | python main.py

# JSON output with critical exit code
python main.py entities.json --output json --fail-on-critical

# Write CSV report
python main.py entities.json --csv-path report.csv
```

## Tests

```bash
pip install pytest pytest-cov ruff
ruff check .
pytest tests/ -v --cov=analyzer --cov=report
```

## CI

GitHub Actions runs ruff and pytest on every push to main.
