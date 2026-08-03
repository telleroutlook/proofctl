# Negative (Tamper) Tests

This directory contains tests that verify the checker **correctly rejects**
malformed or tampered certificates. Every test must produce a non-zero exit code
from the checker.

## Running

```bash
# From project root — requires pytest
pytest tests/negative/

# Point at a specific certificate directory
CERT_DIR=certificates/033/primary pytest tests/negative/

# Use a different checker command
CHECKER_CMD="python3 checker/check_certificate.py" pytest tests/negative/
```

## Structure

| File | Purpose |
|------|---------|
| `conftest.py` | pytest fixtures: `cert_path`, `cert_data`, `checker_cmd` |
| `test_tamper_basic.py` | 5 generic tamper cases (see below) |

## Tamper cases in test_tamper_basic.py

| Test | What it does |
|------|-------------|
| `test_tamper_conclusion_uncertified` | Sets `conclusion = "UNCERTIFIED"` |
| `test_tamper_unknown_field` | Injects an unknown top-level field |
| `test_tamper_wrong_version` | Sets `format_version = "0.0"` |
| `test_tamper_empty_witnesses_a` | Clears `witnesses_a` to `{}` |
| `test_tamper_kappa_zero` | Sets `kappa_upper = "0"` |

## Adding domain-specific tests

Create a new file in this directory, e.g. `test_tamper_weil.py`, and import
the fixtures from `conftest.py`:

```python
def test_tamper_my_case(cert_data, checker_cmd):
    import copy, json, subprocess, tempfile, pathlib
    cert = copy.deepcopy(cert_data)
    # ... mutate cert ...
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        json.dump(cert, f)
        tmp = f.name
    result = subprocess.run(checker_cmd + [tmp], capture_output=True)
    pathlib.Path(tmp).unlink(missing_ok=True)
    assert result.returncode != 0
```
