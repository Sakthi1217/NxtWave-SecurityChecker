import sys
import os

# Add src to pythonpath so we can import the module locally
sys.path.insert(0, os.path.abspath('src'))

from semgrep.formatter.nxtwave_formatter import format_nxtwave_audit

# Mock sample Semgrep JSON results
sample_scan_results = {
    "results": [
        {
            "check_id": "nxtwave-hardcoded-secret",
            "path": "app.py",
            "start": {"line": 14},
            "extra": {
                "severity": "ERROR",
                "message": "Hardcoded AI API key detected."
            }
        },
        {
            "check_id": "other-unrelated-rule",
            "path": "utils.py",
            "start": {"line": 42},
            "extra": {
                "severity": "INFO",
                "message": "Unrelated issue."
            }
        }
    ]
}

def test_formatter():
    print("--- Running Gap-Analysis Formatter on Sample Data ---")
    json_output = format_nxtwave_audit(sample_scan_results)
    print(json_output)

if __name__ == '__main__':
    test_formatter()
