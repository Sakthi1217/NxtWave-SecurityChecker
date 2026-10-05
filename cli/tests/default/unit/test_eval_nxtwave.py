import logging
import json
from click.testing import CliRunner

# We mock out telemetry before importing cli to avoid missing dependencies in this raw environment
import sys
from unittest.mock import MagicMock
sys.modules['opentelemetry'] = MagicMock()
sys.modules['opentelemetry.context'] = MagicMock()
sys.modules['opentelemetry.instrumentation'] = MagicMock()
sys.modules['opentelemetry.instrumentation.requests'] = MagicMock()
sys.modules['opentelemetry.instrumentation.threading'] = MagicMock()
sys.modules['opentelemetry.sdk'] = MagicMock()
sys.modules['opentelemetry.exporter'] = MagicMock()
sys.modules['opentelemetry.exporter.otlp'] = MagicMock()
sys.modules['opentelemetry.exporter.otlp.proto'] = MagicMock()
sys.modules['opentelemetry.exporter.otlp.proto.http'] = MagicMock()
sys.modules['opentelemetry.exporter.otlp.proto.http.trace_exporter'] = MagicMock()

from semgrep.cli import eval_nxtwave


def test_eval_nxtwave_missing_target():
    result = CliRunner().invoke(eval_nxtwave, ["missing-student-project"])

    assert result.exit_code == 2
    assert "does not exist" in result.output


def test_eval_nxtwave_help():
    """Verify the new CLI subcommand renders help correctly."""
    runner = CliRunner()
    result = runner.invoke(eval_nxtwave, ['--help'])

    assert result.exit_code == 0
    assert "Dedicated evaluation command for student AI project analysis" in result.output
    assert "--rules-dir PATH" in result.output

def test_eval_nxtwave_execution(caplog, tmp_path, monkeypatch):
    """Verify the command emits the scanner's structured audit payload."""
    target = tmp_path / "student.py"
    target.write_text("print('student')", encoding="utf-8")

    def fake_scanner(state, rules_dir):
        return {
            "semgrep_audit": {
                "status": "PASSED",
                "compliance_score": 100,
                "total_violations": 0,
                "unimplemented_rules": [],
                "implemented_rules": ["nxtwave-example"],
            }
        }

    monkeypatch.setattr("semgrep.cli.semgrep_scanner_node", fake_scanner)
    runner = CliRunner()
    with caplog.at_level(logging.INFO):
        result = runner.invoke(eval_nxtwave, [str(target)])

        assert result.exit_code == 0
        assert json.loads(result.output)["compliance_score"] == 100
        assert str(target) in caplog.text


def test_eval_nxtwave_scan_error_exits_nonzero(tmp_path, monkeypatch):
    target = tmp_path / "student.py"
    target.write_text("print('student')", encoding="utf-8")
    monkeypatch.setattr(
        "semgrep.cli.semgrep_scanner_node",
        lambda state, rules_dir: {
            "semgrep_audit": {
                "status": "ERROR",
                "error_code": "SCAN_FAILED",
                "message": "scanner unavailable",
            }
        },
    )

    result = CliRunner().invoke(eval_nxtwave, [str(target)])

    assert result.exit_code == 1
    assert json.loads(result.output)["error_code"] == "SCAN_FAILED"
