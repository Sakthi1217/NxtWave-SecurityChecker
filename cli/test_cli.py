from click.testing import CliRunner
import sys
import os
sys.path.insert(0, os.path.abspath('src'))

# Mock the logger and missing telemetry deps
import logging
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

logging.basicConfig(level=logging.INFO)

from semgrep.cli import eval_nxtwave

def test_eval():
    runner = CliRunner()
    result = runner.invoke(eval_nxtwave, ['--help'])
    print("--- HELP OUTPUT ---")
    print(result.output)

    print("--- COMMAND INVOCATION OUTPUT ---")
    result = runner.invoke(eval_nxtwave, ['some/target/path', '--rules-dir', 'custom/rules'])
    print(result.output)

if __name__ == '__main__':
    test_eval()
