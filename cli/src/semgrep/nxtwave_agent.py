"""LangGraph workflow for NxtWave student-project remediation."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

try:
    from typing import TypedDict
except ImportError:
    from typing_extensions import TypedDict

from semgrep.formatter.nxtwave_formatter import NXTWAVE_BASELINE_RULES, format_nxtwave_audit
from semgrep.nxtwave_registry import get_nxtwave_rules_dir


GROQ_MODEL = "llama-3.1-8b-instant"
GROQ_FALLBACK_MODELS = ("llama-3.1-8b-instant", "openai/gpt-oss-120b")
MAX_VERIFICATION_ATTEMPTS = 2


class AuditAgentState(TypedDict, total=False):
    target_path: str
    raw_code: str
    semgrep_audit: Dict[str, Any]
    ai_coaching_feedback: str
    verification_passed: bool
    verification_attempts: int


LLMClient = Callable[[str], str]


def _error_audit(error_code: str, message: str) -> Dict[str, Any]:
    return {
        "status": "ERROR",
        "error_code": error_code,
        "message": message,
        "compliance_score": 0,
        "total_violations": 0,
        "unimplemented_rules": [],
        "implemented_rules": [],
    }


def _read_source(target: Path) -> str:
    paths = [target] if target.is_file() else sorted(target.rglob("*.py"))
    chunks: List[str] = []
    for path in paths:
        try:
            chunks.append(f"# --- {path} ---\n{path.read_text(encoding='utf-8')}" )
        except (OSError, UnicodeError):
            continue
    return "\n\n".join(chunks)


def _run_semgrep(target: Path, rules_dir: str) -> Dict[str, Any]:
    semgrep_executable = shutil.which("semgrep")
    if semgrep_executable is None:
        sibling_name = "semgrep.exe" if os.name == "nt" else "semgrep"
        sibling_executable = Path(sys.executable).with_name(sibling_name)
        semgrep_executable = str(sibling_executable) if sibling_executable.is_file() else None

    command = [semgrep_executable or sys.executable]
    if semgrep_executable is None:
        command.extend(
            [
                "-c",
                "from semgrep.console_scripts.entrypoint import main; main()",
            ]
        )
    command.extend([
        "scan",
        "--json",
        "--config",
        rules_dir,
        "--no-git-ignore",
        "--timeout",
        "10",
    ])
    for excluded in (".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__"):
        command.extend(["--exclude", excluded])
    command.append(str(target))
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        timeout=300,
    )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        detail = completed.stderr.strip() or "Semgrep did not return valid JSON."
        raise RuntimeError(detail)
    if completed.returncode not in (0, 1):
        raise RuntimeError(completed.stderr.strip() or "Semgrep scan failed.")
    return payload


def semgrep_scanner_node(
    state: AuditAgentState,
    rules_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """Run the local Semgrep rules and convert findings to the audit contract."""
    target = Path(state["target_path"])
    if not target.exists() or not os.access(target, os.R_OK):
        return {
            "raw_code": "",
            "semgrep_audit": _error_audit(
                "TARGET_PATH_NOT_FOUND",
                "Target path does not exist or is inaccessible.",
            ),
        }

    selected_rules_dir = rules_dir or get_nxtwave_rules_dir()
    if not Path(selected_rules_dir).is_dir():
        return {
            "raw_code": _read_source(target),
            "semgrep_audit": _error_audit(
                "RULES_PATH_NOT_FOUND",
                "The selected NxtWave rules directory does not exist or is inaccessible.",
            ),
        }

    try:
        scan_results = _run_semgrep(target, selected_rules_dir)
        if isinstance(scan_results, dict) and isinstance(scan_results.get("results"), list):
            scan_results = {
                **scan_results,
                "results": [
                    finding
                    for finding in scan_results["results"]
                    if (
                        (finding.get("check_id") or finding.get("rule_id", ""))
                        .rsplit(".", 1)[-1]
                        in NXTWAVE_BASELINE_RULES
                    )
                ],
            }
        audit = json.loads(
            format_nxtwave_audit(scan_results, sorted(NXTWAVE_BASELINE_RULES))
        )
    except (OSError, RuntimeError, TypeError, ValueError, subprocess.TimeoutExpired) as error:
        audit = _error_audit("SCAN_FAILED", str(error))

    return {"raw_code": _read_source(target), "semgrep_audit": audit}


def _default_llm_client(prompt: str) -> str:
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError("GROQ_API_KEY is not set.")
    try:
        from groq import Groq
    except ImportError as error:
        raise RuntimeError("The optional 'groq' package is not installed.") from error

    client = Groq(api_key=api_key)
    configured_model = os.getenv("GROQ_MODEL", GROQ_MODEL)
    models = tuple(dict.fromkeys((configured_model,) + GROQ_FALLBACK_MODELS))
    for model in models:
        try:
            response = client.chat.completions.create(
                model=model,
                temperature=0.2,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a code-security coach. Give concise, step-by-step remediation "
                            "guidance and explicitly mention every supplied rule ID."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
            )
            return response.choices[0].message.content or ""
        except Exception as error:
            status_code = getattr(error, "status_code", None)
            error_text = str(error).lower()
            model_unavailable = status_code == 404 or "model_not_found" in error_text
            if not model_unavailable or model == models[-1]:
                raise RuntimeError(f"Groq request failed: {error}") from error
    raise RuntimeError("No configured Groq model is available.")


def llm_coaching_node(
    state: AuditAgentState,
    llm_client: Optional[LLMClient] = None,
) -> Dict[str, Any]:
    """Generate remediation guidance for each unimplemented NxtWave rule."""
    audit = state.get("semgrep_audit", {})
    violations = audit.get("unimplemented_rules", [])
    if not violations:
        return {
            "ai_coaching_feedback": "No NxtWave compliance violations were found.",
            "verification_attempts": state.get("verification_attempts", 0) + 1,
        }

    prompt = json.dumps(
        {
            "task": "Explain how a student should remediate these findings.",
            "findings": violations,
            "source_code": state.get("raw_code", ""),
        },
        indent=2,
    )
    try:
        feedback = (llm_client or _default_llm_client)(prompt)
    except RuntimeError as error:
        feedback = f"Remediation generation unavailable: {error}"
    return {
        "ai_coaching_feedback": feedback,
        "verification_attempts": state.get("verification_attempts", 0) + 1,
    }


def reflexion_verifier_node(state: AuditAgentState) -> Dict[str, Any]:
    """Verify that feedback explicitly names every rule requiring remediation."""
    required_ids = {
        finding.get("rule_id")
        for finding in state.get("semgrep_audit", {}).get("unimplemented_rules", [])
        if finding.get("rule_id")
    }
    feedback = state.get("ai_coaching_feedback", "")
    passed = not required_ids or all(rule_id in feedback for rule_id in required_ids)
    return {"verification_passed": passed}


def build_audit_graph(
    rules_dir: Optional[str] = None,
    llm_client: Optional[LLMClient] = None,
) -> Any:
    """Build the LangGraph workflow with a bounded reflexion loop."""
    try:
        from langgraph.graph import END, START, StateGraph
    except ImportError as error:
        raise RuntimeError(
            "The optional 'langgraph' package is required to build the workflow."
        ) from error

    graph = StateGraph(AuditAgentState)
    graph.add_node("semgrep_scanner", lambda state: semgrep_scanner_node(state, rules_dir))
    graph.add_node("llm_coaching", lambda state: llm_coaching_node(state, llm_client))
    graph.add_node("reflexion_verifier", reflexion_verifier_node)
    graph.add_edge(START, "semgrep_scanner")
    graph.add_edge("semgrep_scanner", "llm_coaching")
    graph.add_edge("llm_coaching", "reflexion_verifier")
    graph.add_conditional_edges(
        "reflexion_verifier",
        lambda state: (
            "done"
            if state.get("verification_passed")
            or state.get("verification_attempts", 0) >= MAX_VERIFICATION_ATTEMPTS
            else "retry"
        ),
        {"retry": "llm_coaching", "done": END},
    )
    return graph.compile()


def run_audit(
    target_path: str,
    rules_dir: Optional[str] = None,
    llm_client: Optional[LLMClient] = None,
) -> AuditAgentState:
    """Execute the complete LangGraph audit workflow."""
    workflow = build_audit_graph(rules_dir, llm_client)
    return workflow.invoke({"target_path": target_path, "verification_attempts": 0})
