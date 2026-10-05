"""Streamlit dashboard for NxtWave AutoEval AI."""

from __future__ import annotations

import ast
import os
import subprocess
import sys
import tempfile
import zipfile
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Optional
from urllib.parse import urlparse

# The evaluation agent lives in the Semgrep CLI package in this repository.
CLI_SRC = Path(__file__).parent / "cli" / "src"
if str(CLI_SRC) not in sys.path:
    sys.path.insert(0, str(CLI_SRC))

try:
    import streamlit as st
except ImportError:  # Keep module imports diagnostic-friendly outside Streamlit.
    st = None  # type: ignore[assignment]

from pdf_generator import generate_pdf_scorecard


DEFAULT_CODE = '''from openai import OpenAI

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def answer(user_input):
    return client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": f"Answer this: {user_input}"}],
    )
'''


def _require_streamlit() -> Any:
    if st is None:
        raise RuntimeError("Streamlit is not installed. Install it before running app.py.")
    return st


def _validate_python(code: str) -> Optional[str]:
    try:
        ast.parse(code)
    except SyntaxError as error:
        location = f"line {error.lineno}" if error.lineno else "the submitted code"
        return f"Python syntax error at {location}: {error.msg}"
    return None


@contextmanager
def _stage_submission(
    code: str = "",
    uploaded_bytes: Optional[bytes] = None,
    uploaded_name: str = "",
    github_url: str = "",
):
    """Stage pasted code, a ZIP project, or a public GitHub repository safely."""
    with tempfile.TemporaryDirectory(prefix="nxtwave-project-") as directory:
        root = Path(directory)
        if github_url:
            parsed = urlparse(github_url.strip())
            parts = [part for part in parsed.path.strip("/").split("/") if part]
            if parsed.scheme != "https" or parsed.hostname not in {"github.com", "www.github.com"}:
                raise ValueError("Use an HTTPS GitHub repository URL.")
            if len(parts) != 2 or any(part in {".", ".."} for part in parts):
                raise ValueError("Use a repository URL such as https://github.com/org/project.")
            repository_url = f"https://github.com/{parts[0]}/{parts[1].removesuffix('.git')}.git"
            target = root / "repository"
            completed = subprocess.run(
                ["git", "clone", "--depth", "1", "--single-branch", repository_url, str(target)],
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
            if completed.returncode != 0:
                raise RuntimeError(completed.stderr.strip() or "GitHub repository could not be cloned.")
            yield target
            return

        if uploaded_bytes is not None:
            if not uploaded_name.lower().endswith((".zip", ".py")):
                raise ValueError("Upload a .py file or a .zip project archive.")
            if uploaded_name.lower().endswith(".py"):
                target = root / Path(uploaded_name).name
                target.write_bytes(uploaded_bytes)
                yield target
                return

            target = root / "project"
            target.mkdir()
            with zipfile.ZipFile(__import__("io").BytesIO(uploaded_bytes)) as archive:
                for member in archive.infolist():
                    relative = PurePosixPath(member.filename)
                    if relative.is_absolute() or ".." in relative.parts:
                        raise ValueError("The ZIP contains an unsafe path.")
                    destination = (target / Path(*relative.parts)).resolve()
                    if target.resolve() not in destination.parents and destination != target.resolve():
                        raise ValueError("The ZIP contains an unsafe path.")
                archive.extractall(target)
            yield target
            return

        if not code.strip():
            raise ValueError("Provide Python code, a project archive, or a GitHub URL.")
        target = root / "student_submission.py"
        target.write_text(code, encoding="utf-8")
        yield target


def _audit_with_target(target: Path, rules_dir: Optional[str], api_key: str) -> Dict[str, Any]:
    from semgrep.nxtwave_agent import run_audit

    previous_key = os.environ.get("GROQ_API_KEY")
    try:
        if api_key:
            os.environ["GROQ_API_KEY"] = api_key
        state = run_audit(str(target), rules_dir=rules_dir)
    finally:
        if previous_key is None:
            os.environ.pop("GROQ_API_KEY", None)
        else:
            os.environ["GROQ_API_KEY"] = previous_key

    audit = dict(state.get("semgrep_audit", {}))
    audit["ai_coaching_feedback"] = state.get("ai_coaching_feedback", "")
    audit["verification_passed"] = state.get("verification_passed", False)
    return audit


def _render_results(audit: Dict[str, Any], student_name: str) -> None:
    streamlit = _require_streamlit()
    if audit.get("status") == "ERROR":
        streamlit.error(
            f"Evaluation failed ({audit.get('error_code', 'UNKNOWN')}): "
            f"{audit.get('message', 'Unknown evaluation error')}"
        )
        return

    score = int(audit.get("compliance_score", 0))
    status = str(audit.get("status", "NEEDS_REVISION"))
    streamlit.subheader("Evaluation Results")
    score_column, status_column, violation_column = streamlit.columns(3)
    score_column.metric("Compliance Score", f"{score}%")
    status_column.metric("Status", status)
    violation_column.metric("Total Violations", int(audit.get("total_violations", 0)))

    with streamlit.expander("Passed Rules", expanded=True):
        passed_rules = audit.get("implemented_rules", []) or []
        if passed_rules:
            for rule_id in passed_rules:
                streamlit.success(f"Passed: {rule_id}")
        else:
            streamlit.info("No baseline rules passed.")

    with streamlit.expander("Violations & Remediation", expanded=True):
        violations = audit.get("unimplemented_rules", []) or []
        if not violations:
            streamlit.success("No NxtWave compliance violations found.")
        for finding in violations:
            location = f"{finding.get('file', 'unknown')}:{finding.get('line', '?')}"
            streamlit.error(
                f"[{str(finding.get('priority', 'high')).upper()}] "
                f"{finding.get('rule_id', 'unknown-rule')} | {location}\n\n"
                f"{finding.get('message', 'No remediation message provided.')}"
            )

    with streamlit.expander("Controls Requiring Manual Review", expanded=False):
        streamlit.warning(audit.get("assessment_note", "Some controls require review beyond static analysis."))
        for control in audit.get("manual_review_required", []):
            streamlit.write(
                f"**{str(control.get('priority', 'high')).upper()}** "
                f"[{control.get('category', 'General')}] - {control.get('control')}: "
                f"{control.get('reason')}"
            )

    streamlit.subheader("AI Coaching Guidance")
    streamlit.markdown(audit.get("ai_coaching_feedback", "No coaching feedback generated."))
    pdf_bytes = generate_pdf_scorecard(audit, student_name=student_name)
    streamlit.download_button(
        "Download PDF Scorecard",
        data=pdf_bytes,
        file_name="NxtWave_AutoEval_Scorecard.pdf",
        mime="application/pdf",
        type="primary",
    )


def main() -> None:
    streamlit = _require_streamlit()
    streamlit.set_page_config(
        page_title="NxtWave AutoEval AI",
        page_icon="N",
        layout="wide",
    )
    streamlit.title("NxtWave AutoEval AI")
    streamlit.caption("Automated AI project evaluation, remediation, and certification")

    with streamlit.sidebar:
        streamlit.header("Evaluation Settings")
        student_name = streamlit.text_input("Student name", value="NxtWave Student")
        target_module = streamlit.text_input("Target module", value="student_submission.py")
        api_key = streamlit.text_input(
            "Groq API key override",
            value="",
            type="password",
            help="Used only for this evaluation. The environment variable remains unchanged.",
        )
        from semgrep.formatter.nxtwave_formatter import NXTWAVE_BASELINE_RULES

        streamlit.caption(f"Baseline: {len(NXTWAVE_BASELINE_RULES)} security rules")
        streamlit.caption("Passing threshold: 90%")

    paste_tab, upload_tab, github_tab = streamlit.tabs(
        ["Paste Python Code", "Upload Project", "GitHub Repository"]
    )
    selected_code = ""
    uploaded_file = None
    github_url = ""
    with paste_tab:
        pasted_code = streamlit.text_area(
            "Python submission",
            value=DEFAULT_CODE,
            height=360,
            label_visibility="collapsed",
        )
        selected_code = pasted_code
    with upload_tab:
        uploaded_file = streamlit.file_uploader(
            "Choose a Python file or ZIP project archive", type=["py", "zip"]
        )
        if uploaded_file is not None:
            streamlit.info("The full project directory will be scanned, not only one file.")
    with github_tab:
        github_url = streamlit.text_input(
            "Public GitHub repository URL",
            placeholder="https://github.com/organization/project",
        )
        streamlit.caption("The repository is cloned at shallow depth for this evaluation.")

    if streamlit.button("Evaluate Submission", type="primary", use_container_width=True):
        if not selected_code.strip() and uploaded_file is None and not github_url.strip():
            streamlit.warning("Provide code, upload a project, or enter a GitHub URL.")
            return
        syntax_error = _validate_python(selected_code) if selected_code.strip() else None
        if syntax_error:
            streamlit.error(syntax_error)
            return

        status = streamlit.status("Starting AutoEval workflow...", expanded=True)
        try:
            status.write("1. Running Semgrep SAST scan")
            status.write("2. Performing compliance gap analysis")
            status.write("3. Generating AI coaching via Groq")
            status.write("4. Compiling PDF certificate")
            with streamlit.spinner("Evaluating submission..."):
                upload_bytes = uploaded_file.getvalue() if uploaded_file else None
                upload_name = uploaded_file.name if uploaded_file else ""
                with _stage_submission(
                    code=selected_code,
                    uploaded_bytes=upload_bytes,
                    uploaded_name=upload_name,
                    github_url=github_url,
                ) as target:
                    audit = _audit_with_target(target, None, api_key)
            status.update(label="Evaluation complete", state="complete", expanded=False)
            streamlit.session_state["last_audit"] = audit
            streamlit.session_state["last_student_name"] = student_name
            streamlit.session_state["last_target_module"] = target_module
        except Exception as error:
            status.update(label="Evaluation failed", state="error")
            streamlit.error(f"Unable to evaluate submission: {error}")

    if "last_audit" in streamlit.session_state:
        _render_results(
            streamlit.session_state["last_audit"],
            streamlit.session_state.get("last_student_name", "NxtWave Student"),
        )


if __name__ == "__main__":
    main()
