"""E7: ProVerif artifact generation and execution when ProVerif is available."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from experiments.common import write_result

EXPERIMENT_DIR = "E7_formal_verification"
ROOT = Path(__file__).resolve().parents[2]

QUERY_IDS = (
    "R1_authentication",
    "R2_chain_binding",
    "R3_evidence_and_rule",
    "R4_non_repudiation",
    "R5_anchor_binding",
    "Q6_freshness",
    "Q7_accuser_verification",
    "Q8_two_sided_roots",
)

RESULT_PATTERN = re.compile(r"^RESULT (?P<query>.+?) is (?P<result>true|false)\.$")

NEGATIVE_MODELS = {
    "N1_shared_session_key": (
        "R5",
        (
            "N1",
            """let receiver_anchor(s: bitstring, d: bitstring, n: bitstring,
                    sender_name: bitstring, previous_head: bitstring,
                    anchor_signature: signature, evidence_signature: signature,
                    public_key: pkey, alert_tag: mac_code) =
  receiver_evidence(s, d, n, sender_name, previous_head, evidence_signature,
                    public_key, alert_tag).""",
        ),
    ),
    "N2_remove_copy_hash": (
        "R3",
        (
            "N2",
            """let receiver_evidence(s: bitstring, d: bitstring, n: bitstring,
                      sender_name: bitstring, previous_head: bitstring,
                      evidence_signature: signature, public_key: pkey,
                      alert_tag: mac_code) =
  event NoOp(session_id);
  receiver_rule(s, d, n, sender_name, previous_head, alert_tag).""",
        ),
    ),
    "N3_remove_anchor_window": (
        "freshness/expiry",
        (
            "N3",
            """let receiver_freshness(s: bitstring, d: bitstring, n: bitstring,
                       sender_name: bitstring, previous_head: bitstring,
                       alert_tag: mac_code) =
  event NoOp(session_id);
  receiver_roots(s, d, n, sender_name, previous_head, alert_tag).""",
        ),
    ),
    "N4_remove_rule_re_evaluation": (
        "R3",
        (
            "N4",
            """let receiver_rule(s: bitstring, d: bitstring, n: bitstring,
                  sender_name: bitstring, previous_head: bitstring,
                  alert_tag: mac_code) =
  event NoOp(session_id);
  receiver_freshness(s, d, n, sender_name, previous_head, alert_tag).""",
        ),
    ),
    "N5_single_sided_root": (
        "truncation/equivocation coverage",
        (
            "N5",
            """let receiver_roots(s: bitstring, d: bitstring, n: bitstring,
                   sender_name: bitstring, previous_head: bitstring,
                   alert_tag: mac_code) =
  event SingleSidedRoot(s, d);
  receiver_accuser(s, d, n, sender_name, previous_head, alert_tag).""",
        ),
    ),
    "N6_remove_accuser_signature": (
        "R4",
        (
            "N6",
            """let receiver_accuser(s: bitstring, d: bitstring, n: bitstring,
                     sender_name: bitstring, previous_head: bitstring,
                     alert_tag: mac_code) =
  event NoOp(session_id);
  receiver_final(s, d, n, sender_name, previous_head).""",
        ),
    ),
}

NEGATIVE_EXPECTED_QUERIES = {
    "N1_shared_session_key": ("R5_anchor_binding",),
    "N2_remove_copy_hash": ("R3_evidence_and_rule",),
    "N3_remove_anchor_window": ("Q6_freshness",),
    "N4_remove_rule_re_evaluation": ("R3_evidence_and_rule",),
    "N5_single_sided_root": ("Q8_two_sided_roots",),
    "N6_remove_accuser_signature": (
        "Q7_accuser_verification",
        "R4_non_repudiation",
    ),
}


def _find_proverif() -> Path | None:
    configured = os.environ.get("PROVERIF_EXE")
    if configured:
        path = Path(configured).expanduser()
        if path.is_file():
            return path.resolve()
    local = ROOT / ".tools" / "proverif2.05" / "proverif.exe"
    if local.is_file():
        return local.resolve()
    found = shutil.which("proverif")
    return Path(found).resolve() if found else None


def _parse_summary(stdout: str) -> dict[str, bool]:
    if "Verification summary:" in stdout:
        stdout = stdout.split("Verification summary:", 1)[1]
    records: list[tuple[str, bool]] = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("Query "):
            stripped = f"RESULT {stripped[6:]}"
        match = RESULT_PATTERN.match(stripped)
        if not match or match.group("query").startswith("(even "):
            continue
        records.append((match.group("query"), match.group("result") == "true"))
    return {
        query_id: value
        for query_id, (_, value) in zip(QUERY_IDS, records, strict=False)
    }


def _run_model(executable: Path, model_path: Path, trace_dir: Path) -> dict[str, object]:
    command = [str(executable), str(model_path)]
    completed = subprocess.run(
        command,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=120,
        cwd=ROOT,
    )
    stdout_path = trace_dir / f"{model_path.stem}.stdout.txt"
    stderr_path = trace_dir / f"{model_path.stem}.stderr.txt"
    stdout_path.write_text(completed.stdout, encoding="utf-8")
    stderr_path.write_text(completed.stderr, encoding="utf-8")
    query_results = _parse_summary(completed.stdout)
    return {
        "command": " ".join(command),
        "returncode": completed.returncode,
        "query_results": query_results,
        "query_count": len(query_results),
        "stdout": str(stdout_path),
        "stderr": str(stderr_path),
    }


def run() -> dict[str, object]:
    experiment_path = Path(__file__).resolve().parent
    result_dir = experiment_path / "results" / "latest"
    result_dir.mkdir(parents=True, exist_ok=True)
    model_dir = result_dir / "models"
    model_dir.mkdir(parents=True, exist_ok=True)
    trace_dir = result_dir / "traces"
    trace_dir.mkdir(parents=True, exist_ok=True)
    positive = (experiment_path / "model" / "eba_positive.pv").read_text(encoding="utf-8")
    positive_path = model_dir / "EBA_positive.pv"
    positive_path.write_text(positive, encoding="utf-8")

    generated: dict[str, str] = {}
    for name, (expected_failure, mutation) in NEGATIVE_MODELS.items():
        marker = f"(* NEGATIVE MODEL {name}: expected failure in {expected_failure} *)\n"
        path = model_dir / f"{name}.pv"
        mutation_id, replacement = mutation
        start = f"(* MUTATION:{mutation_id}:START *)"
        end = f"(* MUTATION:{mutation_id}:END *)"
        pattern = re.compile(
            re.escape(start) + r".*?" + re.escape(end),
            flags=re.DOTALL,
        )
        mutated, replacements = pattern.subn(
            f"{start}\n{replacement}\n{end}",
            positive,
            count=1,
        )
        if mutated == positive:
            raise ValueError(f"negative mutation did not match: {name}")
        if replacements != 1:
            raise ValueError(f"negative mutation matched {replacements} times: {name}")
        path.write_text(marker + mutated, encoding="utf-8")
        generated[name] = str(path)

    proverif = _find_proverif()
    runs: dict[str, object] = {}
    if proverif is None:
        status = "blocked_dependency"
        for model_name, model_path in {"EBA_positive": str(positive_path), **generated}.items():
            runs[model_name] = {
                "command": f"proverif {model_path}",
                "status": "not_run",
                "reason": "proverif executable not found",
            }
    else:
        positive_result = _run_model(proverif, positive_path, trace_dir)
        runs["EBA_positive"] = positive_result
        all_queries_passed = (
            positive_result["returncode"] == 0
            and positive_result["query_count"] == len(QUERY_IDS)
            and all(positive_result["query_results"].values())
        )

        negative_checks: dict[str, object] = {}
        for model_name, model_path in {"EBA_positive": str(positive_path), **generated}.items():
            if model_name == "EBA_positive":
                continue
            result = _run_model(proverif, Path(model_path), trace_dir)
            runs[model_name] = result
            query_results = result["query_results"]
            expected_queries = NEGATIVE_EXPECTED_QUERIES[model_name]
            expected_failed = all(
                query_results.get(query_id) is False for query_id in expected_queries
            )
            unaffected_passed = all(
                value
                for query_id, value in query_results.items()
                if query_id not in expected_queries
            )
            negative_checks[model_name] = {
                "expected_failure": NEGATIVE_MODELS[model_name][0],
                "expected_queries": list(expected_queries),
                "expected_failure_observed": expected_failed,
                "unaffected_queries_passed": unaffected_passed,
                "passed": (
                    result["returncode"] == 0
                    and result["query_count"] == len(QUERY_IDS)
                    and expected_failed
                    and unaffected_passed
                ),
            }
        negative_ok = all(check["passed"] for check in negative_checks.values())
        status = (
            "verified"
            if all_queries_passed and negative_ok
            else "verification_failed"
        )
        runs["negative_checks"] = negative_checks

    result = {
        "status": status,
        "proverif_executable": str(proverif) if proverif is not None else None,
        "positive_model": str(positive_path),
        "negative_models_expected_to_fail": {
            name: value[0] for name, value in NEGATIVE_MODELS.items()
        },
        "runs": runs,
        "artifacts_preserved": True,
        "positive_all_queries_passed": (
            bool(
                runs["EBA_positive"].get("query_count") == len(QUERY_IDS)
                and all(runs["EBA_positive"].get("query_results", {}).values())
            )
            if proverif is not None
            else False
        ),
        "negative_expected_failures_passed": (
            all(check["passed"] for check in runs["negative_checks"].values())
            if proverif is not None
            else False
        ),
    }
    write_result(
        EXPERIMENT_DIR,
        result,
        title="E7 ProVerif Positive and Negative Verification",
        summary_lines=[
            f"Execution status: {status}",
            f"Positive model: `{positive_path.name}`",
            f"Negative models generated: {len(generated)}",
            (
                "All eight positive queries passed and all six expected negative "
                "counterexamples were observed."
                if status == "verified"
                else "No formal pass is claimed; inspect query_results and traces."
            ),
        ],
    )
    return result
