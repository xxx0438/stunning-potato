"""Echo command-line interface.

Examples:
    echo health
    echo whoami
    echo gate check --commit abc123 --ai-related
    echo guardrail check --asset loan_agent --tool transfer --args '{"amount":9999}'
    echo asset list --type workflows
    echo eval run --suite 1 --version 42
    echo webhook test --id 5
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Optional

from echo_sdk import EchoClient, __version__
from echo_sdk.exceptions import EchoAPIError, EchoError

# =====================================================
# I/O helpers
# =====================================================
def _print_json(obj: Any) -> None:
    print(json.dumps(obj, indent=2, default=str, ensure_ascii=False))

def _parse_json_arg(value: Optional[str]) -> Any:
    if not value:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON argument: {exc}")

def _client_from_args(args: argparse.Namespace) -> EchoClient:
    return EchoClient(
        base_url=args.base_url,
        token=args.token,
        tenant_id=args.tenant_id,
        actor=args.actor,
        roles=args.roles,
    )

# =====================================================
# Commands
# =====================================================
def cmd_health(args: argparse.Namespace) -> int:
    with _client_from_args(args) as c:
        _print_json(c.health())
    return 0

def cmd_whoami(args: argparse.Namespace) -> int:
    with _client_from_args(args) as c:
        _print_json(c.whoami())
    return 0

def cmd_gate_check(args: argparse.Namespace) -> int:
    """Returns exit code 0 on pass/warn, 1 on block."""
    with _client_from_args(args) as c:
        result = c.gate.check(
            commit_sha=args.commit,
            is_ai_related=args.ai_related,
            provider=args.provider,
            project_id=args.project_id,
            mr_iid=args.mr_iid,
            pipeline_id=args.pipeline_id,
        )
    if args.format == "json":
        _print_json(result.raw)
    else:
        print(f"Status:  {result.status}")
        print(f"Commit:  {result.commit_sha}")
        if result.reasons:
            print("Reasons:")
            for r in result.reasons:
                print(f"  - {r}")
        if result.evaluations:
            print("Evaluations:")
            for e in result.evaluations:
                line = f"  - {e.get('suite')}: {e.get('status')}"
                if "score" in e:
                    line += f" ({e['score']}/{e.get('threshold', '?')})"
                print(line)
    if result.is_blocked:
        return 1
    if result.is_warning and args.strict:
        return 1
    return 0

def cmd_guardrail_check(args: argparse.Namespace) -> int:
    with _client_from_args(args) as c:
        result = c.runtime.guardrail_check(
            asset_version_id=args.version_id,
            asset_name=args.asset,
            tool_name=args.tool,
            tool_args=_parse_json_arg(args.args) or {},
            input_variables=_parse_json_arg(args.input) or {},
            actor=args.who or "",
        )
    if args.format == "json":
        _print_json(result.raw)
    else:
        print(f"Decision: {result.status}")
        for f in result.findings:
            print(f"  [{f.decision}] {f.rule}: {f.reason}")
    if result.is_blocked:
        return 1
    if result.needs_review and args.strict:
        return 1
    return 0

def cmd_asset_list(args: argparse.Namespace) -> int:
    with _client_from_args(args) as c:
        page = c.assets.list(
            q=args.query, asset_type=args.type, owner=args.owner,
            namespace=args.namespace, tag=args.tag,
            limit=args.limit, offset=args.offset,
        )
    if args.format == "json":
        _print_json(page.raw)
    else:
        print(f"{'ID':>5}  {'TYPE':<22}  {'NAMESPACE':<12}  NAME")
        for a in page.items:
            print(f"{a.id:>5}  {a.asset_type:<22}  {a.namespace:<12}  {a.name}")
        print(f"\n{len(page.items)} of {page.total} shown")
    return 0

def cmd_asset_get(args: argparse.Namespace) -> int:
    with _client_from_args(args) as c:
        result = c.assets.get(args.id)
    _print_json(result.raw)
    return 0

def cmd_change_create(args: argparse.Namespace) -> int:
    with _client_from_args(args) as c:
        change = c.changes.create(
            commit_sha=args.commit,
            created_by=args.created_by or os.getenv("USER", "echo-cli"),
            asset_id=args.asset_id,
            asset_version_id=args.version_id,
            pr_id=args.pr_id,
            risk_level=args.risk,
            review_required=args.review_required,
            notes=args.notes or "",
            impact_scope=(args.impact.split(",") if args.impact else None),
        )
    _print_json(change.raw)
    return 0

def cmd_eval_run(args: argparse.Namespace) -> int:
    mock = _parse_json_arg(args.mock_outputs)
    with _client_from_args(args) as c:
        run = c.evaluations.run(
            suite_id=args.suite,
            asset_version_id=args.version,
            change_request_id=args.change,
            mock_outputs=mock,
            triggered_by=args.who or "echo-cli",
        )
    if args.format == "json":
        _print_json(run.raw)
    else:
        print(f"Run #{run.id}: {run.status} | score {run.score}/{run.total_count} cases "
              f"| mode={run.mode}")
        for r in run.results:
            mark = "✓" if r.get("decision") == "pass" else "✗"
            print(f"  {mark} {r.get('case_name')}: {r.get('reason')}")
    return 0 if run.passed else 1

def cmd_webhook_test(args: argparse.Namespace) -> int:
    with _client_from_args(args) as c:
        result = c.webhooks.test(args.id,
                                  event_type=args.event or "echo.test",
                                  sample_payload=_parse_json_arg(args.payload) or {})
    _print_json(result)
    return 0 if result.get("status") == "delivered" else 1

def cmd_webhook_redeliver(args: argparse.Namespace) -> int:
    with _client_from_args(args) as c:
        result = c.webhooks.redeliver(args.id)
    _print_json(result)
    return 0 if result.get("status") == "delivered" else 1

def cmd_audit_summary(args: argparse.Namespace) -> int:
    with _client_from_args(args) as c:
        _print_json(c.audit.summary())
    return 0

def cmd_audit_verify(args: argparse.Namespace) -> int:
    with _client_from_args(args) as c:
        result = c.audit.verify_chain()
    _print_json(result)
    return 0 if result.get("broken_count", 0) == 0 else 1

# =====================================================
# Parser
# =====================================================
def _add_global_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--base-url", default=os.getenv("ECHO_BASE_URL"),
                   help="Echo API base URL (env: ECHO_BASE_URL)")
    p.add_argument("--token", default=os.getenv("ECHO_TOKEN"),
                   help="JWT Bearer token (env: ECHO_TOKEN)")
    p.add_argument("--tenant-id", default=os.getenv("ECHO_TENANT_ID", "default"),
                   help="Tenant identifier (env: ECHO_TENANT_ID)")
    p.add_argument("--actor", default=os.getenv("ECHO_ACTOR"),
                   help="Demo-mode actor (env: ECHO_ACTOR)")
    p.add_argument("--roles", default=os.getenv("ECHO_ROLES"),
                   help="Demo-mode roles, comma-separated (env: ECHO_ROLES)")
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.add_argument("--strict", action="store_true",
                   help="Treat 'warn' as failure (non-zero exit)")

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="echo", description="Echo Agent Governance CLI")
    p.add_argument("--version", action="version",
                   version=f"echo-sdk {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    # health / whoami
    sp = sub.add_parser("health", help="Server health check")
    _add_global_args(sp)
    sp.set_defaults(func=cmd_health)

    sp = sub.add_parser("whoami", help="Show authenticated identity")
    _add_global_args(sp)
    sp.set_defaults(func=cmd_whoami)

    # gate
    sp = sub.add_parser("gate", help="CI gate operations")
    gsub = sp.add_subparsers(dest="gate_command", required=True)
    gc = gsub.add_parser("check", help="Run CI gate for a commit")
    gc.add_argument("--commit", required=True)
    gc.add_argument("--ai-related", action="store_true")
    gc.add_argument("--provider", choices=("gitlab", "datadog"))
    gc.add_argument("--project-id")
    gc.add_argument("--mr-iid")
    gc.add_argument("--pipeline-id")
    _add_global_args(gc)
    gc.set_defaults(func=cmd_gate_check)

    # guardrail
    sp = sub.add_parser("guardrail", help="Runtime guardrail operations")
    rsub = sp.add_subparsers(dest="guardrail_command", required=True)
    rc = rsub.add_parser("check", help="Check a tool inv
