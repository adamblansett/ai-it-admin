from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import Actor
from app.core.config import Settings
from app.db.base import utcnow
from app.db.models import Incident, RemediationDraft, Runbook
from app.governance.service import create_approval_request, record_audit_event
from app.llm.embeddings import compute_deterministic_embedding, hybrid_score
from app.llm.router import LLMRouter
from app.runbooks.guardrails import BLOCKED_COMMAND_MARKER, inspect_commands_for_safety
from app.runbooks.schemas import RemediationAssistIn, RunbookCreateIn, RunbookSearchHit


def _build_excerpt(markdown: str, max_len: int = 260) -> str:
    lines = [ln.strip() for ln in markdown.splitlines() if ln.strip() and not ln.startswith("#")]
    joined = " ".join(lines) if lines else markdown.strip()
    if len(joined) <= max_len:
        return joined
    return joined[: max_len - 3].rstrip() + "..."


async def create_runbook(
    db: AsyncSession,
    *,
    payload: RunbookCreateIn,
    actor: Actor,
    settings: Settings,
) -> Runbook:
    """Create and index a new operational runbook after checking safe commands."""
    clean_slug = payload.slug.strip().lower()
    existing = (
        await db.execute(select(Runbook).where(Runbook.slug == clean_slug))
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Runbook slug '{clean_slug}' already exists.",
        )

    raw_cmds = [c.command for c in payload.safe_commands]
    _, blocked = inspect_commands_for_safety(raw_cmds)
    if blocked:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Runbook safe_commands rejected by zero-blind-shell guardrail: "
                + "; ".join(blocked)
            ),
        )

    index_text = (
        f"{payload.title}\n{payload.service_name}\n{payload.category}\n"
        f"{' '.join(payload.tags)}\n{payload.content_markdown}"
    )
    embedding = compute_deterministic_embedding(
        index_text, dimensions=settings.embedding_dimensions
    )
    now = utcnow()
    runbook = Runbook(
        slug=clean_slug,
        title=payload.title.strip(),
        service_name=payload.service_name.strip(),
        category=payload.category.strip(),
        severity_scope=payload.severity_scope.strip(),
        content_markdown=payload.content_markdown.strip(),
        safe_commands_json=[c.model_dump() for c in payload.safe_commands],
        tags_json=[t.strip().lower() for t in payload.tags if t.strip()],
        embedding_json=embedding,
        updated_by=actor.email,
        created_at=now,
        updated_at=now,
    )
    db.add(runbook)
    await db.flush()

    await record_audit_event(
        db,
        event_type="runbook.created",
        actor=actor,
        entity_type="runbook",
        entity_id=runbook.id,
        action="created",
        details={"slug": runbook.slug, "service_name": runbook.service_name},
    )
    await db.commit()
    await db.refresh(runbook)
    return runbook


async def hybrid_search_runbooks(
    db: AsyncSession,
    *,
    query: str,
    service_name: str | None = None,
    top_k: int = 3,
    dimensions: int = 384,
) -> list[RunbookSearchHit]:
    """Rank indexed runbooks using deterministic vector + keyword hybrid retrieval."""
    rows = list((await db.execute(select(Runbook))).scalars().all())
    if not rows:
        return []

    query_vec = compute_deterministic_embedding(query, dimensions=dimensions)
    scored: list[tuple[float, Runbook]] = []
    for rb in rows:
        doc_text = f"{rb.title}\n{rb.service_name}\n{rb.category}\n{rb.content_markdown}"
        doc_vec = rb.embedding_json
        if not doc_vec or len(doc_vec) != len(query_vec):
            doc_vec = compute_deterministic_embedding(doc_text, dimensions=len(query_vec))
        score = hybrid_score(
            query=query,
            query_vec=query_vec,
            document=doc_text,
            doc_vec=doc_vec,
            tags=rb.tags_json,
            doc_service=rb.service_name,
            target_service=service_name,
        )
        scored.append((score, rb))

    scored.sort(key=lambda pair: (-pair[0], pair[1].title))
    hits: list[RunbookSearchHit] = []
    for score, rb in scored[:top_k]:
        hits.append(
            RunbookSearchHit(
                runbook_id=rb.id,
                slug=rb.slug,
                title=rb.title,
                service_name=rb.service_name,
                category=rb.category,
                score=score,
                excerpt=_build_excerpt(rb.content_markdown),
                safe_commands=list(rb.safe_commands_json or []),
            )
        )
    return hits


async def generate_remediation_draft(
    db: AsyncSession,
    *,
    llm_router: LLMRouter,
    settings: Settings,
    payload: RemediationAssistIn,
    actor: Actor,
) -> RemediationDraft:
    """Generate a cited, advisory-only remediation draft with zero blind shell execution."""
    target_service = payload.service_name.strip() if payload.service_name else None
    effective_query = payload.query_text.strip()

    incident: Incident | None = None
    if payload.incident_id:
        incident = await db.get(Incident, payload.incident_id)
        if incident is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident '{payload.incident_id}' not found.",
            )
        target_service = target_service or incident.service_name
        effective_query = (
            f"{effective_query} | Incident {incident.incident_key}: "
            f"{incident.title} ({incident.service_name})"
        )

    hits = await hybrid_search_runbooks(
        db,
        query=effective_query,
        service_name=target_service,
        top_k=3,
        dimensions=settings.embedding_dimensions,
    )

    citations_summary = "; ".join(f"{h.slug} ({h.score:.2f})" for h in hits) or "none"
    prompt = (
        f"Service: {target_service or 'unspecified'}\n"
        f"Query: {effective_query}\n"
        f"Cited Runbooks: {citations_summary}\n"
        "Provide an advisory root-cause diagnosis and safe verification steps."
    )
    llm_resp = await llm_router.generate(
        prompt=prompt,
        system_prompt=(
            "You are an SRE incident remediation advisor. Never propose destructive commands; "
            "all verification steps require manual operator review."
        ),
        task_type="runbook_remediation",
    )

    _, blocked_patterns = inspect_commands_for_safety([payload.query_text, llm_resp.content])

    proposed_steps: list[dict[str, Any]] = []
    step_no = 1
    for hit in hits[:2]:
        for cmd_obj in hit.safe_commands:
            raw_cmd = str(cmd_obj.get("command", "")).strip()
            safe_list, cmd_blocked = inspect_commands_for_safety([raw_cmd])
            for desc in cmd_blocked:
                if desc not in blocked_patterns:
                    blocked_patterns.append(desc)
            proposed_steps.append(
                {
                    "step_no": step_no,
                    "title": f"[{hit.slug}] {cmd_obj.get('label', 'Diagnostic Check')}",
                    "instruction": (
                        f"Verify using runbook '{hit.title}' ("
                        f"{'read-only' if cmd_obj.get('read_only', True) else 'change-controlled'}"
                        ")."
                    ),
                    "command": safe_list[0],
                    "requires_manual_execution": True,
                }
            )
            step_no += 1

    if blocked_patterns:
        proposed_steps.insert(
            0,
            {
                "step_no": 0,
                "title": "Zero-Blind-Shell Guardrail Triggered",
                "instruction": (
                    "Potentially destructive or dynamic shell syntax was detected and neutralized. "
                    "Automated execution is permanently disabled."
                ),
                "command": BLOCKED_COMMAND_MARKER,
                "requires_manual_execution": True,
            },
        )
        for idx, item in enumerate(proposed_steps, start=1):
            item["step_no"] = idx

    if not proposed_steps:
        proposed_steps.append(
            {
                "step_no": 1,
                "title": "Manual Read-Only Health Inspection",
                "instruction": (
                    "Inspect service /api/v1/health/ready probe, TLS expiry, and recent metrics "
                    "in the telemetry dashboard before applying configuration changes."
                ),
                "command": None,
                "requires_manual_execution": True,
            }
        )

    cited_payload = [
        {
            "runbook_id": h.runbook_id,
            "slug": h.slug,
            "title": h.title,
            "service_name": h.service_name,
            "score": h.score,
            "excerpt": h.excerpt,
        }
        for h in hits
    ]

    draft = RemediationDraft(
        incident_id=incident.id if incident is not None else None,
        query_text=payload.query_text.strip(),
        diagnosis_summary=llm_resp.content,
        cited_runbooks_json=cited_payload,
        proposed_steps_json=proposed_steps,
        blocked_shell_patterns_json=blocked_patterns,
        execution_mode="advisory_only",
        llm_provider=llm_resp.provider,
        pii_redacted=llm_resp.pii_redacted,
        status="pending_approval" if payload.request_approval else "draft",
        created_by=actor.email,
    )
    db.add(draft)
    await db.flush()

    if payload.request_approval:
        approval = await create_approval_request(
            db,
            entity_type="remediation_draft",
            entity_id=draft.id,
            action_requested="advisory_remediation_review",
            summary=(
                f"Advisory remediation plan for {target_service or 'infrastructure'} "
                f"citing {len(cited_payload)} runbook(s)"
            ),
            diff_preview=proposed_steps,
            risk_level="high" if blocked_patterns else "medium",
            requested_by=actor.email,
        )
        draft.approval_id = approval.id

    await record_audit_event(
        db,
        event_type="runbook.remediation_drafted",
        actor=actor,
        entity_type="remediation_draft",
        entity_id=draft.id,
        action="drafted",
        details={
            "execution_mode": "advisory_only",
            "cited_count": len(cited_payload),
            "blocked_patterns_count": len(blocked_patterns),
            "approval_requested": payload.request_approval,
        },
    )
    await db.commit()
    await db.refresh(draft)
    return draft
