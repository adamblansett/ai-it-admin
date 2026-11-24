from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import Actor, get_current_actor, require_roles
from app.core.config import Settings, get_settings
from app.db.models import RemediationDraft, Runbook
from app.db.session import get_db
from app.llm.router import LLMRouter, get_llm_router
from app.runbooks.schemas import (
    RemediationAssistIn,
    RemediationDraftOut,
    RunbookCreateIn,
    RunbookOut,
    RunbookSearchHit,
    RunbookSearchIn,
)
from app.runbooks.service import (
    create_runbook,
    generate_remediation_draft,
    hybrid_search_runbooks,
)

router = APIRouter(prefix="/runbooks", tags=["runbooks"])


@router.get("", response_model=list[RunbookOut])
async def list_runbooks(
    service_name: str | None = Query(default=None),
    category: str | None = Query(default=None),
    _: Actor = Depends(get_current_actor),
    db: AsyncSession = Depends(get_db),
) -> list[RunbookOut]:
    """List operational runbooks."""
    stmt = select(Runbook).order_by(Runbook.service_name.asc(), Runbook.title.asc())
    if service_name:
        stmt = stmt.where(Runbook.service_name == service_name)
    if category:
        stmt = stmt.where(Runbook.category == category)
    rows = list((await db.execute(stmt)).scalars().all())
    return [RunbookOut.model_validate(row) for row in rows]


@router.post("", response_model=RunbookOut)
async def post_runbook(
    payload: RunbookCreateIn,
    actor: Actor = Depends(require_roles("operator", "it_approver", "admin")),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> RunbookOut:
    """Create and vector-index a new runbook."""
    rb = await create_runbook(db, payload=payload, actor=actor, settings=settings)
    return RunbookOut.model_validate(rb)


@router.post("/search", response_model=list[RunbookSearchHit])
async def post_search_runbooks(
    payload: RunbookSearchIn,
    _: Actor = Depends(get_current_actor),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> list[RunbookSearchHit]:
    """Run hybrid semantic + keyword search across indexed runbooks."""
    return await hybrid_search_runbooks(
        db,
        query=payload.query,
        service_name=payload.service_name,
        top_k=payload.top_k,
        dimensions=settings.embedding_dimensions,
    )


@router.post("/assist", response_model=RemediationDraftOut)
async def post_remediation_assist(
    payload: RemediationAssistIn,
    actor: Actor = Depends(require_roles("operator", "it_approver", "admin")),
    db: AsyncSession = Depends(get_db),
    llm_router: LLMRouter = Depends(get_llm_router),
    settings: Settings = Depends(get_settings),
) -> RemediationDraftOut:
    """Generate a citation-grounded advisory remediation plan (zero blind shell execution)."""
    draft = await generate_remediation_draft(
        db,
        llm_router=llm_router,
        settings=settings,
        payload=payload,
        actor=actor,
    )
    return RemediationDraftOut.model_validate(draft)


@router.get("/drafts", response_model=list[RemediationDraftOut])
async def list_remediation_drafts(
    _: Actor = Depends(get_current_actor),
    db: AsyncSession = Depends(get_db),
) -> list[RemediationDraftOut]:
    """List advisory remediation drafts."""
    stmt = select(RemediationDraft).order_by(RemediationDraft.created_at.desc())
    rows = list((await db.execute(stmt)).scalars().all())
    return [RemediationDraftOut.model_validate(row) for row in rows]
