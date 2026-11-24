from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import Actor, require_roles
from app.core.config import Settings, get_settings
from app.db.session import get_db
from app.llm.router import LLMRouter, get_llm_router
from app.seed.demo_data import seed_demo_dataset

router = APIRouter(prefix="/seed", tags=["seed"])


@router.post("/demo")
async def post_seed_demo(
    reset: bool = Query(default=False),
    actor: Actor = Depends(require_roles("operator", "it_approver", "admin")),
    db: AsyncSession = Depends(get_db),
    llm_router: LLMRouter = Depends(get_llm_router),
    settings: Settings = Depends(get_settings),
) -> dict[str, object]:
    """Seed realistic enterprise IT demo data (reset=true requires it_approver or admin)."""
    if reset and actor.role not in ("it_approver", "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only it_approver or admin may reset demo data.",
        )
    return await seed_demo_dataset(
        db,
        llm_router=llm_router,
        settings=settings,
        actor=actor,
        reset=reset,
    )
