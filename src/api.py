from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Dict, List, Optional

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from src.analyzer import Event
from src.dashboard import DASHBOARD_HTML
from src.database import Base, engine, get_db
from src.parser import parse_log_line
from src.report import AnalysisReport, build_report
from src.repository import AnalysisRepository


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="Security Log Analyzer API",
    description=(
        "Analyze authentication logs and detect suspicious activity."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    return DASHBOARD_HTML


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze")
async def analyze_log(
    file: UploadFile = File(...),
    failed_threshold: int = Query(default=5, ge=1),
    minimum_users: int = Query(default=2, ge=1),
    window_threshold: int = Query(default=3, ge=1),
    window_minutes: int = Query(default=2, ge=1),
    db: Session = Depends(get_db),
) -> AnalysisReport:
    # Ensure tables are created if startup lifespan hasn't been triggered by TestClient
    Base.metadata.create_all(bind=engine)

    file_content = await file.read()

    try:
        text = file_content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=400,
            detail="The uploaded file must use UTF-8 encoding.",
        ) from None

    events: list[Event] = []

    for line_number, line in enumerate(
        text.splitlines(),
        start=1,
    ):
        if not line.strip():
            continue

        try:
            event = parse_log_line(line)
        except ValueError as error:
            raise HTTPException(
                status_code=400,
                detail=f"Line {line_number}: {error}",
            ) from None

        events.append(event)

    report = build_report(
        events=events,
        failed_threshold=failed_threshold,
        minimum_users=minimum_users,
        window_threshold=window_threshold,
        window_minutes=window_minutes,
    )

    repo = AnalysisRepository(db)
    filename = file.filename or "uploaded_log.log"
    repo.save_analysis(
        filename=filename,
        failed_threshold=failed_threshold,
        minimum_users=minimum_users,
        window_threshold=window_threshold,
        window_minutes=window_minutes,
        report=report,
    )

    return report


@app.get("/analyses")
def list_analyses(db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    Base.metadata.create_all(bind=engine)
    repo = AnalysisRepository(db)
    analyses = repo.get_all_analyses()
    return [
        {
            "id": a.id,
            "filename": a.filename,
            "timestamp": a.timestamp.isoformat(),
            "total_events": a.total_events,
            "parameters": {
                "failed_threshold": a.failed_threshold,
                "minimum_users": a.minimum_users,
                "window_threshold": a.window_threshold,
                "window_minutes": a.window_minutes,
            },
        }
        for a in analyses
    ]


@app.get("/analyses/{analysis_id}")
def get_analysis(
    analysis_id: int, db: Session = Depends(get_db)
) -> Dict[str, Any]:
    Base.metadata.create_all(bind=engine)
    repo = AnalysisRepository(db)
    analysis = repo.get_analysis_by_id(analysis_id)
    if not analysis:
        raise HTTPException(
            status_code=404,
            detail=f"Analysis with ID {analysis_id} not found.",
        )
    return repo.to_dict(analysis)
