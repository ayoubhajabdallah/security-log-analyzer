from fastapi import FastAPI, File, HTTPException, Query, UploadFile

from src.analyzer import Event
from src.parser import parse_log_line
from src.report import AnalysisReport, build_report


app = FastAPI(
    title="Security Log Analyzer API",
    description=(
        "Analyze authentication logs and detect suspicious activity."
    ),
    version="1.0.0",
)


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
) -> AnalysisReport:
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

    return build_report(
        events=events,
        failed_threshold=failed_threshold,
        minimum_users=minimum_users,
        window_threshold=window_threshold,
        window_minutes=window_minutes,
    )