from typing import Optional
import json

import httpx

from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from .database import get_db, test_database_connection
from .models import (
    Scan,
    Endpoint,
    Finding,
    MLPrediction,
    Probe,
    AgentTrace,
)
from .openapi_parser import (
    analyze_openapi,
    parse_openapi_content,
    save_to_database,
)
from .reporting import (
    build_report,
    report_to_html,
)

from scanner.auto_scan import discover_and_scan


# ============================================================
# SENTINELAPI
# ============================================================

app = FastAPI(
    title="SentinelAPI",
    description=(
        "AI-assisted Zero-Trust API Vulnerability Scanner"
    ),
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://localhost:3000",
        "http://127.0.0.1:8080",
        "http://localhost:8080",
        "*",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():
    return {
        "name": "SentinelAPI",
        "version": "2.0.0",
        "status": "running",
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():
    try:
        database_ok = test_database_connection()

        return {
            "status": "healthy",
            "database": (
                "connected"
                if database_ok
                else "unavailable"
            ),
        }

    except Exception as exc:
        return {
            "status": "unhealthy",
            "database": "error",
            "error": str(exc),
        }


# ============================================================
# OPENAPI IMPORT
# ============================================================

@app.post("/api/import")
async def import_openapi(
    file: Optional[UploadFile] = File(default=None),
    openapi_url: Optional[str] = Form(default=None),
    target: str = Form(
        default="http://127.0.0.1:8001"
    ),
    db: Session = Depends(get_db),
):
    """
    Import OpenAPI JSON/YAML specification.

    Supports:
    - JSON file
    - YAML file
    - OpenAPI URL
    """

    if file is None and not openapi_url:
        raise HTTPException(
            status_code=400,
            detail=(
                "Provide either an OpenAPI file "
                "or an OpenAPI URL."
            ),
        )

    try:

        # ----------------------------------------------------
        # FILE IMPORT
        # ----------------------------------------------------

        if file is not None:

            filename = (
                file.filename
                or "openapi.json"
            )

            allowed_extensions = {
                ".json",
                ".yaml",
                ".yml",
            }

            extension = ""

            if "." in filename:
                extension = (
                    "."
                    + filename.rsplit(
                        ".",
                        1
                    )[1].lower()
                )

            if extension not in allowed_extensions:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Only .json, .yaml "
                        "and .yml files are supported."
                    ),
                )

            content = await file.read()

            if not content:
                raise HTTPException(
                    status_code=400,
                    detail="Uploaded file is empty.",
                )

            try:
                text_content = content.decode(
                    "utf-8"
                )

            except UnicodeDecodeError:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "OpenAPI file must be "
                        "UTF-8 encoded."
                    ),
                )

            openapi_data = parse_openapi_content(
                text_content,
                filename,
            )

        # ----------------------------------------------------
        # URL IMPORT
        # ----------------------------------------------------

        else:

            try:

                response = httpx.get(
                    openapi_url,
                    timeout=10.0,
                )

                response.raise_for_status()

                try:
                    openapi_data = response.json()

                except ValueError:

                    openapi_data = (
                        parse_openapi_content(
                            response.text,
                            "openapi.yaml",
                        )
                    )

            except Exception as exc:

                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Could not load OpenAPI URL: "
                        + str(exc)
                    ),
                )

        # ----------------------------------------------------
        # ANALYZE OPENAPI
        # ----------------------------------------------------

        analysis = analyze_openapi(
            openapi_data
        )

        endpoints = analysis[
            "endpoints"
        ]

        # ----------------------------------------------------
        # SAVE TO DATABASE
        # ----------------------------------------------------

        api_spec, saved_endpoints = (
            save_to_database(
                db=db,
                base_url=target,
                openapi_data=openapi_data,
                endpoints=endpoints,
            )
        )

        return {
            "success": True,

            "api_spec_id": api_spec.id,

            "title": analysis[
                "title"
            ],

            "version": analysis[
                "version"
            ],

            "openapi_version": (
                analysis[
                    "openapi_version"
                ]
            ),

            "endpoint_count": (
                analysis[
                    "endpoint_count"
                ]
            ),

            "method_counts": (
                analysis[
                    "method_counts"
                ]
            ),

            "authentication": (
                analysis[
                    "authentication"
                ]
            ),

            "object_id_count": (
                analysis[
                    "object_id_count"
                ]
            ),

            "authorization_candidate_count": (
                analysis[
                    "authorization_candidate_count"
                ]
            ),

            "object_parameters": (
                analysis[
                    "object_parameters"
                ]
            ),

            "endpoints": endpoints,
        }

    except HTTPException:
        raise

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


# ============================================================
# START AI SCAN
# ============================================================

@app.post("/api/scan")
def start_scan(
    target: str = Form(
        default="http://127.0.0.1:8001"
    ),

    owner_identity: str = Form(
        default="alice"
    ),

    test_identity: str = Form(
        default="bob"
    ),

    resource_seeds: str = Form(
        default=""
    ),

    openapi_url: Optional[str] = Form(
        default=None
    ),

    db: Session = Depends(get_db),
):
    """
    Start a controlled SentinelAPI scan.

    Example:

    {
        "/orders/{order_id}": "B204"
    }
    """

    try:

        parsed_resource_seeds = {}

        # ----------------------------------------------------
        # RESOURCE SEEDS
        # ----------------------------------------------------

        if resource_seeds.strip():

            try:
                parsed_resource_seeds = (
                    json.loads(
                        resource_seeds
                    )
                )

            except json.JSONDecodeError:

                raise HTTPException(
                    status_code=400,
                    detail=(
                        "resource_seeds must "
                        "contain valid JSON."
                    ),
                )

            if not isinstance(
                parsed_resource_seeds,
                dict,
            ):

                raise HTTPException(
                    status_code=400,
                    detail=(
                        "resource_seeds must "
                        "be a JSON object."
                    ),
                )

        # ----------------------------------------------------
        # RUN SCAN
        # ----------------------------------------------------

        result = discover_and_scan(
            db=db,
            target=target,
            owner_identity=owner_identity,
            test_identity=test_identity,
            resource_seeds=(
                parsed_resource_seeds
            ),
            openapi_url=openapi_url,
        )

        return {
            "success": True,
            **result,
        }

    except HTTPException:
        raise

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


# ============================================================
# GET ALL SCANS
# ============================================================

@app.get("/api/scans")
def get_scans(
    db: Session = Depends(get_db),
):
    scans = (
        db.query(Scan)
        .order_by(
            Scan.id.desc()
        )
        .all()
    )

    return [
        {
            "id": scan.id,
            "name": scan.name,
            "target": scan.target,
            "status": scan.status,
            "created_at": scan.created_at,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
        }
        for scan in scans
    ]


# ============================================================
# GET SINGLE SCAN
# ============================================================

@app.get("/api/scans/{scan_id}")
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
):
    scan = (
        db.query(Scan)
        .filter(
            Scan.id == scan_id
        )
        .first()
    )

    if scan is None:

        raise HTTPException(
            status_code=404,
            detail="Scan not found.",
        )

    findings = (
        db.query(Finding)
        .filter(
            Finding.scan_id == scan_id
        )
        .all()
    )

    probes = (
        db.query(Probe)
        .filter(
            Probe.scan_id == scan_id
        )
        .all()
    )

    traces = (
        db.query(AgentTrace)
        .filter(
            AgentTrace.scan_id == scan_id
        )
        .order_by(
            AgentTrace.step.asc(),
            AgentTrace.id.asc(),
        )
        .all()
    )

    return {
        "scan": {
            "id": scan.id,
            "name": scan.name,
            "target": scan.target,
            "status": scan.status,
            "created_at": scan.created_at,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
        },

        "findings": [
            {
                "id": finding.id,
                "endpoint_id": (
                    finding.endpoint_id
                ),
                "vulnerability_type": (
                    finding.vulnerability_type
                ),
                "severity": finding.severity,
                "title": finding.title,
                "description": (
                    finding.description
                ),
                "evidence": finding.evidence,
                "confirmed": (
                    finding.confirmed
                ),
            }
            for finding in findings
        ],

        "probes": [
            {
                "id": probe.id,
                "endpoint_id": (
                    probe.endpoint_id
                ),
                "identity_a": (
                    probe.identity_a
                ),
                "identity_b": (
                    probe.identity_b
                ),
                "status_code_a": (
                    probe.status_code_a
                ),
                "status_code_b": (
                    probe.status_code_b
                ),
            }
            for probe in probes
        ],

        "agent_trace": [
            {
                "step": trace.step,
                "phase": trace.phase,
                "action": trace.action,
                "target": trace.target,
                "observation": (
                    trace.observation
                ),
                "decision": trace.decision,
                "result": trace.result,
            }
            for trace in traces
        ],
    }


# ============================================================
# GET ENDPOINTS
# ============================================================

@app.get("/api/endpoints")
def get_endpoints(
    db: Session = Depends(get_db),
):
    endpoints = (
        db.query(Endpoint)
        .order_by(
            Endpoint.id.asc()
        )
        .all()
    )

    return [
        {
            "id": endpoint.id,
            "api_spec_id": (
                endpoint.api_spec_id
            ),
            "method": endpoint.method,
            "path": endpoint.path,
            "summary": endpoint.summary,
            "requires_auth": (
                endpoint.requires_auth
            ),
        }
        for endpoint in endpoints
    ]


# ============================================================
# GET FINDINGS
# ============================================================

@app.get("/api/findings")
def get_findings(
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    query = db.query(Finding)

    if scan_id is not None:

        query = query.filter(
            Finding.scan_id == scan_id
        )

    findings = (
        query
        .order_by(
            Finding.id.desc()
        )
        .all()
    )

    return [
        {
            "id": finding.id,
            "scan_id": finding.scan_id,
            "endpoint_id": (
                finding.endpoint_id
            ),
            "vulnerability_type": (
                finding.vulnerability_type
            ),
            "severity": finding.severity,
            "title": finding.title,
            "description": (
                finding.description
            ),
            "evidence": finding.evidence,
            "confirmed": finding.confirmed,
        }
        for finding in findings
    ]


# ============================================================
# GET ML PREDICTIONS
# ============================================================

@app.get("/api/predictions")
def get_predictions(
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    predictions = (
        db.query(MLPrediction)
        .order_by(
            MLPrediction.id.desc()
        )
        .all()
    )

    return [
        {
            "id": prediction.id,
            "endpoint_id": (
                prediction.endpoint_id
            ),
            "probability": (
                prediction.probability
            ),
            "priority": (
                prediction.priority
            ),
            "model_version": (
                prediction.model_version
            ),
            "created_at": (
                prediction.created_at
            ),
        }
        for prediction in predictions
    ]


# ============================================================
# GET PROBES
# ============================================================

@app.get("/api/probes")
def get_probes(
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    query = db.query(Probe)

    if scan_id is not None:

        query = query.filter(
            Probe.scan_id == scan_id
        )

    probes = (
        query
        .order_by(
            Probe.id.desc()
        )
        .all()
    )

    return [
        {
            "id": probe.id,
            "scan_id": probe.scan_id,
            "endpoint_id": (
                probe.endpoint_id
            ),
            "identity_a": (
                probe.identity_a
            ),
            "identity_b": (
                probe.identity_b
            ),
            "status_code_a": (
                probe.status_code_a
            ),
            "status_code_b": (
                probe.status_code_b
            ),
        }
        for probe in probes
    ]


# ============================================================
# GET AGENT TRACE
# ============================================================

@app.get("/api/agent-trace/{scan_id}")
def get_agent_trace(
    scan_id: int,
    db: Session = Depends(get_db),
):
    traces = (
        db.query(AgentTrace)
        .filter(
            AgentTrace.scan_id == scan_id
        )
        .order_by(
            AgentTrace.step.asc(),
            AgentTrace.id.asc(),
        )
        .all()
    )

    return [
        {
            "id": trace.id,
            "step": trace.step,
            "phase": trace.phase,
            "action": trace.action,
            "target": trace.target,
            "observation": (
                trace.observation
            ),
            "decision": trace.decision,
            "result": trace.result,
            "created_at": (
                trace.created_at
            ),
        }
        for trace in traces
    ]


# ============================================================
# BASIC REPORT
# ============================================================

@app.get("/api/reports/{scan_id}")
def get_report(
    scan_id: int,
    db: Session = Depends(get_db),
):
    try:

        report = build_report(
            db,
            scan_id,
        )

        return report

    except ValueError as exc:

        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )


# ============================================================
# FULL REPORT
# ============================================================

@app.get("/api/reports/{scan_id}/full")
def get_full_report(
    scan_id: int,
    db: Session = Depends(get_db),
):
    try:

        report = build_report(
            db,
            scan_id,
        )

        return report

    except ValueError as exc:

        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )


# ============================================================
# HTML REPORT
# ============================================================

@app.get(
    "/api/reports/{scan_id}/html",
    response_class=HTMLResponse,
)
def get_html_report(
    scan_id: int,
    db: Session = Depends(get_db),
):
    try:

        report = build_report(
            db,
            scan_id,
        )

        html = report_to_html(
            report
        )

        return HTMLResponse(
            content=html
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )


# ============================================================
# LIST AVAILABLE REPORTS
# ============================================================

@app.get("/api/reports")
def list_reports(
    db: Session = Depends(get_db),
):
    scans = (
        db.query(Scan)
        .order_by(
            Scan.id.desc()
        )
        .all()
    )

    reports = []

    for scan in scans:

        reports.append(
            {
                "scan_id": scan.id,
                "name": scan.name,
                "target": scan.target,
                "status": scan.status,

                "json_report": (
                    f"/api/reports/{scan.id}"
                ),

                "full_report": (
                    f"/api/reports/{scan.id}/full"
                ),

                "html_report": (
                    f"/api/reports/{scan.id}/html"
                ),
            }
        )

    return reports