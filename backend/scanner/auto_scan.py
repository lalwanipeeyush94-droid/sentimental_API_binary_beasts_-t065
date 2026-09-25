import json
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from app.models import (
    APISpec,
    Endpoint,
    Scan,
    MLPrediction,
    Probe,
    Finding,
    AgentTrace,
)

from app.openapi_parser import (
    load_openapi,
    extract_endpoints,
)

from ml.predictor import predict_endpoint
from agent.planner import plan_next_test
from scanner.bola import test_bola
from scanner.evidence import generate_bola_evidence


# ============================================================
# SAFE AUTHORIZED TARGETS
# ============================================================

SAFE_TARGETS = {
    "http://127.0.0.1:8001",
    "http://localhost:8001",
    "http://127.0.0.1:8002",
    "http://localhost:8002",
}


# ============================================================
# TARGET VALIDATION
# ============================================================

def validate_target(target: str) -> str:

    if not target:
        raise ValueError("Target is required.")

    target = target.rstrip("/")

    if target not in SAFE_TARGETS:
        raise ValueError(
            f"Target '{target}' is not an authorized "
            "SentinelAPI sandbox target."
        )

    parsed = urlparse(target)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError(
            "Only HTTP/HTTPS targets are supported."
        )

    return target


# ============================================================
# OPENAPI URL LOADER
# ============================================================

def load_openapi_from_url(url: str):

    if not url:
        raise ValueError("OpenAPI URL is required.")

    response = httpx.get(
        url,
        timeout=10.0,
        follow_redirects=False,
    )

    response.raise_for_status()

    from app.openapi_parser import parse_openapi_content

    content_type = response.headers.get(
        "content-type",
        ""
    ).lower()

    if "yaml" in content_type or "yml" in content_type:
        filename = "openapi.yaml"
    else:
        filename = "openapi.json"

    return parse_openapi_content(
        response.text,
        filename
    )


# ============================================================
# RESOURCE SEED
# ============================================================

def get_resource_seed(
    path: str,
    resource_seeds: dict
):

    if not resource_seeds:
        return None

    if path in resource_seeds:
        return resource_seeds[path]

    normalized_path = path.rstrip("/")

    for seed_path, resource_id in resource_seeds.items():

        if str(seed_path).rstrip("/") == normalized_path:
            return resource_id

    return None


# ============================================================
# NORMALIZE ML PREDICTION
#
# Supports different return formats from predictor.py
# without modifying the frozen ML model.
# ============================================================

def normalize_prediction(prediction):

    probability = None
    priority = None

    # --------------------------------------------------------
    # Dictionary return
    # --------------------------------------------------------

    if isinstance(prediction, dict):

        possible_probability_keys = [
            "probability",
            "bola_probability",
            "ml_probability",
            "score",
            "confidence",
            "prob",
        ]

        for key in possible_probability_keys:

            if key in prediction:

                try:

                    probability = float(
                        prediction[key]
                    )

                    break

                except (
                    TypeError,
                    ValueError
                ):

                    pass

        possible_priority_keys = [
            "priority",
            "risk",
            "level",
        ]

        for key in possible_priority_keys:

            if key in prediction:

                priority = str(
                    prediction[key]
                ).upper()

                break

    # --------------------------------------------------------
    # Numeric return
    # --------------------------------------------------------

    elif isinstance(
        prediction,
        (int, float)
    ):

        probability = float(
            prediction
        )

    # --------------------------------------------------------
    # Tuple / List return
    # --------------------------------------------------------

    elif isinstance(
        prediction,
        (tuple, list)
    ):

        if len(prediction) > 0:

            try:

                probability = float(
                    prediction[0]
                )

            except (
                TypeError,
                ValueError
            ):

                probability = None

        if len(prediction) > 1:

            if isinstance(
                prediction[1],
                str
            ):

                priority = (
                    prediction[1]
                    .upper()
                )

    # --------------------------------------------------------
    # Validate probability
    # --------------------------------------------------------

    if probability is None:

        raise ValueError(
            "ML predictor did not return a usable "
            "probability value."
        )

    # Clamp probability safely.
    probability = max(
        0.0,
        min(
            1.0,
            probability
        )
    )

    # --------------------------------------------------------
    # Calculate priority if predictor did not return one.
    # These thresholds match the frozen predictor behavior.
    # --------------------------------------------------------

    if priority is None:

        if probability >= 0.75:

            priority = "HIGH"

        elif probability >= 0.45:

            priority = "MEDIUM"

        else:

            priority = "LOW"

    return probability, priority


# ============================================================
# BUILD SAFE CANDIDATES
# ============================================================

def build_candidates(
    endpoints,
    predictions,
    resource_seeds
):

    candidates = []

    prediction_map = {}

    for prediction in predictions:

        prediction_map[
            prediction["endpoint_id"]
        ] = prediction

    for endpoint in endpoints:

        endpoint_id = endpoint["id"]

        method = str(
            endpoint["method"]
        ).upper()

        path = endpoint["path"]

        # Only GET endpoints are automatically tested.
        if method != "GET":
            continue

        resource_id = get_resource_seed(
            path,
            resource_seeds
        )

        if not resource_id:
            continue

        prediction = prediction_map.get(
            endpoint_id,
            {}
        )

        candidates.append({

            "endpoint_id": endpoint_id,

            "method": method,

            "path": path,

            "resource_id": resource_id,

            "ml_probability": float(
                prediction.get(
                    "probability",
                    0.0
                )
            ),

            "priority": prediction.get(
                "priority",
                "LOW"
            ),

        })

    return candidates


# ============================================================
# SAVE API SPEC + ENDPOINTS
# ============================================================

def save_api_spec_and_endpoints(
    db,
    openapi_data,
    extracted_endpoints,
    source
):

    info = openapi_data.get(
        "info",
        {}
    )

    api_spec = APISpec(

        name=info.get(
            "title",
            "Imported API"
        ),

        version=info.get(
            "version",
            "1.0.0"
        ),

        source=source,

    )

    db.add(api_spec)

    db.flush()

    saved_endpoints = []

    for item in extracted_endpoints:

        endpoint = Endpoint(

            api_spec_id=api_spec.id,

            method=str(
                item.get(
                    "method",
                    "GET"
                )
            ).upper(),

            path=item.get(
                "path",
                "/"
            ),

            summary=item.get(
                "summary",
                ""
            ),

            requires_auth=bool(
                item.get(
                    "requires_auth",
                    True
                )
            ),

        )

        db.add(endpoint)

        saved_endpoints.append(
            endpoint
        )

    db.flush()

    return (
        api_spec,
        saved_endpoints
    )


# ============================================================
# MAIN SCAN FUNCTION
# ============================================================

def discover_and_scan(
    db=None,
    target: str = "http://127.0.0.1:8002",
    owner_identity: str = "alice",
    test_identity: str = "bob",
    resource_seeds: dict | None = None,
    openapi_url: str | None = None,
):

    resource_seeds = resource_seeds or {}

    target = validate_target(
        target
    )

    own_db = False

    if db is None:

        from app.database import SessionLocal

        db = SessionLocal()

        own_db = True

    scan = None

    try:

        # ====================================================
        # 1. CREATE SCAN
        # ====================================================

        scan = Scan(

            name="SentinelAPI Security Scan",

            target=target,

            status="running",

            started_at=datetime.now(
                timezone.utc
            ),

        )

        db.add(scan)

        db.commit()

        db.refresh(scan)

        scan_id = scan.id

        # ====================================================
        # 2. LOAD OPENAPI
        # ====================================================

        if openapi_url:

            openapi_data = (
                load_openapi_from_url(
                    openapi_url
                )
            )

            source = openapi_url

        else:

            openapi_data = load_openapi(
                target
            )

            source = (
                f"{target}/openapi.json"
            )

        # ====================================================
        # 3. EXTRACT ENDPOINTS
        # ====================================================

        extracted_endpoints = (
            extract_endpoints(
                openapi_data
            )
        )

        if not extracted_endpoints:

            raise ValueError(
                "No API endpoints were discovered "
                "from the OpenAPI specification."
            )

        # ====================================================
        # 4. SAVE API SPEC + ENDPOINTS
        # ====================================================

        (
            api_spec,
            saved_endpoints
        ) = save_api_spec_and_endpoints(

            db=db,

            openapi_data=openapi_data,

            extracted_endpoints=(
                extracted_endpoints
            ),

            source=source,

        )

        db.commit()

        # ====================================================
        # 5. ML PREDICTIONS
        # ====================================================

        predictions = []

        for endpoint in saved_endpoints:

            raw_prediction = (
                predict_endpoint(

                    path=endpoint.path,

                    method=endpoint.method,

                    summary=(
                        endpoint.summary or ""
                    ),

                    api_type="REST",

                )
            )

            # ----------------------------------------------
            # IMPORTANT FIX:
            # Normalize predictor output instead of assuming
            # prediction["probability"] exists.
            # ----------------------------------------------

            (
                probability,
                priority
            ) = normalize_prediction(
                raw_prediction
            )

            ml_record = MLPrediction(

                endpoint_id=endpoint.id,

                probability=probability,

                priority=priority,

                model_version="Kaggle-MLP-v2",

            )

            db.add(ml_record)

            predictions.append({

                "endpoint_id": endpoint.id,

                "probability": probability,

                "priority": priority,

            })

        db.commit()

        # ====================================================
        # 6. ENDPOINT DICTIONARIES
        # ====================================================

        endpoint_dicts = []

        for endpoint in saved_endpoints:

            endpoint_dicts.append({

                "id": endpoint.id,

                "method": endpoint.method,

                "path": endpoint.path,

                "summary": endpoint.summary,

            })

        # ====================================================
        # 7. BUILD SAFE CANDIDATES
        # ====================================================

        candidates = build_candidates(

            endpoint_dicts,

            predictions,

            resource_seeds,

        )

        # ====================================================
        # 8. INITIAL AGENT TRACE
        # ====================================================

        step = 1

        initial_trace = AgentTrace(

            scan_id=scan_id,

            step=step,

            phase="OBSERVE_AND_PLAN",

            action="DISCOVER_CANDIDATES",

            target=target,

            observation=(
                f"{len(candidates)} safe BOLA "
                "candidate(s) discovered."
            ),

            decision=(
                "The bounded agent will only test "
                "GET endpoints with known resource IDs."
            ),

            result=None,

        )

        db.add(initial_trace)

        db.commit()

        # ====================================================
        # 9. AGENT LOOP
        # ====================================================

        while candidates:

            plan = plan_next_test(
                candidates
            )

            if plan.get(
                "action"
            ) == "STOP":

                break

            selected_endpoint_id = (
                plan.get(
                    "endpoint_id"
                )
            )

            selected_path = (
                plan.get(
                    "path"
                )
            )

            selected_resource_id = (
                plan.get(
                    "resource_id"
                )
            )

            if not selected_endpoint_id:

                break

            # =================================================
            # 10. AGENT DECISION TRACE
            # =================================================

            step += 1

            decision_trace = AgentTrace(

                scan_id=scan_id,

                step=step,

                phase="AGENT_PLAN",

                action="TEST_BOLA",

                target=selected_path,

                observation=(
                    "ML probability = "
                    f"{plan.get('ml_probability', 0):.4f}; "
                    "priority = "
                    f"{plan.get('priority', 'LOW')}"
                ),

                decision=(
                    f"Selected {selected_path} "
                    "for controlled BOLA testing."
                ),

                result=None,

            )

            db.add(
                decision_trace
            )

            db.commit()

            # =================================================
            # 11. CONTROLLED BOLA TEST
            # =================================================

            result = test_bola(

                base_url=target,

                order_id=(
                    selected_resource_id
                ),

                owner=owner_identity,

                other_user=test_identity,

            )

            owner_status = (
                result[
                    "owner_status"
                ]
            )

            other_status = (
                result[
                    "other_user_status"
                ]
            )

            # =================================================
            # 12. STORE PROBE
            # =================================================

            probe = Probe(

                scan_id=scan_id,

                endpoint_id=(
                    selected_endpoint_id
                ),

                identity_a=(
                    owner_identity
                ),

                identity_b=(
                    test_identity
                ),

                status_code_a=(
                    owner_status
                ),

                status_code_b=(
                    other_status
                ),

                created_at=datetime.now(
                    timezone.utc
                ),

            )

            db.add(probe)

            # =================================================
            # 13. DETERMINISTIC EVIDENCE
            # =================================================

            evidence = (
                generate_bola_evidence(

                    url=result["url"],

                    order_id=(
                        selected_resource_id
                    ),

                    owner=owner_identity,

                    other_user=(
                        test_identity
                    ),

                    owner_status=(
                        owner_status
                    ),

                    other_user_status=(
                        other_status
                    ),

                )
            )

            confirmed = bool(
                evidence.get(
                    "confirmed"
                )
            )

            # =================================================
            # 14. RESULT TRACE
            # =================================================

            step += 1

            result_trace = AgentTrace(

                scan_id=scan_id,

                step=step,

                phase="OBSERVE_RESULT",

                action="BOLA_PROBE",

                target=result["url"],

                observation=(
                    f"{owner_identity} -> "
                    f"{owner_status}; "
                    f"{test_identity} -> "
                    f"{other_status}"
                ),

                decision=(
                    "Authorization contrast evaluated "
                    "by deterministic evidence."
                ),

                result=(
                    "BOLA CONFIRMED"
                    if confirmed
                    else "NO BOLA CONFIRMED"
                ),

            )

            db.add(
                result_trace
            )

            # =================================================
            # 15. CREATE FINDING
            # =================================================

            if confirmed:

                finding = Finding(

                    scan_id=scan_id,

                    endpoint_id=(
                        selected_endpoint_id
                    ),

                    vulnerability_type="BOLA",

                    severity="HIGH",

                    title=(
                        "Broken Object Level Authorization"
                    ),

                    description=(
                        "The test identity was able to "
                        "access a resource owned by another "
                        "identity."
                    ),

                    evidence=json.dumps(
                        evidence
                    ),

                    confirmed=True,

                )

                db.add(
                    finding
                )

            db.commit()

            # =================================================
            # 16. REMOVE TESTED CANDIDATE
            # =================================================

            candidates = [

                candidate

                for candidate in candidates

                if candidate[
                    "endpoint_id"
                ] != selected_endpoint_id

            ]

        # ====================================================
        # 17. STOP TRACE
        # ====================================================

        step += 1

        stop_trace = AgentTrace(

            scan_id=scan_id,

            step=step,

            phase="STOP",

            action="STOP",

            target=target,

            observation=(
                "No remaining safe BOLA candidates."
            ),

            decision=(
                "The bounded agent stopped after "
                "completing all available safe tests."
            ),

            result="SCAN_COMPLETED",

        )

        db.add(
            stop_trace
        )

        # ====================================================
        # 18. COMPLETE SCAN
        # ====================================================

        scan.status = "completed"

        scan.completed_at = (
            datetime.now(
                timezone.utc
            )
        )

        db.commit()

        return {

            "scan_id": scan_id,

            "status": "completed",

            "message": (
                "SentinelAPI security scan completed."
            ),

        }

    except Exception as exc:

        db.rollback()

        if scan is not None:

            scan.status = "failed"

            scan.completed_at = (
                datetime.now(
                    timezone.utc
                )
            )

            db.commit()

        raise exc

    finally:

        if own_db:

            db.close()