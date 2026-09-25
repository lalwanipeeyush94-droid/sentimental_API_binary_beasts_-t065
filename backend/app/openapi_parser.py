import json
from typing import Any, Dict, List, Tuple

import httpx
import yaml
from sqlalchemy.orm import Session

from .models import APISpec, Endpoint


SUPPORTED_METHODS = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "options",
    "head",
}


RESOURCE_KEYWORDS = {
    "id",
    "order",
    "user",
    "account",
    "payment",
    "invoice",
    "profile",
    "record",
    "resource",
    "channel",
    "document",
    "file",
}


def load_openapi(base_url: str) -> dict:
    """
    Fetch OpenAPI specification from an authorized API target.
    """

    url = f"{base_url.rstrip('/')}/openapi.json"

    response = httpx.get(
        url,
        timeout=10.0,
    )

    response.raise_for_status()

    return response.json()


def parse_openapi_content(
    content: str,
    filename: str = "openapi.json",
) -> dict:
    """
    Parse uploaded OpenAPI JSON/YAML content.
    """

    extension = filename.lower().split(".")[-1]

    if extension in {"yaml", "yml"}:

        data = yaml.safe_load(content)

    else:

        try:
            data = json.loads(content)

        except json.JSONDecodeError:

            # Fallback: sometimes a YAML specification
            # may be uploaded with a .json extension.
            data = yaml.safe_load(content)

    if not isinstance(data, dict):
        raise ValueError(
            "Invalid OpenAPI specification."
        )

    if "openapi" not in data and "swagger" not in data:
        raise ValueError(
            "Uploaded file is not a valid OpenAPI/Swagger specification."
        )

    if "paths" not in data:
        raise ValueError(
            "OpenAPI specification does not contain any paths."
        )

    return data


def extract_path_parameters(
    path: str,
    operation: Dict[str, Any],
) -> List[str]:
    """
    Extract path parameters such as:

    /orders/{order_id}
    /users/{user_id}
    """

    parameters = []

    # Parameters directly defined on the operation
    for parameter in operation.get("parameters", []):

        if not isinstance(parameter, dict):
            continue

        if parameter.get("in") == "path":

            name = parameter.get("name")

            if name:
                parameters.append(name)

    # Parameters declared at path level
    return parameters


def detect_object_parameters(
    path: str,
    operation: Dict[str, Any],
) -> List[str]:
    """
    Identify parameters that may represent object/resource IDs.

    This is only candidate detection.
    It does NOT confirm a vulnerability.
    """

    candidates = []

    path_lower = path.lower()

    # Path parameters
    for parameter in operation.get("parameters", []):

        if not isinstance(parameter, dict):
            continue

        if parameter.get("in") != "path":
            continue

        name = str(parameter.get("name", ""))

        name_lower = name.lower()

        if (
            any(
                keyword in name_lower
                for keyword in RESOURCE_KEYWORDS
            )
            or any(
                keyword in path_lower
                for keyword in RESOURCE_KEYWORDS
            )
        ):
            candidates.append(name)

    # Fallback: detect {something_id} directly from path
    for segment in path.split("/"):

        if (
            segment.startswith("{")
            and segment.endswith("}")
        ):

            parameter_name = segment[1:-1]

            if parameter_name not in candidates:
                candidates.append(parameter_name)

    return candidates


def detect_authentication(
    openapi_data: dict,
) -> List[str]:
    """
    Detect authentication schemes declared in OpenAPI.
    """

    schemes = []

    components = openapi_data.get(
        "components",
        {},
    )

    security_schemes = components.get(
        "securitySchemes",
        {},
    )

    for name, scheme in security_schemes.items():

        if not isinstance(scheme, dict):
            continue

        scheme_type = scheme.get(
            "type",
            "",
        ).lower()

        if scheme_type == "http":

            http_scheme = scheme.get(
                "scheme",
                "",
            ).lower()

            if http_scheme == "bearer":
                schemes.append("JWT Bearer")

            elif http_scheme == "basic":
                schemes.append("Basic Auth")

            else:
                schemes.append(
                    f"HTTP {http_scheme.upper()}"
                )

        elif scheme_type == "apiKey":

            schemes.append("API Key")

        elif scheme_type == "oauth2":

            schemes.append("OAuth 2.0")

        elif scheme_type == "openIdConnect":

            schemes.append(
                "OpenID Connect"
            )

        else:

            schemes.append(
                str(scheme.get("type"))
            )

    return list(dict.fromkeys(schemes))


def extract_endpoints(
    openapi_data: dict,
) -> List[Dict[str, Any]]:
    """
    Extract endpoint metadata from OpenAPI.

    The parser only discovers information from the
    specification. It does not execute requests.
    """

    endpoints = []

    paths = openapi_data.get(
        "paths",
        {},
    )

    for path, path_data in paths.items():

        if not isinstance(path_data, dict):
            continue

        for method, details in path_data.items():

            method_lower = method.lower()

            if method_lower not in SUPPORTED_METHODS:
                continue

            if not isinstance(details, dict):
                details = {}

            object_parameters = detect_object_parameters(
                path,
                details,
            )

            path_parameters = extract_path_parameters(
                path,
                details,
            )

            endpoints.append(
                {
                    "method": method.upper(),
                    "path": path,
                    "summary": details.get(
                        "summary"
                    ),
                    "description": details.get(
                        "description"
                    ),
                    "operation_id": details.get(
                        "operationId"
                    ),
                    "tags": details.get(
                        "tags",
                        [],
                    ),
                    "requires_auth": bool(
                        details.get(
                            "security"
                        )
                        or openapi_data.get(
                            "security"
                        )
                    ),
                    "path_parameters": path_parameters,
                    "object_parameters": object_parameters,
                }
            )

    return endpoints


def save_to_database(
    db: Session,
    base_url: str,
    openapi_data: dict,
    endpoints: list,
) -> Tuple[APISpec, List[Endpoint]]:
    """
    Save parsed OpenAPI information to PostgreSQL.
    """

    info = openapi_data.get(
        "info",
        {},
    )

    api_title = info.get(
        "title",
        "Unknown API",
    )

    api_version = info.get(
        "version",
        "Unknown",
    )

    api_spec = (
        db.query(APISpec)
        .filter(
            APISpec.source == base_url
        )
        .first()
    )

    if api_spec is None:

        api_spec = APISpec(
            name=api_title,
            version=api_version,
            source=base_url,
        )

        db.add(api_spec)
        db.commit()
        db.refresh(api_spec)

    else:

        api_spec.name = api_title
        api_spec.version = api_version

        db.commit()
        db.refresh(api_spec)

    saved_endpoints = []

    for endpoint_data in endpoints:

        existing_endpoint = (
            db.query(Endpoint)
            .filter(
                Endpoint.api_spec_id
                == api_spec.id,
                Endpoint.method
                == endpoint_data["method"],
                Endpoint.path
                == endpoint_data["path"],
            )
            .first()
        )

        if existing_endpoint is None:

            endpoint = Endpoint(
                api_spec_id=api_spec.id,
                method=endpoint_data[
                    "method"
                ],
                path=endpoint_data[
                    "path"
                ],
                summary=(
                    endpoint_data.get(
                        "summary"
                    )
                    or endpoint_data.get(
                        "description"
                    )
                ),
                requires_auth=endpoint_data.get(
                    "requires_auth",
                    True,
                ),
            )

            db.add(endpoint)
            db.commit()
            db.refresh(endpoint)

        else:

            endpoint = existing_endpoint

            endpoint.summary = (
                endpoint_data.get(
                    "summary"
                )
                or endpoint_data.get(
                    "description"
                )
            )

            endpoint.requires_auth = endpoint_data.get(
                "requires_auth",
                True,
            )

            db.commit()
            db.refresh(endpoint)

        saved_endpoints.append(endpoint)

    return api_spec, saved_endpoints


def analyze_openapi(
    openapi_data: dict,
) -> Dict[str, Any]:
    """
    Generate frontend-ready analysis information.
    """

    endpoints = extract_endpoints(
        openapi_data
    )

    authentication = detect_authentication(
        openapi_data
    )

    method_counts = {}

    object_parameters = []

    for endpoint in endpoints:

        method = endpoint["method"]

        method_counts[method] = (
            method_counts.get(method, 0) + 1
        )

        for parameter in endpoint[
            "object_parameters"
        ]:

            object_parameters.append(
                {
                    "path": endpoint["path"],
                    "method": method,
                    "parameter": parameter,
                }
            )

    authorization_candidates = [
        endpoint
        for endpoint in endpoints
        if endpoint["object_parameters"]
    ]

    return {
        "openapi_version": (
            openapi_data.get(
                "openapi"
            )
            or openapi_data.get(
                "swagger"
            )
        ),
        "title": openapi_data.get(
            "info",
            {},
        ).get(
            "title",
            "Unknown API",
        ),
        "version": openapi_data.get(
            "info",
            {},
        ).get(
            "version",
            "Unknown",
        ),
        "authentication": authentication,
        "endpoint_count": len(
            endpoints
        ),
        "method_counts": method_counts,
        "object_id_count": len(
            object_parameters
        ),
        "authorization_candidate_count": len(
            authorization_candidates
        ),
        "object_parameters": object_parameters,
        "endpoints": endpoints,
    }