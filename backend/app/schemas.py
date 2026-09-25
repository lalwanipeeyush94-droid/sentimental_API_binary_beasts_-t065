from typing import Dict, Optional

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    """
    Configuration for one SentinelAPI scan.
    """

    target: str = Field(
        default="http://127.0.0.1:8001",
        description="Authorized API target"
    )

    owner_identity: str = Field(
        default="alice",
        description="Identity that owns the test resource"
    )

    test_identity: str = Field(
        default="bob",
        description="Identity used to test unauthorized access"
    )

    resource_seeds: Dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Known resource IDs for authorized sandbox testing. "
            "Example: {'/orders/{order_id}': 'B204'}"
        )
    )

    openapi_url: Optional[str] = Field(
        default=None,
        description="Optional OpenAPI specification URL"
    )


class ScanResponse(BaseModel):
    scan_id: int
    status: str
    message: str