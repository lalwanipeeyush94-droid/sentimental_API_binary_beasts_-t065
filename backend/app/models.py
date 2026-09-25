from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
)
from sqlalchemy.sql import func

from .database import Base


class APISpec(Base):
    __tablename__ = "api_specs"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    version = Column(String(50))
    source = Column(Text)
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
    )


class Endpoint(Base):
    __tablename__ = "endpoints"

    id = Column(Integer, primary_key=True, index=True)
    api_spec_id = Column(
        Integer,
        ForeignKey("api_specs.id"),
        nullable=False,
    )
    method = Column(String(10), nullable=False)
    path = Column(String(500), nullable=False)
    summary = Column(Text)
    requires_auth = Column(Boolean, default=True)
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
    )


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    target = Column(String(500))
    status = Column(String(50), default="pending")

    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
    )


class MLPrediction(Base):
    __tablename__ = "ml_predictions"

    id = Column(Integer, primary_key=True, index=True)

    endpoint_id = Column(
        Integer,
        ForeignKey("endpoints.id"),
        nullable=False,
    )

    probability = Column(Float, nullable=False)
    priority = Column(String(50))
    model_version = Column(String(100))

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
    )


class Probe(Base):
    __tablename__ = "probes"

    id = Column(Integer, primary_key=True, index=True)

    scan_id = Column(
        Integer,
        ForeignKey("scans.id"),
        nullable=False,
    )

    endpoint_id = Column(
        Integer,
        ForeignKey("endpoints.id"),
        nullable=False,
    )

    identity_a = Column(String(100))
    identity_b = Column(String(100))

    status_code_a = Column(Integer)
    status_code_b = Column(Integer)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
    )


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)

    scan_id = Column(
        Integer,
        ForeignKey("scans.id"),
        nullable=False,
    )

    endpoint_id = Column(
        Integer,
        ForeignKey("endpoints.id"),
        nullable=False,
    )

    vulnerability_type = Column(
        String(100),
        nullable=False,
    )

    severity = Column(String(50))
    title = Column(String(255))
    description = Column(Text)
    evidence = Column(Text)

    confirmed = Column(
        Boolean,
        default=False,
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
    )


class AgentTrace(Base):
    __tablename__ = "agent_traces"

    id = Column(Integer, primary_key=True, index=True)

    scan_id = Column(
        Integer,
        ForeignKey("scans.id"),
        nullable=False,
    )

    step = Column(Integer, nullable=False)

    phase = Column(String(100))

    action = Column(String(100))

    target = Column(String(500))

    observation = Column(Text)

    decision = Column(Text)

    result = Column(Text)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
    )