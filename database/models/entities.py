from __future__ import annotations

import enum
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.models.base import Base, TimestampMixin


class JobStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"
    timed_out = "timed_out"


class FindingState(str, enum.Enum):
    suspected = "suspected"
    detected = "detected"
    manually_validated = "manually_validated"
    false_positive = "false_positive"


class Severity(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class ScanJob(Base, TimestampMixin):
    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    profile: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[JobStatus] = mapped_column(Enum(JobStatus), default=JobStatus.queued, index=True)
    targets: Mapped[list] = mapped_column(JSON, default=list)
    options: Mapped[dict] = mapped_column(JSON, default=dict)
    scope_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    requested_by: Mapped[str] = mapped_column(String(128), default="local-user")
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=300)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    raw_artifact_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    assets: Mapped[list["Asset"]] = relationship(back_populates="scan_job", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan_job", cascade="all, delete-orphan")
    evidence: Mapped[list["Evidence"]] = relationship(back_populates="scan_job", cascade="all, delete-orphan")
    audit_events: Mapped[list["AuditEvent"]] = relationship(back_populates="scan_job", cascade="all, delete-orphan")


class Asset(Base, TimestampMixin):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("scan_job_id", "asset_key", name="uq_asset_scan_key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id", ondelete="CASCADE"), index=True)
    asset_key: Mapped[str] = mapped_column(String(255), index=True)  # ip/hostname/cidr
    asset_type: Mapped[str] = mapped_column(String(32), default="host")
    ip_address: Mapped[Optional[str]] = mapped_column(String(128), index=True, nullable=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), index=True, nullable=True)
    mac_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    os_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    os_accuracy: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="unknown")
    labels: Mapped[dict] = mapped_column(JSON, default=dict)
    details: Mapped[dict] = mapped_column(JSON, default=dict)

    scan_job: Mapped["ScanJob"] = relationship(back_populates="assets")
    ports: Mapped[list["Port"]] = relationship(back_populates="asset", cascade="all, delete-orphan")


class Port(Base, TimestampMixin):
    __tablename__ = "ports"
    __table_args__ = (UniqueConstraint("asset_id", "port", "protocol", name="uq_port_asset_proto"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    port: Mapped[int] = mapped_column(Integer, index=True)
    protocol: Mapped[str] = mapped_column(String(16), default="tcp")
    state: Mapped[str] = mapped_column(String(32), default="unknown")
    details: Mapped[dict] = mapped_column(JSON, default=dict)

    asset: Mapped["Asset"] = relationship(back_populates="ports")
    services: Mapped[list["Service"]] = relationship(back_populates="port", cascade="all, delete-orphan")


class Service(Base, TimestampMixin):
    __tablename__ = "services"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    port_id: Mapped[int] = mapped_column(ForeignKey("ports.id", ondelete="CASCADE"), index=True)
    name: Mapped[Optional[str]] = mapped_column(String(128), index=True, nullable=True)
    product: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    version: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    extrainfo: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tunnel: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    banner: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cpe: Mapped[list] = mapped_column(JSON, default=list)
    http: Mapped[dict] = mapped_column(JSON, default=dict)
    tls: Mapped[dict] = mapped_column(JSON, default=dict)
    details: Mapped[dict] = mapped_column(JSON, default=dict)

    port: Mapped["Port"] = relationship(back_populates="services")
    findings: Mapped[list["Finding"]] = relationship(back_populates="service")


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[Optional[int]] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    service_id: Mapped[Optional[int]] = mapped_column(ForeignKey("services.id", ondelete="SET NULL"), nullable=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    state: Mapped[FindingState] = mapped_column(Enum(FindingState), default=FindingState.suspected, index=True)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.info, index=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cve_ids: Mapped[list] = mapped_column(JSON, default=list)
    cwe_ids: Mapped[list] = mapped_column(JSON, default=list)
    epss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    kev: Mapped[bool] = mapped_column(Boolean, default=False)
    evidence_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    references: Mapped[list] = mapped_column(JSON, default=list)
    mitre_attack: Mapped[list] = mapped_column(JSON, default=list)
    correlation: Mapped[dict] = mapped_column(JSON, default=dict)  # IP->Port->Service->Version->CVE
    raw: Mapped[dict] = mapped_column(JSON, default=dict)

    scan_job: Mapped["ScanJob"] = relationship(back_populates="findings")
    service: Mapped[Optional["Service"]] = relationship(back_populates="findings")
    evidence_items: Mapped[list["Evidence"]] = relationship(back_populates="finding")


class Evidence(Base, TimestampMixin):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[Optional[int]] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"), nullable=True)
    kind: Mapped[str] = mapped_column(String(64), index=True)  # raw_output, pcap, screenshot, log
    path: Mapped[str] = mapped_column(Text)
    content_type: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)

    scan_job: Mapped["ScanJob"] = relationship(back_populates="evidence")
    finding: Mapped[Optional["Finding"]] = relationship(back_populates="evidence_items")


class AuditEvent(Base, TimestampMixin):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_job_id: Mapped[Optional[int]] = mapped_column(ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True)
    actor: Mapped[str] = mapped_column(String(128), default="system")
    action: Mapped[str] = mapped_column(String(128), index=True)
    target: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    outcome: Mapped[str] = mapped_column(String(32), default="ok")
    details: Mapped[dict] = mapped_column(JSON, default=dict)

    scan_job: Mapped[Optional["ScanJob"]] = relationship(back_populates="audit_events")


class Report(Base, TimestampMixin):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_job_id: Mapped[Optional[int]] = mapped_column(ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True, index=True)
    format: Mapped[str] = mapped_column(String(16), index=True)
    path: Mapped[str] = mapped_column(Text)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
