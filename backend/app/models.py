from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, Float, JSON, UniqueConstraint
from sqlalchemy.sql import func
from .db import Base

class Workspace(Base):
    __tablename__ = "workspaces"
    id = Column(String, primary_key=True)
    name = Column(String(150), nullable=False)
    description = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Site(Base):
    __tablename__ = "sites"
    id = Column(String, primary_key=True)
    workspace_id = Column(String, ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(150), nullable=False)
    country = Column(String(100), default="")
    city = Column(String(100), default="")
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True)
    username = Column(String(80), nullable=False, unique=True, index=True)
    password = Column(String(160), nullable=False)
    role = Column(String(30), nullable=False, default="viewer")
    display_name = Column(String(150), default="")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Segment(Base):
    __tablename__ = "segments"
    id = Column(String, primary_key=True)
    site_id = Column(String, ForeignKey("sites.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(150), nullable=False)
    cidr = Column(String(64), default="")
    vlan = Column(Integer, nullable=True)
    zone_type = Column(String(50), default="")
    main_device_id = Column(String, nullable=True)
    perimeter_device_id = Column(String, nullable=True)
    color = Column(String(30), default="")
    collapsed = Column(Boolean, default=False)
    x_position = Column(Float, nullable=True)
    y_position = Column(Float, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    __table_args__ = (UniqueConstraint("site_id", "name", name="uq_segment_site_name"),)

class Device(Base):
    __tablename__ = "devices"
    id = Column(String, primary_key=True)
    site_id = Column(String, ForeignKey("sites.id", ondelete="CASCADE"), nullable=False)
    segment_id = Column(String, ForeignKey("segments.id", ondelete="SET NULL"), nullable=True)
    hostname = Column(String(150), nullable=False, index=True)
    management_ip = Column(String(64), default="", index=True)
    device_type = Column(String(50), nullable=False, default="unknown")
    icon = Column(String(50), default="auto")
    role = Column(String(50), default="host")
    tier = Column(Integer, default=6)
    vendor = Column(String(100), default="")
    model = Column(String(100), default="")
    serial_number = Column(String(100), default="")
    status = Column(String(30), default="UNKNOWN")
    is_main = Column(Boolean, default=False)
    is_perimeter = Column(Boolean, default=False)
    parent_device_id = Column(String, ForeignKey("devices.id", ondelete="SET NULL"), nullable=True)
    x_position = Column(Float, nullable=True)
    y_position = Column(Float, nullable=True)
    metadata_json = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    __table_args__ = (UniqueConstraint("site_id", "hostname", name="uq_device_site_hostname"),)

class Interface(Base):
    __tablename__ = "interfaces"
    id = Column(String, primary_key=True)
    device_id = Column(String, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(100), nullable=False)
    ip_address = Column(String(64), default="")
    mac_address = Column(String(64), default="")
    vlan = Column(Integer, nullable=True)
    zone = Column(String(100), default="")
    status = Column(String(30), default="UNKNOWN")
    speed = Column(String(50), default="")
    description = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    __table_args__ = (UniqueConstraint("device_id", "name", name="uq_interface_device_name"),)

class Link(Base):
    __tablename__ = "links"
    id = Column(String, primary_key=True)
    source_device_id = Column(String, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    target_device_id = Column(String, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    source_interface = Column(String(100), default="")
    target_interface = Column(String(100), default="")
    link_type = Column(String(50), default="physical_link")
    status = Column(String(30), default="UNKNOWN")
    label = Column(String(150), default="")
    discovery_method = Column(String(50), default="manual")
    metadata_json = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Service(Base):
    __tablename__ = "services"
    id = Column(String, primary_key=True)
    workspace_id = Column(String, ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(150), nullable=False)
    service_type = Column(String(50), default="")
    criticality = Column(String(30), default="medium")
    status = Column(String(30), default="UNKNOWN")
    owner = Column(String(150), default="")
    description = Column(Text, default="")
    metadata_json = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    __table_args__ = (UniqueConstraint("workspace_id", "name", name="uq_service_workspace_name"),)

class Dependency(Base):
    __tablename__ = "dependencies"
    id = Column(String, primary_key=True)
    source_type = Column(String(50), nullable=False)  # service/device/segment
    source_id = Column(String, nullable=False)
    target_type = Column(String(50), nullable=False)  # service/device/segment
    target_id = Column(String, nullable=False)
    dependency_type = Column(String(50), default="depends_on")
    criticality = Column(String(30), default="medium")
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class DiagramVersion(Base):
    __tablename__ = "diagram_versions"
    id = Column(String, primary_key=True)
    workspace_id = Column(String, ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(150), nullable=False)
    version = Column(String(50), nullable=False)
    snapshot_json = Column(JSON, default=dict)
    created_by = Column(String(80), default="system")
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(String, primary_key=True)
    username = Column(String(80), default="system")
    user_role = Column(String(30), default="system")
    action = Column(String(80), nullable=False)
    entity_type = Column(String(80), nullable=False)
    entity_id = Column(String, default="")
    message = Column(Text, default="")
    metadata_json = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
