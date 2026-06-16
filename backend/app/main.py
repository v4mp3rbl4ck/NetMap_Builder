import csv
import base64
import hashlib
import hmac
import io
import ipaddress
import json
import os
import secrets
import time
import uuid
import xml.etree.ElementTree as ET
from contextvars import ContextVar
from typing import Any, Dict, List, Optional, Tuple

from fastapi import Depends, FastAPI, File, HTTPException, Request, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import delete, inspect, or_, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from .db import Base, SessionLocal, engine, get_db
from .models import (
    AuditLog,
    Dependency,
    Device,
    DiagramVersion,
    Interface,
    Link,
    Segment,
    Service,
    Site,
    User,
    Workspace,
)

APP_VERSION = os.getenv("APP_VERSION", "v.1.5.0")
DEFAULT_WORKSPACE_ID = "default-workspace"
DEFAULT_SITE_ID = "default-site"
AUTH_SECRET = os.getenv("AUTH_SECRET") or os.getenv("SECRET_KEY") or "netmap-dev-secret-change-me"
TOKEN_TTL_SECONDS = int(os.getenv("TOKEN_TTL_SECONDS", str(8 * 60 * 60)))
PASSWORD_ITERATIONS = int(os.getenv("PASSWORD_ITERATIONS", "260000"))
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(5 * 1024 * 1024)))
LOGIN_RATE_LIMIT_WINDOW = int(os.getenv("LOGIN_RATE_LIMIT_WINDOW", "300"))
LOGIN_RATE_LIMIT_MAX = int(os.getenv("LOGIN_RATE_LIMIT_MAX", "8"))
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").strip().lower() in {"1", "true", "yes", "si", "sí"}
BOOTSTRAP_ADMIN_USER = os.getenv("NETMAP_ADMIN_USER", "admin").strip().lower() or "admin"
BOOTSTRAP_ADMIN_PASSWORD = os.getenv("NETMAP_ADMIN_PASSWORD", "change-me-admin-password")
PASSWORD_SCHEME = "pbkdf2_sha256"
PUBLIC_API_PATHS = {"/api/auth/login", "/api/auth/logout", "/api/health"}
ADMIN_ONLY_PATHS = {"/api/users", "/api/reset", "/api/seed-demo"}
EXPORT_ROLES = {"admin", "editor"}
WRITE_ROLES = {"admin", "editor"}
READ_ROLES = {"admin", "editor", "viewer", "auditor"}
login_attempts: Dict[str, List[float]] = {}

current_username: ContextVar[str] = ContextVar("current_username", default="system")
current_role: ContextVar[str] = ContextVar("current_role", default="admin")

DEVICE_TYPES = {"firewall", "router", "switch", "server", "endpoint", "printer", "access_point", "camera", "nas", "ups", "cloud", "internet", "network", "unknown"}
STATUSES = {"UP", "DOWN", "WARNING", "UNKNOWN", "DEGRADED"}
LINK_TYPES = {"physical_link", "l2_link", "l3_link", "firewall_link", "vpn_link", "wireless_link", "service_dependency", "uplink", "backup_link", "internet_link", "manual"}
ENTITY_TYPES = {"device", "service", "segment"}
USER_ROLES = {"admin", "editor", "viewer", "auditor"}

def cors_origins() -> List[str]:
    origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
    return origins or ["http://localhost:8080", "http://127.0.0.1:8080"]


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("ascii"))


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return f"{PASSWORD_SCHEME}${PASSWORD_ITERATIONS}${b64url_encode(salt)}${b64url_encode(digest)}"


def verify_password(password: str, stored: str) -> bool:
    if not stored:
        return False
    if not stored.startswith(f"{PASSWORD_SCHEME}$"):
        return hmac.compare_digest(stored, password)
    try:
        _, iterations, salt, expected = stored.split("$", 3)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), b64url_decode(salt), int(iterations))
        return hmac.compare_digest(b64url_encode(digest), expected)
    except Exception:
        return False


def password_needs_rehash(stored: str) -> bool:
    return not stored.startswith(f"{PASSWORD_SCHEME}$")


def sign_payload(payload: Dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    body = b64url_encode(raw)
    signature = hmac.new(AUTH_SECRET.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest()
    return f"{body}.{b64url_encode(signature)}"


def verify_token(token: str) -> Dict[str, Any]:
    try:
        body, signature = token.split(".", 1)
        expected = b64url_encode(hmac.new(AUTH_SECRET.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            raise ValueError("bad signature")
        payload = json.loads(b64url_decode(body).decode("utf-8"))
        if int(payload.get("exp", 0)) < int(time.time()):
            raise ValueError("expired")
        return payload
    except Exception as exc:
        raise HTTPException(401, "Sesión inválida o expirada") from exc


def create_session_token(user: User) -> str:
    now = int(time.time())
    return sign_payload({
        "sub": user.id,
        "username": user.username,
        "iat": now,
        "exp": now + TOKEN_TTL_SECONDS,
    })


def token_from_request(request: Request) -> str:
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return request.cookies.get("netmap_session", "")


def client_key(request: Request, username: str = "") -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    ip = forwarded.split(",", 1)[0].strip() or (request.client.host if request.client else "unknown")
    return f"{ip}:{username.strip().lower()}"


def check_login_rate_limit(request: Request, username: str):
    key = client_key(request, username)
    now = time.time()
    attempts = [t for t in login_attempts.get(key, []) if now - t < LOGIN_RATE_LIMIT_WINDOW]
    if len(attempts) >= LOGIN_RATE_LIMIT_MAX:
        login_attempts[key] = attempts
        raise HTTPException(429, "Demasiados intentos de login. Intenta nuevamente más tarde.")
    attempts.append(now)
    login_attempts[key] = attempts


def clear_login_rate_limit(request: Request, username: str):
    login_attempts.pop(client_key(request, username), None)


def is_admin_only_path(path: str) -> bool:
    return any(path == p or path.startswith(f"{p}/") for p in ADMIN_ONLY_PATHS)


def authorize_role(path: str, method: str, role: str):
    if role not in READ_ROLES:
        raise HTTPException(403, "Rol inválido o sin permisos")
    if is_admin_only_path(path) and role != "admin":
        raise HTTPException(403, "Solo administradores pueden ejecutar esta acción")
    if path.startswith("/api/export/") and role not in EXPORT_ROLES:
        raise HTTPException(403, "Tu rol no permite exportar información")
    if path.startswith("/api/import/") and role not in WRITE_ROLES:
        raise HTTPException(403, "Tu rol no permite importar información")
    if method in {"POST", "PATCH", "DELETE"} and role not in WRITE_ROLES:
        raise HTTPException(403, "Permiso denegado para este rol")


app = FastAPI(title="NetMap Builder API", version=APP_VERSION)
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

@app.middleware("http")
async def security_and_context(request: Request, call_next):
    username = "anonymous"
    role = "anonymous"
    token_user = current_username.set(username)
    token_role = current_role.set(role)
    try:
        path = request.url.path
        if path.startswith("/api/") and request.method != "OPTIONS" and path not in PUBLIC_API_PATHS:
            payload = verify_token(token_from_request(request))
            with SessionLocal() as auth_db:
                user = auth_db.get(User, payload.get("sub"))
                if not user or not user.is_active:
                    return JSONResponse({"detail": "Sesión inválida o usuario inactivo"}, status_code=401)
                username = user.username
                role = user.role
                current_username.set(username)
                current_role.set(role)
                authorize_role(path, request.method, role)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = os.getenv(
            "CONTENT_SECURITY_POLICY",
            "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; connect-src 'self'; font-src 'self' data:; object-src 'none'; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        )
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response
    except HTTPException as exc:
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
    finally:
        current_username.reset(token_user)
        current_role.reset(token_role)

# -----------------------------
# Helpers
# -----------------------------

def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def bool_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "si", "sí"}


def int_or_none(value: Any) -> Optional[int]:
    if value is None or str(value).strip() == "":
        return None
    try:
        return int(float(str(value).strip()))
    except ValueError:
        return None


def validate_ip(value: str, *, required: bool = False) -> str:
    value = (value or "").strip()
    if not value:
        if required:
            raise ValueError("IP requerida")
        return ""
    ipaddress.ip_address(value)
    return value


def validate_cidr(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    ipaddress.ip_network(value, strict=False)
    return value


def validate_vlan(value: Optional[int]) -> Optional[int]:
    if value is None:
        return None
    if value < 0 or value > 4094:
        raise ValueError("VLAN fuera de rango 0-4094")
    return value


def clean_type(value: str) -> str:
    value = (value or "unknown").strip().lower() or "unknown"
    if value not in DEVICE_TYPES:
        raise ValueError(f"Tipo desconocido: {value}")
    return value


def clean_status(value: str) -> str:
    value = (value or "UNKNOWN").strip().upper() or "UNKNOWN"
    if value not in STATUSES:
        raise ValueError(f"Estado desconocido: {value}")
    return value


def clean_link_type(value: str) -> str:
    value = (value or "physical_link").strip() or "physical_link"
    if value not in LINK_TYPES:
        raise ValueError(f"Tipo de relación inválido: {value}")
    return value


def audit(db: Session, action: str, entity_type: str, entity_id: str = "", message: str = "", metadata: Optional[dict] = None):
    db.add(AuditLog(
        id=new_id("audit"),
        username=current_username.get("system"),
        user_role=current_role.get("system"),
        action=action,
        entity_type=entity_type,
        entity_id=entity_id or "",
        message=message or "",
        metadata_json=metadata or {},
    ))


def ensure_defaults(db: Session):
    """Create seed data in FK-safe order.

    SQLAlchemy does not always infer insert order when models only declare
    ForeignKey columns and no ORM relationships. PostgreSQL enforces FKs, so
    the default workspace must be flushed before inserting the default site,
    and the default workspace must be flushed before services/versions that
    reference it.
    """
    ws = db.get(Workspace, DEFAULT_WORKSPACE_ID)
    if not ws:
        ws = Workspace(id=DEFAULT_WORKSPACE_ID, name="Workspace Demo", description="Workspace por defecto")
        db.add(ws)
        db.flush()

    site = db.get(Site, DEFAULT_SITE_ID)
    if not site:
        site = Site(id=DEFAULT_SITE_ID, workspace_id=DEFAULT_WORKSPACE_ID, name="Sede Principal", country="", city="")
        db.add(site)
        db.flush()

    users = [(BOOTSTRAP_ADMIN_USER, BOOTSTRAP_ADMIN_PASSWORD, "admin", "Administrador")]
    for username, password, role, display in users:
        if not db.query(User).filter(User.username == username).first():
            db.add(User(id=new_id("user"), username=username, password=hash_password(password), role=role, display_name=display))

    db.commit()


def get_or_create_segment(db: Session, name: str, cidr: str = "", vlan: Optional[int] = None, site_id: str = DEFAULT_SITE_ID) -> Segment:
    name = (name or "Sin segmento").strip() or "Sin segmento"
    cidr = validate_cidr(cidr)
    vlan = validate_vlan(vlan)
    seg = db.query(Segment).filter(Segment.site_id == site_id, Segment.name == name).first()
    if seg:
        if cidr and not seg.cidr:
            seg.cidr = cidr
        if vlan is not None and seg.vlan is None:
            seg.vlan = vlan
        return seg
    seg = Segment(id=new_id("seg"), site_id=site_id, name=name, cidr=cidr, vlan=vlan, zone_type="", color="")
    db.add(seg)
    db.flush()
    audit(db, "create", "segment", seg.id, f"Segmento creado: {name}")
    return seg


def device_by_name_or_ip(db: Session, name: str = "", ip: str = "") -> Optional[Device]:
    query = db.query(Device).filter(Device.site_id == DEFAULT_SITE_ID)
    filters = []
    if name:
        filters.append(Device.hostname == name)
    if ip:
        filters.append(Device.management_ip == ip)
    if not filters:
        return None
    return query.filter(or_(*filters)).first()


def entity_name(db: Session, entity_type: str, entity_id: str) -> str:
    if entity_type == "device":
        obj = db.get(Device, entity_id)
        return obj.hostname if obj else entity_id
    if entity_type == "service":
        obj = db.get(Service, entity_id)
        return obj.name if obj else entity_id
    if entity_type == "segment":
        obj = db.get(Segment, entity_id)
        return obj.name if obj else entity_id
    return entity_id


def resolve_entity_id(db: Session, entity_type: str, name: str) -> Optional[str]:
    et = (entity_type or "").lower()
    if et == "device":
        d = device_by_name_or_ip(db, name, name)
        return d.id if d else None
    if et == "service":
        s = db.query(Service).filter(Service.workspace_id == DEFAULT_WORKSPACE_ID, Service.name == name).first()
        return s.id if s else None
    if et == "segment":
        s = db.query(Segment).filter(Segment.site_id == DEFAULT_SITE_ID, Segment.name == name).first()
        return s.id if s else None
    return None


def guess_type_from_ports(ports: List[Dict[str, Any]]) -> str:
    open_ports = {str(p.get("port")) for p in ports}
    services = {str(p.get("service", "")).lower() for p in ports}
    if "9100" in open_ports or "printer" in services:
        return "printer"
    if "161" in open_ports or "snmp" in services:
        return "network"
    if "80" in open_ports or "443" in open_ports or "http" in services or "https" in services:
        return "server"
    if "22" in open_ports or "3389" in open_ports or "445" in open_ports:
        return "server"
    return "endpoint"


def infer_tier(device_type: str, role: str = "") -> int:
    dtype = (device_type or "").lower()
    role = (role or "").lower()
    if "internet" in dtype or "cloud" in dtype:
        return 0
    if "firewall" in dtype or "perimeter" in role:
        return 1
    if "router" in dtype:
        return 2
    if "core" in role:
        return 3
    if "switch" in dtype and "access" in role:
        return 5
    if "switch" in dtype:
        return 4
    return 6

# -----------------------------
# Serializers
# -----------------------------

def serialize_user(u: User) -> dict:
    return {"id": u.id, "username": u.username, "role": u.role, "display_name": u.display_name, "is_active": u.is_active, "created_at": u.created_at.isoformat() if u.created_at else None}


def serialize_device(d: Device) -> dict:
    return {
        "id": d.id,
        "site_id": d.site_id,
        "segment_id": d.segment_id,
        "hostname": d.hostname,
        "management_ip": d.management_ip,
        "device_type": d.device_type,
        "icon": d.icon or "auto",
        "role": d.role,
        "tier": d.tier,
        "vendor": d.vendor,
        "model": d.model,
        "serial_number": d.serial_number,
        "status": d.status,
        "is_main": d.is_main,
        "is_perimeter": d.is_perimeter,
        "parent_device_id": d.parent_device_id,
        "x_position": d.x_position,
        "y_position": d.y_position,
        "metadata": d.metadata_json or {},
        "created_at": d.created_at.isoformat() if d.created_at else None,
    }


def serialize_segment(s: Segment) -> dict:
    return {
        "id": s.id,
        "site_id": s.site_id,
        "name": s.name,
        "cidr": s.cidr,
        "vlan": s.vlan,
        "zone_type": s.zone_type,
        "main_device_id": s.main_device_id,
        "perimeter_device_id": s.perimeter_device_id,
        "color": s.color,
        "collapsed": bool(s.collapsed),
        "x_position": s.x_position,
        "y_position": s.y_position,
    }


def serialize_interface(i: Interface) -> dict:
    return {
        "id": i.id,
        "device_id": i.device_id,
        "name": i.name,
        "ip_address": i.ip_address,
        "mac_address": i.mac_address,
        "vlan": i.vlan,
        "zone": i.zone,
        "status": i.status,
        "speed": i.speed,
        "description": i.description,
        "created_at": i.created_at.isoformat() if i.created_at else None,
    }


def serialize_link(l: Link) -> dict:
    return {
        "id": l.id,
        "source_device_id": l.source_device_id,
        "target_device_id": l.target_device_id,
        "source_interface": l.source_interface,
        "target_interface": l.target_interface,
        "link_type": l.link_type,
        "status": l.status,
        "label": l.label,
        "discovery_method": l.discovery_method,
        "metadata": l.metadata_json or {},
        "link_group": (l.metadata_json or {}).get("link_group", ""),
        "link_role": (l.metadata_json or {}).get("link_role", ""),
        "parallel_count": (l.metadata_json or {}).get("parallel_count"),
        "created_at": l.created_at.isoformat() if l.created_at else None,
    }


def serialize_service(s: Service) -> dict:
    return {
        "id": s.id,
        "workspace_id": s.workspace_id,
        "name": s.name,
        "service_type": s.service_type,
        "criticality": s.criticality,
        "status": s.status,
        "owner": s.owner,
        "description": s.description,
        "metadata": s.metadata_json or {},
    }


def serialize_dependency(d: Dependency, db: Optional[Session] = None) -> dict:
    result = {
        "id": d.id,
        "source_type": d.source_type,
        "source_id": d.source_id,
        "target_type": d.target_type,
        "target_id": d.target_id,
        "dependency_type": d.dependency_type,
        "criticality": d.criticality,
    }
    if db:
        result["source_name"] = entity_name(db, d.source_type, d.source_id)
        result["target_name"] = entity_name(db, d.target_type, d.target_id)
    return result


def serialize_version(v: DiagramVersion) -> dict:
    return {"id": v.id, "workspace_id": v.workspace_id, "name": v.name, "version": v.version, "created_by": v.created_by, "created_at": v.created_at.isoformat() if v.created_at else None}


def state_payload(db: Session) -> dict:
    ensure_defaults(db)
    devices = db.query(Device).order_by(Device.tier.asc(), Device.hostname.asc()).all()
    role = current_role.get("system")
    return {
        "version": APP_VERSION,
        "workspace": {"id": DEFAULT_WORKSPACE_ID, "name": "Workspace Demo"},
        "site": {"id": DEFAULT_SITE_ID, "name": "Sede Principal"},
        "segments": [serialize_segment(s) for s in db.query(Segment).order_by(Segment.name.asc()).all()],
        "devices": [serialize_device(d) for d in devices],
        "interfaces": [serialize_interface(i) for i in db.query(Interface).order_by(Interface.device_id.asc(), Interface.name.asc()).all()],
        "links": [serialize_link(l) for l in db.query(Link).all()],
        "services": [serialize_service(s) for s in db.query(Service).order_by(Service.name.asc()).all()],
        "dependencies": [serialize_dependency(d, db) for d in db.query(Dependency).all()],
        "versions": [serialize_version(v) for v in db.query(DiagramVersion).order_by(DiagramVersion.created_at.desc()).limit(30).all()],
        "users": [serialize_user(u) for u in db.query(User).order_by(User.username.asc()).all()] if role == "admin" else [],
        "audit": [
            {
                "id": a.id,
                "username": a.username,
                "user_role": a.user_role,
                "action": a.action,
                "entity_type": a.entity_type,
                "entity_id": a.entity_id,
                "message": a.message,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(100).all()
        ] if role in {"admin", "auditor"} else [],
    }

# -----------------------------
# Pydantic models
# -----------------------------

class LoginIn(BaseModel):
    username: str
    password: str

class UserIn(BaseModel):
    username: str
    password: str
    role: str = "viewer"
    display_name: str = ""
    is_active: bool = True

class UserPatch(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    role: Optional[str] = None
    display_name: Optional[str] = None
    is_active: Optional[bool] = None

class DeviceIn(BaseModel):
    hostname: str
    management_ip: str = ""
    device_type: str = "unknown"
    icon: str = "auto"
    role: str = "host"
    tier: int = 6
    segment_id: Optional[str] = None
    segment_name: Optional[str] = None
    cidr: str = ""
    vlan: Optional[int] = None
    vendor: str = ""
    model: str = ""
    serial_number: str = ""
    status: str = "UNKNOWN"
    is_main: bool = False
    is_perimeter: bool = False
    parent_device_id: Optional[str] = None
    x_position: Optional[float] = None
    y_position: Optional[float] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

class DevicePatch(BaseModel):
    hostname: Optional[str] = None
    management_ip: Optional[str] = None
    device_type: Optional[str] = None
    icon: Optional[str] = None
    role: Optional[str] = None
    tier: Optional[int] = None
    segment_id: Optional[str] = None
    segment_name: Optional[str] = None
    cidr: Optional[str] = None
    vlan: Optional[int] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    serial_number: Optional[str] = None
    status: Optional[str] = None
    is_main: Optional[bool] = None
    is_perimeter: Optional[bool] = None
    parent_device_id: Optional[str] = None
    x_position: Optional[float] = None
    y_position: Optional[float] = None
    metadata: Optional[Dict[str, Any]] = None

class BulkPatch(BaseModel):
    ids: List[str]
    patch: DevicePatch


class BulkRelationIn(BaseModel):
    ids: List[str]
    target_device_id: str
    link_type: str = "uplink"
    status: str = "UP"
    label: str = "depende del principal"
    direction: str = "target_to_selected"
    set_parent: bool = True

class LinkIn(BaseModel):
    source_device_id: str
    target_device_id: str
    source_interface: str = ""
    target_interface: str = ""
    link_type: str = "physical_link"
    status: str = "UP"
    label: str = ""
    discovery_method: str = "manual"
    link_group: str = ""
    link_role: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)

class InterfaceIn(BaseModel):
    device_id: str
    name: str
    ip_address: str = ""
    mac_address: str = ""
    vlan: Optional[int] = None
    zone: str = ""
    status: str = "UNKNOWN"
    speed: str = ""
    description: str = ""

class SegmentIn(BaseModel):
    name: str
    cidr: str = ""
    vlan: Optional[int] = None
    zone_type: str = ""
    color: str = ""
    main_device_id: Optional[str] = None
    perimeter_device_id: Optional[str] = None
    collapsed: bool = False
    x_position: Optional[float] = None
    y_position: Optional[float] = None

class SegmentPatch(BaseModel):
    name: Optional[str] = None
    cidr: Optional[str] = None
    vlan: Optional[int] = None
    zone_type: Optional[str] = None
    color: Optional[str] = None
    main_device_id: Optional[str] = None
    perimeter_device_id: Optional[str] = None
    collapsed: Optional[bool] = None
    x_position: Optional[float] = None
    y_position: Optional[float] = None

class ServiceIn(BaseModel):
    name: str
    service_type: str = ""
    criticality: str = "medium"
    status: str = "UNKNOWN"
    owner: str = ""
    description: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)

class DependencyIn(BaseModel):
    source_type: str
    source_id: str
    target_type: str
    target_id: str
    dependency_type: str = "depends_on"
    criticality: str = "medium"

class PositionIn(BaseModel):
    x_position: float
    y_position: float

class VersionIn(BaseModel):
    name: str = "Mapa Principal"
    version: str = APP_VERSION


def migrate_schema():
    inspector = inspect(engine)
    dialect = engine.dialect.name
    def has_table(name: str) -> bool:
        return name in inspector.get_table_names()
    def cols(name: str) -> set[str]:
        if not has_table(name):
            return set()
        return {c["name"] for c in inspector.get_columns(name)}
    statements = []
    segment_cols = cols("segments")
    if "collapsed" not in segment_cols:
        statements.append("ALTER TABLE segments ADD COLUMN collapsed BOOLEAN DEFAULT FALSE")
    if "x_position" not in segment_cols:
        statements.append("ALTER TABLE segments ADD COLUMN x_position DOUBLE PRECISION")
    if "y_position" not in segment_cols:
        statements.append("ALTER TABLE segments ADD COLUMN y_position DOUBLE PRECISION")
    audit_cols = cols("audit_logs")
    if "username" not in audit_cols:
        statements.append("ALTER TABLE audit_logs ADD COLUMN username VARCHAR(80) DEFAULT 'system'")
    if "user_role" not in audit_cols:
        statements.append("ALTER TABLE audit_logs ADD COLUMN user_role VARCHAR(30) DEFAULT 'system'")
    with engine.begin() as conn:
        for stmt in statements:
            try:
                conn.execute(text(stmt))
            except Exception:
                # Safe fallback: existing databases may already have the column or a dialect-specific limitation.
                pass

# -----------------------------
# Startup
# -----------------------------

@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    migrate_schema()
    db = next(get_db())
    try:
        ensure_defaults(db)
        if db.query(Device).count() == 0:
            seed_demo(db)
    finally:
        db.close()

# -----------------------------
# Auth and core endpoints
# -----------------------------

@app.post("/api/auth/login")
def login(payload: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    ensure_defaults(db)
    username = payload.username.strip().lower()
    check_login_rate_limit(request, username)
    user = db.query(User).filter(User.username == username, User.is_active == True).first()
    if not user or not verify_password(payload.password, user.password):
        audit(db, "login_failed", "user", "", f"Login fallido: {username}")
        db.commit()
        raise HTTPException(401, "Credenciales inválidas")
    if password_needs_rehash(user.password):
        user.password = hash_password(payload.password)
        audit(db, "security", "user", user.id, f"Password migrado a hash seguro: {user.username}")
    audit(db, "login", "user", user.id, f"Login correcto: {user.username}")
    db.commit()
    clear_login_rate_limit(request, username)
    token = create_session_token(user)
    response.set_cookie(
        "netmap_session",
        token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=TOKEN_TTL_SECONDS,
        path="/",
    )
    return {"ok": True, "user": serialize_user(user), "token": token, "expires_in": TOKEN_TTL_SECONDS}


@app.post("/api/auth/logout")
def logout(response: Response):
    response.delete_cookie("netmap_session", path="/")
    return {"ok": True}

def require_admin():
    if current_role.get("system") != "admin":
        raise HTTPException(403, "Solo administradores pueden administrar usuarios")

def normalize_user_payload(db: Session, payload: UserIn | UserPatch, user_id: Optional[str] = None) -> Dict[str, Any]:
    data = payload.model_dump(exclude_unset=True)
    if "username" in data and data["username"] is not None:
        data["username"] = data["username"].strip().lower()
        if not data["username"]:
            raise HTTPException(400, "Username vacío")
        q = db.query(User).filter(User.username == data["username"])
        if user_id:
            q = q.filter(User.id != user_id)
        if q.first():
            raise HTTPException(409, "Username duplicado")
    if "password" in data and data["password"] is not None:
        data["password"] = data["password"].strip()
        if not data["password"]:
            data.pop("password", None)
        elif len(data["password"]) < 10:
            raise HTTPException(400, "La contraseña debe tener al menos 10 caracteres")
        else:
            data["password"] = hash_password(data["password"])
    if "role" in data and data["role"] is not None:
        data["role"] = data["role"].strip().lower()
        if data["role"] not in USER_ROLES:
            raise HTTPException(400, f"Rol inválido: {data['role']}")
    if "display_name" in data and data["display_name"] is not None:
        data["display_name"] = data["display_name"].strip()
    return data

@app.post("/api/users")
def create_user(payload: UserIn, db: Session = Depends(get_db)):
    require_admin()
    data = normalize_user_payload(db, payload)
    if not data.get("password"):
        raise HTTPException(400, "Contraseña requerida")
    user = User(id=new_id("user"), **data)
    db.add(user)
    audit(db, "create", "user", user.id, f"Usuario creado: {user.username}")
    db.commit()
    return state_payload(db)

@app.patch("/api/users/{user_id}")
def update_user(user_id: str, payload: UserPatch, db: Session = Depends(get_db)):
    require_admin()
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "Usuario no encontrado")
    data = normalize_user_payload(db, payload, user_id=user_id)
    if current_username.get("") == user.username and data.get("is_active") is False:
        raise HTTPException(400, "No puedes desactivar tu propio usuario")
    if current_username.get("") == user.username and data.get("role") and data.get("role") != "admin":
        raise HTTPException(400, "No puedes quitarte el rol admin a ti mismo")
    for k, v in data.items():
        setattr(user, k, v)
    audit(db, "update", "user", user.id, f"Usuario actualizado: {user.username}", data)
    db.commit()
    return state_payload(db)

@app.delete("/api/users/{user_id}")
def delete_user(user_id: str, db: Session = Depends(get_db)):
    require_admin()
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "Usuario no encontrado")
    if current_username.get("") == user.username:
        raise HTTPException(400, "No puedes eliminar tu propio usuario")
    if user.role == "admin" and db.query(User).filter(User.role == "admin", User.is_active == True, User.id != user_id).count() == 0:
        raise HTTPException(400, "Debe existir al menos un administrador activo")
    username = user.username
    db.delete(user)
    audit(db, "delete", "user", user_id, f"Usuario eliminado: {username}")
    db.commit()
    return state_payload(db)

@app.get("/api/health")
def health(db: Session = Depends(get_db)):
    return {"ok": True, "version": APP_VERSION, "devices": db.query(Device).count()}

@app.get("/api/state")
def get_state(db: Session = Depends(get_db)):
    return state_payload(db)

@app.post("/api/reset")
def reset_all(db: Session = Depends(get_db)):
    for model in [Dependency, Service, Link, Interface, Device, Segment, DiagramVersion, AuditLog]:
        db.execute(delete(model))
    db.commit()
    ensure_defaults(db)
    audit(db, "reset", "workspace", DEFAULT_WORKSPACE_ID, "Data eliminada por el usuario")
    db.commit()
    return state_payload(db)

@app.post("/api/seed-demo")
def seed_demo_endpoint(db: Session = Depends(get_db)):
    seed_demo(db, clear=True)
    return state_payload(db)

# -----------------------------
# CRUD Devices
# -----------------------------

def validate_device_payload(db: Session, payload: DeviceIn | DevicePatch, device_id: Optional[str] = None) -> Tuple[Optional[str], Dict[str, Any]]:
    data = payload.model_dump(exclude_unset=True)
    if "hostname" in data and data["hostname"] is not None:
        data["hostname"] = data["hostname"].strip()
        if not data["hostname"]:
            raise HTTPException(400, "Hostname vacío")
        q = db.query(Device).filter(Device.site_id == DEFAULT_SITE_ID, Device.hostname == data["hostname"])
        if device_id:
            q = q.filter(Device.id != device_id)
        if q.first():
            raise HTTPException(409, "Hostname duplicado")
    if "management_ip" in data and data["management_ip"] is not None:
        try:
            data["management_ip"] = validate_ip(data["management_ip"])
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        if data["management_ip"]:
            q = db.query(Device).filter(Device.site_id == DEFAULT_SITE_ID, Device.management_ip == data["management_ip"])
            if device_id:
                q = q.filter(Device.id != device_id)
            if q.first():
                raise HTTPException(409, "IP duplicada")
    if "cidr" in data and data.get("cidr"):
        try:
            data["cidr"] = validate_cidr(data["cidr"])
        except ValueError:
            raise HTTPException(400, "CIDR inválido")
    if "vlan" in data:
        try:
            data["vlan"] = validate_vlan(data.get("vlan"))
        except ValueError as exc:
            raise HTTPException(400, str(exc))
    if "device_type" in data and data["device_type"] is not None:
        try:
            data["device_type"] = clean_type(data["device_type"])
        except ValueError as exc:
            raise HTTPException(400, str(exc))
    if "status" in data and data["status"] is not None:
        try:
            data["status"] = clean_status(data["status"])
        except ValueError as exc:
            raise HTTPException(400, str(exc))
    if "parent_device_id" in data and data.get("parent_device_id"):
        if data["parent_device_id"] == device_id:
            raise HTTPException(400, "Un dispositivo no puede ser su propio parent")
        if not db.get(Device, data["parent_device_id"]):
            raise HTTPException(400, "Parent/upstream inexistente")
    segment_id = data.get("segment_id")
    if segment_id == "":
        segment_id = None
        data["segment_id"] = None
    if data.get("parent_device_id") == "":
        data["parent_device_id"] = None
    if data.get("segment_name") or data.get("cidr") or data.get("vlan") is not None:
        seg = get_or_create_segment(db, data.get("segment_name") or "Sin segmento", data.get("cidr") or "", data.get("vlan"))
        segment_id = seg.id
    elif segment_id:
        if not db.get(Segment, segment_id):
            raise HTTPException(400, "Segmento inexistente")
    return segment_id, data

@app.post("/api/devices")
def create_device(payload: DeviceIn, db: Session = Depends(get_db)):
    ensure_defaults(db)
    segment_id, data = validate_device_payload(db, payload)
    if not data.get("hostname"):
        raise HTTPException(400, "Hostname requerido")
    dev = Device(
        id=new_id("dev"),
        site_id=DEFAULT_SITE_ID,
        segment_id=segment_id,
        hostname=data.get("hostname"),
        management_ip=data.get("management_ip") or "",
        device_type=data.get("device_type") or "unknown",
        icon=data.get("icon") or "auto",
        role=data.get("role") or "host",
        tier=data.get("tier") if data.get("tier") is not None else infer_tier(data.get("device_type", "unknown"), data.get("role", "host")),
        vendor=data.get("vendor") or "",
        model=data.get("model") or "",
        serial_number=data.get("serial_number") or "",
        status=data.get("status") or "UNKNOWN",
        is_main=bool(data.get("is_main")),
        is_perimeter=bool(data.get("is_perimeter")),
        parent_device_id=data.get("parent_device_id") or None,
        x_position=data.get("x_position"),
        y_position=data.get("y_position"),
        metadata_json=data.get("metadata") or {},
    )
    db.add(dev)
    db.flush()
    if dev.parent_device_id:
        db.add(Link(id=new_id("link"), source_device_id=dev.parent_device_id, target_device_id=dev.id, link_type="uplink", status="UP", label="parent/upstream", discovery_method="parent"))
    audit(db, "create", "device", dev.id, f"Dispositivo creado: {dev.hostname}")
    db.commit()
    return serialize_device(dev)

@app.patch("/api/devices/{device_id}")
def update_device(device_id: str, payload: DevicePatch, db: Session = Depends(get_db)):
    dev = db.get(Device, device_id)
    if not dev:
        raise HTTPException(404, "Dispositivo no encontrado")
    segment_id, data = validate_device_payload(db, payload, device_id)
    if segment_id is not None:
        dev.segment_id = segment_id
    old_parent = dev.parent_device_id
    for key, value in data.items():
        if key in {"segment_name", "cidr", "vlan", "metadata"}:
            continue
        if hasattr(dev, key):
            setattr(dev, key, value)
    if "metadata" in data and data["metadata"] is not None:
        dev.metadata_json = data["metadata"]
    if "parent_device_id" in data and old_parent != dev.parent_device_id:
        # Remove old auto-parent links and create the new one if needed.
        for l in db.query(Link).filter(Link.target_device_id == dev.id, Link.discovery_method.in_(["parent", "csv_parent"])).all():
            db.delete(l)
        if dev.parent_device_id:
            if not db.query(Link).filter(Link.source_device_id == dev.parent_device_id, Link.target_device_id == dev.id).first():
                db.add(Link(id=new_id("link"), source_device_id=dev.parent_device_id, target_device_id=dev.id, link_type="uplink", status="UP", label="parent/upstream", discovery_method="parent"))
    audit(db, "update", "device", dev.id, f"Dispositivo actualizado: {dev.hostname}")
    db.commit()
    db.refresh(dev)
    return serialize_device(dev)

@app.patch("/api/devices/{device_id}/position")
def update_position(device_id: str, payload: PositionIn, db: Session = Depends(get_db)):
    dev = db.get(Device, device_id)
    if not dev:
        raise HTTPException(404, "Dispositivo no encontrado")
    dev.x_position = payload.x_position
    dev.y_position = payload.y_position
    audit(db, "move", "device", dev.id, f"Nodo movido: {dev.hostname}", {"x": payload.x_position, "y": payload.y_position})
    db.commit()
    return {"ok": True}

@app.post("/api/devices/{device_id}/duplicate")
def duplicate_device(device_id: str, db: Session = Depends(get_db)):
    dev = db.get(Device, device_id)
    if not dev:
        raise HTTPException(404, "Dispositivo no encontrado")
    base = f"{dev.hostname}-COPY"
    name = base
    n = 1
    while db.query(Device).filter(Device.site_id == DEFAULT_SITE_ID, Device.hostname == name).first():
        n += 1
        name = f"{base}-{n}"
    copy = Device(
        id=new_id("dev"), site_id=dev.site_id, segment_id=dev.segment_id, hostname=name, management_ip="",
        device_type=dev.device_type, icon=dev.icon, role=dev.role, tier=dev.tier, vendor=dev.vendor, model=dev.model,
        serial_number="", status=dev.status, is_main=False, is_perimeter=False, parent_device_id=dev.parent_device_id,
        x_position=(dev.x_position or 0) + 60 if dev.x_position is not None else None,
        y_position=(dev.y_position or 0) + 60 if dev.y_position is not None else None,
        metadata_json={"duplicated_from": dev.id},
    )
    db.add(copy)
    audit(db, "duplicate", "device", copy.id, f"Dispositivo duplicado: {dev.hostname} → {copy.hostname}")
    db.commit()
    return serialize_device(copy)

@app.post("/api/devices/bulk")
def bulk_update(payload: BulkPatch, db: Session = Depends(get_db)):
    if not payload.ids:
        raise HTTPException(400, "No hay dispositivos seleccionados")
    updated = 0
    parent_changes = 0
    for device_id in payload.ids:
        dev = db.get(Device, device_id)
        if not dev:
            continue
        old_parent = dev.parent_device_id
        segment_id, data = validate_device_payload(db, payload.patch, device_id)
        if segment_id is not None:
            dev.segment_id = segment_id
        for key, value in data.items():
            if key in {"hostname", "management_ip", "segment_name", "cidr", "vlan", "metadata"}:
                continue
            if hasattr(dev, key) and value is not None:
                setattr(dev, key, value)
        if "parent_device_id" in data and old_parent != dev.parent_device_id:
            parent_changes += 1
            for l in db.query(Link).filter(Link.target_device_id == dev.id, Link.discovery_method.in_(["parent", "csv_parent", "bulk_parent"])).all():
                db.delete(l)
            if dev.parent_device_id:
                if not db.query(Link).filter(Link.source_device_id == dev.parent_device_id, Link.target_device_id == dev.id, Link.link_type == "uplink").first():
                    db.add(Link(
                        id=new_id("link"),
                        source_device_id=dev.parent_device_id,
                        target_device_id=dev.id,
                        link_type="uplink",
                        status="UP",
                        label="parent/upstream masivo",
                        discovery_method="bulk_parent",
                    ))
        updated += 1
    audit(db, "bulk_update", "device", "", f"Edición masiva: {updated} dispositivos; parent actualizado en {parent_changes}")
    db.commit()
    return {"updated": updated, "parent_changes": parent_changes, "state": state_payload(db)}

@app.post("/api/devices/bulk-relate")
def bulk_relate(payload: BulkRelationIn, db: Session = Depends(get_db)):
    if not payload.ids:
        raise HTTPException(400, "No hay dispositivos seleccionados")
    target = db.get(Device, payload.target_device_id)
    if not target:
        raise HTTPException(400, "El equipo principal / destino no existe")
    try:
        link_type = clean_link_type(payload.link_type)
        status = clean_status(payload.status)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if payload.direction not in {"target_to_selected", "selected_to_target"}:
        raise HTTPException(400, "Dirección inválida")

    created = 0
    skipped = 0
    parent_updates = 0
    processed: List[str] = []
    for device_id in payload.ids:
        if device_id == payload.target_device_id:
            skipped += 1
            continue
        dev = db.get(Device, device_id)
        if not dev:
            skipped += 1
            continue
        if payload.direction == "target_to_selected":
            source_id, target_id = payload.target_device_id, device_id
            if payload.set_parent and dev.parent_device_id != payload.target_device_id:
                for l in db.query(Link).filter(Link.target_device_id == dev.id, Link.discovery_method.in_(["parent", "csv_parent", "bulk_parent"])).all():
                    db.delete(l)
                dev.parent_device_id = payload.target_device_id
                parent_updates += 1
        else:
            source_id, target_id = device_id, payload.target_device_id

        duplicate = db.query(Link).filter(
            Link.source_device_id == source_id,
            Link.target_device_id == target_id,
            Link.link_type == link_type,
        ).first()
        if duplicate:
            skipped += 1
        else:
            db.add(Link(
                id=new_id("link"),
                source_device_id=source_id,
                target_device_id=target_id,
                link_type=link_type,
                status=status,
                label=payload.label or "relación masiva",
                discovery_method="bulk_relation",
                metadata_json={"bulk_relation": True, "principal_device_id": payload.target_device_id},
            ))
            created += 1
        processed.append(device_id)

    audit(db, "bulk_relate", "link", "", f"Relación masiva con {target.hostname}: {created} creadas, {skipped} omitidas, {parent_updates} parent actualizados", {"target_device_id": payload.target_device_id, "processed": processed})
    db.commit()
    return {"created": created, "skipped": skipped, "parent_updates": parent_updates, "state": state_payload(db)}

@app.post("/api/devices/bulk-delete")
def bulk_delete(ids: List[str], db: Session = Depends(get_db)):
    count = 0
    for device_id in ids:
        dev = db.get(Device, device_id)
        if dev:
            db.delete(dev)
            count += 1
    audit(db, "bulk_delete", "device", "", f"Eliminación masiva: {count} dispositivos")
    db.commit()
    return {"deleted": count, "state": state_payload(db)}

@app.delete("/api/devices/{device_id}")
def delete_device(device_id: str, db: Session = Depends(get_db)):
    dev = db.get(Device, device_id)
    if not dev:
        raise HTTPException(404, "Dispositivo no encontrado")
    name = dev.hostname
    # SQLAlchemy cascade handles links due to FK; clean dependencies manually.
    for dep in db.query(Dependency).filter(or_(Dependency.source_id == device_id, Dependency.target_id == device_id)).all():
        db.delete(dep)
    db.delete(dev)
    audit(db, "delete", "device", device_id, f"Dispositivo eliminado: {name}")
    db.commit()
    return {"ok": True}

# -----------------------------
# Interfaces
# -----------------------------

def validate_interface_payload(db: Session, payload: InterfaceIn, interface_id: Optional[str] = None) -> Dict[str, Any]:
    data = payload.model_dump(exclude_unset=True)
    if not db.get(Device, data.get("device_id")):
        raise HTTPException(400, "Dispositivo de la interfaz no existe")
    data["name"] = (data.get("name") or "").strip()
    if not data["name"]:
        raise HTTPException(400, "Nombre de interfaz requerido")
    if data.get("ip_address"):
        try:
            data["ip_address"] = validate_ip(data.get("ip_address") or "")
        except ValueError as exc:
            raise HTTPException(400, str(exc))
    if "vlan" in data:
        try:
            data["vlan"] = validate_vlan(data.get("vlan"))
        except ValueError as exc:
            raise HTTPException(400, str(exc))
    if data.get("status"):
        try:
            data["status"] = clean_status(data.get("status") or "UNKNOWN")
        except ValueError as exc:
            raise HTTPException(400, str(exc))
    q = db.query(Interface).filter(Interface.device_id == data["device_id"], Interface.name == data["name"])
    if interface_id:
        q = q.filter(Interface.id != interface_id)
    if q.first():
        raise HTTPException(409, "La interfaz ya existe para ese dispositivo")
    return data

@app.post("/api/interfaces")
def create_interface(payload: InterfaceIn, db: Session = Depends(get_db)):
    data = validate_interface_payload(db, payload)
    intf = Interface(id=new_id("if"), **data)
    db.add(intf)
    audit(db, "create", "interface", intf.id, f"Interfaz creada: {data['name']}")
    db.commit()
    return serialize_interface(intf)

@app.patch("/api/interfaces/{interface_id}")
def update_interface(interface_id: str, payload: InterfaceIn, db: Session = Depends(get_db)):
    intf = db.get(Interface, interface_id)
    if not intf:
        raise HTTPException(404, "Interfaz no encontrada")
    data = validate_interface_payload(db, payload, interface_id)
    for k, v in data.items():
        if hasattr(intf, k):
            setattr(intf, k, v)
    audit(db, "update", "interface", intf.id, f"Interfaz actualizada: {intf.name}")
    db.commit()
    return serialize_interface(intf)

@app.delete("/api/interfaces/{interface_id}")
def delete_interface(interface_id: str, db: Session = Depends(get_db)):
    intf = db.get(Interface, interface_id)
    if not intf:
        raise HTTPException(404, "Interfaz no encontrada")
    db.delete(intf)
    audit(db, "delete", "interface", interface_id, f"Interfaz eliminada: {intf.name}")
    db.commit()
    return {"ok": True}

# -----------------------------
# Links, segments, services, dependencies
# -----------------------------

@app.post("/api/links")
def create_link(payload: LinkIn, db: Session = Depends(get_db)):
    if payload.source_device_id == payload.target_device_id:
        raise HTTPException(400, "No se permite una relación hacia el mismo dispositivo")
    if not db.get(Device, payload.source_device_id) or not db.get(Device, payload.target_device_id):
        raise HTTPException(400, "Origen o destino no existe")
    try:
        payload.link_type = clean_link_type(payload.link_type)
        payload.status = clean_status(payload.status)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    duplicate = db.query(Link).filter(Link.source_device_id == payload.source_device_id, Link.target_device_id == payload.target_device_id, Link.source_interface == payload.source_interface, Link.target_interface == payload.target_interface, Link.link_type == payload.link_type).first()
    if duplicate:
        raise HTTPException(409, "Relación duplicada")
    meta = dict(payload.metadata or {})
    if payload.link_group:
        meta["link_group"] = payload.link_group.strip()
    if payload.link_role:
        meta["link_role"] = payload.link_role.strip()
    link = Link(id=new_id("link"), **payload.model_dump(exclude={"metadata", "link_group", "link_role"}), metadata_json=meta)
    db.add(link)
    audit(db, "create", "link", link.id, "Relación creada", meta)
    db.commit()
    return serialize_link(link)

@app.patch("/api/links/{link_id}")
def update_link(link_id: str, payload: LinkIn, db: Session = Depends(get_db)):
    link = db.get(Link, link_id)
    if not link:
        raise HTTPException(404, "Relación no encontrada")
    data = payload.model_dump()
    try:
        data["link_type"] = clean_link_type(data["link_type"])
        data["status"] = clean_status(data["status"])
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    meta = dict(data.get("metadata") or {})
    if data.get("link_group"):
        meta["link_group"] = str(data.get("link_group") or "").strip()
    else:
        meta.pop("link_group", None)
    if data.get("link_role"):
        meta["link_role"] = str(data.get("link_role") or "").strip()
    else:
        meta.pop("link_role", None)
    for key, value in data.items():
        if key in {"metadata", "link_group", "link_role"}:
            continue
        if hasattr(link, key):
            setattr(link, key, value)
    link.metadata_json = meta
    audit(db, "update", "link", link.id, "Relación actualizada", meta)
    db.commit()
    return serialize_link(link)

@app.delete("/api/links/{link_id}")
def delete_link(link_id: str, db: Session = Depends(get_db)):
    link = db.get(Link, link_id)
    if not link:
        raise HTTPException(404, "Relación no encontrada")
    db.delete(link)
    audit(db, "delete", "link", link_id, "Relación eliminada")
    db.commit()
    return {"ok": True}

@app.post("/api/segments")
def create_segment(payload: SegmentIn, db: Session = Depends(get_db)):
    try:
        seg = get_or_create_segment(db, payload.name, payload.cidr, payload.vlan)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    seg.zone_type = payload.zone_type
    seg.color = payload.color
    seg.main_device_id = payload.main_device_id
    seg.perimeter_device_id = payload.perimeter_device_id
    seg.collapsed = payload.collapsed
    if payload.x_position is not None:
        seg.x_position = payload.x_position
    if payload.y_position is not None:
        seg.y_position = payload.y_position
    audit(db, "upsert", "segment", seg.id, f"Segmento guardado: {seg.name}")
    db.commit()
    return serialize_segment(seg)

@app.patch("/api/segments/{segment_id}")
def patch_segment(segment_id: str, payload: SegmentPatch, db: Session = Depends(get_db)):
    seg = db.get(Segment, segment_id)
    if not seg:
        raise HTTPException(404, "Segmento no encontrado")
    data = payload.model_dump(exclude_unset=True)
    if "name" in data and data["name"] is not None:
        data["name"] = data["name"].strip()
        if not data["name"]:
            raise HTTPException(400, "Nombre de segmento vacío")
        q = db.query(Segment).filter(Segment.site_id == seg.site_id, Segment.name == data["name"], Segment.id != segment_id)
        if q.first():
            raise HTTPException(409, "Segmento duplicado")
    if data.get("cidr"):
        try:
            data["cidr"] = validate_cidr(data["cidr"])
        except ValueError:
            raise HTTPException(400, "CIDR inválido")
    if "vlan" in data:
        try:
            data["vlan"] = validate_vlan(data.get("vlan"))
        except ValueError as exc:
            raise HTTPException(400, str(exc))
    for k, v in data.items():
        if hasattr(seg, k):
            setattr(seg, k, v)
    audit(db, "update", "segment", seg.id, f"Segmento actualizado: {seg.name}")
    db.commit()
    return serialize_segment(seg)

@app.patch("/api/segments/{segment_id}/position")
def update_segment_position(segment_id: str, payload: PositionIn, db: Session = Depends(get_db)):
    seg = db.get(Segment, segment_id)
    if not seg:
        raise HTTPException(404, "Segmento no encontrado")
    seg.x_position = payload.x_position
    seg.y_position = payload.y_position
    audit(db, "move", "segment", seg.id, f"Segmento movido: {seg.name}", {"x": payload.x_position, "y": payload.y_position})
    db.commit()
    return {"ok": True}

@app.delete("/api/segments/{segment_id}")
def delete_segment(segment_id: str, db: Session = Depends(get_db)):
    seg = db.get(Segment, segment_id)
    if not seg:
        raise HTTPException(404, "Segmento no encontrado")
    db.delete(seg)
    audit(db, "delete", "segment", segment_id, f"Segmento eliminado: {seg.name}")
    db.commit()
    return {"ok": True}

@app.post("/api/services")
def create_service(payload: ServiceIn, db: Session = Depends(get_db)):
    if not payload.name.strip():
        raise HTTPException(400, "Nombre del servicio requerido")
    svc = db.query(Service).filter(Service.workspace_id == DEFAULT_WORKSPACE_ID, Service.name == payload.name).first()
    if svc:
        svc.service_type = payload.service_type
        svc.criticality = payload.criticality
        svc.status = payload.status
        svc.owner = payload.owner
        svc.description = payload.description
        svc.metadata_json = payload.metadata
    else:
        svc = Service(id=new_id("svc"), workspace_id=DEFAULT_WORKSPACE_ID, name=payload.name, service_type=payload.service_type, criticality=payload.criticality, status=payload.status, owner=payload.owner, description=payload.description, metadata_json=payload.metadata)
        db.add(svc)
    audit(db, "upsert", "service", svc.id, f"Servicio guardado: {svc.name}")
    db.commit()
    return serialize_service(svc)

@app.delete("/api/services/{service_id}")
def delete_service(service_id: str, db: Session = Depends(get_db)):
    svc = db.get(Service, service_id)
    if not svc:
        raise HTTPException(404, "Servicio no encontrado")
    name = svc.name
    for dep in db.query(Dependency).filter(or_(Dependency.source_id == service_id, Dependency.target_id == service_id)).all():
        db.delete(dep)
    db.delete(svc)
    audit(db, "delete", "service", service_id, f"Servicio eliminado: {name}")
    db.commit()
    return {"ok": True}

@app.post("/api/dependencies")
def create_dependency(payload: DependencyIn, db: Session = Depends(get_db)):
    if payload.source_type not in ENTITY_TYPES or payload.target_type not in ENTITY_TYPES:
        raise HTTPException(400, "Tipo de entidad inválido")
    if payload.source_id == payload.target_id and payload.source_type == payload.target_type:
        raise HTTPException(400, "No se permite dependencia hacia sí mismo")
    if not entity_name(db, payload.source_type, payload.source_id) or not entity_name(db, payload.target_type, payload.target_id):
        raise HTTPException(400, "Entidad origen o destino no existe")
    duplicate = db.query(Dependency).filter(Dependency.source_type == payload.source_type, Dependency.source_id == payload.source_id, Dependency.target_type == payload.target_type, Dependency.target_id == payload.target_id, Dependency.dependency_type == payload.dependency_type).first()
    if duplicate:
        raise HTTPException(409, "Dependencia duplicada")
    dep = Dependency(id=new_id("dep"), **payload.model_dump())
    db.add(dep)
    audit(db, "create", "dependency", dep.id, "Dependencia creada")
    db.commit()
    return serialize_dependency(dep, db)

@app.delete("/api/dependencies/{dependency_id}")
def delete_dependency(dependency_id: str, db: Session = Depends(get_db)):
    dep = db.get(Dependency, dependency_id)
    if not dep:
        raise HTTPException(404, "Dependencia no encontrada")
    db.delete(dep)
    audit(db, "delete", "dependency", dependency_id, "Dependencia eliminada")
    db.commit()
    return {"ok": True}

# -----------------------------
# Imports / Exports
# -----------------------------

async def read_upload_text(file: UploadFile) -> str:
    raw = await file.read()
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"Archivo demasiado grande. Máximo permitido: {MAX_UPLOAD_BYTES // (1024 * 1024)} MB")
    for enc in ["utf-8-sig", "utf-8", "latin-1"]:
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="ignore")


def reject_unsafe_xml(text: str):
    head = text[:2048].lower()
    if "<!doctype" in head or "<!entity" in head:
        raise HTTPException(400, "XML rechazado: no se permiten DOCTYPE ni ENTITY")


def parse_csv_upload(text: str) -> List[dict]:
    """Parse CSV files created by Excel, LibreOffice or plain editors.

    The original importer assumed comma-separated files only. Some users opened
    the template in spreadsheet software and saved it using semicolons, which
    could leave the backend with malformed rows. This parser normalizes headers
    and supports comma, semicolon, tab and pipe delimiters.
    """
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    normalized_rows: List[dict] = []
    for row in reader:
        clean = {}
        for key, value in (row or {}).items():
            if key is None:
                continue
            norm_key = str(key).replace("\ufeff", "").strip().lower()
            clean[norm_key] = str(value or "").strip()
        if any(v for v in clean.values()):
            normalized_rows.append(clean)
    return normalized_rows


def rollback_and_400(db: Session, message: str, errors: Optional[list] = None):
    db.rollback()
    raise HTTPException(status_code=400, detail={"message": message, "errors": errors or []})


@app.post("/api/import/devices")
async def import_devices(file: UploadFile = File(...), merge: bool = True, db: Session = Depends(get_db)):
    text = await read_upload_text(file)
    rows = parse_csv_upload(text)
    if not rows:
        raise HTTPException(400, "El archivo CSV está vacío o no tiene encabezados válidos")

    created, updated, errors = 0, 0, []
    pending_parents: List[Tuple[str, str]] = []
    changed_device_names: List[str] = []

    try:
        ensure_defaults(db)
        for idx, row in enumerate(rows, start=2):
            try:
                hostname = (row.get("hostname") or row.get("host") or row.get("name") or "").strip()
                if not hostname:
                    errors.append({"row": idx, "message": "hostname vacío"})
                    continue

                ip = validate_ip(row.get("ip") or row.get("management_ip") or "")
                seg_name = (row.get("segment") or row.get("segmento") or row.get("network") or "").strip()
                if not seg_name:
                    errors.append({"row": idx, "message": "segmento vacío"})
                    continue

                dev_type = clean_type(row.get("type") or row.get("device_type") or "unknown")
                status = clean_status(row.get("status") or "UNKNOWN")
                vlan = validate_vlan(int_or_none(row.get("vlan")))
                cidr = validate_cidr(row.get("cidr") or "")
                seg = get_or_create_segment(db, seg_name, cidr, vlan)

                dev_by_hostname = device_by_name_or_ip(db, hostname, "")
                dev_by_ip = device_by_name_or_ip(db, "", ip) if ip else None
                dev = dev_by_hostname or dev_by_ip

                if dev_by_hostname and dev_by_ip and dev_by_hostname.id != dev_by_ip.id:
                    errors.append({"row": idx, "message": f"conflicto: hostname {hostname} e IP {ip} pertenecen a equipos distintos"})
                    continue
                if dev and not merge:
                    errors.append({"row": idx, "message": "dispositivo duplicado"})
                    continue

                if not dev:
                    dev = Device(id=new_id("dev"), site_id=DEFAULT_SITE_ID, hostname=hostname)
                    db.add(dev)
                    created += 1
                else:
                    updated += 1

                dev.hostname = hostname
                dev.segment_id = seg.id
                dev.management_ip = ip
                dev.device_type = dev_type
                dev.icon = (row.get("icon") or "auto").strip() or "auto"
                dev.role = (row.get("role") or "host").strip() or "host"
                dev.tier = int_or_none(row.get("tier")) or infer_tier(dev.device_type, dev.role)
                dev.status = status
                dev.vendor = row.get("vendor") or ""
                dev.model = row.get("model") or ""
                dev.serial_number = row.get("serial_number") or row.get("serial") or ""
                dev.is_main = bool_value(row.get("is_main"))
                dev.is_perimeter = bool_value(row.get("is_perimeter"))
                dev.metadata_json = {"source": "devices_csv"}
                changed_device_names.append(hostname)

                parent_name = (row.get("parent") or row.get("upstream") or "").strip()
                if parent_name:
                    pending_parents.append((hostname, parent_name))
            except ValueError as exc:
                errors.append({"row": idx, "message": str(exc)})
            except SQLAlchemyError as exc:
                return rollback_and_400(db, f"Error de base de datos en fila {idx}: {exc.__class__.__name__}", errors)
            except Exception as exc:
                errors.append({"row": idx, "message": str(exc)})

        # Force INSERT/UPDATE of devices before resolving parent links, so Postgres
        # can validate foreign keys in the correct order.
        db.flush()

        for child_name, parent_name in pending_parents:
            child = device_by_name_or_ip(db, child_name, "")
            parent = device_by_name_or_ip(db, parent_name, "")
            if child and parent:
                if child.id == parent.id:
                    errors.append({"row": "parent", "message": f"parent inválido: {child_name} no puede depender de sí mismo"})
                    continue
                child.parent_device_id = parent.id
                if not db.query(Link).filter(Link.source_device_id == parent.id, Link.target_device_id == child.id).first():
                    db.add(Link(id=new_id("link"), source_device_id=parent.id, target_device_id=child.id, link_type="uplink", status="UP", label="parent/upstream", discovery_method="csv_parent"))
            else:
                errors.append({"row": "parent", "message": f"parent inexistente: {child_name} -> {parent_name}"})

        audit(db, "import", "devices", "", f"Importación devices.csv: {created} creados, {updated} actualizados", {"errors": errors})
        db.commit()
    except IntegrityError as exc:
        return rollback_and_400(db, "No se pudo importar por conflicto de datos duplicados o relación inválida", errors + [{"row": "commit", "message": str(exc.orig)}])
    except SQLAlchemyError as exc:
        return rollback_and_400(db, "No se pudo importar por error de base de datos", errors + [{"row": "commit", "message": str(exc)}])

    return {"created": created, "updated": updated, "errors": errors, "state": state_payload(db)}

@app.post("/api/import/interfaces")
async def import_interfaces(file: UploadFile = File(...), db: Session = Depends(get_db)):
    text = await read_upload_text(file)
    rows = parse_csv_upload(text)
    created, updated, errors = 0, 0, []
    for idx, row in enumerate(rows, start=2):
        try:
            device_name = (row.get("device") or row.get("hostname") or row.get("device_name") or "").strip()
            dev = device_by_name_or_ip(db, device_name, device_name)
            if not dev:
                errors.append({"row": idx, "message": f"dispositivo no encontrado: {device_name}"})
                continue
            name = (row.get("interface") or row.get("name") or row.get("port") or "").strip()
            if not name:
                errors.append({"row": idx, "message": "interfaz vacía"})
                continue
            vlan = validate_vlan(int_or_none(row.get("vlan")))
            ip = validate_ip(row.get("ip") or row.get("ip_address") or "")
            status = clean_status(row.get("status") or "UNKNOWN")
            intf = db.query(Interface).filter(Interface.device_id == dev.id, Interface.name == name).first()
            if not intf:
                intf = Interface(id=new_id("if"), device_id=dev.id, name=name)
                db.add(intf)
                created += 1
            else:
                updated += 1
            intf.ip_address = ip
            intf.mac_address = row.get("mac") or row.get("mac_address") or ""
            intf.vlan = vlan
            intf.zone = row.get("zone") or row.get("segment") or ""
            intf.status = status
            intf.speed = row.get("speed") or ""
            intf.description = row.get("description") or row.get("descripcion") or ""
        except Exception as exc:
            errors.append({"row": idx, "message": str(exc)})
    audit(db, "import", "interfaces", "", f"Importación interfaces.csv: {created} creadas, {updated} actualizadas", {"errors": errors})
    db.commit()
    return {"created": created, "updated": updated, "errors": errors, "state": state_payload(db)}

@app.post("/api/import/links")
async def import_links(file: UploadFile = File(...), db: Session = Depends(get_db)):
    text = await read_upload_text(file)
    rows = parse_csv_upload(text)
    created, errors = 0, []
    for idx, row in enumerate(rows, start=2):
        try:
            source_name = (row.get("source_device") or row.get("source") or "").strip()
            target_name = (row.get("target_device") or row.get("target") or "").strip()
            source = device_by_name_or_ip(db, source_name, "")
            target = device_by_name_or_ip(db, target_name, "")
            if not source or not target:
                errors.append({"row": idx, "message": f"origen o destino no encontrado: {source_name} -> {target_name}"})
                continue
            link_type = clean_link_type(row.get("link_type") or "physical_link")
            status = clean_status(row.get("status") or "UP")
            source_if = (row.get("source_interface") or row.get("source_port") or "").strip()
            target_if = (row.get("target_interface") or row.get("target_port") or "").strip()
            if source_if and not db.query(Interface).filter(Interface.device_id == source.id, Interface.name == source_if).first():
                db.add(Interface(id=new_id("if"), device_id=source.id, name=source_if, status="UNKNOWN", description="Creada automáticamente desde links.csv"))
            if target_if and not db.query(Interface).filter(Interface.device_id == target.id, Interface.name == target_if).first():
                db.add(Interface(id=new_id("if"), device_id=target.id, name=target_if, status="UNKNOWN", description="Creada automáticamente desde links.csv"))
            if db.query(Link).filter(Link.source_device_id == source.id, Link.target_device_id == target.id, Link.source_interface == source_if, Link.target_interface == target_if, Link.link_type == link_type).first():
                errors.append({"row": idx, "message": "relación duplicada"})
                continue
            meta = {}
            if row.get("link_group"):
                meta["link_group"] = row.get("link_group")
            if row.get("link_role"):
                meta["link_role"] = row.get("link_role")
            if row.get("notes"):
                meta["notes"] = row.get("notes")
            db.add(Link(id=new_id("link"), source_device_id=source.id, target_device_id=target.id, source_interface=source_if, target_interface=target_if, link_type=link_type, status=status, label=row.get("label") or "", discovery_method=row.get("discovery_method") or "csv", metadata_json=meta))
            created += 1
        except Exception as exc:
            errors.append({"row": idx, "message": str(exc)})
    audit(db, "import", "links", "", f"Importación links.csv: {created} creados", {"errors": errors})
    db.commit()
    return {"created": created, "errors": errors, "state": state_payload(db)}

@app.post("/api/import/dependencies")
async def import_dependencies(file: UploadFile = File(...), db: Session = Depends(get_db)):
    text = await read_upload_text(file)
    rows = list(csv.DictReader(io.StringIO(text)))
    created, errors = 0, []
    for idx, row in enumerate(rows, start=2):
        source_type = (row.get("source_type") or "").strip().lower()
        target_type = (row.get("target_type") or "").strip().lower()
        source_name = (row.get("source_name") or row.get("source") or "").strip()
        target_name = (row.get("target_name") or row.get("target") or "").strip()
        source_id = resolve_entity_id(db, source_type, source_name)
        target_id = resolve_entity_id(db, target_type, target_name)
        if not source_id or not target_id:
            errors.append({"row": idx, "message": "no se pudo resolver source/target"})
            continue
        if db.query(Dependency).filter(Dependency.source_type == source_type, Dependency.source_id == source_id, Dependency.target_type == target_type, Dependency.target_id == target_id).first():
            errors.append({"row": idx, "message": "dependencia duplicada"})
            continue
        db.add(Dependency(id=new_id("dep"), source_type=source_type, source_id=source_id, target_type=target_type, target_id=target_id, dependency_type=row.get("dependency_type") or "depends_on", criticality=row.get("criticality") or "medium"))
        created += 1
    audit(db, "import", "dependencies", "", f"Importación dependencies.csv: {created} creadas", {"errors": errors})
    db.commit()
    return {"created": created, "errors": errors, "state": state_payload(db)}

@app.post("/api/import/nmap")
async def import_nmap(file: UploadFile = File(...), db: Session = Depends(get_db)):
    xml_text = await read_upload_text(file)
    reject_unsafe_xml(xml_text)
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise HTTPException(400, f"XML Nmap inválido: {exc}") from exc
    created, updated, services_created = 0, 0, 0
    nmap_segment = get_or_create_segment(db, "Nmap Discovery", "", None)
    for host in root.findall("host"):
        status_el = host.find("status")
        host_status = (status_el.get("state") if status_el is not None else "unknown").upper()
        addr_el = host.find("address[@addrtype='ipv4']") or host.find("address")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")
        hostname = ""
        hn = host.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name", "")
        hostname = hostname or f"HOST-{ip.replace('.', '-')}"
        ports = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            ports.append({"port": port.get("portid"), "protocol": port.get("protocol"), "service": svc.get("name") if svc is not None else "", "product": svc.get("product") if svc is not None else "", "version": svc.get("version") if svc is not None else ""})
        dev = device_by_name_or_ip(db, hostname, ip)
        if not dev:
            dev = Device(id=new_id("dev"), site_id=DEFAULT_SITE_ID, segment_id=nmap_segment.id, hostname=hostname, management_ip=ip)
            db.add(dev)
            created += 1
        else:
            updated += 1
        dev.status = "UP" if host_status == "UP" else host_status
        dev.device_type = guess_type_from_ports(ports)
        dev.icon = "auto"
        dev.role = "host"
        dev.tier = infer_tier(dev.device_type, dev.role)
        meta = dev.metadata_json or {}
        meta["nmap_ports"] = ports
        meta["nmap_last_import"] = file.filename
        dev.metadata_json = meta
        db.flush()
        for p in ports:
            svc_name = f"{hostname}:{p.get('port')}/{p.get('protocol')} {p.get('service') or ''}".strip()
            svc = db.query(Service).filter(Service.workspace_id == DEFAULT_WORKSPACE_ID, Service.name == svc_name).first()
            if not svc:
                svc = Service(id=new_id("svc"), workspace_id=DEFAULT_WORKSPACE_ID, name=svc_name, service_type=p.get("service") or "port", criticality="medium", status="UP", description=f"Detectado por Nmap en {ip}", metadata_json=p)
                db.add(svc)
                db.flush()
                db.add(Dependency(id=new_id("dep"), source_type="service", source_id=svc.id, target_type="device", target_id=dev.id, dependency_type="runs_on", criticality="medium"))
                services_created += 1
    audit(db, "import", "nmap", "", f"Nmap XML importado: {created} creados, {updated} actualizados, {services_created} servicios")
    db.commit()
    return {"created": created, "updated": updated, "services_created": services_created, "state": state_payload(db)}

@app.get("/api/export/inventory.csv")
def export_inventory_csv(db: Session = Depends(get_db)):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["hostname", "ip", "type", "role", "tier", "segment", "cidr", "vlan", "is_main", "is_perimeter", "parent", "status", "vendor", "model"])
    segments = {s.id: s for s in db.query(Segment).all()}
    devices = {d.id: d for d in db.query(Device).all()}
    for d in db.query(Device).order_by(Device.hostname.asc()).all():
        seg = segments.get(d.segment_id)
        parent = devices.get(d.parent_device_id)
        writer.writerow([d.hostname, d.management_ip, d.device_type, d.role, d.tier, seg.name if seg else "", seg.cidr if seg else "", seg.vlan if seg else "", d.is_main, d.is_perimeter, parent.hostname if parent else "", d.status, d.vendor, d.model])
    return {"filename": f"netmap-inventory-{APP_VERSION}.csv", "content": output.getvalue()}

@app.post("/api/import/project")
def import_project(snapshot: Dict[str, Any], db: Session = Depends(get_db)):
    if not snapshot.get("devices") and not snapshot.get("segments"):
        raise HTTPException(400, "El archivo JSON no contiene datos de mapa válidos.")
    for model in [Dependency, Service, Link, Interface, Device, Segment, AuditLog]:
        db.execute(delete(model))
    db.commit()
    ensure_defaults(db)
    for s in snapshot.get("segments", []):
        db.add(Segment(id=s["id"], site_id=s.get("site_id") or DEFAULT_SITE_ID, name=s["name"], cidr=s.get("cidr") or "", vlan=s.get("vlan"), zone_type=s.get("zone_type") or "", main_device_id=s.get("main_device_id"), perimeter_device_id=s.get("perimeter_device_id"), color=s.get("color") or "", collapsed=bool(s.get("collapsed")), x_position=s.get("x_position"), y_position=s.get("y_position")))
    db.flush()
    for d in snapshot.get("devices", []):
        db.add(Device(id=d["id"], site_id=d.get("site_id") or DEFAULT_SITE_ID, segment_id=d.get("segment_id"), hostname=d["hostname"], management_ip=d.get("management_ip") or "", device_type=d.get("device_type") or "unknown", icon=d.get("icon") or "auto", role=d.get("role") or "host", tier=d.get("tier") or 6, vendor=d.get("vendor") or "", model=d.get("model") or "", serial_number=d.get("serial_number") or "", status=d.get("status") or "UNKNOWN", is_main=bool(d.get("is_main")), is_perimeter=bool(d.get("is_perimeter")), parent_device_id=d.get("parent_device_id"), x_position=d.get("x_position"), y_position=d.get("y_position"), metadata_json=d.get("metadata") or {}))
    db.flush()
    for l in snapshot.get("links", []):
        db.add(Link(id=l["id"], source_device_id=l["source_device_id"], target_device_id=l["target_device_id"], source_interface=l.get("source_interface") or "", target_interface=l.get("target_interface") or "", link_type=l.get("link_type") or "physical_link", status=l.get("status") or "UNKNOWN", label=l.get("label") or "", discovery_method=l.get("discovery_method") or "restore", metadata_json=l.get("metadata") or {}))
    for s in snapshot.get("services", []):
        db.add(Service(id=s["id"], workspace_id=s.get("workspace_id") or DEFAULT_WORKSPACE_ID, name=s["name"], service_type=s.get("service_type") or "", criticality=s.get("criticality") or "medium", status=s.get("status") or "UNKNOWN", owner=s.get("owner") or "", description=s.get("description") or "", metadata_json=s.get("metadata") or {}))
    for dep in snapshot.get("dependencies", []):
        db.add(Dependency(id=dep["id"], source_type=dep["source_type"], source_id=dep["source_id"], target_type=dep["target_type"], target_id=dep["target_id"], dependency_type=dep.get("dependency_type") or "depends_on", criticality=dep.get("criticality") or "medium"))
    audit(db, "restore", "project", "import", "Proyecto importado desde archivo JSON")
    db.commit()
    return state_payload(db)

# -----------------------------
# Impact, paths, versions
# -----------------------------

def impact_tier(device: Device) -> int:
    text = " ".join([device.hostname or "", device.device_type or "", device.icon or "", device.role or ""]).lower()
    if "internet" in text:
        return 0
    if device.tier is not None:
        return device.tier
    return infer_tier(device.device_type, device.role)


def add_support_edge(graph: Dict[Tuple[str, str], List[dict]], source_type: str, source_id: str, target_type: str, target_id: str, via: str, edge_id: str = "", criticality: str = "medium"):
    if not source_id or not target_id or (source_type == target_type and source_id == target_id):
        return
    graph.setdefault((source_type, source_id), []).append({
        "type": target_type,
        "id": target_id,
        "via": via,
        "edge_id": edge_id,
        "criticality": criticality or "medium",
    })


def oriented_link_devices(link: Link, devices: Dict[str, Device]) -> Tuple[Optional[str], Optional[str], str]:
    source = devices.get(link.source_device_id)
    target = devices.get(link.target_device_id)
    if not source or not target:
        return None, None, "link"
    if target.parent_device_id == source.id:
        return source.id, target.id, "parent/upstream"
    if source.parent_device_id == target.id:
        return target.id, source.id, "parent/upstream"
    source_tier = impact_tier(source)
    target_tier = impact_tier(target)
    if source_tier < target_tier:
        return source.id, target.id, link.link_type or "link"
    if target_tier < source_tier:
        return target.id, source.id, link.link_type or "link"
    if source.is_main or source.is_perimeter:
        return source.id, target.id, link.link_type or "link"
    if target.is_main or target.is_perimeter:
        return target.id, source.id, link.link_type or "link"
    return source.id, target.id, link.link_type or "link"


def build_support_graph(db: Session) -> Tuple[Dict[Tuple[str, str], List[dict]], Dict[str, Device]]:
    graph: Dict[Tuple[str, str], List[dict]] = {}
    devices = {d.id: d for d in db.query(Device).all()}
    device_downstream_ids = set()

    for link in db.query(Link).all():
        upstream_id, downstream_id, via = oriented_link_devices(link, devices)
        if upstream_id and downstream_id:
            add_support_edge(graph, "device", upstream_id, "device", downstream_id, via, link.id, "high" if link.link_type in {"uplink", "internet_link", "firewall_link"} else "medium")
            device_downstream_ids.add(downstream_id)

    for dev in devices.values():
        if dev.parent_device_id and dev.parent_device_id in devices:
            add_support_edge(graph, "device", dev.parent_device_id, "device", dev.id, "parent/upstream", "", "high")
            device_downstream_ids.add(dev.id)

    internet_roots = sorted([d for d in devices.values() if impact_tier(d) == 0], key=lambda d: d.hostname)
    if internet_roots:
        internet = internet_roots[0]
        for dev in devices.values():
            if dev.id != internet.id and dev.id not in device_downstream_ids and impact_tier(dev) > 0:
                add_support_edge(graph, "device", internet.id, "device", dev.id, "internet_root", "", "high")

    for dep in db.query(Dependency).all():
        add_support_edge(graph, dep.target_type, dep.target_id, dep.source_type, dep.source_id, dep.dependency_type or "depends_on", dep.id, dep.criticality or "medium")

    for seg in db.query(Segment).all():
        segment_gateways = {seg.main_device_id, seg.perimeter_device_id}
        for dev in devices.values():
            if dev.segment_id != seg.id:
                continue
            if dev.id in segment_gateways or dev.is_main or dev.is_perimeter:
                add_support_edge(graph, "device", dev.id, "segment", seg.id, "segment_gateway", "", "high")
            add_support_edge(graph, "segment", seg.id, "device", dev.id, "segment_member", "", "medium")

    return graph, devices


def expand_downstream(db: Session, root_type: str, root_id: str):
    graph, _devices = build_support_graph(db)
    affected_devices, affected_services, affected_segments = set(), set(), set()
    visited = set()
    impact_edges = []
    root_key = (root_type, root_id)
    queue: List[Tuple[str, str, List[dict]]] = [(root_type, root_id, [{"type": root_type, "id": root_id, "name": entity_name(db, root_type, root_id)}])]
    paths = []

    while queue:
        entity_type, entity_id, path = queue.pop(0)
        key = (entity_type, entity_id)
        if key in visited:
            continue
        visited.add(key)

        for edge in graph.get(key, []):
            next_key = (edge["type"], edge["id"])
            if next_key == root_key:
                continue
            if edge["type"] == "device":
                affected_devices.add(edge["id"])
            elif edge["type"] == "service":
                affected_services.add(edge["id"])
            elif edge["type"] == "segment":
                affected_segments.add(edge["id"])

            npath = path + [{
                "type": edge["type"],
                "id": edge["id"],
                "name": entity_name(db, edge["type"], edge["id"]),
                "via": edge["via"],
                "criticality": edge["criticality"],
            }]
            paths.append(npath)
            impact_edges.append({
                "source_type": entity_type,
                "source_id": entity_id,
                "target_type": edge["type"],
                "target_id": edge["id"],
                "via": edge["via"],
                "edge_id": edge.get("edge_id") or "",
                "criticality": edge["criticality"],
            })
            if next_key not in visited:
                queue.append((edge["type"], edge["id"], npath))

    return affected_devices, affected_services, affected_segments, paths, impact_edges

@app.get("/api/impact/{device_id}")
def impact(device_id: str, db: Session = Depends(get_db)):
    root = db.get(Device, device_id)
    if not root:
        raise HTTPException(404, "Dispositivo no encontrado")
    affected_devices, affected_services, affected_segments, paths, impact_edges = expand_downstream(db, "device", device_id)
    devices = [serialize_device(d) for d in db.query(Device).filter(Device.id.in_(affected_devices)).order_by(Device.tier.asc(), Device.hostname.asc()).all()] if affected_devices else []
    services = [serialize_service(s) for s in db.query(Service).filter(Service.id.in_(affected_services)).order_by(Service.criticality.desc(), Service.name.asc()).all()] if affected_services else []
    segments = [serialize_segment(s) for s in db.query(Segment).filter(Segment.id.in_(affected_segments)).order_by(Segment.name.asc()).all()] if affected_segments else []
    critical_services = [s for s in services if s.get("criticality") in {"high", "critical"}]
    severity = "critical" if len(critical_services) >= 1 or len(services) >= 3 or len(devices) >= 10 else "high" if services or len(devices) >= 3 or segments else "medium"
    blast_radius = {
        "devices": len(devices),
        "services": len(services),
        "segments": len(segments),
        "links": len([e for e in impact_edges if e.get("edge_id")]),
        "paths": len(paths),
        "critical_services": len(critical_services),
    }
    summary = f"{blast_radius['devices']} dispositivos, {blast_radius['services']} servicios y {blast_radius['segments']} segmentos afectados"
    return {
        "root_cause": serialize_device(root),
        "affected_devices": devices,
        "affected_services": services,
        "affected_segments": segments,
        "paths": paths[:50],
        "impact_edges": impact_edges,
        "blast_radius": blast_radius,
        "severity": severity,
        "summary": summary,
    }

@app.post("/api/versions")
def save_version(payload: VersionIn, db: Session = Depends(get_db)):
    snapshot = state_payload(db)
    version = DiagramVersion(id=new_id("ver"), workspace_id=DEFAULT_WORKSPACE_ID, name=payload.name, version=payload.version, snapshot_json=snapshot, created_by=current_username.get("system"))
    db.add(version)
    audit(db, "create", "diagram_version", version.id, f"Versión guardada: {payload.name} {payload.version}")
    db.commit()
    return serialize_version(version)

@app.get("/api/versions")
def list_versions(db: Session = Depends(get_db)):
    return [serialize_version(v) for v in db.query(DiagramVersion).order_by(DiagramVersion.created_at.desc()).all()]

@app.get("/api/versions/{version_id}")
def get_version(version_id: str, db: Session = Depends(get_db)):
    version = db.get(DiagramVersion, version_id)
    if not version:
        raise HTTPException(404, "Versión no encontrada")
    data = serialize_version(version)
    data["snapshot"] = version.snapshot_json or {}
    return data

@app.post("/api/versions/{version_id}/restore")
def restore_version(version_id: str, db: Session = Depends(get_db)):
    version = db.get(DiagramVersion, version_id)
    if not version:
        raise HTTPException(404, "Versión no encontrada")
    snapshot = version.snapshot_json or {}
    for model in [Dependency, Service, Link, Interface, Device, Segment, AuditLog]:
        db.execute(delete(model))
    db.commit()
    ensure_defaults(db)
    for s in snapshot.get("segments", []):
        db.add(Segment(id=s["id"], site_id=s.get("site_id") or DEFAULT_SITE_ID, name=s["name"], cidr=s.get("cidr") or "", vlan=s.get("vlan"), zone_type=s.get("zone_type") or "", main_device_id=s.get("main_device_id"), perimeter_device_id=s.get("perimeter_device_id"), color=s.get("color") or "", collapsed=bool(s.get("collapsed")), x_position=s.get("x_position"), y_position=s.get("y_position")))
    db.flush()
    for d in snapshot.get("devices", []):
        db.add(Device(id=d["id"], site_id=d.get("site_id") or DEFAULT_SITE_ID, segment_id=d.get("segment_id"), hostname=d["hostname"], management_ip=d.get("management_ip") or "", device_type=d.get("device_type") or "unknown", icon=d.get("icon") or "auto", role=d.get("role") or "host", tier=d.get("tier") or 6, vendor=d.get("vendor") or "", model=d.get("model") or "", serial_number=d.get("serial_number") or "", status=d.get("status") or "UNKNOWN", is_main=bool(d.get("is_main")), is_perimeter=bool(d.get("is_perimeter")), parent_device_id=d.get("parent_device_id"), x_position=d.get("x_position"), y_position=d.get("y_position"), metadata_json=d.get("metadata") or {}))
    db.flush()
    for l in snapshot.get("links", []):
        db.add(Link(id=l["id"], source_device_id=l["source_device_id"], target_device_id=l["target_device_id"], source_interface=l.get("source_interface") or "", target_interface=l.get("target_interface") or "", link_type=l.get("link_type") or "physical_link", status=l.get("status") or "UNKNOWN", label=l.get("label") or "", discovery_method=l.get("discovery_method") or "restore", metadata_json=l.get("metadata") or {}))
    for s in snapshot.get("services", []):
        db.add(Service(id=s["id"], workspace_id=s.get("workspace_id") or DEFAULT_WORKSPACE_ID, name=s["name"], service_type=s.get("service_type") or "", criticality=s.get("criticality") or "medium", status=s.get("status") or "UNKNOWN", owner=s.get("owner") or "", description=s.get("description") or "", metadata_json=s.get("metadata") or {}))
    for dep in snapshot.get("dependencies", []):
        db.add(Dependency(id=dep["id"], source_type=dep["source_type"], source_id=dep["source_id"], target_type=dep["target_type"], target_id=dep["target_id"], dependency_type=dep.get("dependency_type") or "depends_on", criticality=dep.get("criticality") or "medium"))
    audit(db, "restore", "diagram_version", version.id, f"Versión restaurada: {version.name} {version.version}")
    db.commit()
    return state_payload(db)

@app.get("/api/versions/compare/{a_id}/{b_id}")
def compare_versions(a_id: str, b_id: str, db: Session = Depends(get_db)):
    a = db.get(DiagramVersion, a_id)
    b = db.get(DiagramVersion, b_id)
    if not a or not b:
        raise HTTPException(404, "Versión no encontrada")
    sa = a.snapshot_json or {}
    sb = b.snapshot_json or {}
    def ids(snapshot, key): return {x.get("id") for x in snapshot.get(key, [])}
    return {
        "a": serialize_version(a),
        "b": serialize_version(b),
        "devices_added": list(ids(sb, "devices") - ids(sa, "devices")),
        "devices_removed": list(ids(sa, "devices") - ids(sb, "devices")),
        "links_added": list(ids(sb, "links") - ids(sa, "links")),
        "links_removed": list(ids(sa, "links") - ids(sb, "links")),
        "services_added": list(ids(sb, "services") - ids(sa, "services")),
        "services_removed": list(ids(sa, "services") - ids(sb, "services")),
    }

# -----------------------------
# Demo data
# -----------------------------

def seed_demo(db: Session, clear: bool = False):
    ensure_defaults(db)
    if clear:
        for model in [Dependency, Service, Link, Interface, Device, Segment, DiagramVersion, AuditLog]:
            db.execute(delete(model))
        db.commit()
    if db.query(Device).count() > 0 and not clear:
        return
    wan = get_or_create_segment(db, "WAN", "10.0.0.0/30", None)
    core = get_or_create_segment(db, "Core", "192.168.1.0/24", 1)
    users = get_or_create_segment(db, "Usuarios", "192.168.50.0/24", 50)
    servers = get_or_create_segment(db, "Servidores", "192.168.60.0/24", 60)
    devices = [
        ("INTERNET", "", "internet", "external", 0, wan.id, "UP", None),
        ("FW-EDGE-01", "10.0.0.1", "firewall", "perimeter", 1, wan.id, "UP", "INTERNET"),
        ("SW-CORE-01", "192.168.1.2", "switch", "core", 3, core.id, "UP", "FW-EDGE-01"),
        ("SW-ACCESS-01", "192.168.50.2", "switch", "access", 5, users.id, "UP", "SW-CORE-01"),
        ("PC-001", "192.168.50.20", "endpoint", "host", 6, users.id, "UP", "SW-ACCESS-01"),
        ("PRINTER-01", "192.168.50.40", "printer", "host", 6, users.id, "UP", "SW-ACCESS-01"),
        ("SRV-APP-01", "192.168.60.10", "server", "app", 6, servers.id, "UP", "SW-CORE-01"),
        ("SRV-DB-01", "192.168.60.11", "server", "db", 6, servers.id, "UP", "SW-CORE-01"),
    ]
    by_name = {}
    for name, ip, dtype, role, tier, seg_id, status, parent_name in devices:
        dev = Device(id=new_id("dev"), site_id=DEFAULT_SITE_ID, segment_id=seg_id, hostname=name, management_ip=ip, device_type=dtype, icon="auto", role=role, tier=tier, status=status, is_main=role in {"core"}, is_perimeter=role == "perimeter", metadata_json={"source": "demo"})
        db.add(dev)
        db.flush()
        by_name[name] = dev
    for name, ip, dtype, role, tier, seg_id, status, parent_name in devices:
        if parent_name:
            child = by_name[name]
            parent = by_name[parent_name]
            child.parent_device_id = parent.id
            db.add(Link(id=new_id("link"), source_device_id=parent.id, target_device_id=child.id, link_type="physical_link", status="UP", label="demo", discovery_method="demo"))
    svc = Service(id=new_id("svc"), workspace_id=DEFAULT_WORKSPACE_ID, name="Portal Web", service_type="web", criticality="high", status="UP", owner="TI", description="Servicio demo")
    db.add(svc)
    db.flush()
    db.add(Dependency(id=new_id("dep"), source_type="service", source_id=svc.id, target_type="device", target_id=by_name["SRV-APP-01"].id, dependency_type="runs_on", criticality="high"))
    db.add(Dependency(id=new_id("dep"), source_type="device", source_id=by_name["SRV-APP-01"].id, target_type="device", target_id=by_name["SW-CORE-01"].id, dependency_type="depends_on", criticality="high"))
    db.add(Dependency(id=new_id("dep"), source_type="segment", source_id=users.id, target_type="device", target_id=by_name["SW-ACCESS-01"].id, dependency_type="depends_on", criticality="medium"))
    db.add(Dependency(id=new_id("dep"), source_type="segment", source_id=servers.id, target_type="device", target_id=by_name["SW-CORE-01"].id, dependency_type="depends_on", criticality="high"))
    audit(db, "seed", "workspace", DEFAULT_WORKSPACE_ID, "Demo cargada")
    db.commit()
