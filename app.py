"""
Inventory Management System - Backend
Supports PostgreSQL (recommended) and SQLite (fallback).

Entities:
  - Users (authentication & roles)
  - Suppliers
  - Customers
  - Products (+ current stock)
  - Stock Movements (history)
  - Purchases (+ line items)
  - Sales (+ line items)
  - Payments
  - Audit Logs
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt
)
from werkzeug.security import generate_password_hash, check_password_hash
try:
    import bcrypt
except ImportError:
    bcrypt = None
from datetime import datetime, date, timedelta
from decimal import Decimal
from email.message import EmailMessage
from functools import wraps
import hashlib
import os
import secrets
import smtplib
import uuid
from pathlib import Path
from urllib.parse import quote
from dotenv import load_dotenv
from sqlalchemy.exc import IntegrityError

load_dotenv()

app = Flask(__name__)
CORS(app, supports_credentials=True)

# ---------------------------------------------------------------------------
# Database configuration
# Prefer PostgreSQL via DATABASE_URL. Fall back to SQLite for local dev.
# Example PostgreSQL URL:
#   postgresql://username:password@localhost:5432/inventory_db
# ---------------------------------------------------------------------------
DATABASE_URL = os.environ.get("DATABASE_URL")

if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    # Heroku-style URLs need the scheme fixed for SQLAlchemy
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Keep the default SQLite database beside app.py so the application uses a
# predictable, persistent database file on Windows and other local systems.
BASE_DIR = Path(__file__).resolve().parent
LOCAL_DB_PATH = BASE_DIR / "inventory.db"
LOCAL_DB_URI = f"sqlite:///{LOCAL_DB_PATH.as_posix()}"

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL or LOCAL_DB_URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,          # reconnect if connection dropped
    "pool_recycle": 300,
}

# ---------------------------------------------------------------------------
# JWT configuration
# ---------------------------------------------------------------------------
app.config["JWT_SECRET_KEY"] = os.environ.get(
    "JWT_SECRET_KEY",
    "change-this-to-a-long-random-secret-in-production-please"
)
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=8)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)
app.config["JWT_TOKEN_LOCATION"] = ["headers"]
app.config["JWT_HEADER_NAME"] = "Authorization"
app.config["JWT_HEADER_TYPE"] = "Bearer"

# Password-reset delivery is environment-driven. Local development may use a
# console link; production never exposes a reset token in an API response.
app.config["APP_ENV"] = os.environ.get("APP_ENV", "development").strip().lower()
app.config["APP_BASE_URL"] = os.environ.get("APP_BASE_URL", "http://127.0.0.1:5000").rstrip("/")
app.config["SMTP_HOST"] = os.environ.get("SMTP_HOST", "").strip()
app.config["SMTP_PORT"] = int(os.environ.get("SMTP_PORT", "587"))
app.config["SMTP_USERNAME"] = os.environ.get("SMTP_USERNAME", "").strip()
app.config["SMTP_PASSWORD"] = os.environ.get("SMTP_PASSWORD", "")
app.config["SMTP_FROM"] = os.environ.get("SMTP_FROM", "noreply@inventory.local").strip()
app.config["SMTP_USE_TLS"] = os.environ.get("SMTP_USE_TLS", "true").strip().lower() in {"1", "true", "yes", "on"}
app.config["RESET_CONSOLE_FALLBACK"] = os.environ.get(
    "RESET_CONSOLE_FALLBACK",
    "false" if app.config["APP_ENV"] == "production" else "true",
).strip().lower() in {"1", "true", "yes", "on"}
app.config["PASSWORD_RESET_TTL_MINUTES"] = int(os.environ.get("PASSWORD_RESET_TTL_MINUTES", "30"))

db = SQLAlchemy(app)
jwt = JWTManager(app)


@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({"success": False, "error": "Token has expired"}), 401


@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({"success": False, "error": "Invalid token"}), 401


@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({"success": False, "error": "Authorization token is required"}), 401


@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    return jsonify({"success": False, "error": "Token has been revoked"}), 401


# ---------------------------------------------------------------------------
# Role-Based Access Control (RBAC)
# ---------------------------------------------------------------------------
#
# Roles:
#   admin   – full access including user management
#   manager – all business operations; cannot manage users or hard-clear data
#   staff   – day-to-day: products CRUD (no delete), stock, sales create
#
# Permissions are checked with @permission_required("resource:action")
# or the simpler @role_required("admin", "manager").

ROLE_PERMISSIONS = {
    "admin": {
        "*",  # wildcard – everything
    },
    "manager": {
        "products:read", "products:create", "products:update", "products:delete",
        "stock:adjust",
        "suppliers:read", "suppliers:create", "suppliers:update", "suppliers:delete",
        "customers:read", "customers:create", "customers:update", "customers:delete",
        "purchases:read", "purchases:create", "purchases:receive",
        "sales:read", "sales:create",
        "payments:read", "payments:create",
        "audit:read",
        "dashboard:read",
        "users:read",
    },
    "staff": {
        "products:read", "products:create", "products:update",
        "stock:adjust",
        "suppliers:read",
        "customers:read", "customers:create",
        "sales:read", "sales:create",
        "payments:read",
        "dashboard:read",
    },
}


def _role_has_permission(role: str, permission: str) -> bool:
    perms = ROLE_PERMISSIONS.get(role, set())
    if "*" in perms:
        return True
    if permission in perms:
        return True
    # resource-level wildcard e.g. "products:*"
    resource = permission.split(":")[0] if ":" in permission else permission
    if f"{resource}:*" in perms:
        return True
    return False


def permission_required(*permissions):
    """Require JWT and at least one of the listed permissions."""
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            claims = get_jwt()
            role = claims.get("role", "staff")
            if not any(_role_has_permission(role, p) for p in permissions):
                return jsonify({
                    "success": False,
                    "error": f"Insufficient permissions. Required: {', '.join(permissions)}",
                }), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def role_required(*roles):
    """Require JWT and one of the given roles."""
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            claims = get_jwt()
            if claims.get("role") not in roles:
                return jsonify({
                    "success": False,
                    "error": "Insufficient permissions",
                }), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def get_current_user_id():
    """Return the user id from the JWT, or None if not authenticated."""
    try:
        return get_jwt_identity()
    except Exception:
        return None


def get_current_role():
    try:
        return get_jwt().get("role", "staff")
    except Exception:
        return None


# ===========================================================================
# MODELS
# ===========================================================================

def generate_uuid():
    return str(uuid.uuid4())


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    full_name = db.Column(db.String(150))
    role = db.Column(db.String(30), default="staff")  # admin, manager, staff
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        # Support legacy bcrypt hashes migrated from the previous database.
        if self.password_hash and self.password_hash.startswith(("$2a$", "$2b$", "$2y$")):
            if bcrypt is None:
                return False
            try:
                return bcrypt.checkpw(password.encode("utf-8"), self.password_hash.encode("utf-8"))
            except (ValueError, TypeError):
                return False
        return check_password_hash(self.password_hash, password)

    def to_dict(self, include_sensitive=False):
        data = {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "fullName": self.full_name,
            "role": self.role,
            "isActive": self.is_active,
            "createdAt": self.created_at.isoformat() if self.created_at else None,
        }
        return data


class Supplier(db.Model):
    __tablename__ = "suppliers"

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    name = db.Column(db.String(200), nullable=False, index=True)
    contact_person = db.Column(db.String(150))
    email = db.Column(db.String(120))
    phone = db.Column(db.String(40))
    address = db.Column(db.Text)
    notes = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    purchases = db.relationship("Purchase", back_populates="supplier", lazy="dynamic")

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "contactPerson": self.contact_person,
            "email": self.email,
            "phone": self.phone,
            "address": self.address,
            "notes": self.notes,
            "isActive": self.is_active,
            "createdAt": self.created_at.isoformat() if self.created_at else None,
        }


class Customer(db.Model):
    __tablename__ = "customers"

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    name = db.Column(db.String(200), nullable=False, index=True)
    contact_person = db.Column(db.String(150))
    email = db.Column(db.String(120))
    phone = db.Column(db.String(40))
    address = db.Column(db.Text)
    notes = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    sales = db.relationship("Sale", back_populates="customer", lazy="dynamic")

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "contactPerson": self.contact_person,
            "email": self.email,
            "phone": self.phone,
            "address": self.address,
            "notes": self.notes,
            "isActive": self.is_active,
            "createdAt": self.created_at.isoformat() if self.created_at else None,
        }


class Product(db.Model):
    __tablename__ = "products"

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    sku = db.Column(db.String(50), unique=True, nullable=False, index=True)
    name = db.Column(db.String(200), nullable=False, index=True)
    category = db.Column(db.String(100), default="Uncategorized", index=True)
    description = db.Column(db.Text)
    cost_price = db.Column(db.Numeric(12, 2), default=0)      # what we pay
    selling_price = db.Column(db.Numeric(12, 2), nullable=False)  # what we sell for
    quantity = db.Column(db.Integer, default=0)               # current stock
    unit = db.Column(db.String(20), default="pcs", nullable=False)
    reorder_point = db.Column(db.Integer, default=10)
    supplier_id = db.Column(db.String(36), db.ForeignKey("suppliers.id"), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    image_data = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    supplier = db.relationship("Supplier", backref="products")
    stock_movements = db.relationship("StockMovement", back_populates="product", lazy="dynamic")

    def get_status(self):
        if self.quantity <= 0:
            return "out"
        elif self.quantity <= self.reorder_point:
            return "low"
        return "ok"

    def to_dict(self, include_image=False):
        data = {
            "id": self.id,
            "sku": self.sku,
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "costPrice": float(self.cost_price) if self.cost_price is not None else 0,
            "price": float(self.selling_price),          # keep 'price' for frontend compatibility
            "sellingPrice": float(self.selling_price),
            "quantity": self.quantity,
            "unit": self.unit,
            "reorderPoint": self.reorder_point,
            "supplierId": self.supplier_id,
            "status": self.get_status(),
            "isActive": self.is_active,
            "createdAt": self.created_at.isoformat() if self.created_at else None,
        }
        if include_image:
            data["imageData"] = self.image_data
        return data


class StockMovement(db.Model):
    """Immutable record of every stock change (purchase, sale, adjustment, etc.)."""
    __tablename__ = "stock_movements"

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    product_id = db.Column(db.String(36), db.ForeignKey("products.id"), nullable=False, index=True)
    movement_type = db.Column(db.String(30), nullable=False)  # PURCHASE, SALE, ADJUSTMENT, RETURN
    quantity_change = db.Column(db.Integer, nullable=False)   # + or -
    quantity_after = db.Column(db.Integer, nullable=False)
    reference_type = db.Column(db.String(30))                 # purchase, sale, manual
    reference_id = db.Column(db.String(36))                   # id of related document
    notes = db.Column(db.Text)
    created_by = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    product = db.relationship("Product", back_populates="stock_movements")
    user = db.relationship("User")

    def to_dict(self):
        return {
            "id": self.id,
            "productId": self.product_id,
            "movementType": self.movement_type,
            "quantityChange": self.quantity_change,
            "quantityAfter": self.quantity_after,
            "referenceType": self.reference_type,
            "referenceId": self.reference_id,
            "notes": self.notes,
            "createdBy": self.created_by,
            "createdAt": self.created_at.isoformat() if self.created_at else None,
        }


class Purchase(db.Model):
    __tablename__ = "purchases"

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    reference = db.Column(db.String(50), unique=True, index=True)  # e.g. PO-2026-0001
    supplier_id = db.Column(db.String(36), db.ForeignKey("suppliers.id"), nullable=False)
    purchase_date = db.Column(db.Date, default=date.today)
    status = db.Column(db.String(30), default="draft")  # draft, ordered, received, cancelled
    subtotal = db.Column(db.Numeric(14, 2), default=0)
    tax_amount = db.Column(db.Numeric(14, 2), default=0)
    total_amount = db.Column(db.Numeric(14, 2), default=0)
    notes = db.Column(db.Text)
    created_by = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    supplier = db.relationship("Supplier", back_populates="purchases")
    items = db.relationship("PurchaseItem", back_populates="purchase", cascade="all, delete-orphan")
    payments = db.relationship("Payment", back_populates="purchase", lazy="dynamic")

    def to_dict(self, include_items=False):
        data = {
            "id": self.id,
            "reference": self.reference,
            "supplierId": self.supplier_id,
            "supplierName": self.supplier.name if self.supplier else None,
            "purchaseDate": self.purchase_date.isoformat() if self.purchase_date else None,
            "status": self.status,
            "subtotal": float(self.subtotal or 0),
            "taxAmount": float(self.tax_amount or 0),
            "totalAmount": float(self.total_amount or 0),
            "notes": self.notes,
            "createdAt": self.created_at.isoformat() if self.created_at else None,
        }
        if include_items:
            data["items"] = [item.to_dict() for item in self.items]
        return data


class PurchaseItem(db.Model):
    __tablename__ = "purchase_items"

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    purchase_id = db.Column(db.String(36), db.ForeignKey("purchases.id"), nullable=False)
    product_id = db.Column(db.String(36), db.ForeignKey("products.id"), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit_cost = db.Column(db.Numeric(12, 2), nullable=False)
    line_total = db.Column(db.Numeric(14, 2), nullable=False)

    purchase = db.relationship("Purchase", back_populates="items")
    product = db.relationship("Product")

    def to_dict(self):
        return {
            "id": self.id,
            "purchaseId": self.purchase_id,
            "productId": self.product_id,
            "productName": self.product.name if self.product else None,
            "sku": self.product.sku if self.product else None,
            "quantity": self.quantity,
            "unitCost": float(self.unit_cost),
            "lineTotal": float(self.line_total),
        }


class Sale(db.Model):
    __tablename__ = "sales"

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    reference = db.Column(db.String(50), unique=True, index=True)  # e.g. INV-2026-0001
    customer_id = db.Column(db.String(36), db.ForeignKey("customers.id"), nullable=True)  # null = walk-in
    sale_date = db.Column(db.Date, default=date.today)
    status = db.Column(db.String(30), default="completed")  # draft, completed, cancelled, refunded
    subtotal = db.Column(db.Numeric(14, 2), default=0)
    tax_amount = db.Column(db.Numeric(14, 2), default=0)
    discount_amount = db.Column(db.Numeric(14, 2), default=0)
    total_amount = db.Column(db.Numeric(14, 2), default=0)
    notes = db.Column(db.Text)
    created_by = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    customer = db.relationship("Customer", back_populates="sales")
    items = db.relationship("SaleItem", back_populates="sale", cascade="all, delete-orphan")
    payments = db.relationship("Payment", back_populates="sale", lazy="dynamic")

    def to_dict(self, include_items=False):
        data = {
            "id": self.id,
            "reference": self.reference,
            "customerId": self.customer_id,
            "customerName": self.customer.name if self.customer else "Walk-in Customer",
            "saleDate": self.sale_date.isoformat() if self.sale_date else None,
            "status": self.status,
            "subtotal": float(self.subtotal or 0),
            "taxAmount": float(self.tax_amount or 0),
            "discountAmount": float(self.discount_amount or 0),
            "totalAmount": float(self.total_amount or 0),
            "notes": self.notes,
            "createdAt": self.created_at.isoformat() if self.created_at else None,
        }
        if include_items:
            data["items"] = [item.to_dict() for item in self.items]
        return data


class SaleItem(db.Model):
    __tablename__ = "sale_items"

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    sale_id = db.Column(db.String(36), db.ForeignKey("sales.id"), nullable=False)
    product_id = db.Column(db.String(36), db.ForeignKey("products.id"), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit_price = db.Column(db.Numeric(12, 2), nullable=False)
    line_total = db.Column(db.Numeric(14, 2), nullable=False)

    sale = db.relationship("Sale", back_populates="items")
    product = db.relationship("Product")

    def to_dict(self):
        return {
            "id": self.id,
            "saleId": self.sale_id,
            "productId": self.product_id,
            "productName": self.product.name if self.product else None,
            "sku": self.product.sku if self.product else None,
            "quantity": self.quantity,
            "unitPrice": float(self.unit_price),
            "lineTotal": float(self.line_total),
        }


class Payment(db.Model):
    __tablename__ = "payments"

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    payment_type = db.Column(db.String(20), nullable=False)  # sale, purchase
    sale_id = db.Column(db.String(36), db.ForeignKey("sales.id"), nullable=True)
    purchase_id = db.Column(db.String(36), db.ForeignKey("purchases.id"), nullable=True)
    amount = db.Column(db.Numeric(14, 2), nullable=False)
    payment_method = db.Column(db.String(40), default="cash")  # cash, mpesa, bank, card, cheque
    reference = db.Column(db.String(100))  # transaction / cheque number
    payment_date = db.Column(db.Date, default=date.today)
    notes = db.Column(db.Text)
    created_by = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    sale = db.relationship("Sale", back_populates="payments")
    purchase = db.relationship("Purchase", back_populates="payments")
    user = db.relationship("User")

    def to_dict(self):
        return {
            "id": self.id,
            "paymentType": self.payment_type,
            "saleId": self.sale_id,
            "purchaseId": self.purchase_id,
            "amount": float(self.amount),
            "paymentMethod": self.payment_method,
            "reference": self.reference,
            "paymentDate": self.payment_date.isoformat() if self.payment_date else None,
            "notes": self.notes,
            "createdAt": self.created_at.isoformat() if self.created_at else None,
        }


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    entity_type = db.Column(db.String(50))          # product, sale, purchase, etc.
    entity_id = db.Column(db.String(36))
    action = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text)
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    user = db.relationship("User")

    def to_dict(self):
        return {
            "id": self.id,
            "entityType": self.entity_type,
            "entityId": self.entity_id,
            "action": self.action,
            "details": self.details,
            "userId": self.user_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


class LoginEvent(db.Model):
    """An authentication attempt snapshot used for today's admin activity view."""
    __tablename__ = "login_events"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True, index=True)
    username = db.Column(db.String(80), nullable=True)
    role = db.Column(db.String(30), nullable=True)
    outcome = db.Column(db.String(20), nullable=False, index=True)  # success or denied
    occurred_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    user = db.relationship("User")

    def to_dict(self):
        return {
            "id": self.id,
            "occurredAt": self.occurred_at.isoformat() if self.occurred_at else None,
            "username": self.username,
            "fullName": self.user.full_name if self.user else None,
            "role": self.role,
            "outcome": self.outcome,
        }


class PasswordResetToken(db.Model):
    """One-time password reset token; only the SHA-256 digest is persisted."""
    __tablename__ = "password_reset_tokens"

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, index=True)
    token_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    used_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user = db.relationship("User")


# ===========================================================================
# HELPERS
# ===========================================================================

def log_audit(entity_type, entity_id, action, details, user_id=None):
    entry = AuditLog(
        entity_type=entity_type,
        entity_id=str(entity_id) if entity_id else None,
        action=action,
        details=details,
        user_id=user_id,
    )
    db.session.add(entry)


def utc_now():
    return datetime.utcnow()


def utc_day_bounds():
    start = datetime.combine(utc_now().date(), datetime.min.time())
    return start, start + timedelta(days=1)


def record_login_event(user=None, username=None, outcome="denied"):
    """Persist a minimal authentication outcome without password or request data."""
    event = LoginEvent(
        user_id=user.id if user else None,
        username=user.username if user else username,
        role=user.role if user else None,
        outcome=outcome,
        occurred_at=utc_now(),
    )
    db.session.add(event)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("Could not record login event")


def hash_reset_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def build_reset_url(raw_token):
    return f"{app.config['APP_BASE_URL']}/?reset_token={quote(raw_token)}"


def send_password_reset_email(user, reset_url):
    """Send a reset link through SMTP or a development-only console fallback."""
    host = app.config["SMTP_HOST"]
    if host:
        message = EmailMessage()
        message["Subject"] = "Reset your Inventory Manager password"
        message["From"] = app.config["SMTP_FROM"]
        message["To"] = user.email
        message.set_content(
            "We received a request to reset your Inventory Manager password.\\n\\n"
            f"Open this link within {app.config['PASSWORD_RESET_TTL_MINUTES']} minutes:\\n"
            f"{reset_url}\\n\\n"
            "If you did not request this, you can ignore this email."
        )
        with smtplib.SMTP(host, app.config["SMTP_PORT"], timeout=10) as server:
            if app.config["SMTP_USE_TLS"]:
                server.starttls()
            if app.config["SMTP_USERNAME"]:
                server.login(app.config["SMTP_USERNAME"], app.config["SMTP_PASSWORD"])
            server.send_message(message)
        return True

    if app.config["APP_ENV"] != "production" and app.config["RESET_CONSOLE_FALLBACK"]:
        app.logger.warning("Password reset link for %s (development only): %s", user.email, reset_url)
        return True

    app.logger.error("Password reset delivery is not configured")
    return False


def record_stock_movement(product, quantity_change, movement_type,
                          reference_type=None, reference_id=None,
                          notes=None, user_id=None):
    """Update product quantity and create an immutable stock movement record."""
    new_qty = product.quantity + quantity_change
    if new_qty < 0:
        raise ValueError(f"Insufficient stock for {product.sku}. Available: {product.quantity}")

    product.quantity = new_qty
    movement = StockMovement(
        product_id=product.id,
        movement_type=movement_type,
        quantity_change=quantity_change,
        quantity_after=new_qty,
        reference_type=reference_type,
        reference_id=reference_id,
        notes=notes,
        created_by=user_id,
    )
    db.session.add(movement)
    return movement


def generate_reference(prefix: str) -> str:
    """Simple sequential reference generator (PO-2026-0001, INV-2026-0001...)."""
    year = datetime.utcnow().year
    if prefix == "PO":
        count = Purchase.query.filter(Purchase.reference.like(f"PO-{year}-%")).count()
    else:
        count = Sale.query.filter(Sale.reference.like(f"INV-{year}-%")).count()
    return f"{prefix}-{year}-{count + 1:04d}"


# ===========================================================================
# CREATE TABLES + DEFAULT ADMIN
# ===========================================================================

with app.app_context():
    db.create_all()
    if app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite"):
        try:
            columns = {row[1] for row in db.session.execute(db.text("PRAGMA table_info(products)")).fetchall()}
            if "image_data" not in columns:
                db.session.execute(db.text("ALTER TABLE products ADD COLUMN image_data TEXT"))
                db.session.commit()
        except Exception:
            db.session.rollback()

    # Seed development users only when explicitly enabled. Never print passwords.
    defaults = [
        ("admin", "admin@inventory.local", "System Administrator", "admin", "admin123"),
        ("manager", "manager@inventory.local", "Store Manager", "manager", "manager123"),
        ("staff", "staff@inventory.local", "Shop Staff", "staff", "staff123"),
    ]
    created = []
    seed_demo_accounts = os.environ.get("SEED_DEMO_ACCOUNTS", "false").strip().lower() in {"1", "true", "yes", "on"}
    for username, email, full_name, role, password in (defaults if seed_demo_accounts else []):
        if not User.query.filter_by(username=username).first():
            u = User(username=username, email=email, full_name=full_name, role=role)
            u.set_password(password)
            db.session.add(u)
            created.append(f"{username}/{password} ({role})")
    if created:
        db.session.commit()
        print(f"✅ {len(created)} development account(s) initialized. Credentials are not displayed.")


# ===========================================================================
# FRONTEND + API ROUTES
# ===========================================================================

@app.route("/", methods=["GET"])
def serve_frontend():
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), "index.html")


@app.route("/api/health", methods=["GET"])
def health_check():
    db_type = "postgresql" if "postgresql" in app.config["SQLALCHEMY_DATABASE_URI"] else "sqlite"
    return jsonify({
        "status": "ok",
        "message": "Inventory API is running",
        "database": db_type,
    })


# ===========================================================================
# USERS
# ===========================================================================

# ===========================================================================
# AUTHENTICATION (JWT)
# ===========================================================================

def get_request_data():
    """Read JSON requests and regular browser form submissions consistently."""
    data = request.get_json(silent=True)
    if data is None:
        data = request.form.to_dict()
    return data if isinstance(data, dict) else {}


def issue_auth_tokens(user):
    """Return the shared token payload used by login and registration."""
    additional_claims = {
        "role": user.role,
        "username": user.username,
    }
    access_token = create_access_token(
        identity=user.id,
        additional_claims=additional_claims,
    )
    refresh_token = create_refresh_token(
        identity=user.id,
        additional_claims=additional_claims,
    )
    return {
        "user": user.to_dict(),
        "accessToken": access_token,
        "refreshToken": refresh_token,
        "tokenType": "Bearer",
        "expiresIn": int(app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds()),
    }


@app.route("/api/auth/register", methods=["POST"])
def register():
    """Create a public staff account and sign the new user in."""
    data = get_request_data()

    username_value = data.get("username")
    email_value = data.get("email")
    full_name_value = data.get("fullName")
    username = username_value.strip() if isinstance(username_value, str) else ""
    email = email_value.strip().lower() if isinstance(email_value, str) else ""
    full_name = full_name_value.strip() if isinstance(full_name_value, str) and full_name_value.strip() else None
    password = data.get("password")
    confirmation = data.get("confirmPassword")

    if not username or not email or not isinstance(password, str) or not password:
        return jsonify({
            "success": False,
            "error": "Username, email, and password are required",
        }), 400
    if len(password) < 8:
        return jsonify({
            "success": False,
            "error": "Password must be at least 8 characters",
        }), 400
    if confirmation is not None and confirmation != password:
        return jsonify({"success": False, "error": "Passwords do not match"}), 400
    if "@" not in email or "." not in email.rsplit("@", 1)[-1]:
        return jsonify({"success": False, "error": "A valid email is required"}), 400
    if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
        return jsonify({
            "success": False,
            "error": "Username or email already exists",
        }), 409

    user = User(
        username=username,
        email=email,
        full_name=full_name,
        role="staff",
        is_active=True,
    )
    user.set_password(password)

    try:
        db.session.add(user)
        db.session.flush()
        log_audit("user", user.id, "REGISTER", f"Registered user {user.username}", user_id=user.id)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({
            "success": False,
            "error": "Username or email already exists",
        }), 409
    except Exception as error:
        db.session.rollback()
        return jsonify({"success": False, "error": str(error)}), 500

    return jsonify({
        "success": True,
        "message": "Account created",
        "data": issue_auth_tokens(user),
    }), 201


@app.route("/api/auth/login", methods=["POST"])
def login():
    """
    Authenticate and return access + refresh tokens.
    Body: { "username": "...", "password": "..." }
    """
    data = get_request_data()
    username_value = data.get("username")
    username = username_value.strip() if isinstance(username_value, str) else ""
    password = data.get("password")
    if not username or not isinstance(password, str) or not password:
        record_login_event(username=username or None, outcome="denied")
        return jsonify({"success": False, "error": "Username and password required"}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password) or not user.is_active:
        record_login_event(user=user, username=username, outcome="denied")
        return jsonify({"success": False, "error": "Invalid credentials"}), 401

    record_login_event(user=user, outcome="success")
    return jsonify({
        "success": True,
        "message": "Login successful",
        "data": issue_auth_tokens(user),
    })


@app.route("/api/auth/forgot-password", methods=["POST"])
def forgot_password():
    """Start a reset without revealing whether an email belongs to an account."""
    data = get_request_data()
    email_value = data.get("email")
    email = email_value.strip().lower() if isinstance(email_value, str) else ""
    generic_response = {
        "success": True,
        "message": "If an account matches that email, reset instructions are on the way.",
    }

    user = User.query.filter_by(email=email).first() if email else None
    if user and user.is_active:
        raw_token = secrets.token_urlsafe(32)
        PasswordResetToken.query.filter_by(user_id=user.id, used_at=None).update(
            {"used_at": utc_now()}, synchronize_session=False
        )
        reset_record = PasswordResetToken(
            user_id=user.id,
            token_hash=hash_reset_token(raw_token),
            expires_at=utc_now() + timedelta(minutes=app.config["PASSWORD_RESET_TTL_MINUTES"]),
        )
        db.session.add(reset_record)
        try:
            db.session.commit()
            if not send_password_reset_email(user, build_reset_url(raw_token)):
                app.logger.error("Password reset instructions could not be delivered for user %s", user.id)
        except Exception:
            db.session.rollback()
            app.logger.exception("Could not create password reset token")

    return jsonify(generic_response), 202


@app.route("/api/auth/reset-password", methods=["POST"])
def reset_password():
    data = get_request_data()
    raw_token = data.get("token")
    password = data.get("password")
    confirmation = data.get("confirmPassword")

    if not isinstance(password, str) or not password:
        return jsonify({"success": False, "error": "A new password is required"}), 400
    if len(password) < 8:
        return jsonify({"success": False, "error": "Password must be at least 8 characters"}), 400
    if confirmation != password:
        return jsonify({"success": False, "error": "Passwords do not match"}), 400

    reset_record = None
    if isinstance(raw_token, str) and raw_token:
        reset_record = PasswordResetToken.query.filter_by(
            token_hash=hash_reset_token(raw_token)
        ).first()
    if (
        not reset_record
        or reset_record.used_at is not None
        or reset_record.expires_at <= utc_now()
    ):
        return jsonify({
            "success": False,
            "code": "RESET_TOKEN_INVALID",
            "error": "This reset link is no longer valid. Request another reset.",
        }), 400

    user = User.query.get(reset_record.user_id)
    if not user or not user.is_active:
        return jsonify({
            "success": False,
            "code": "RESET_TOKEN_INVALID",
            "error": "This reset link is no longer valid. Request another reset.",
        }), 400

    user.set_password(password)
    now = utc_now()
    reset_record.used_at = now
    PasswordResetToken.query.filter(
        PasswordResetToken.user_id == user.id,
        PasswordResetToken.used_at.is_(None),
    ).update({"used_at": now}, synchronize_session=False)
    log_audit("user", user.id, "PASSWORD_RESET", f"Reset password for {user.username}", user_id=user.id)
    db.session.commit()
    return jsonify({"success": True, "message": "Password updated"})


@app.route("/api/admin/access-today", methods=["GET"])
@role_required("admin")
def access_today():
    start, end = utc_day_bounds()
    base_query = LoginEvent.query.filter(
        LoginEvent.occurred_at >= start,
        LoginEvent.occurred_at < end,
    )
    successful = base_query.filter(LoginEvent.outcome == "success").count()
    denied = base_query.filter(LoginEvent.outcome == "denied").count()
    unique_people = base_query.filter(
        LoginEvent.outcome == "success",
        LoginEvent.user_id.isnot(None),
    ).with_entities(db.func.count(db.distinct(LoginEvent.user_id))).scalar() or 0
    events = base_query.order_by(LoginEvent.occurred_at.desc()).limit(100).all()

    return jsonify({
        "success": True,
        "data": {
            "date": start.date().isoformat(),
            "summary": {
                "uniquePeople": int(unique_people),
                "successful": successful,
                "denied": denied,
            },
            "events": [event.to_dict() for event in events],
        },
    })


@app.route("/api/auth/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    """Issue a new access token using a valid refresh token."""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user or not user.is_active:
        return jsonify({"success": False, "error": "User not found or inactive"}), 401

    additional_claims = {
        "role": user.role,
        "username": user.username,
    }
    access_token = create_access_token(
        identity=user.id,
        additional_claims=additional_claims,
    )
    return jsonify({
        "success": True,
        "data": {
            "accessToken": access_token,
            "tokenType": "Bearer",
            "expiresIn": int(app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds()),
        },
    })


@app.route("/api/auth/me", methods=["GET"])
@jwt_required()
def me():
    """Return the currently authenticated user."""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 404
    return jsonify({"success": True, "data": user.to_dict()})


@app.route("/api/auth/profile", methods=["PUT"])
@jwt_required()
def update_profile():
    """Allow every authenticated user to safely update their own details/password."""
    user = User.query.get(get_jwt_identity())
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 404
    data = get_request_data()
    email = data.get("email")
    full_name = data.get("fullName")
    if email is not None:
        email = str(email).strip().lower()
        if "@" not in email or "." not in email.rsplit("@", 1)[-1]:
            return jsonify({"success": False, "error": "A valid email is required"}), 400
        existing = User.query.filter(User.email == email, User.id != user.id).first()
        if existing:
            return jsonify({"success": False, "error": "Email already in use"}), 409
        user.email = email
    if full_name is not None:
        user.full_name = str(full_name).strip() or None

    current_password = data.get("currentPassword")
    new_password = data.get("newPassword")
    if new_password is not None and new_password != "":
        if not isinstance(current_password, str) or not user.check_password(current_password):
            return jsonify({"success": False, "error": "Current password is incorrect"}), 400
        if not isinstance(new_password, str) or len(new_password) < 8:
            return jsonify({"success": False, "error": "New password must be at least 8 characters"}), 400
        if current_password == new_password:
            return jsonify({"success": False, "error": "New password must be different from the current password"}), 400
        user.set_password(new_password)

    try:
        log_audit("user", user.id, "PROFILE_UPDATE", f"Updated own profile for {user.username}", user_id=user.id)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"success": False, "error": "Email already in use"}), 409
    return jsonify({"success": True, "data": user.to_dict(), "message": "Profile updated successfully"})


@app.route("/api/auth/logout", methods=["POST"])
@jwt_required()
def logout():
    """
    Stateless JWT logout – client simply discards the token.
    (For a blacklist you would store jti here; kept simple for now.)
    """
    return jsonify({"success": True, "message": "Logged out successfully"})


@app.route("/api/auth/permissions", methods=["GET"])
@jwt_required()
def my_permissions():
    """Return the authenticated user's role and permission set (for UI RBAC)."""
    claims = get_jwt()
    role = claims.get("role", "staff")
    perms = sorted(ROLE_PERMISSIONS.get(role, set()))
    return jsonify({
        "success": True,
        "data": {
            "role": role,
            "permissions": perms,
            "isAdmin": role == "admin",
            "isManager": role in ("admin", "manager"),
        },
    })


# ===========================================================================
# ROLES & PERMISSIONS
# ===========================================================================

ROLE_DESCRIPTIONS = {
    "admin": "Full system access, including user and role administration.",
    "manager": "Business operations access with user viewing and no role administration.",
    "staff": "Day-to-day inventory operations with limited administration access.",
}

ROLE_PERMISSION_LABELS = {
    "products:read": "View products",
    "products:create": "Create products",
    "products:update": "Edit products",
    "products:delete": "Delete products",
    "stock:adjust": "Adjust stock",
    "suppliers:read": "View suppliers",
    "suppliers:create": "Create suppliers",
    "suppliers:update": "Edit suppliers",
    "suppliers:delete": "Delete suppliers",
    "customers:read": "View customers",
    "customers:create": "Create customers",
    "customers:update": "Edit customers",
    "customers:delete": "Delete customers",
    "purchases:read": "View purchases",
    "purchases:create": "Create purchases",
    "purchases:receive": "Receive purchases",
    "sales:read": "View sales",
    "sales:create": "Create sales",
    "payments:read": "View payments",
    "payments:create": "Create payments",
    "audit:read": "View audit logs",
    "dashboard:read": "View dashboard",
    "users:read": "View users",
}

@app.route("/api/roles", methods=["GET"])
@role_required("admin")
def list_roles():
    roles = []
    for role, permissions in ROLE_PERMISSIONS.items():
        expanded = [] if "*" in permissions else sorted(permissions)
        roles.append({
            "name": role,
            "description": ROLE_DESCRIPTIONS.get(role, ""),
            "permissions": expanded,
            "permissionLabels": [ROLE_PERMISSION_LABELS.get(p, p) for p in expanded],
            "isFullAccess": "*" in permissions,
        })
    return jsonify({"success": True, "data": roles})


# ===========================================================================
# USERS (admin only for management)
# ===========================================================================

@app.route("/api/users", methods=["GET"])
@role_required("admin", "manager")
def list_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return jsonify({"success": True, "data": [u.to_dict() for u in users]})


@app.route("/api/users", methods=["POST"])
@role_required("admin")
def create_user():
    data = request.json or {}
    required = ["username", "email", "password"]
    for f in required:
        if not data.get(f):
            return jsonify({"success": False, "error": f"Missing field: {f}"}), 400

    if User.query.filter_by(username=data["username"]).first():
        return jsonify({"success": False, "error": "Username already exists"}), 400
    if User.query.filter_by(email=data["email"]).first():
        return jsonify({"success": False, "error": "Email already exists"}), 400

    role = str(data.get("role", "staff")).strip().lower()
    if role not in ROLE_PERMISSIONS:
        return jsonify({"success": False, "error": "Invalid role. Choose admin, manager, or staff."}), 400
    password = data.get("password")
    if not isinstance(password, str) or len(password) < 8:
        return jsonify({"success": False, "error": "Password must be at least 8 characters"}), 400

    user = User(
        username=data["username"],
        email=data["email"],
        full_name=data.get("fullName"),
        role=role,
    )
    user.set_password(password)
    db.session.add(user)
    log_audit("user", user.id, "CREATE", f"Created user {user.username}",
              user_id=get_jwt_identity())
    db.session.commit()
    return jsonify({"success": True, "data": user.to_dict()}), 201


@app.route("/api/users/<user_id>", methods=["PUT"])
@role_required("admin")
def update_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 404

    data = request.json or {}
    if "email" in data:
        existing = User.query.filter(User.email == data["email"], User.id != user_id).first()
        if existing:
            return jsonify({"success": False, "error": "Email already in use"}), 400
        user.email = data["email"]
    if "fullName" in data:
        user.full_name = data["fullName"]
    if "role" in data:
        new_role = str(data["role"]).strip().lower()
        if new_role not in ROLE_PERMISSIONS:
            return jsonify({"success": False, "error": "Invalid role. Choose admin, manager, or staff."}), 400
        if user.id == get_jwt_identity() and new_role != "admin":
            return jsonify({"success": False, "error": "You cannot remove your own admin role."}), 400
        if user.role == "admin" and new_role != "admin":
            remaining_admins = User.query.filter(
                User.role == "admin", User.is_active == True, User.id != user.id
            ).count()
            if remaining_admins == 0:
                return jsonify({"success": False, "error": "At least one active administrator must remain."}), 400
        user.role = new_role
    if "isActive" in data:
        requested_active = bool(data["isActive"])
        if user.id == get_jwt_identity() and not requested_active:
            return jsonify({"success": False, "error": "You cannot deactivate your own account."}), 400
        if user.role == "admin" and not requested_active and user.is_active:
            remaining_admins = User.query.filter(
                User.role == "admin", User.is_active == True, User.id != user.id
            ).count()
            if remaining_admins == 0:
                return jsonify({"success": False, "error": "At least one active administrator must remain."}), 400
        user.is_active = requested_active
    if data.get("password"):
        if len(str(data["password"])) < 8:
            return jsonify({"success": False, "error": "Password must be at least 8 characters"}), 400
        user.set_password(data["password"])

    log_audit("user", user.id, "UPDATE", f"Updated user {user.username}",
              user_id=get_jwt_identity())
    db.session.commit()
    return jsonify({"success": True, "data": user.to_dict()})


@app.route("/api/users/<user_id>", methods=["DELETE"])
@role_required("admin")
def delete_user(user_id):
    if user_id == get_jwt_identity():
        return jsonify({"success": False, "error": "Cannot delete your own account"}), 400
    user = User.query.get(user_id)
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 404
    user.is_active = False
    log_audit("user", user.id, "DELETE", f"Deactivated user {user.username}",
              user_id=get_jwt_identity())
    db.session.commit()
    return jsonify({"success": True, "message": "User deactivated"})


# ===========================================================================
# SUPPLIERS
# ===========================================================================

@app.route("/api/suppliers", methods=["GET"])
def list_suppliers():
    active_only = request.args.get("active", "true").lower() == "true"
    q = Supplier.query
    if active_only:
        q = q.filter_by(is_active=True)
    suppliers = q.order_by(Supplier.name).all()
    return jsonify({"success": True, "data": [s.to_dict() for s in suppliers]})


@app.route("/api/suppliers", methods=["POST"])
@permission_required("suppliers:create")
def create_supplier():
    data = request.json or {}
    if not data.get("name"):
        return jsonify({"success": False, "error": "Name is required"}), 400

    supplier = Supplier(
        name=data["name"],
        contact_person=data.get("contactPerson"),
        email=data.get("email"),
        phone=data.get("phone"),
        address=data.get("address"),
        notes=data.get("notes"),
    )
    db.session.add(supplier)
    log_audit("supplier", supplier.id, "CREATE", f"Created supplier {supplier.name}")
    db.session.commit()
    return jsonify({"success": True, "data": supplier.to_dict()}), 201


@app.route("/api/suppliers/<supplier_id>", methods=["GET"])
def get_supplier(supplier_id):
    supplier = Supplier.query.get(supplier_id)
    if not supplier:
        return jsonify({"success": False, "error": "Supplier not found"}), 404
    return jsonify({"success": True, "data": supplier.to_dict()})


@app.route("/api/suppliers/<supplier_id>", methods=["PUT"])
@permission_required("suppliers:update")
def update_supplier(supplier_id):
    supplier = Supplier.query.get(supplier_id)
    if not supplier:
        return jsonify({"success": False, "error": "Supplier not found"}), 404

    data = request.json or {}
    supplier.name = data.get("name", supplier.name)
    supplier.contact_person = data.get("contactPerson", supplier.contact_person)
    supplier.email = data.get("email", supplier.email)
    supplier.phone = data.get("phone", supplier.phone)
    supplier.address = data.get("address", supplier.address)
    supplier.notes = data.get("notes", supplier.notes)
    if "isActive" in data:
        supplier.is_active = bool(data["isActive"])

    log_audit("supplier", supplier.id, "UPDATE", f"Updated supplier {supplier.name}")
    db.session.commit()
    return jsonify({"success": True, "data": supplier.to_dict()})


@app.route("/api/suppliers/<supplier_id>", methods=["DELETE"])
@permission_required("suppliers:delete")
def delete_supplier(supplier_id):
    supplier = Supplier.query.get(supplier_id)
    if not supplier:
        return jsonify({"success": False, "error": "Supplier not found"}), 404
    # Soft delete
    supplier.is_active = False
    log_audit("supplier", supplier.id, "DELETE", f"Deactivated supplier {supplier.name}")
    db.session.commit()
    return jsonify({"success": True, "message": "Supplier deactivated"})


# ===========================================================================
# CUSTOMERS
# ===========================================================================

@app.route("/api/customers", methods=["GET"])
def list_customers():
    active_only = request.args.get("active", "true").lower() == "true"
    q = Customer.query
    if active_only:
        q = q.filter_by(is_active=True)
    customers = q.order_by(Customer.name).all()
    return jsonify({"success": True, "data": [c.to_dict() for c in customers]})


@app.route("/api/customers", methods=["POST"])
@permission_required("customers:create")
def create_customer():
    data = request.json or {}
    if not data.get("name"):
        return jsonify({"success": False, "error": "Name is required"}), 400

    customer = Customer(
        name=data["name"],
        contact_person=data.get("contactPerson"),
        email=data.get("email"),
        phone=data.get("phone"),
        address=data.get("address"),
        notes=data.get("notes"),
    )
    db.session.add(customer)
    log_audit("customer", customer.id, "CREATE", f"Created customer {customer.name}")
    db.session.commit()
    return jsonify({"success": True, "data": customer.to_dict()}), 201


@app.route("/api/customers/<customer_id>", methods=["GET"])
def get_customer(customer_id):
    customer = Customer.query.get(customer_id)
    if not customer:
        return jsonify({"success": False, "error": "Customer not found"}), 404
    return jsonify({"success": True, "data": customer.to_dict()})


@app.route("/api/customers/<customer_id>", methods=["PUT"])
@permission_required("customers:update")
def update_customer(customer_id):
    customer = Customer.query.get(customer_id)
    if not customer:
        return jsonify({"success": False, "error": "Customer not found"}), 404

    data = request.json or {}
    customer.name = data.get("name", customer.name)
    customer.contact_person = data.get("contactPerson", customer.contact_person)
    customer.email = data.get("email", customer.email)
    customer.phone = data.get("phone", customer.phone)
    customer.address = data.get("address", customer.address)
    customer.notes = data.get("notes", customer.notes)
    if "isActive" in data:
        customer.is_active = bool(data["isActive"])

    log_audit("customer", customer.id, "UPDATE", f"Updated customer {customer.name}")
    db.session.commit()
    return jsonify({"success": True, "data": customer.to_dict()})


@app.route("/api/customers/<customer_id>", methods=["DELETE"])
@permission_required("customers:delete")
def delete_customer(customer_id):
    customer = Customer.query.get(customer_id)
    if not customer:
        return jsonify({"success": False, "error": "Customer not found"}), 404
    customer.is_active = False
    log_audit("customer", customer.id, "DELETE", f"Deactivated customer {customer.name}")
    db.session.commit()
    return jsonify({"success": True, "message": "Customer deactivated"})


# ===========================================================================
# PRODUCTS (kept compatible with existing frontend)
# ===========================================================================

@app.route("/api/products", methods=["GET"])
def get_products():
    try:
        filter_status = request.args.get("filter", "all")
        search = request.args.get("search", "").strip().lower()
        sort_by = request.args.get("sort_by", "created_at")
        sort_order = request.args.get("sort_order", "desc")

        query = Product.query.filter_by(is_active=True)

        if search:
            query = query.filter(
                db.or_(
                    Product.sku.ilike(f"%{search}%"),
                    Product.name.ilike(f"%{search}%"),
                    Product.category.ilike(f"%{search}%"),
                )
            )

        sortable = {
            "sku": Product.sku,
            "name": Product.name,
            "category": Product.category,
            "price": Product.selling_price,
            "quantity": Product.quantity,
            "reorderPoint": Product.reorder_point,
            "created_at": Product.created_at,
        }
        col = sortable.get(sort_by, Product.created_at)
        query = query.order_by(col.desc() if sort_order == "desc" else col.asc())

        products = query.all()

        if filter_status == "low":
            products = [p for p in products if p.get_status() in ("low", "out")]
        elif filter_status == "ok":
            products = [p for p in products if p.get_status() == "ok"]

        total_skus = len(products)
        total_units = sum(p.quantity for p in products)
        total_value = sum(float(p.selling_price) * p.quantity for p in products)
        low_stock_count = len([p for p in products if p.get_status() in ("low", "out")])

        return jsonify({
            "success": True,
            "data": [p.to_dict() for p in products],
            "stats": {
                "totalSkus": total_skus,
                "totalUnits": total_units,
                "totalValue": total_value,
                "lowStockCount": low_stock_count,
            },
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/products/<product_id>", methods=["GET"])
def get_product(product_id):
    product = Product.query.get(product_id)
    if not product or not product.is_active:
        return jsonify({"success": False, "error": "Product not found"}), 404
    return jsonify({"success": True, "data": product.to_dict(include_image=True)})


@app.route("/api/products", methods=["POST"])
@permission_required("products:create")
def add_product():
    try:
        data = request.json or {}
        required = ["sku", "name", "price"]
        for field in required:
            if field not in data:
                return jsonify({"success": False, "error": f"Missing field: {field}"}), 400

        if Product.query.filter_by(sku=data["sku"]).first():
            return jsonify({"success": False, "error": f'SKU "{data["sku"]}" already exists'}), 400

        initial_qty = int(data.get("quantity", 0))
        image_data = validate_image_data(data.get("imageData"))
        product = Product(
            sku=data["sku"],
            name=data["name"],
            category=data.get("category", "Uncategorized"),
            description=data.get("description"),
            cost_price=Decimal(str(data.get("costPrice", 0))),
            selling_price=Decimal(str(data["price"])),
            quantity=0,  # will be set by stock movement below
            unit=data.get("unit", "pcs"),
            reorder_point=int(data.get("reorderPoint", 10)),
            supplier_id=data.get("supplierId"),
            image_data=image_data,
        )
        db.session.add(product)
        db.session.flush()

        if initial_qty > 0:
            record_stock_movement(
                product, initial_qty, "ADJUSTMENT",
                reference_type="initial", notes="Initial stock on product creation"
            )

        log_audit("product", product.id, "ADD", f"Added product: {product.name} (SKU: {product.sku})")
        db.session.commit()
        return jsonify({"success": True, "message": "Product added", "data": product.to_dict()}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/products/<product_id>", methods=["PUT"])
@permission_required("products:update")
def update_product(product_id):
    try:
        product = Product.query.get(product_id)
        if not product:
            return jsonify({"success": False, "error": "Product not found"}), 404

        data = request.json or {}
        if "sku" in data and data["sku"] != product.sku:
            if Product.query.filter(Product.sku == data["sku"], Product.id != product_id).first():
                return jsonify({"success": False, "error": f'SKU "{data["sku"]}" already exists'}), 400

        old = product.to_dict()
        product.sku = data.get("sku", product.sku)
        product.name = data.get("name", product.name)
        product.category = data.get("category", product.category)
        product.description = data.get("description", product.description)
        if "costPrice" in data:
            product.cost_price = Decimal(str(data["costPrice"]))
        if "price" in data:
            product.selling_price = Decimal(str(data["price"]))
        product.reorder_point = int(data.get("reorderPoint", product.reorder_point))
        product.unit = data.get("unit", product.unit)
        if "imageData" in data:
            product.image_data = validate_image_data(data.get("imageData"))
        if "supplierId" in data:
            product.supplier_id = data["supplierId"]

        changes = []
        new = product.to_dict()
        for key in ["sku", "name", "category", "price", "reorderPoint", "unit"]:
            if old.get(key) != new.get(key):
                changes.append(f'{key}: "{old.get(key)}" → "{new.get(key)}"')
        if changes:
            log_audit("product", product.id, "UPDATE", f"Updated: {'; '.join(changes)}")

        db.session.commit()
        return jsonify({"success": True, "message": "Product updated", "data": product.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/products/<product_id>/stock", methods=["PUT"])
@permission_required("stock:adjust")
def update_stock(product_id):
    """Manual stock adjustment (compatible with existing frontend + / - buttons)."""
    try:
        data = request.json or {}
        delta = int(data.get("delta", 0))
        notes = data.get("notes", "Manual adjustment")

        product = Product.query.get(product_id)
        if not product:
            return jsonify({"success": False, "error": "Product not found"}), 404

        record_stock_movement(
            product, delta, "ADJUSTMENT",
            reference_type="manual", notes=notes
        )
        log_audit("product", product.id, "STOCK_CHANGE",
                  f"Stock changed by {delta} → now {product.quantity}")
        db.session.commit()
        return jsonify({"success": True, "message": "Stock updated", "data": product.to_dict()})
    except ValueError as ve:
        db.session.rollback()
        return jsonify({"success": False, "error": str(ve)}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/products/<product_id>", methods=["DELETE"])
@permission_required("products:delete")
def delete_product(product_id):
    try:
        product = Product.query.get(product_id)
        if not product:
            return jsonify({"success": False, "error": "Product not found"}), 404

        product.is_active = False  # soft delete
        log_audit("product", product.id, "DELETE", f"Deleted product: {product.name} (SKU: {product.sku})")
        db.session.commit()
        return jsonify({"success": True, "message": f'Product "{product.name}" deleted'})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/products/bulk", methods=["POST"])
@permission_required("products:create")
def bulk_import():
    try:
        data = request.json or {}
        products_data = data.get("products", [])
        imported = 0
        for item in products_data:
            if Product.query.filter_by(sku=item["sku"]).first():
                continue
            product = Product(
                sku=item["sku"],
                name=item["name"],
                category=item.get("category", "Uncategorized"),
                cost_price=Decimal(str(item.get("costPrice", 0))),
                selling_price=Decimal(str(item["price"])),
                quantity=int(item.get("quantity", 0)),
                unit=item.get("unit", "pcs"),
                reorder_point=int(item.get("reorderPoint", 10)),
            )
            db.session.add(product)
            imported += 1
        log_audit("product", None, "BULK_IMPORT", f"Imported {imported} products")
        db.session.commit()
        return jsonify({"success": True, "message": f"Imported {imported} products"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500


# ===========================================================================
# STOCK MOVEMENTS (history)
# ===========================================================================

@app.route("/api/stock-movements", methods=["GET"])
def list_stock_movements():
    product_id = request.args.get("productId")
    limit = request.args.get("limit", 100, type=int)
    q = StockMovement.query
    if product_id:
        q = q.filter_by(product_id=product_id)
    movements = q.order_by(StockMovement.created_at.desc()).limit(limit).all()
    return jsonify({"success": True, "data": [m.to_dict() for m in movements]})


# ===========================================================================
# PURCHASES
# ===========================================================================

@app.route("/api/purchases", methods=["GET"])
def list_purchases():
    status = request.args.get("status")
    q = Purchase.query
    if status:
        q = q.filter_by(status=status)
    purchases = q.order_by(Purchase.created_at.desc()).all()
    return jsonify({"success": True, "data": [p.to_dict() for p in purchases]})


@app.route("/api/purchases", methods=["POST"])
@permission_required("purchases:create")
def create_purchase():
    """
    Body example:
    {
      "supplierId": "...",
      "purchaseDate": "2026-08-22",
      "status": "received",          # or "ordered" / "draft"
      "notes": "...",
      "items": [
        {"productId": "...", "quantity": 10, "unitCost": 150.00}
      ]
    }
    When status == "received", stock is increased automatically.
    """
    try:
        data = request.json or {}
        if not data.get("supplierId"):
            return jsonify({"success": False, "error": "supplierId is required"}), 400
        if not data.get("items"):
            return jsonify({"success": False, "error": "At least one item is required"}), 400

        purchase = Purchase(
            reference=generate_reference("PO"),
            supplier_id=data["supplierId"],
            purchase_date=datetime.strptime(data["purchaseDate"], "%Y-%m-%d").date()
            if data.get("purchaseDate") else date.today(),
            status=data.get("status", "draft"),
            notes=data.get("notes"),
        )
        db.session.add(purchase)
        db.session.flush()

        subtotal = Decimal("0")
        for item_data in data["items"]:
            product = Product.query.get(item_data["productId"])
            if not product:
                raise ValueError(f"Product {item_data['productId']} not found")
            qty = int(item_data["quantity"])
            unit_cost = Decimal(str(item_data["unitCost"]))
            line_total = qty * unit_cost
            subtotal += line_total

            item = PurchaseItem(
                purchase_id=purchase.id,
                product_id=product.id,
                quantity=qty,
                unit_cost=unit_cost,
                line_total=line_total,
            )
            db.session.add(item)

            # Increase stock if goods are received
            if purchase.status == "received":
                record_stock_movement(
                    product, qty, "PURCHASE",
                    reference_type="purchase", reference_id=purchase.id,
                    notes=f"Purchase {purchase.reference}"
                )
                # Optionally update cost price
                product.cost_price = unit_cost

        purchase.subtotal = subtotal
        purchase.tax_amount = Decimal(str(data.get("taxAmount", 0)))
        purchase.total_amount = subtotal + purchase.tax_amount

        log_audit("purchase", purchase.id, "CREATE",
                  f"Created purchase {purchase.reference} – {purchase.status}")
        db.session.commit()
        return jsonify({"success": True, "data": purchase.to_dict(include_items=True)}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/purchases/<purchase_id>", methods=["GET"])
def get_purchase(purchase_id):
    purchase = Purchase.query.get(purchase_id)
    if not purchase:
        return jsonify({"success": False, "error": "Purchase not found"}), 404
    return jsonify({"success": True, "data": purchase.to_dict(include_items=True)})


@app.route("/api/purchases/<purchase_id>/receive", methods=["POST"])
@permission_required("purchases:receive")
def receive_purchase(purchase_id):
    """Mark a purchase as received and update stock."""
    try:
        purchase = Purchase.query.get(purchase_id)
        if not purchase:
            return jsonify({"success": False, "error": "Purchase not found"}), 404
        if purchase.status == "received":
            return jsonify({"success": False, "error": "Already received"}), 400

        for item in purchase.items:
            product = item.product
            record_stock_movement(
                product, item.quantity, "PURCHASE",
                reference_type="purchase", reference_id=purchase.id,
                notes=f"Received {purchase.reference}"
            )
            product.cost_price = item.unit_cost

        purchase.status = "received"
        log_audit("purchase", purchase.id, "RECEIVE", f"Received goods for {purchase.reference}")
        db.session.commit()
        return jsonify({"success": True, "data": purchase.to_dict(include_items=True)})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500


# ===========================================================================
# SALES
# ===========================================================================

@app.route("/api/sales", methods=["GET"])
def list_sales():
    status = request.args.get("status")
    q = Sale.query
    if status:
        q = q.filter_by(status=status)
    sales = q.order_by(Sale.created_at.desc()).all()
    return jsonify({"success": True, "data": [s.to_dict() for s in sales]})


@app.route("/api/sales", methods=["POST"])
@permission_required("sales:create")
def create_sale():
    """
    Body example:
    {
      "customerId": "...",          # optional
      "saleDate": "2026-08-22",
      "discountAmount": 0,
      "taxAmount": 0,
      "notes": "...",
      "items": [
        {"productId": "...", "quantity": 2, "unitPrice": 2500.00}
      ]
    }
    Stock is decreased immediately for completed sales.
    """
    try:
        data = request.json or {}
        if not data.get("items"):
            return jsonify({"success": False, "error": "At least one item is required"}), 400

        sale = Sale(
            reference=generate_reference("INV"),
            customer_id=data.get("customerId"),
            created_by=get_jwt_identity(),
            sale_date=datetime.strptime(data["saleDate"], "%Y-%m-%d").date()
            if data.get("saleDate") else date.today(),
            status=data.get("status", "completed"),
            discount_amount=Decimal(str(data.get("discountAmount", 0))),
            tax_amount=Decimal(str(data.get("taxAmount", 0))),
            notes=data.get("notes"),
        )
        db.session.add(sale)
        db.session.flush()

        subtotal = Decimal("0")
        for item_data in data["items"]:
            product = Product.query.get(item_data["productId"])
            if not product:
                raise ValueError(f"Product {item_data['productId']} not found")
            qty = int(item_data["quantity"])
            unit_price = Decimal(str(item_data.get("unitPrice", product.selling_price)))
            line_total = qty * unit_price
            subtotal += line_total

            item = SaleItem(
                sale_id=sale.id,
                product_id=product.id,
                quantity=qty,
                unit_price=unit_price,
                line_total=line_total,
            )
            db.session.add(item)

            if sale.status == "completed":
                record_stock_movement(
                    product, -qty, "SALE",
                    reference_type="sale", reference_id=sale.id,
                    notes=f"Sale {sale.reference}"
                )

        sale.subtotal = subtotal
        sale.total_amount = subtotal - sale.discount_amount + sale.tax_amount

        log_audit("sale", sale.id, "CREATE", f"Created sale {sale.reference}")
        db.session.commit()
        return jsonify({"success": True, "data": sale.to_dict(include_items=True)}), 201
    except ValueError as ve:
        db.session.rollback()
        return jsonify({"success": False, "error": str(ve)}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/sales/<sale_id>", methods=["GET"])
def get_sale(sale_id):
    sale = Sale.query.get(sale_id)
    if not sale:
        return jsonify({"success": False, "error": "Sale not found"}), 404
    return jsonify({"success": True, "data": sale.to_dict(include_items=True)})


# ===========================================================================
# PAYMENTS
# ===========================================================================

@app.route("/api/payments", methods=["GET"])
def list_payments():
    sale_id = request.args.get("saleId")
    purchase_id = request.args.get("purchaseId")
    q = Payment.query
    if sale_id:
        q = q.filter_by(sale_id=sale_id)
    if purchase_id:
        q = q.filter_by(purchase_id=purchase_id)
    payments = q.order_by(Payment.created_at.desc()).all()
    return jsonify({"success": True, "data": [p.to_dict() for p in payments]})


@app.route("/api/payments", methods=["POST"])
@permission_required("payments:create")
def create_payment():
    """
    Body:
    {
      "paymentType": "sale" | "purchase",
      "saleId": "...",          # required if type=sale
      "purchaseId": "...",      # required if type=purchase
      "amount": 5000.00,
      "paymentMethod": "mpesa",
      "reference": "TXN123",
      "paymentDate": "2026-08-22",
      "notes": "..."
    }
    """
    try:
        data = request.json or {}
        ptype = data.get("paymentType")
        if ptype not in ("sale", "purchase"):
            return jsonify({"success": False, "error": "paymentType must be 'sale' or 'purchase'"}), 400
        if not data.get("amount"):
            return jsonify({"success": False, "error": "amount is required"}), 400

        payment = Payment(
            payment_type=ptype,
            sale_id=data.get("saleId") if ptype == "sale" else None,
            purchase_id=data.get("purchaseId") if ptype == "purchase" else None,
            amount=Decimal(str(data["amount"])),
            payment_method=data.get("paymentMethod", "cash"),
            reference=data.get("reference"),
            payment_date=datetime.strptime(data["paymentDate"], "%Y-%m-%d").date()
            if data.get("paymentDate") else date.today(),
            notes=data.get("notes"),
        )
        db.session.add(payment)
        log_audit("payment", payment.id, "CREATE",
                  f"Payment of {payment.amount} ({payment.payment_method}) for {ptype}")
        db.session.commit()
        return jsonify({"success": True, "data": payment.to_dict()}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500


# ===========================================================================
# AUDIT LOGS
# ===========================================================================

@app.route("/api/audit-logs", methods=["GET"])
@permission_required("audit:read")
def get_audit_logs():
    limit = request.args.get("limit", 50, type=int)
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(limit).all()
    return jsonify({"success": True, "data": [log.to_dict() for log in logs]})


# ===========================================================================
# SALES REPORTS
# ===========================================================================

@app.route("/api/reports/daily-sales", methods=["GET"])
@role_required("admin", "manager")
def daily_sales_report():
    """Return completed sales and product quantities for a selected day."""
    raw_date = request.args.get("date")
    try:
        report_date = datetime.strptime(raw_date, "%Y-%m-%d").date() if raw_date else date.today()
    except ValueError:
        return jsonify({"success": False, "error": "Date must use YYYY-MM-DD"}), 400

    sales = Sale.query.filter(
        Sale.sale_date == report_date,
        Sale.status == "completed"
    ).order_by(Sale.created_at.asc()).all()

    product_totals = {}
    total_quantity = 0
    total_amount = Decimal("0")
    for sale in sales:
        total_amount += Decimal(str(sale.total_amount or 0))
        for item in sale.items:
            key = item.product_id
            if key not in product_totals:
                product_totals[key] = {
                    "productId": item.product_id,
                    "productName": item.product.name if item.product else "Unknown product",
                    "sku": item.product.sku if item.product else None,
                    "quantity": 0,
                    "salesAmount": Decimal("0"),
                }
            product_totals[key]["quantity"] += item.quantity
            product_totals[key]["salesAmount"] += Decimal(str(item.line_total or 0))
            total_quantity += item.quantity

    products = []
    for row in product_totals.values():
        row["salesAmount"] = float(row["salesAmount"])
        products.append(row)
    products.sort(key=lambda x: (-x["quantity"], x["productName"].lower()))

    return jsonify({
        "success": True,
        "data": {
            "date": report_date.isoformat(),
            "saleCount": len(sales),
            "totalQuantity": total_quantity,
            "totalAmount": float(total_amount),
            "products": products,
            "sales": [s.to_dict(include_items=True) for s in sales],
        },
    })


@app.route("/api/reports/daily-sales.csv", methods=["GET"])
@role_required("admin", "manager")
def daily_sales_report_csv():
    raw_date = request.args.get("date")
    try:
        report_date = datetime.strptime(raw_date, "%Y-%m-%d").date() if raw_date else date.today()
    except ValueError:
        return jsonify({"success": False, "error": "Date must use YYYY-MM-DD"}), 400
    sales = Sale.query.filter(Sale.sale_date == report_date, Sale.status == "completed").order_by(Sale.created_at.asc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Daily Sales Report", report_date.isoformat()])
    writer.writerow(["Completed Sales", len(sales)])
    writer.writerow([])
    writer.writerow(["Product", "SKU", "Quantity Sold", "Sales Amount (Ksh)"])
    totals = {}
    for sale in sales:
        for item in sale.items:
            key = item.product_id
            row = totals.setdefault(key, [item.product.name if item.product else "Unknown product", item.product.sku if item.product else "", 0, Decimal("0")])
            row[2] += item.quantity
            row[3] += Decimal(str(item.line_total or 0))
    for row in sorted(totals.values(), key=lambda x: (-x[2], str(x[0]).lower())):
        writer.writerow([row[0], row[1], row[2], f"{row[3]:.2f}"])
    writer.writerow([])
    writer.writerow(["Total Units Sold", sum(r[2] for r in totals.values())])
    writer.writerow(["Total Sales Value (Ksh)", f"{sum((r[3] for r in totals.values()), Decimal('0')):.2f}"])
    response = app.response_class(output.getvalue(), mimetype="text/csv; charset=utf-8")
    response.headers["Content-Disposition"] = f'attachment; filename="sales-report-{report_date.isoformat()}.csv"'
    return response


# ===========================================================================
# DASHBOARD SUMMARY
# ===========================================================================

@app.route("/api/dashboard", methods=["GET"])
@permission_required("dashboard:read")
def dashboard():
    total_products = Product.query.filter_by(is_active=True).count()
    low_stock = Product.query.filter(
        Product.is_active == True,
        Product.quantity <= Product.reorder_point
    ).count()
    total_suppliers = Supplier.query.filter_by(is_active=True).count()
    total_customers = Customer.query.filter_by(is_active=True).count()

    # Simple sales total (all time)
    sales_total = db.session.query(db.func.coalesce(db.func.sum(Sale.total_amount), 0)).scalar()
    purchases_total = db.session.query(db.func.coalesce(db.func.sum(Purchase.total_amount), 0)).scalar()

    return jsonify({
        "success": True,
        "data": {
            "totalProducts": total_products,
            "lowStockCount": low_stock,
            "totalSuppliers": total_suppliers,
            "totalCustomers": total_customers,
            "salesTotal": float(sales_total or 0),
            "purchasesTotal": float(purchases_total or 0),
        }
    })


# ===========================================================================
# RUN
# ===========================================================================

if __name__ == "__main__":
    db_uri = app.config["SQLALCHEMY_DATABASE_URI"]
    db_name = "PostgreSQL" if "postgresql" in db_uri else "SQLite (/tmp/inventory.db)"
    print("🚀 Inventory Management API")
    print(f"📊 Database : {db_name}")
    print("📍 Running  : http://0.0.0.0:5000")
    print("🔐 Authentication enabled. Manage accounts from Admin → Users.")
    app.run(debug=True, host="0.0.0.0", port=5000)
