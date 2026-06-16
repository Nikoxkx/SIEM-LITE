"""
User and RBAC models: user accounts, roles, permissions, and session tokens.
"""

import os
import uuid
import json
import hmac
import time
import hashlib
import secrets
import logging
from datetime import datetime, timezone, timedelta
from enum import Enum

logger = logging.getLogger(__name__)


class Permission(Enum):
    """Granular permissions for RBAC."""
    # Event permissions
    VIEW_EVENTS = "events:view"
    SEARCH_EVENTS = "events:search"
    EXPORT_EVENTS = "events:export"
    INGEST_EVENTS = "events:ingest"

    # Alert permissions
    VIEW_ALERTS = "alerts:view"
    ACK_ALERTS = "alerts:ack"
    RESOLVE_ALERTS = "alerts:resolve"
    ESCALATE_ALERTS = "alerts:escalate"
    DELETE_ALERTS = "alerts:delete"

    # Rule permissions
    VIEW_RULES = "rules:view"
    CREATE_RULES = "rules:create"
    EDIT_RULES = "rules:edit"
    DELETE_RULES = "rules:delete"
    TEST_RULES = "rules:test"
    ENABLE_RULES = "rules:enable"

    # Incident permissions
    VIEW_INCIDENTS = "incidents:view"
    CREATE_INCIDENTS = "incidents:create"
    EDIT_INCIDENTS = "incidents:edit"
    DELETE_INCIDENTS = "incidents:delete"

    # Dashboard permissions
    VIEW_DASHBOARDS = "dashboards:view"
    EDIT_DASHBOARDS = "dashboards:edit"

    # Admin permissions
    MANAGE_USERS = "admin:users"
    MANAGE_ROLES = "admin:roles"
    MANAGE_SETTINGS = "admin:settings"
    VIEW_AUDIT_LOG = "admin:audit"
    MANAGE_COLLECTORS = "admin:collectors"
    MANAGE_PARSERS = "admin:parsers"
    MANAGE_THREAT_INTEL = "admin:threat_intel"
    MANAGE_STORAGE = "admin:storage"
    SYSTEM_ADMIN = "admin:system"


class Role:
    """
    A role with a set of permissions. Users are assigned roles.

    Pre-defined roles:
        - admin: Full access
        - analyst: View/search events, manage alerts, view rules
        - responder: View events, manage alerts and incidents
        - viewer: Read-only access
    """

    # Pre-defined role definitions
    PREDEFINED_ROLES = {
        "admin": [p.value for p in Permission],
        "analyst": [
            Permission.VIEW_EVENTS.value, Permission.SEARCH_EVENTS.value,
            Permission.EXPORT_EVENTS.value, Permission.VIEW_ALERTS.value,
            Permission.ACK_ALERTS.value, Permission.RESOLVE_ALERTS.value,
            Permission.VIEW_RULES.value, Permission.TEST_RULES.value,
            Permission.VIEW_INCIDENTS.value, Permission.EDIT_INCIDENTS.value,
            Permission.VIEW_DASHBOARDS.value,
        ],
        "responder": [
            Permission.VIEW_EVENTS.value, Permission.SEARCH_EVENTS.value,
            Permission.VIEW_ALERTS.value, Permission.ACK_ALERTS.value,
            Permission.RESOLVE_ALERTS.value, Permission.ESCALATE_ALERTS.value,
            Permission.VIEW_INCIDENTS.value, Permission.CREATE_INCIDENTS.value,
            Permission.EDIT_INCIDENTS.value, Permission.VIEW_DASHBOARDS.value,
        ],
        "viewer": [
            Permission.VIEW_EVENTS.value, Permission.VIEW_ALERTS.value,
            Permission.VIEW_INCIDENTS.value, Permission.VIEW_DASHBOARDS.value,
        ],
    }

    def __init__(self, name, permissions=None, description=""):
        self.name = name
        self.description = description
        if permissions is None:
            permissions = self.PREDEFINED_ROLES.get(name, [])
        if isinstance(permissions, str):
            permissions = [permissions]
        self.permissions = set(permissions)
        self.created_at = datetime.now(timezone.utc)

    def has_permission(self, permission):
        """Check if the role has a specific permission."""
        if isinstance(permission, Permission):
            permission = permission.value
        return permission in self.permissions

    def add_permission(self, permission):
        """Add a permission to the role."""
        if isinstance(permission, Permission):
            permission = permission.value
        self.permissions.add(permission)

    def remove_permission(self, permission):
        """Remove a permission from the role."""
        if isinstance(permission, Permission):
            permission = permission.value
        self.permissions.discard(permission)

    def to_dict(self):
        return {
            "name": self.name,
            "description": self.description,
            "permissions": sorted(self.permissions),
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data):
        role = cls(data["name"], data.get("permissions", []), data.get("description", ""))
        return role

    def __repr__(self):
        return f"Role(name={self.name!r}, perms={len(self.permissions)})"


class SessionToken:
    """A session token for authenticated users."""

    def __init__(self, user_id, expires_in=3600, token=None):
        self.token = token or secrets.token_urlsafe(32)
        self.user_id = user_id
        self.created_at = datetime.now(timezone.utc)
        self.expires_at = self.created_at + timedelta(seconds=expires_in)
        self.last_activity = self.created_at
        self.ip_address = None
        self.user_agent = None

    @property
    def is_expired(self):
        return datetime.now(timezone.utc) > self.expires_at

    def refresh(self, expires_in=3600):
        """Extend the session."""
        self.expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        self.last_activity = datetime.now(timezone.utc)

    def touch(self):
        """Update last activity timestamp."""
        self.last_activity = datetime.now(timezone.utc)

    def to_dict(self):
        return {
            "token": self.token,
            "user_id": self.user_id,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
        }


class User:
    """
    A system user with authentication credentials and role assignments.
    """

    # Password hashing parameters
    PBKDF2_ITERATIONS = 100000
    SALT_LENGTH = 32
    HASH_ALGORITHM = "sha256"

    def __init__(self, **kwargs):
        self.user_id = kwargs.get("user_id") or f"USR-{uuid.uuid4().hex[:8].upper()}"
        self.username = kwargs.get("username", "")
        self.email = kwargs.get("email", "")
        self.full_name = kwargs.get("full_name", "")
        self.display_name = kwargs.get("display_name", self.username)
        self.password_hash = kwargs.get("password_hash")
        self.password_salt = kwargs.get("password_salt")

        # Roles
        roles = kwargs.get("roles", ["viewer"])
        if isinstance(roles, str):
            roles = [roles]
        self.roles = list(roles)
        self.permissions = set(kwargs.get("permissions", []))

        # Status
        self.is_active = kwargs.get("is_active", True)
        self.is_locked = kwargs.get("is_locked", False)
        self.is_admin = "admin" in self.roles

        # Security
        self.failed_login_attempts = kwargs.get("failed_login_attempts", 0)
        self.max_login_attempts = kwargs.get("max_login_attempts", 5)
        self.lockout_until = kwargs.get("lockout_until")

        # Timing
        now = datetime.now(timezone.utc)
        self.created_at = kwargs.get("created_at", now)
        self.updated_at = kwargs.get("updated_at", now)
        self.last_login = kwargs.get("last_login")
        self.last_login_ip = kwargs.get("last_login_ip")
        self.password_changed_at = kwargs.get("password_changed_at")
        self.must_change_password = kwargs.get("must_change_password", False)

        # Preferences
        self.preferences = kwargs.get("preferences", {})
        self.api_keys = kwargs.get("api_keys", [])

        # Sessions
        self._sessions = {}

    @classmethod
    def create(cls, username, password, email="", roles=None, **kwargs):
        """Create a new user with a plaintext password (hashed automatically)."""
        user = cls(username=username, email=email, roles=roles or ["viewer"], **kwargs)
        user.set_password(password)
        return user

    def set_password(self, password):
        """Set the user's password (hashed with PBKDF2)."""
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        self.password_salt = secrets.token_hex(self.SALT_LENGTH)
        self.password_hash = self._hash_password(password, self.password_salt)
        self.password_changed_at = datetime.now(timezone.utc)
        self.must_change_password = False
        self.updated_at = datetime.now(timezone.utc)

    def _hash_password(self, password, salt):
        """Hash a password with PBKDF2."""
        dk = hashlib.pbkdf2_hmac(
            self.HASH_ALGORITHM,
            password.encode("utf-8"),
            bytes.fromhex(salt),
            self.PBKDF2_ITERATIONS,
        )
        return dk.hex()

    def verify_password(self, password):
        """Verify a plaintext password against the stored hash."""
        if not self.password_hash or not self.password_salt:
            return False
        computed = self._hash_password(password, self.password_salt)
        return hmac.compare_digest(computed, self.password_hash)

    def check_password_strength(self, password):
        """Check password strength. Returns (score 0-4, list of issues)."""
        issues = []
        score = 0
        if len(password) >= 8:
            score += 1
        else:
            issues.append("Password must be at least 8 characters")
        if len(password) >= 12:
            score += 1
        if any(c.islower() for c in password) and any(c.isupper() for c in password):
            score += 1
        else:
            issues.append("Use both uppercase and lowercase letters")
        if any(c.isdigit() for c in password):
            score += 1
        else:
            issues.append("Include numbers")
        if any(not c.isalnum() for c in password):
            score += 1
        else:
            issues.append("Include special characters")
        if password.lower() in ("password", "admin", "12345678", "qwerty"):
            score = 0
            issues.append("Password is too common")
        return min(score, 4), issues

    def add_role(self, role_name):
        """Add a role to the user."""
        if role_name not in self.roles:
            self.roles.append(role_name)
            if role_name == "admin":
                self.is_admin = True
            self.updated_at = datetime.now(timezone.utc)

    def remove_role(self, role_name):
        """Remove a role from the user."""
        if role_name in self.roles:
            self.roles.remove(role_name)
            if role_name == "admin":
                self.is_admin = "admin" in self.roles
            self.updated_at = datetime.now(timezone.utc)

    def has_permission(self, permission):
        """Check if user has a permission through any of their roles."""
        if isinstance(permission, Permission):
            permission = permission.value
        # Check direct permission
        if permission in self.permissions:
            return True
        # Check role-based permissions
        for role_name in self.roles:
            role_perms = Role.PREDEFINED_ROLES.get(role_name, [])
            if permission in role_perms:
                return True
            if role_name == "admin":
                return True
        return False

    def has_any_permission(self, permissions):
        """Check if user has any of the given permissions."""
        return any(self.has_permission(p) for p in permissions)

    def has_all_permissions(self, permissions):
        """Check if user has all of the given permissions."""
        return all(self.has_permission(p) for p in permissions)

    def record_login(self, success, ip_address=None):
        """Record a login attempt."""
        if success:
            self.failed_login_attempts = 0
            self.is_locked = False
            self.lockout_until = None
            self.last_login = datetime.now(timezone.utc)
            self.last_login_ip = ip_address
        else:
            self.failed_login_attempts += 1
            if self.failed_login_attempts >= self.max_login_attempts:
                self.is_locked = True
                self.lockout_until = datetime.now(timezone.utc) + timedelta(minutes=30)
        self.updated_at = datetime.now(timezone.utc)

    def is_locked_out(self):
        """Check if the user is currently locked out."""
        if not self.is_locked:
            return False
        if self.lockout_until and datetime.now(timezone.utc) > self.lockout_until:
            self.is_locked = False
            self.failed_login_attempts = 0
            return False
        return True

    def create_session(self, expires_in=3600):
        """Create a new session token."""
        session = SessionToken(self.user_id, expires_in)
        self._sessions[session.token] = session
        return session

    def get_session(self, token):
        """Get a session by token."""
        session = self._sessions.get(token)
        if session and not session.is_expired:
            session.touch()
            return session
        elif session:
            del self._sessions[token]
        return None

    def revoke_session(self, token):
        """Revoke a session."""
        if token in self._sessions:
            del self._sessions[token]
            return True
        return False

    def revoke_all_sessions(self):
        """Revoke all sessions."""
        self._sessions.clear()

    def generate_api_key(self, name="default"):
        """Generate an API key for the user."""
        api_key = secrets.token_urlsafe(40)
        key_entry = {
            "key_id": str(uuid.uuid4())[:8],
            "name": name,
            "key_hash": hashlib.sha256(api_key.encode()).hexdigest(),
            "key_prefix": api_key[:8],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_used": None,
        }
        self.api_keys.append(key_entry)
        self.updated_at = datetime.now(timezone.utc)
        return api_key

    def verify_api_key(self, api_key):
        """Verify an API key."""
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        for key_entry in self.api_keys:
            if hmac.compare_digest(key_entry["key_hash"], key_hash):
                key_entry["last_used"] = datetime.now(timezone.utc).isoformat()
                return True
        return False

    def to_dict(self, include_sensitive=False):
        """Serialize user to dictionary."""
        data = {
            "user_id": self.user_id,
            "username": self.username,
            "email": self.email,
            "full_name": self.full_name,
            "display_name": self.display_name,
            "roles": self.roles,
            "permissions": sorted(self.permissions),
            "is_active": self.is_active,
            "is_admin": self.is_admin,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "last_login_ip": self.last_login_ip,
            "failed_login_attempts": self.failed_login_attempts,
            "preferences": self.preferences,
        }
        if include_sensitive:
            data["password_hash"] = self.password_hash
            data["password_salt"] = self.password_salt
            data["api_keys"] = self.api_keys
        return data

    def to_json(self, indent=None):
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data):
        return cls(**data)

    def __repr__(self):
        return f"User(username={self.username!r}, roles={self.roles})"

    def __eq__(self, other):
        if not isinstance(other, User):
            return False
        return self.user_id == other.user_id

    def __hash__(self):
        return hash(self.user_id)
