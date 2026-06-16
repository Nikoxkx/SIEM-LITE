"""
Cryptographic utility functions.

Provides hashing, encryption, token generation, and HMAC signing.
"""

import os
import base64
import hashlib
import hmac
import secrets
import uuid as uuid_module
import json
import time
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Supported hash algorithms
HASH_ALGORITHMS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
    "sha3_256": hashlib.sha3_256,
    "sha3_512": hashlib.sha3_512,
}


def hash_string(data, algorithm="sha256"):
    """Hash a string using the specified algorithm.

    Args:
        data: String or bytes to hash.
        algorithm: Hash algorithm name.

    Returns:
        Hexadecimal hash string.
    """
    if algorithm not in HASH_ALGORITHMS:
        raise ValueError(f"Unknown hash algorithm: {algorithm}")
    if isinstance(data, str):
        data = data.encode("utf-8")
    return HASH_ALGORITHMS[algorithm](data).hexdigest()


def hash_file(file_path, algorithm="sha256", chunk_size=65536):
    """Hash a file using the specified algorithm.

    Args:
        file_path: Path to the file.
        algorithm: Hash algorithm name.
        chunk_size: Bytes to read at a time.

    Returns:
        Hexadecimal hash string.
    """
    if algorithm not in HASH_ALGORITHMS:
        raise ValueError(f"Unknown hash algorithm: {algorithm}")
    hasher = HASH_ALGORITHMS[algorithm]()
    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except (IOError, OSError) as exc:
        logger.error("Failed to hash file %s: %s", file_path, exc)
        return None


def hash_with_salt(data, salt=None, algorithm="sha256", iterations=100000):
    """Hash data with a salt using PBKDF2.

    Args:
        data: String to hash.
        salt: Salt bytes (generated if not provided).
        algorithm: Hash algorithm for PBKDF2.
        iterations: Number of PBKDF2 iterations.

    Returns:
        Tuple of (hash_hex, salt_hex).
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    if salt is None:
        salt = os.urandom(32)
    elif isinstance(salt, str):
        salt = bytes.fromhex(salt)
    dk = hashlib.pbkdf2_hmac(algorithm, data, salt, iterations)
    return dk.hex(), salt.hex()


def encrypt_data(data, key=None):
    """Encrypt data using a simple XOR-based cipher (NOT for production use).

    For production, use proper AES encryption. This is a lightweight
    obfuscation for demonstration purposes.

    Args:
        data: String or bytes to encrypt.
        key: Encryption key (generated if not provided).

    Returns:
        Tuple of (encrypted_base64, key_hex).
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    if key is None:
        key = secrets.token_bytes(32)
    elif isinstance(key, str):
        key = bytes.fromhex(key)

    # Simple XOR cipher (obfuscation, not real encryption)
    key_len = len(key)
    encrypted = bytearray(len(data))
    for i, byte in enumerate(data):
        encrypted[i] = byte ^ key[i % key_len]

    return base64.b64encode(encrypted).decode("ascii"), key.hex()


def decrypt_data(encrypted_b64, key_hex):
    """Decrypt data that was encrypted with encrypt_data.

    Args:
        encrypted_b64: Base64-encoded encrypted data.
        key_hex: Hexadecimal key string.

    Returns:
        Decrypted string.
    """
    encrypted = base64.b64decode(encrypted_b64)
    key = bytes.fromhex(key_hex)
    key_len = len(key)
    decrypted = bytearray(len(encrypted))
    for i, byte in enumerate(encrypted):
        decrypted[i] = byte ^ key[i % key_len]
    return decrypted.decode("utf-8", errors="replace")


def generate_token(length=32):
    """Generate a cryptographically secure random token.

    Args:
        length: Length of the token in bytes.

    Returns:
        URL-safe base64-encoded token string.
    """
    return secrets.token_urlsafe(length)


def generate_uuid():
    """Generate a random UUID4 string."""
    return str(uuid_module.uuid4())


def generate_short_id(length=8):
    """Generate a short random ID."""
    return secrets.token_hex(length // 2)


def encode_base64(data):
    """Base64 encode a string or bytes."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.b64encode(data).decode("ascii")


def decode_base64(data):
    """Base64 decode a string."""
    if isinstance(data, str):
        data = data.encode("ascii")
    return base64.b64decode(data).decode("utf-8", errors="replace")


def secure_compare(a, b):
    """Constant-time string comparison to prevent timing attacks."""
    if isinstance(a, str):
        a = a.encode("utf-8")
    if isinstance(b, str):
        b = b.encode("utf-8")
    return hmac.compare_digest(a, b)


class HMACSigner:
    """HMAC message signer for API authentication and webhooks."""

    def __init__(self, secret, algorithm="sha256"):
        """Initialize with a secret key.

        Args:
            secret: Secret key string or bytes.
            algorithm: Hash algorithm (sha256, sha512).
        """
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        self.secret = secret
        self.algorithm = algorithm

    def sign(self, message):
        """Sign a message and return the HMAC hex digest.

        Args:
            message: String or bytes to sign.

        Returns:
            Hexadecimal HMAC signature.
        """
        if isinstance(message, str):
            message = message.encode("utf-8")
        return hmac.new(self.secret, message, self.algorithm).hexdigest()

    def verify(self, message, signature):
        """Verify a message signature.

        Args:
            message: Original message.
            signature: Expected signature.

        Returns:
            True if signature is valid.
        """
        computed = self.sign(message)
        return secure_compare(computed, signature)

    def sign_request(self, method, path, body="", timestamp=None):
        """Sign an HTTP request.

        Creates a signature over: METHOD\nPATH\nTIMESTAMP\nBODY
        """
        if timestamp is None:
            timestamp = str(int(time.time()))
        if isinstance(body, dict):
            body = json.dumps(body)
        message = f"{method.upper()}\n{path}\n{timestamp}\n{body}"
        signature = self.sign(message)
        return {
            "timestamp": timestamp,
            "signature": signature,
            "algorithm": f"hmac-{self.algorithm}",
        }

    def verify_request(self, method, path, body, timestamp, signature, max_age=300):
        """Verify a signed HTTP request.

        Args:
            max_age: Maximum age of the request in seconds (replay protection).

        Returns:
            True if the request is valid and not expired.
        """
        # Check timestamp freshness
        try:
            req_time = int(timestamp)
            current_time = int(time.time())
            if abs(current_time - req_time) > max_age:
                logger.warning("Request timestamp expired")
                return False
        except (ValueError, TypeError):
            return False

        if isinstance(body, dict):
            body = json.dumps(body)
        message = f"{method.upper()}\n{path}\n{timestamp}\n{body}"
        return self.verify(message, signature)


def generate_jwt(payload, secret, algorithm="HS256", expires_in=3600):
    """Generate a simple JWT token (header.payload.signature).

    This is a minimal JWT implementation for demonstration.
    For production, use the PyJWT library.

    Args:
        payload: Dictionary of claims.
        secret: Signing secret.
        algorithm: Signing algorithm.
        expires_in: Token validity in seconds.

    Returns:
        JWT token string.
    """
    header = {"alg": algorithm, "typ": "JWT"}

    # Add standard claims
    now = int(time.time())
    payload = dict(payload)
    payload["iat"] = now
    payload["exp"] = now + expires_in

    header_json = json.dumps(header, separators=(",", ":"), sort_keys=True)
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)

    header_b64 = base64.urlsafe_b64encode(header_json.encode()).rstrip(b"=").decode()
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).rstrip(b"=").decode()

    message = f"{header_b64}.{payload_b64}"
    signer = HMACSigner(secret)
    signature = signer.sign(message)

    return f"{message}.{signature}"


def verify_jwt(token, secret):
    """Verify and decode a JWT token.

    Args:
        token: JWT token string.
        secret: Signing secret.

    Returns:
        Payload dictionary if valid, None otherwise.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        message = f"{parts[0]}.{parts[1]}"
        signature = parts[2]

        signer = HMACSigner(secret)
        if not signer.verify(message, signature):
            return None

        # Decode payload
        payload_b64 = parts[1]
        # Add padding
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        payload_json = base64.urlsafe_b64decode(payload_b64).decode()
        payload = json.loads(payload_json)

        # Check expiration
        if "exp" in payload:
            if int(time.time()) > payload["exp"]:
                return None

        return payload
    except (json.JSONDecodeError, ValueError, KeyError) as exc:
        logger.debug("JWT verification failed: %s", exc)
        return None
