import hashlib
import hmac
import re

from cryptography.fernet import Fernet, InvalidToken
from flask import current_app


class IdentityConfigurationError(RuntimeError):
    pass


def normalize_cpf(value):
    if not isinstance(value, str) or len(value) > 32 or not re.fullmatch(r"[0-9.\-\s]*", value):
        return None
    digits = re.sub(r"\D", "", value)
    if len(digits) != 11 or digits == digits[0] * 11:
        return None
    total = sum(int(digits[index]) * (10 - index) for index in range(9))
    first = (total * 10) % 11
    first = 0 if first == 10 else first
    if first != int(digits[9]):
        return None
    total = sum(int(digits[index]) * (11 - index) for index in range(10))
    second = (total * 10) % 11
    second = 0 if second == 10 else second
    return digits if second == int(digits[10]) else None


def normalize_cnpj(value):
    if not isinstance(value, str) or len(value) > 32 or not re.fullmatch(r"[A-Za-z0-9./\-\s]*", value):
        return None
    identifier = re.sub(r"[./\-\s]", "", value).upper()
    if not re.fullmatch(r"[A-Z0-9]{12}\d{2}", identifier):
        return None
    if identifier[:12] == identifier[0] * 12:
        return None
    weights = (5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2)
    total = sum((ord(char) - 48) * weight for char, weight in zip(identifier[:12], weights))
    first = 0 if total % 11 < 2 else 11 - total % 11
    weights = (6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2)
    total = sum((ord(char) - 48) * weight for char, weight in zip(identifier[:13], weights))
    second = 0 if total % 11 < 2 else 11 - total % 11
    return identifier if identifier[12:] == f"{first}{second}" else None


def format_cpf(value):
    return f"{value[:3]}.{value[3:6]}.{value[6:9]}-{value[9:]}"


def mask_cpf(value):
    return f"***.***.{value[6:9]}-**"


def format_cnpj(value):
    return f"{value[:2]}.{value[2:5]}.{value[5:8]}/{value[8:12]}-{value[12:]}"


def _cipher():
    key = current_app.config.get("CPF_ENCRYPTION_KEY")
    if not key:
        raise IdentityConfigurationError(
            "Configure a chave persistente CPF_ENCRYPTION_KEY para armazenar ou consultar CPFs."
        )
    try:
        if isinstance(key, str):
            key = key.encode("ascii")
        return Fernet(key), key
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise IdentityConfigurationError(
            "CPF_ENCRYPTION_KEY deve ser uma chave Fernet válida e persistente."
        ) from error


def protect_cpf(value):
    cipher, key = _cipher()
    encrypted = cipher.encrypt(value.encode("ascii")).decode("ascii")
    lookup = hmac.new(key, value.encode("ascii"), hashlib.sha256).hexdigest()
    return encrypted, lookup


def reveal_cpf(value):
    cipher, _ = _cipher()
    try:
        return cipher.decrypt(value.encode("ascii")).decode("ascii")
    except (InvalidToken, UnicodeEncodeError) as error:
        raise IdentityConfigurationError(
            "O CPF armazenado não pode ser descriptografado; confira a chave CPF_ENCRYPTION_KEY."
        ) from error
