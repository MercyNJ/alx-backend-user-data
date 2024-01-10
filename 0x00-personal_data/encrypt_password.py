#!/usr/bin/env python3
"""
encrypt_password module
"""

import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hashes a password using bcrypt.

    Args:
        password (str): The plaintext password to hash.

    Returns:
        bytes: The salted, hashed password.
    """
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    return hashed_password


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validates a plaintext password against a hashed password using bcrypt.
    Args:
    hashed_password (bytes): The salted, hashed password.
    password (str): The plaintext password to check.

    Returns:
    bool: True if the password is valid, False otherwise.
    """

    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
