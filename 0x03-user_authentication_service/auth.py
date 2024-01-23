#!/usr/bin/env python3
"""
Authentication Module.
"""

import bcrypt


def _hash_password(password: str) -> bytes:
    """
    Hash the input password using bcrypt.hashpw.
    """
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password
