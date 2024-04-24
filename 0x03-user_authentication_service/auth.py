#!/usr/bin/env python3
"""Auth Module
"""
import bcrypt


def _hash_password(password: str) -> bytes:
    """ takes in a password string arguments and returns bytes.
    """
    byte_password = password.encode('utf-8')
    hashed_password = bcrypt.hashpw(byte_password, bcrypt.gensalt())
    return hashed_password
