#!/usr/bin/env python3
"""Auth Module
"""
import uuid
from user import User
import bcrypt
from db import DB
from sqlalchemy.orm.exc import NoResultFound


def _hash_password(password: str) -> bytes:
    """ takes in a password string arguments and returns bytes.
    """
    byte_password = password.encode('utf-8')
    hashed_password = bcrypt.hashpw(byte_password, bcrypt.gensalt())
    return hashed_password


def _generate_uuid() -> str:
    """ Returns a string representation of a new UUID."""
    return str(uuid.uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """ take mandatory email and password, registers the user in the db.
        Returns the user object.
        """
        try:
            user = self._db.find_user_by(email=email)
            if user:
                raise ValueError(f"User {email} already exists")
        except NoResultFound:
            hashed_password = _hash_password(password)
            user = self._db.add_user(email, hashed_password)
        return user

    def valid_login(self, email: str, password: str) -> bool:
        """Checks if email and password are valid.
        Returns True if valid else false.
        """
        try:
            user = self._db.find_user_by(email=email)
            provided_pswd_bytes = password.encode('utf-8')
            return bcrypt.checkpw(provided_pswd_bytes, user.hashed_password)
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """It takes an email string argument
        and returns the session ID as a string.
        """
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except Exception:
            return None
