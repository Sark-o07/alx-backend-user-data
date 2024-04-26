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
        """Register user into database

        Parameters
        ---------
        email: str
            user email
        hashed_password: str
            user hashed or hidden password

        Returns
        -------
        object
            user object
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

        Parameters
        ----------
        email: str
            user email
        password: str
            user password

        Returns
        -------
        Bool
            True if valid else false.
        """
        try:
            user = self._db.find_user_by(email=email)
            provided_pswd_bytes = password.encode('utf-8')
            return bcrypt.checkpw(provided_pswd_bytes, user.hashed_password)
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """It creates session_id for a user

        Parameters
        ----------
        email: str
            user email

        Returns
        -------
        str
            the session ID as a string.
        """
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except Exception:
            return None

    def get_user_from_session_id(self, session_id: str) -> User:
        """ It gets user from session ID

        Parameters
        ----------
        session_id: str
            user session_id

        Returns
        -------
        User or None
            the corresponding User or None
        """
        if not session_id:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None
        return user

    def destroy_session(self, user_id: str):
        """ It removes User's session_id

        Parameters
        ----------
        user_id: str
            user ID

        Returns
        -------
        None
        """
        try:
            self._db.update_user(user_id, session_id=None)
        except Exception:
            return None

    def get_reset_password_token(self, email: str) -> str:
        """  Generate a UUID and update the user’s reset_token database field.

        Parameters
        ----------

        email: str
            user email

        Returns
        -------
        str
            the token
        """
        user = self._db.find_user_by(email=email)
        if not user:
            raise ValueError
        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token
