#!/usr/bin/env python3
"""
Authentication Module.
"""
from db import DB
from user import User
import bcrypt
from sqlalchemy.orm.exc import NoResultFound
import uuid
from typing import Union


def _hash_password(password: str) -> bytes:
    """
    Hash the input password using bcrypt.hashpw.
    """
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password


def _generate_uuid() -> str:
    """
    Generate a string representation of a new UUID.
    """
    return str(uuid.uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
        Register a new user.
        """
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            hashed_password = _hash_password(password)
            new_user = self._db.add_user(email, hashed_password)
            return new_user
        else:
            raise ValueError('User {} already exists'.format(email))

    def valid_login(self, email: str, password: str) -> bool:
        """
        Validate user login credentials.
        """
        try:
            user = self._db.find_user_by(email=email)

            if user is not None:
                password_bytes = password.encode('utf-8')
                hashed_password = user.hashed_password
                if bcrypt.checkpw(password_bytes, hashed_password):
                    return True
        except NoResultFound:
            return False
        return False

    def create_session(self, email: str) -> str:
        """
        Create a new session for the user and return the session ID.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None

        if user:
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        else:
            return None

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """
        Get user corresponding to the given session ID.
        """
        if session_id is None:
            return None

        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None
        else:
            return user

    def destroy_session(self, user_id: int) -> None:
        """
        Destroy session for the user with the given user_id.
        """
        if user_id is None:
            return None

        self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """
        Generate a reset password token for the user.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError

        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)

        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """
        Update the user's password using the provided reset_token.
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError

        hashed_password = _hash_password(password)
        self._db.update_user(
                user.id,
                hashed_password=hashed_password,
                reset_token=None)
