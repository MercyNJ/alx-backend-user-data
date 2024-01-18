#!/usr/bin/env python3
"""
Session authentication module with expiration functionality.
"""

from api.v1.auth.session_auth import SessionAuth
from datetime import datetime, timedelta
from models.user import User
import os


class SessionExpAuth(SessionAuth):
    """
    Session with expiration class.
    """

    def __init__(self):
        """
        Initialization.
        """
        session_duration_str = os.getenv('SESSION_DURATION', '0')

        try:
            self.session_duration = int(session_duration_str)
        except ValueError:
            self.session_duration = 0

    def create_session(self, user_id=None):
        """
        Overide create session of superclass.
        """
        session_id = super().create_session(user_id)

        if session_id is None:
            return None

        session_dictionary = {
                "user_id": user_id,
                "created_at": datetime.now()
                }

        self.user_id_by_session_id[session_id] = session_dictionary
        return session_id

    def user_id_for_session_id(self, session_id=None):
        """
        Get a user by their session id.
        """
        if session_id is None:
            return None
        if session_id not in self.user_id_by_session_id.keys():
            return None

        session_dictionary = self.user_id_by_session_id.get(session_id)
        if session_dictionary is None:
            return None
        if self.session_duration <= 0:
            return session_dictionary.get('user_id')
        created_at = session_dictionary.get('created_at')

        if created_at is None:
            return None

        expired_time = created_at + timedelta(seconds=self.session_duration)

        if expired_time < datetime.now():
            return None
        return session_dictionary.get('user_id')
