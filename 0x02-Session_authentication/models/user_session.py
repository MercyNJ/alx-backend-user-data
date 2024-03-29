#!/usr/bin/env python3
"""
User Session model
"""

from models.base import Base


class UserSession(Base):
    """
    class for user session.
    """
    def __init__(self, *args: list, **kwargs: dict):
        """
        Initialization.
        """
        super().__init__(*args, **kwargs)
        self.user_id = kwargs.get('user_id')
        self.session_id = kwargs.get('session_id')
