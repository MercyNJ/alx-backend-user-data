#!/usr/bin/env python3
"""
Module to manage API authentication.
"""

from flask import request
from typing import List, TypeVar
import os


class Auth:
    """
    Authenticationc
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ Checks if authentication is required for a given path """
        if path is None:
            return True

        if excluded_paths is None or excluded_paths == []:
            return True

        if path in excluded_paths:
            return False

        for excluded_path in excluded_paths:
            if excluded_path.startswith(path):
                return False
            elif path.startswith(excluded_path):
                return False
            elif excluded_path[-1] == "*":
                if path.startswith(excluded_path[:-1]):
                    return False

        return True

    def authorization_header(self, request=None) -> str:
        """ Retrieves the Authorization header from the request """
        if request is None or 'Authorization' not in request.headers:
            return None
        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """ Retrieves the current user from the request """
        return None

    def session_cookie(self, request=None):
        """
        Returns a cookie value from a request.
        """
        if request is None:
            return None

        session_cookie_name = os.getenv("SESSION_NAME", "_my_session_id")
        return request.cookies.get(session_cookie_name)
