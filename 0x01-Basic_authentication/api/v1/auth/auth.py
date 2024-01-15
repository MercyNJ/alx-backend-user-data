#!/usr/bin/env python3
"""
Module to manage API authentication.
"""

from flask import request
from typing import List, TypeVar


class Auth:
    """
    Authenticationc
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ Checks if authentication is required for a given path """
        if path is None or excluded_paths is None or not excluded_paths:
            return True
        path = path.rstrip('/') + '/'

        return path not in excluded_paths

    def authorization_header(self, request=None) -> str:
        """ Retrieves the Authorization header from the request """
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ Retrieves the current user from the request """
        return None
