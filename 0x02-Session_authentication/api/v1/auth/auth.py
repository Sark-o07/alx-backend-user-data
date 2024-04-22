#!/usr/bin/env python3
""" A module to manage API authentication
"""
from typing import List, TypeVar
from flask import request


class Auth:
    """An authentication classs
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Determines wether a given path needs authentication
        Args:
            - path (str): the url path to be checked
            - excluded_paths (list): a list of url path that
            - do not require authentication.
        Return:
            - True if path is not in excluded_paths, else False
        """

        if path is None:
            return True
        elif excluded_paths is None or excluded_paths == []:
            return True
        elif path in excluded_paths:
            return False
        else:
            for i in excluded_paths:
                if i.startswith(path):
                    return False
                if path.startswith(i):
                    return False
                if i[-1] == '*':
                    if path.startswith(i[:-1]):
                        return False

        return True

    def authorization_header(self, request=None) -> str:
        """
        Returns the authorization header from the request object
        Arg:
            - request (obj): An object representing the HTTP request.
        """
        if request is None:
            return None
        header = request.headers.get('Authorization')
        if header is None:
            return None
        return header

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Returns User instance based on information from the request object
        Arg:
            - request (obj): An object representing the HTTP request.
        """
        return None

    def session_cookie(self, request=None): 
        """Returns a cookie value from a request"""
        if request is None:
            return None
        session_id = request.cookies.get('_my_session_id')
        return session_id


