#!/usr/bin/env python3
""" A module to manage API authentication
"""
from typing import List, TypeVar
from flask import request


class Auth:
    """An authentication classs
    """


    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ Determines wether a given path needs authentication
        Args:
            path (str): the url path to be checked
            excluded_paths (list): a list of url path that needs no validation
        Return:
            True if path needs authentication to be validated else False
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
        return None
    
    def current_user(self, request=None) -> TypeVar('User'):
        return None