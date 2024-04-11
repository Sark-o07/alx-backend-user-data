#!/usr/bin/env python3
"""
 a function called filter_datum that returns the log message obfuscated
 """
import re
from typing import List


def filter_datum(fields: List[str], redaction: str,
                 message: str,  separator: str) -> str:
    """
    returns obfuscated log message
    Args:
        fields (list): list of strings with fields to obfuscate in the message
        redaction (str):  The string used to replace the field value
        message (str): The log line to be obfuscated
        separator (str): The string that separates the fields in the message
    """

    for field in fields:
        message = re.sub(field+'=.*?'+separator,
                         field+'='+redaction+separator, message)
    return message
