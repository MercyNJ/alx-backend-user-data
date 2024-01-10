#!/usr/bin/env python3
"""
filtered_logger module
"""

import re
from typing import List


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """
    Obfuscate specified fields in the log message using regex.

    Arguments:
        fields: A list of strings repr all fields to obfuscate.
        redaction: A string repr by what the field will be obfuscated.
        message: A string representing the log line.
        separator: A string repr the separator.

    Returns:
        The log message with specified fields obfuscated.
    """
    return re.sub(
            r'(\b(?:{}))[^{};]+'.format("|".join(fields), re.escape(
                separator)), r'\1=' + redaction, message, flags=re.MULTILINE)
