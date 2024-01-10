#!/usr/bin/env python3
"""
filtered_logger module
"""

import re
from typing import List
import logging


PII_FIELDS = ("name", "email", "phone", "ssn", "password")


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """
        Initialization.
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Filter values in incoming log records.
        """
        log_message = super().format(record)
        return filter_datum(
                self.fields, self.REDACTION, log_message, self.SEPARATOR)


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


def get_logger() -> logging.Logger:
    """
    Create and configure the 'user_data' logger.
    """

    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)

    stream_handler = logging.StreamHandler()
    formatter = RedactingFormatter(fields=list(PII_FIELDS))
    stream_handler.setFormatter(formatter)

    logger.addHandler(stream_handler)

    logger.propagate = False

    return logger
