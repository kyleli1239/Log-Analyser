import re
from datetime import datetime
from typing import Optional

def extract_ip_from_json(log_object: dict):
    """
    Extracts IP address from a JSON log object.
    """
    # Attempts to retrieve and return the IP address from the log object
    # If the ip key doesn't exist, returns None
    try:
        return log_object.get("ip")
    except Exception:
        return None


def extract_json_timestamp(log_object: dict):
    """
    Extracts and parses timestamp from JSON object.
    """
    timestamp_str = log_object.get("timestamp")

    # If timestamp string is missing, return None
    if not timestamp_str:
        return None


    # Attempts to parse the timestamp string into a datetime object
    # If parsing fails, returns None
    try:
        return datetime.fromisoformat(timestamp_str)
    except ValueError:
        return None


def extract_json_event_type(log_object: dict):
    """
    Extracts event type from JSON logs. Event type is stored in the "level field"
    """
    # Retrieves and returns the value in the "level" field
    level = log_object.get("level")
    return level.upper()