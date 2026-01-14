import re
from datetime import datetime
from typing import Optional

def extract_text_ip(text: str):
    """
    Searches for an IP address and returns if found
    """
    # Regex looks for an IP address pattern
    # [0-9]{1,3}\. matches one to three digits followed by a dot e.g "192."
    # {3} repeats the previous pattern three times to match the first three octets of the IP address e.g 192.168.0.
    # [0-9]{1,3} matches the last octet of the IP address
    # \b is a word boundary. Ensures that the match is a whole word (not part of a larger string)
    match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text)

    # If no match is found, return None
    if not match:
        return None
    
    # If a match is found, return the matched IP address
    else:
        return match.group(0)
    

def extract_text_timestamp(text: str):
    """
    Extracts and parses timestamp from text log entry.
    """
    # Linux / SSH timestamp format
    # Regex looks for a timestamp pattern like "Jan 04 15:16:01"
    # [A-Z][a-z]{2}\s matches the month abbreviation (e.g Jan)
    # \d{2}\s matches the day of the month (e.g 04)
    # \d{2}:\d{2}:\d{2} matches the time in HH:MM:SS format (e.g 15:16:01)
    match = re.match(r"([A-Z][a-z]{2}\s+\d{2}\s+\d{2}:\d{2}:\d{2})", text)

    # If a match is found, attempts to parse and return the timestamp as a datetime object
    if match:
        timestamp_str = match.group(1)
        try:
            # Year is missing in this format, so the current year is added by default
            timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
            return timestamp.replace(year=datetime.now().year)
        except ValueError:
            return None

    # HTTP timestamp log format
    # Regex looks for a timestamp pattern like "20/Nov/2025:20:20:29"
    # d{2} / matches the day of the month followed by a slash (e.g 20/)
    # [A-Za-z]{3} / matches the month abbreviation followed by a slash (e.g Nov/)
    # \d{4}: matches the year followed by a colon (e.g 2025:)
    # \d{2}:\d{2}:\d{2} matches the time in HH:MM:SS format (e.g 20:20:29)
    match = re.search(r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})", text)

    # If a match is found, attempts to parse and return the timestamp as a datetime object
    if match:
        timestamp_str = match.group(1)
        try:
            return datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            return None


def extract_text_user(text: str):
    """
    Extracts the user from log entries (SSH and Linux log files) using multiple regex and
    returns the username if found. Otherwise returns none if no user is found 
    """
    # Patterns are ordered from most specific to most generic
    # Otherwise regex "for username" and "for invalid user username" will overlapse
    patterns = [
        r"invalid user\s+([a-zA-Z0-9._-]+)", # e.g for invalid user username
        r"user=([a-zA-Z0-9._-]+)", # e.g user=username
        r"user\s+([a-zA-Z0-9._-]+)", # e.g user username
        r"for\s+([a-zA-Z0-9._-]+)" # e.g for username
        ]
    
    # Loop tries each regex pattern in order on the text (case insensitive)
    # If one match is found, the extracted user is returned and function stops 
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)
        
    # If no match is found, return None
    return None


def extract_text_event_type(text: str):
    """
    Extracts the event type from log entries. First checks if the entry has a HTTP method 
    using regex. Then checks the text through a series of cases and returns the appropriate 
    event type. If all cases fail, return "unknown"
    """
    # Regex looks for a pattern like ""HEAD /"
    # "([A-Z]+) captures one or more uppercase letters after a " like "HEAD and "GET
    # \s+\/ ensures the captured string has 1 or more whitespaces after followed by a /
    http_match = re.search(r'"([A-Z]+)\s+\/',text)

    # If a match is found, return http_request and the event type
    if http_match:
        return f"http_request {http_match.group(1)}"
    
    text_lower = text.lower()

    if "invalid user" in text_lower:
        return "invalid_user"
    
    if "authentication failure" in text_lower:
        return "auth_failed"
    
    if "failed password" in text_lower:
        return "auth_failed"
    
    if "accepted" in text_lower and "password" in text_lower:
        return "auth_success"
    
    if "session opened" in text_lower:
        return "session_open"
    
    if "session closed" in text_lower:
        return "session_close"

    if "reverse mapping" in text_lower:
        return "reverse_mapping"

    if "check pass" in text_lower:
        return "password_check"
    
    if "connection closed" in text_lower:
        return "connection_close" \

    # return "unknown" if all cases fail
    return "unknown"

