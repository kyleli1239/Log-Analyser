from datetime import datetime
from core.parser_text import *
from core.parser_json import *

def normalise_text_entry(entry: dict):
    """
    Normalises a text-based log entry (produced during log ingestion) into a 
    structured dictionary using parsing functions to extract data.
    """
    # Retrieving data from the raw_entry key in the dictionary
    raw_data = entry["raw_entry"]

    # Using functions from parser_text.py to extract data from the log entry
    timestamp = extract_text_timestamp(raw_data)
    ip = extract_text_ip(raw_data)
    user = extract_text_user(raw_data)
    event_type = extract_text_event_type(raw_data)

    # Append values to the dictionary and return the dictionary
    return {
        "timestamp": timestamp,
        "source": entry["source_file"],
        "line": entry["line"],
        "ip": ip,
        "user": user,
        "event_type": event_type,
        "details": {}, # Temporary placeholder value
        "raw": raw_data
    }



def normalise_json_entry(entry: dict):
    """
    Normalises a JSON log entry (produced during log ingestion) into a 
    structured dictionary using parsing functions to extract data.
    """
    # Retrieving data from the raw_entry key in the dictionary
    raw_data = entry["raw_entry"]

    # Using functions from parser_text.py to extract data from the log entry
    timestamp = extract_json_timestamp(raw_data)
    event_type = extract_json_event_type(raw_data)

    # Extract value from the "details" key in the JSON file
    details = raw_data.get("details", {})

    # Future JSON logs may contain IP/user keys
    # If no value is stored under the key, return None
    ip = raw_data.get("ip", None)
    user = raw_data.get("user",None)

    # Append values to the dictionary and return the dictionary
    return {
        "timestamp": timestamp,
        "source": entry["source_file"],
        "line": entry["line"],
        "ip": ip,
        "user": user,
        "event_type": event_type,
        "details": details,
        "raw": raw_data
    }


def normalise_all(entries: list):
    """
    Normalises a list of log entries by using the appropiate normalise function based
    on its log type.
    """
    # List to store all the normalised entries, which consist of a dictionary
    normalised = []

    # Process each log entry individually and append to list
    for entry in entries:
        log_type = entry["log_type"]

        # If log type is application (JSON), use JSON normaliser
        if log_type == "application":
            normalised.append(normalise_json_entry(entry))

        # If log type is text, use text normaliser
        else:
            normalised.append(normalise_text_entry(entry))

    # Return normalised list
    return normalised

