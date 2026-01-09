import os
import json


def detect_log_type(filename: str):
    """
    Takes the filename as input and returns a string indicating the log type.
    """
    # Converts filename to lowercase for case-insensitive comparison
    filename = filename.lower()

    if "ssh" in filename:
        return "ssh"
    elif "linux" in filename:
        return "linux"
    elif "http" in filename:
        return "http"
    elif filename.endswith(".json"):
        return "application"
    else:
        return "unknown"


def read_text_log(filepath: str, log_type: str):
    """
    Reads text-based log file and ingests its entries.
    """
    # Initialise an empty list to store ingested log entries
    data = []

    # Opens the log file in read mode and uses UTF-8 encoding
    with open(filepath, "r", encoding="utf-8") as file: 

        # Appends every line to a separate dictionary, which is then appended to the list
        for line_number, line in enumerate(file, start=1):
            line = line.strip() # Removes whitespace
            if line: # Empty lines are skipped
                data.append({
                    "source_file": os.path.basename(filepath),
                    "log_type": log_type,
                    "line": line_number,
                    "raw_entry": line # Each log entry is stored in a dictionary
                })

    # List of ingested log entries is returned
    return data


def read_json_log(filepath: str):
    """
    Reads JSON-based log file and ingests its entries.
    """
    # Initialise an empty list to store ingested log entries
    data = []

    # Opens the log file in read mode and uses UTF-8 encoding
    with open(filepath, "r", encoding="utf-8") as file:

        # Appends every line to a separate dictionary, which is then appended to the list
        for line_number, line in enumerate(file, start=1):
            log_object = json.loads(line) # Converts JSON string to dictionary
            data.append({
                "source_file": os.path.basename(filepath),
                "log_type": "application",
                "line": line_number,
                "raw_entry": log_object # Each log entry is stored in a dictionary
            })
    # List of ingested log entries is returned
    return data


def ingest(logs_directory: str):
    """
    Ingests all log files from the specified directory.
    """
    # Initialise an empty list to store all the ingested log entries
    combined_data = []

    # Iterates through all files in the logs directory
    for filename in os.listdir(logs_directory):
        filepath = os.path.join(logs_directory, filename)

        # Skips if it's not a file (e.g a directory)
        if not os.path.isfile(filepath):
            continue

        # Detects log type based on filename using the function defined earlier
        log_type = detect_log_type(filename)

        # Calls appropriate ingestion function based on file type
        if filename.lower().endswith(".json"):
            combined_data.extend(read_json_log(filepath))
        else: # Treats all other files as text-based logs
            combined_data.extend(read_text_log(filepath, log_type))

    # List of all ingested log entries is returned
    return combined_data