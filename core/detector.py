import yaml
from collections import defaultdict, deque
from datetime import datetime, timedelta
import json

def create_alert(rule, entry, details=None):
    """
    Creates a standardised alert dictionary
    """
    # entry[""] extracts the value from the normalised log entry
    return{
        "rule": rule,
        "timestamp": entry["timestamp"],
        "source": entry["source"],
        "line": entry["line"],
        "ip": entry["ip"],
        "user": entry["user"],
        "event_type": entry["event_type"],
        "details": details or {} # {} ensures "details" always contains a dictionary preventing future errors
    }

def detect_blacklisted_ip(entries, config):
    """
    Detect activity from blacklisted IPs
    """
    # Initialise list to store all generated alerts
    alerts = []

    # Loads the list of blacklisted IPs from the config 
    blacklist = config["blacklisted_ip"]

    # Iterates through every log entry
    for entry in entries:
        ip = entry["ip"] # Extracts IP address from log entry

    # If IP is in the blacklist, create an alert and append to list
        if ip in blacklist:
            alerts.append(create_alert("blacklisted_ip", entry, details={"ip": ip}))

    return alerts

def detect_business_hours(entries, config):
    """
    Detect activity during out of business hours
    """
    # Initialise list to store all generated alerts
    alerts = []

    # Loads the business hours from the config 
    # strptime() parses the string into a usable datetime object
    # time() ensures information about the dates is removed
    start = datetime.strptime(config["business_hours"]["start"],"%H:%M").time()
    end = datetime.strptime(config["business_hours"]["end"],"%H:%M").time()

    # Iterates through every log entry
    for entry in entries:
        timestamp = entry["timestamp"] # Extracts the log entry's timestamp

        # If timestamp isn't a datetime, continue (e.g timestamp is empty)
        if not isinstance(timestamp, datetime):
            continue

        timestamp = timestamp.time() # Removes the date

        # If timestamp is out of the business hours, create an alert and append to list
        # strftime() Formats the datetime object into a string
        if timestamp < start or timestamp > end:
            alerts.append(create_alert("out_of_business_hours", entry, details={"time":timestamp.strftime("%H:%M")}))
    
    return alerts

def detect_xss(entries, config):
    """
    Detect potential XSS attempts
    """
    # Initialise list to store all generated alerts
    alerts = []

    # Loads the common XSS phrases from the config 
    patterns = config["xss"]["patterns"]

    # Iterates through every log entry
    for entry in entries:

        # Checks to see whether data inside the field "raw" is a dictionary (for JSON files)
        # If it's a dictionary, use get() to extract data from the field "details"
        if isinstance(entry["raw"], dict):
            raw = str(entry["raw"])
            details = entry.get("details","")

            # If details contain a field called "payload", extract its data (payload contains XSS attempts)
            if "payload" in details:
                raw = details["payload"]
                
        else:    
            raw = str(entry["raw"]) # Extracts the raw log line (for text-based files)

        # If log entry contains a XSS pattern, create an alert and append to list
        for pattern in patterns:
            if pattern in raw:
                alerts.append(create_alert("xss", entry, details={"patterns":pattern}))
    return alerts
    
def detect_sql_injection(entries, config):
    """
    Detect potential SQL injection attempts
    """
    # Initialise list to store all generated alerts
    alerts = []

    # Loads the common SQL injection phrases from the config 
    patterns = config["sql_injection"]["patterns"]

    # Iterates through every log entry
    for entry in entries:

        # Checks to see whether data inside the field "raw" is a dictionary (for JSON files)
        # If it's a dictionary, use get() to extract data from the field "details"
        if isinstance(entry["raw"], dict):
            raw = str(entry["raw"])
            details = entry.get("details","")

            # If details contain a field called "payload", extract its data (payload contains XSS attempts)
            if "payload" in details:
                raw = details["payload"]
            
        else:    
            raw = str(entry["raw"]) # Extracts the raw log line (for text-based files)

        # If log entry contains a SQL injection pattern, create an alert and append to list
        for pattern in patterns:
            if pattern in raw:
                alerts.append(create_alert("sql_injection", entry, details={"patterns":pattern}))

    return alerts


def detect_repeated_login(entries, config):
    """
    Detect repeated logins within a time window by tracking IP and user individually
    (uses sliding window algorithm)
    """
    # Initialise list to store all generated alerts
    alerts = []

    # Loads the max attempts and time window from the config
    max_attempts = config["repeated_login"]["max_attempts"]
    window_seconds = config["repeated_login"]["time_window"]

    # Sliding windows for IP and user
    ip_window = defaultdict(lambda: deque())
    user_window = defaultdict(lambda: deque())


    # Iterates through every log entry
    for entry in entries:
        ip = entry["ip"] # Retrieve IP from log entry
        user = entry["user"] # Retrieve user from log entry
        timestamp = entry["timestamp"] # Retrieves timestamp from log entry

        # Both IP and user can't be empty
        if ip is None and user is None:
            continue

        # Timestamp can't be empty
        if timestamp is None:
            continue

        # Only failed authentications should be checked
        if entry["event_type"] != "auth_failed":
            continue

        # ------------------------------------------------
        # Track repeated failures by IP address
        if ip is not None:
            dq = ip_window[ip]
            dq.append(timestamp)

            cutoff = timestamp - timedelta(seconds=window_seconds)

            # Remove timestamp older than the time window
            while dq and dq [0] < cutoff:
                dq.popleft()

            if len(dq) >= max_attempts:
                alerts.append(create_alert("repeated_login", entry, details = {"entity":ip,
                                                                               "attempts":len(dq),
                                                                               "window_seconds": window_seconds}))
        # ------------------------------------------------
        # Track repeated failures by user
        if user is not None:
            dq = user_window[user]
            dq.append(timestamp)

            cutoff = timestamp - timedelta(seconds=window_seconds)

            # Remove timestamp older than the time window
            while dq and dq [0] < cutoff:
                dq.popleft()

            if len(dq) >= max_attempts:
                alerts.append(create_alert("repeated_login", entry, details = {"entity":user,
                                                                               "attempts":len(dq),
                                                                               "window_seconds": window_seconds}))
    return alerts

def run_all_detections(entries, config):
    """
    Calls all previous detect functions
    """
    # Initialise list to append and store the returned alerts
    alerts = []
    alerts.extend(detect_blacklisted_ip(entries, config))
    alerts.extend(detect_business_hours(entries, config))
    alerts.extend(detect_sql_injection(entries, config))
    alerts.extend(detect_xss(entries, config))
    alerts.extend(detect_repeated_login(entries, config))
    
    return alerts