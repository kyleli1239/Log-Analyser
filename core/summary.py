import os
from datetime import datetime
from collections import defaultdict

def generate_summary_filename(directory="output"):
    """
    Generates a file with the name in the format 
    anomaly_summary_YYYY-MM-DD_HH-MM-SS.txt
    """
    # Gets the current date and time
    current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    filename = "anomaly_summary_" + current_datetime + ".txt"

    return os.path.join(directory, filename)

def create_summary_file(alerts, config):
    """
    Creates the anomaly summary file (split into separate sections for each log file)
    """
    filepath = generate_summary_filename()

    # If no alerts, write "No anomalies detected"
    if not alerts:
        with open(filepath,"w") as f:
            f.write("No anomalies detected \n")
        return filepath
    
    # Alerts are grouped by their source file
    # defaultdict(list) creates
    #  a dictionary. Default value is an empty list
    groups = defaultdict(list)
    for alert in alerts:
        groups[alert["source"]].append(alert)

    # Extracts list of blacklisted IPs from config
    blacklisted_ip = config["blacklisted_ip"]

    with open(filepath, "w") as f:

        # Writes the filename and the total number of alert
        f.write(f"{filepath}\n\n")
        f.write(f"Total alerts: {len(alerts)}\n\n")

        for source, group in groups.items():
            
            # Heading for each log file
            f.write("---------------------------------------------------------------------------------\n")
            f.write(f"{source}\n")
            f.write("---------------------------------------------------------------------------------\n")

            #------------------------------------
            # SQL injection and XSS section
            #------------------------------------
            sql_count = 0
            xss_count = 0

            # If the alert's rule is sql injection / xss, increment counter
            for alert in group:
                if alert["rule"] == "sql_injection":
                    sql_count = sql_count + 1
                elif alert["rule"] == "xss":
                    xss_count = xss_count + 1

            # Writes the number of SQL injection / XSS attempts
            f.write(f"Possible SQL injection attempts: {sql_count}\n\n")
            f.write(f"Possible XSS attempts: {xss_count}\n\n")

            #------------------------------------
            # Blacklisted IP section
            #------------------------------------

            # Only runs if config contains blacklisted IP addresses
            if blacklisted_ip:
                f.write("Activity from blacklisted IP addresses\n")

                # Create a set to store all the IPs that appear in this log's alerts
                # set() removes duplicate data
                seen_ip = set()

                # Extract IP from each alert and append to the list
                for alert in group:
                    if alert["ip"]:
                        seen_ip.add(alert["ip"])

                # For each IP in blacklist, check if IP appeared in alerts (seen_ip)
                for ip in blacklisted_ip:
                    if ip in seen_ip:
                        f.write(f"{ip}: True\n") # True = activity detected
                    else:
                        f.write(f"{ip}: False\n") # False = No activity detected
            
            else:
                f.write("No blaclisted IP addresses\n\n")

            f.write(f"\n")

            #------------------------------------
            # Repeated failed login section
            #------------------------------------
            # Creates dictionary to store an entity (IP/user) and a value. Default value is 0
            repeated_logins = defaultdict(int)
     
            # Iterates through the alerts for specific log file
            for alert in group:
                # If the alert's rule is repeated login, extract the entity (IP/user)
                if alert ["rule"] == "repeated_login":
                    entity = alert["details"]["entity"]
                    attempts = alert["details"]["attempts"]
                    repeated_logins [entity] = attempts

            # If there is a repeated login, write into file
            if repeated_logins:
                f.write("Repeated failed login attempts\n")
                for entity, count in repeated_logins.items(): # Count is number of repeat logins from entity
                    f.write(f"{entity}: {count}\n")
            
            else:
                f.write("No repeated failed login attempts\n")

            f.write(f"\n\n")

        #------------------------------------
        # More detailed alert list section
        #------------------------------------
        f.write("---------------------------------------------------------------------------------\n")
        f.write(f"Detailed alerts\n")
        f.write("---------------------------------------------------------------------------------\n")

        for alert in alerts: # Extracts data from the alerts
            line = alert["line"]
            source = alert["source"]
            timestamp = alert["timestamp"]
            event_type = alert["event_type"]
            rule = alert["rule"]
            ip = alert["ip"]
            user = alert["user"]
            details = alert["details"]
        
            # Writes the alerts onto the file
            f.write(f"Alert at line {line} in {source} {timestamp} ({event_type})\n")
            f.write(f"{rule} detected. ")

            # Each log entry will contain extra details based on the rule
            if rule == "repeated_login" or rule == "out_of_business_hours":
                f.write(f"IP = {ip}, User = {user}")      

            if rule == "sql_injection" or rule == "xss":
                patterns = details["patterns"]
                f.write(f"Pattern = {patterns} ")  

            if rule == "blacklisted_ip":
                f.write(f"IP = {ip}")

            f.write(f"\n\n")

    return filepath





