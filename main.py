from core.log_ingestor import ingest
from core.normaliser import normalise_all
from core.detector import run_all_detections
import yaml

def load_config(path="config/config.yaml"):
    """
    Loads the YAML config file
    """
    with open(path,"r") as file:
        # Parses the YAML content and it into a Python dictionary
        return yaml.safe_load(file)

def main():
    """
    Main function that runs. Calls other functions.
    """
    # Calls the ingest function and stores the returned list
    logs = ingest("logs")
    
    # Calls the normalise function and stores the returned normalised list
    normalised_logs = normalise_all(logs)

    # Calls functions from detector.py to load the YAML config file
    config = load_config()
    alerts = run_all_detections(normalised_logs, config)

    # Prints the total number of log entries ingested
    print(f"Total log entries ingested: {len(logs)}")

    # Prints the total number of log entries normalised
    print(f"Total log entries normalised: {len(normalised_logs)}")

    # Prints the total number of alerts flagged
    print(f"Total alerts: {len(alerts)}")

if __name__ == "__main__":
    # Runs main function when main.py is directly ran
    main()