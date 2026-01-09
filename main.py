from core.log_ingestor import ingest
from core.normaliser import normalise_all
import json

def main():
    """
    Main function that runs. Calls other functions.
    """
    # Calls the ingest function and stores the returned list
    logs = ingest("logs")
    
    # Calls the normalise function and stores the returned normalised list
    normalised_logs = normalise_all(logs)

    # Prints the total number of log entries ingested
    print(f"Total log entries ingested: {len(logs)}")

    # Prints the total number of log entries normalised
    print(f"Total log entries normalised: {len(normalised_logs)}")

    # Prints entries for testing purposes
    for entry in normalised_logs[:100000]:
        print(json.dumps(entry, default=str, indent=4))

if __name__ == "__main__":
    # Runs main function when main.py is directly ran
    main()