from core.log_ingestor import ingest

def main():
    """
    Main function that runs. Calls other functions.
    """
    # Calls the ingest function and stores the returned list in logs
    logs = ingest("logs")

    # Prints the total number of log entries ingested
    print(f"Total log entries ingested: {len(logs)}")

if __name__ == "__main__":
    # Runs main function when main.py is directly ran
    main()