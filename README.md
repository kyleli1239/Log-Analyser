# LogSentinel - Log Analyser

LogSentinel analyses logs and outputs an anomaly summary file containing alerts

## Setup instruction

### 1. Download Dependencies and Python Packages

This application requires Python (preferably a later version like Python 3.9 or higher) and the following package to be installed:

**PyYaml** - For the config file

You can install package using `pip install PyYaml`

### 2. Input log files into the log directory and run the main program **main.py**

## Sample Input for Testing

* Use the log files already supplied in the logs directory (application_log.json, http_access.log, Linux_2k.log and SSH_2k.log).

* Edit the rules in config.yaml in the config directory. This will change the detection rules.

* Run `python main.py` on a terminal or directly run main.py on a code editor such as VS code.

* In the output directory, an anomaly summary file will be created. Inside this file, there will be a summary of suspicious activity in the log files.