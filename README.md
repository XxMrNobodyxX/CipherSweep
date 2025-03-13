# SSL Cipher TLS and Cipher Scanner

A tool to scan web applications for SSL/TLS cipher strength using and output to a table or CSV file.

## Features

- Scans web applications for supported SSL/TLS ciphers
- Identifies weak and strong ciphers
- Detects support for outdated TLS versions (1.0 and 1.1)
- Supports scanning multiple hosts from a file
- Outputs results in a formatted table and optionally to CSV

  ![image](https://github.com/user-attachments/assets/6594d93f-d826-4b67-876c-71e91ea4e84f)

## Requirements

- Python 3.6+
- nmap installed on your system
- Python packages: 
  - tabulate

## Installation

1. Clone this repository
2. Install required packages:
   ```
   pip install -r requirements.txt
   ```
3. Ensure nmap is installed on your system

## Usage

```
python3 CipherSweep.py example.com
```

Scan a specific port:
```
python3 CipherSweep.py example.com --port 8443
```

Scan multiple hosts from a file:
```
python3 CipherSweep.py hosts.txt --file
```

Save results to CSV:
```
python3 CipherSweep.py example.com --output results.csv
```

## Updating Cipher Lists

The cipher lists are stored in separate JSON files for easier maintenance:

- `strong_ciphers.json`: Contains the list of strong ciphers
- `weak_ciphers.json`: Contains the list of weak ciphers

To update the cipher lists, simply edit these JSON files. The changes will be automatically loaded the next time you run the script.

### Adding New Strong Ciphers

To add new strong ciphers, edit `strong_ciphers.json` and add the cipher names to the JSON array.

### Adding New Weak Ciphers

To add new weak ciphers, edit `weak_ciphers.json` and add the cipher names to the JSON array.

## How It Works

1. The script uses nmap to scan the target host for supported SSL/TLS ciphers
2. It extracts the cipher information from the nmap output
3. It classifies each cipher as strong, weak, or unknown based on the cipher lists
4. It displays the results in a formatted table and optionally saves to CSV
