import re
import argparse
from tabulate import tabulate
import textwrap
import csv
from config import get_strong_ciphers, get_weak_ciphers, is_strong_cipher, is_weak_cipher
import subprocess

RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

def run_nmap_scan(hostname, port):
    """ Run nmap scan to get supported ciphers using subprocess """
    try:
        # Run the nmap command with ssl-enum-ciphers script
        result = subprocess.run(
            ['nmap', '-p', str(port), '--script', 'ssl-enum-ciphers', hostname],
            capture_output=True, text=True, check=True
        )
        
        # Return the standard output
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running nmap scan: {e}")
        return ""

def extract_ciphers(nmap_output):
    """ Extract ciphers from nmap output """
    cipher_pattern = r'(TLS_[A-Z_]+(?:_[A-Z0-9]+)+)'
    cipher_lines = re.findall(cipher_pattern, nmap_output)
    return [cipher.strip() for cipher in cipher_lines]

def extract_tls_versions(nmap_output):
    """ Extract TLS version support from nmap output """
    tls_1_0 = "TLSv1.0" in nmap_output
    tls_1_1 = "TLSv1.1" in nmap_output
    return tls_1_0, tls_1_1

def classify_ciphers(ciphers):
    """ Classify ciphers into strong and weak """
    strong = []
    weak = []
    unknown = []
    
    for cipher in ciphers:
        if is_strong_cipher(cipher):
            strong.append(cipher)
        elif is_weak_cipher(cipher):
            weak.append(cipher)
        else:
            unknown.append(cipher)
    
    return strong, weak, unknown

def format_ciphers(ciphers, max_width=50, color=None):
    """Format ciphers into a wrapped string with optional color."""
    wrapped = '\n'.join(textwrap.wrap(ciphers, max_width))
    if color:
        return f"{color}{wrapped}{RESET}"
    return wrapped

def format_tls_support(supports_tls):
    """Format TLS support with color."""
    if supports_tls:
        return f"{RED}Yes{RESET}"
    return f"{GREEN}No{RESET}"

def scan_host(hostname, port=443):
    """ Scan the host and check cipher strengths using nmap """
    print(f"Scanning {hostname}:{port}...")

    nmap_output = run_nmap_scan(hostname, port)
    
    if not nmap_output:
        print("Failed to retrieve nmap scan results.")
        return None

    ciphers = extract_ciphers(nmap_output)
    tls_1_0, tls_1_1 = extract_tls_versions(nmap_output)
    
    if not ciphers:
        print("No ciphers found.")
        return None

    strong, weak, unknown = classify_ciphers(ciphers)

    return [
        hostname,
        format_tls_support(tls_1_0),
        format_tls_support(tls_1_1),
        format_ciphers(", ".join(weak), color=RED),
        format_ciphers(", ".join(strong), color=GREEN),
        format_ciphers(", ".join(unknown))
    ]

def scan_from_file(filename, port=443):
    """ Scan multiple hosts from a file """
    results = []
    with open(filename, 'r') as f:
        hosts = f.read().splitlines()
    
    for host in hosts:
        result = scan_host(host.strip(), port)
        if result:
            results.append(result)
    
    return results

def save_to_csv(results, output_file):
    """Save results to a CSV file with table headers as the first row."""
    headers = ["Hostname", "Supports TLS 1.0", "Supports TLS 1.1", "Weak Ciphers", "Strong Ciphers", "Unknown Ciphers"]
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        writer.writeheader()
        for row in results:
            cleaned_row = [re.sub(r'\033\[[0-9;]*m', '', str(cell)) for cell in row]
            writer.writerow(dict(zip(headers, cleaned_row)))
    print(f"Results saved to {output_file}")

def print_banner():
    banner = """
 ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗ ███████╗██╗    ██╗███████╗███████╗██████╗ 
██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗██╔════╝██║    ██║██╔════╝██╔════╝██╔══██╗
██║     ██║██████╔╝███████║█████╗  ██████╔╝███████╗██║ █╗ ██║█████╗  █████╗  ██████╔╝
██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗╚════██║██║███╗██║██╔══╝  ██╔══╝  ██╔═══╝ 
╚██████╗██║██║     ██║  ██║███████╗██║  ██║███████║╚███╔███╔╝███████╗███████╗██║     
 ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝                                                                                     
    """
    print(f"{GREEN}{banner}{RESET}")

if __name__ == "__main__":
    print_banner()
    
    parser = argparse.ArgumentParser(description="CipherSweep: SSL Cipher Strength Scanner using nmap")
    parser.add_argument("input", help="Hostname of the web application or file containing list of hostnames")
    parser.add_argument("--port", help="Port (default 443)", default=443, type=int)
    parser.add_argument("--file", action="store_true", help="Input is a file containing list of hostnames")
    parser.add_argument("--output", help="Output CSV file name")
    
    args = parser.parse_args()

    if args.file:
        results = scan_from_file(args.input, args.port)
    else:
        result = scan_host(args.input, args.port)
        results = [result] if result else []

    if results:
        print(tabulate(results, headers=["Hostname", "Supports TLS 1.0", "Supports TLS 1.1", "Weak Ciphers", "Strong Ciphers", "Unknown Ciphers"], 
                       tablefmt="grid", maxcolwidths=[None, None, None, 50, 50, 50]))
        
        if args.output:
            save_to_csv(results, args.output)
    else:
        print("No results to display.")
