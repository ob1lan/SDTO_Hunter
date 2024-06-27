# Subdomain Finder

Subdomain Finder is a Python script to find subdomains of a given domain using various tools and techniques. It also checks for potential subdomain takeover vulnerabilities.

## Features

- Uses Sublist3r, Subfinder, Amass (passive, brute force, active), and ffuf for subdomain enumeration.
- Logs results of each tool to separate files.
- Checks for potential subdomain takeover vulnerabilities.
- Saves discovered subdomains to a file.

## Requirements

- Python 3.x
- [Sublist3r](https://github.com/aboul3la/Sublist3r)
- [Subfinder](https://github.com/projectdiscovery/subfinder)
- [Amass](https://github.com/OWASP/Amass)
- [ffuf](https://github.com/ffuf/ffuf)
- `requests` Python library: `pip install requests`

## Installation

Clone the repository:
```bash
git clone https://github.com/ob1lan/SDTO_Hunter
```
## Usage
```bash
python subdomain_finder.py <domain> [<domain2> ... <domainN>]
```
## Example
```bash
python subdomain_finder.py example.com
```
This will search for subdomains of example.com using the tools mentioned and save the results to separate log files. It will also check for potential subdomain takeover vulnerabilities.

## Logs
- <domain>_sublist3r.log
- <domain>_subfinder.log
- <domain>_amass_passive.log
- <domain>_amass_brute.log
- <domain>_amass_active.log
- <domain>_ffuf.log

## Subdomain Takeover Check
The script checks for indicators of potential subdomain takeover vulnerabilities using common error messages returned by various platforms.
