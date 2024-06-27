import sublist3r
import subprocess
import sys
import requests
import re
import os

def find_subdomains(domain):
    subdomains = set()
    
    # Using Sublist3r
    try:
        initial_count = len(subdomains)
        sublist3r_results = sublist3r.main(domain, 40, savefile=None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
        if sublist3r_results:
            subdomains.update(sublist3r_results)
        new_count = len(subdomains) - initial_count
        print(f"Sublist3r found {new_count} new subdomains for {domain}. Total so far: {len(subdomains)}")
        write_to_log(f"{domain}_sublist3r.log", sublist3r_results)
    except Exception as e:
        print(f"Error occurred while enumerating subdomains for {domain} with Sublist3r: {e}")
    
    # Using Subfinder
    try:
        initial_count = len(subdomains)
        result = subprocess.run(['subfinder', '-d', domain, '-silent'], capture_output=True, text=True)
        subdomains.update(result.stdout.splitlines())
        new_count = len(subdomains) - initial_count
        print(f"Subfinder found {new_count} new subdomains for {domain}. Total so far: {len(subdomains)}")
        write_to_log(f"{domain}_subfinder.log", result.stdout.splitlines())
    except Exception as e:
        print(f"Error occurred while enumerating subdomains for {domain} with Subfinder: {e}")
    
    # Using Amass (Passive)
    try:
        initial_count = len(subdomains)
        result = subprocess.run(['amass', 'enum', '-passive', '-d', domain], capture_output=True, text=True)
        parsed_result = parse_amass_output(result.stdout)
        subdomains.update(parsed_result)
        new_count = len(subdomains) - initial_count
        print(f"Amass (Passive) found {new_count} new subdomains for {domain}. Total so far: {len(subdomains)}")
        write_to_log(f"{domain}_amass_passive.log", result.stdout.splitlines())
    except Exception as e:
        print(f"Error occurred while enumerating subdomains for {domain} with Amass (Passive): {e}")
    
    # Using Amass (Brute Force)
    try:
        initial_count = len(subdomains)
        result = subprocess.run(['amass', 'enum', '-brute', '-d', domain], capture_output=True, text=True)
        parsed_result = parse_amass_output(result.stdout)
        subdomains.update(parsed_result)
        new_count = len(subdomains) - initial_count
        print(f"Amass (Brute Force) found {new_count} new subdomains for {domain}. Total so far: {len(subdomains)}")
        write_to_log(f"{domain}_amass_brute.log", result.stdout.splitlines())
    except Exception as e:
        print(f"Error occurred while enumerating subdomains for {domain} with Amass (Brute Force): {e}")

    # Using Amass (Active)
    try:
        initial_count = len(subdomains)
        result = subprocess.run(['amass', 'enum', '-active', '-d', domain], capture_output=True, text=True)
        parsed_result = parse_amass_output(result.stdout)
        subdomains.update(parsed_result)
        new_count = len(subdomains) - initial_count
        print(f"Amass (Active) found {new_count} new subdomains for {domain}. Total so far: {len(subdomains)}")
        write_to_log(f"{domain}_amass_active.log", result.stdout.splitlines())
    except Exception as e:
        print(f"Error occurred while enumerating subdomains for {domain} with Amass (Active): {e}")
    
    # Using ffuf with wordlist
    try:
        initial_count = len(subdomains)
        result = subprocess.run(['ffuf', '-w', '/usr/share/wordlists/amass/subdomains-top1mil-5000.txt', '-u', f'http://FUZZ.{domain}', '-mc', '200,201,202,301,302,307,401,403,405,407'], capture_output=True, text=True)
        parsed_result = parse_ffuf_output(result.stdout, domain)
        subdomains.update(parsed_result)
        new_count = len(subdomains) - initial_count
        print(f"ffuf found {new_count} new subdomains for {domain}. Total so far: {len(subdomains)}")
        write_to_log(f"{domain}_ffuf.log", result.stdout.splitlines())
    except Exception as e:
        print(f"Error occurred while enumerating subdomains for {domain} with ffuf: {e}")

    return list(subdomains)

def parse_amass_output(output):
    subdomains = set()
    for line in output.splitlines():
        match = re.search(r"(\S+\.\S+)\s*\(FQDN\)", line)
        if match:
            subdomains.add(match.group(1))
    return subdomains

def parse_ffuf_output(output, domain):
    subdomains = set()
    for line in output.splitlines():
        if line.startswith("http://"):
            subdomain = line.split(' ')[0].replace(f'http://', '').replace('/', '')
            subdomains.add(subdomain)
    return subdomains

def write_to_log(filename, data):
    with open(filename, 'w') as file:
        for line in data:
            file.write(f"{line}\n")

def check_for_takeover(subdomain):
    takeover_indicators = {
        'S3': 'NoSuchBucket',
        'GitHub': 'There isn’t a GitHub Pages site here.',
        'Heroku': 'There is no app configured at that hostname.',
        'Bitbucket': 'Repository not found',
        'GitLab': 'The page could not be found or you don\'t have permission to view it.',
        'Shopify': 'Sorry, this shop is currently unavailable.',
        'Tumblr': 'Whatever you were looking for doesn\'t currently exist at this address.',
        'Squarespace': 'This page is unavailable.',
        'WordPress': 'Do you want to register *.wordpress.com?',
        'CloudFront': 'Bad request. We can\'t connect to the server for this app or website at this time.',
        'Fastly': 'Fastly error: unknown domain',
        'Pantheon': 'The gods are wise, but do not know of the site which you seek.',
        'Zendesk': 'Help Center Closed',
        'Unbounce': 'The requested URL was not found on this server.',
        'Desk': 'Sorry, We Couldn\'t Find That Page',
        'UserVoice': 'This UserVoice subdomain is currently available!',
        'Surge': 'project not found',
        'Intercom': 'This page is not available',
        'Webflow': 'The page you are looking for doesn\'t exist or has been moved',
        'Azure': 'The resource you are looking for has been removed, had its name changed, or is temporarily unavailable.',
        'DigitalOcean': 'Domain is not configured',
        'Kinsta': 'No site configured at this domain',
        'Ghost': 'The thing you were looking for is no longer here, or never was'
    }    
    try:
        response = requests.get(f"http://{subdomain}", timeout=5)
        content = response.text
        
        for platform, indicator in takeover_indicators.items():
            if indicator in content:
                return True, platform
    except requests.exceptions.RequestException:
        pass
    
    return False, None

def write_to_file(domain, subdomains):
    output_file = f"{domain}_subdomains.txt"
    with open(output_file, 'w') as file:
        for subdomain in subdomains:
            file.write(subdomain + '\n')
    print(f"Subdomains for {domain} saved to {output_file}")

def main(domains):
    for domain in domains:
        print(f"Searching for subdomains in: {domain}")
        subdomains = find_subdomains(domain)
        write_to_file(domain, subdomains)
        
        for subdomain in subdomains:
            is_vulnerable, platform = check_for_takeover(subdomain)
            if is_vulnerable:
                print(f"\033[91mPotential subdomain takeover vulnerability detected on {subdomain} ({platform})\033[0m")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python subdomain_finder.py <domain> [<domain2> ... <domainN>]")
        sys.exit(1)
    
    input_domains = sys.argv[1:]
    main(input_domains)
