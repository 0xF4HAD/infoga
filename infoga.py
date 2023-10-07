import whois
import dns.resolver
import shodan
import socket
import argparse
import requests
from bs4 import BeautifulSoup


def get_whois_info(domain):
    try:
        print('[++] Getting Whois info...')
        print('=' * 50)
        w = whois.query(domain)

        print('[*] Name: {}'.format(w.name))
        print('[*] Registrar: {}'.format(w.registrar))
        print('[*] Creation Date: {}'.format(w.creation_date))
        print('[*] Expiration Date: {}'.format(w.expiration_date))
        print('[*] Name Servers: {}'.format(w.name_servers))
        print('[*] Registrant: {}'.format(w.registrant))
    except Exception as e:
        print('[-] Error getting Whois info: {}'.format(e))


def get_dns_info(domain):
    try:
        print('\n[++] Getting DNS info...')
        print('=' * 50)

        def print_records(records, record_type):
            for record in records:
                print('[*] {} Record: {}'.format(record_type, record.to_text()))

        for record_type in ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']:
            try:
                records = dns.resolver.resolve(domain, record_type)
                print_records(records, record_type)
            except Exception as e:
                print('[-] {} Record could not resolve'.format(record_type))

    except Exception as e:
        print('[-] Error getting DNS info: {}'.format(e))


# Function to get DNS info including reverse DNS lookup

def get_reversedns_lookup(domain):
    try:
        print('\n[++] Reverse DNS Lookup...')
        print('=' * 50)
        ip = socket.gethostbyname(domain)
        if ip:
            print('[*] IP Address: {}'.format(ip))

            # Reverse DNS lookup
            try:
                hostnames = socket.gethostbyaddr(ip)
                print('[*] Reverse DNS Lookup:')
                for hostname in hostnames:
                    print('   - {}'.format(hostname))
            except Exception as e:
                print('[-] Reverse DNS lookup failed: {}'.format(e))
    except Exception as e:
        print('[-] Error getting DNS info: {}'.format(e))


def get_geolocation_info(domain):
    try:
        print('\n[++] Getting Geolocation info...')
        print('=' * 50)
        ip = socket.gethostbyname(domain)
        if ip:
            response = requests.get(
                'http://geolocation-db.com/json/' + ip).json()
            print('[*] Country Code: {}'.format(response['country_code']))
            print('[*] Country Name: {}'.format(response['country_name']))
            print('[*] City: {}'.format(response['city']))
            print('[*] Postal: {}'.format(response['postal']))
            print('[*] Latitude: {}'.format(response['latitude']))
            print('[*] Longitude: {}'.format(response['longitude']))
            print('[*] IPv4: {}'.format(response['IPv4']))
            print('[*] State: {}'.format(response['state']))

    except Exception as e:
        print('[-] Error getting Geolocation info: {}'.format(e))


def get_shodan_info(domain):
    try:
        print('\n[++] Getting Shodan info...')
        print('=' * 50)
        ip = socket.gethostbyname(domain)
        if ip:
            api = shodan.Shodan("YourShodanApiKey")
            results = api.search(ip)
            print('[**] Results found: {}'.format(results['total']))
            for result in results['matches']:
                print('[*] IP: {}'.format(result['ip_str']))
                print('[*] Data:\n{}'.format(result['data']))
                print()
    except Exception as e:
        print('[-] Error getting Shodan info: {}'.format(e))


# Function to extract email addresses from a webpage
def extract_emails(url):
    try:
        print('[++] Extracting Email Addresses...')
        print('=' * 50)
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        emails = set()
        for email in soup.find_all('a', href=True):
            if 'mailto:' in email['href']:
                emails.add(email['href'].replace('mailto:', ''))
        if emails:
            for email in emails:
                print('[*] Email: {}'.format(email))
        else:
            print('[-] No email addresses found on the webpage.')
    except Exception as e:
        print('[-] Error extracting email addresses: {}'.format(e))


# Function to get website title


def get_website_title(url):
    try:
        print('\n[++] Getting Website Title...')
        print('=' * 50)
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        title = soup.title.string.strip() if soup.title else 'N/A'
        print('[*] Website Title: {}'.format(title))
    except Exception as e:
        print('[-] Error getting website title: {}'.format(e))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Information Gathering Tool')
    parser.add_argument(
        '-d', '--domain', help='Enter the domain name for footprinting')
    parser.add_argument(
        '-s', '--shodan', help='Enter the IP for Shodan search')
    parser.add_argument(
        '-o', '--output', help='Enter the file to write output to.')
    parser.add_argument('-e', '--extract-emails',
                        help='Enter a URL to extract email addresses from a webpage')
    args = parser.parse_args()
    domain = args.domain
    shodan_ip = args.shodan
    output = args.output
    extract_emails_url = args.extract_emails

    if domain:
        get_whois_info(domain)
        get_dns_info(domain)
        get_reversedns_lookup(domain)
        get_geolocation_info(domain)
    else:
        print('[-] Please provide a domain with -d option.')

    if shodan_ip:
        get_shodan_info(shodan_ip)
    else:
        print('[-] Please provide an IP with -s option.')

    if extract_emails_url:
        extract_emails(extract_emails_url)

    if domain:
        get_website_title(f'http://{domain}')
