import whois
import dns.resolver
import shodan
import socket
import argparse
import requests
from bs4 import BeautifulSoup
from colorama import init,Fore
import pyfiglet


init()
green =Fore.GREEN
greenx =Fore.LIGHTGREEN_EX
yellow =Fore.YELLOW
red = Fore.RED
blue=Fore.LIGHTBLUE_EX
reset =Fore.RESET


banner = pyfiglet.figlet_format('inf0g4')
print(f'{blue}')
print(banner)
print(f'{reset}')
print(f'{blue}Script{reset}: {red}0xF4HAD{reset}')

print(f'{green}={reset}' * 50)
print('         DNS Information Gathering Tools        ')
print(f'{green}={reset}' * 50)

def get_whois_info(domain):
    try:
        print(f'\n{greenx}[++] Getting Whois info...')
        print(f'{green}={reset}' * 50)
        
        w = whois.query(domain)
        print(f'{yellow}[*]{reset} Name: {w.name}')
        print(f'{yellow}[*]{reset} Registrar: {w.registrar}')
        print(f'{yellow}[*]{reset} Creation Date: {w.creation_date}')
        print(f'{yellow}[*]{reset} Expiration Date: {w.expiration_date}')
        print(f'{yellow}[*]{reset} Name Servers: {w.name_servers}')
        print(f'{yellow}[*]{reset} Registrant: {w.registrant}')
    except Exception as e:
        print(f'{red}[*]{reset} Error getting Whois info: {e}')


def get_dns_info(domain):
    try:
        
        print(f'\n{greenx}[++] Getting DNS info...')
        print(f'{green}={reset}' * 50)

        def print_records(records, record_type):
            for record in records:
                print(f'{yellow}[*]{reset} {record_type} Record: {record.to_text()}')

        for record_type in ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']:
            try:
                records = dns.resolver.resolve(domain, record_type)
                print_records(records, record_type)
            except Exception as e:
                print(f'{red}[-]{reset} {record_type} Record could not resolve')

    except Exception as e:
        print(f'{red}[-]{reset} Error getting DNS info: {e}')

       
# Function to get DNS info including reverse DNS lookup

def get_reversedns_lookup(domain):
    try:
        print(f'\n{greenx}[++] Reverse DNS Lookup...')
        print(f'{green}={reset}' * 50)
        ip = socket.gethostbyname(domain)
        if ip:
            print(f'{yellow}[*]{reset}IP Address: {ip}')

            # Reverse DNS lookup
            try:
                hostnames = socket.gethostbyaddr(ip)
                print(f'{yellow}[*]{reset} Reverse DNS Lookup:')
                for hostname in hostnames:
                    print('   - {}'.format(hostname))
            except Exception as e:
                print(f'{yellow}[-]{reset} Reverse DNS lookup failed: {e}')
    except Exception as e:
        print(f'{yellow}[-]{reset} Error getting DNS info: {e}')


def get_geolocation_info(domain):
    try:
        
        print(f'\n{greenx}[++] Getting Geolocation info...')
        print(f'{green}={reset}' * 50)
        ip = socket.gethostbyname(domain)
        if ip:
            response = requests.get(
                'http://geolocation-db.com/json/' + ip).json()
            print('{}[*]{} Country Code: {}'.format(yellow,reset,response['country_code']))
            print('{}[*]{} Country Name: {}'.format(yellow,reset,response['country_name']))
            print('{}[*]{} City: {}'.format(yellow,reset,response['city']))
            print('{}[*]{} Postal: {}'.format(yellow,reset,response['postal']))
            print('{}[*]{} Latitude: {}'.format(yellow,reset,response['latitude']))
            print('{}[*]{} Longitude: {}'.format(yellow,reset,response['longitude']))
            print('{}[*]{} IPv4: {}'.format(yellow,reset,response['IPv4']))
            print('{}[*]{} State: {}'.format(yellow,reset,response['state']))

    except Exception as e:
        print('{}[-]{} Error getting Geolocation info: {}'.format(red,reset,e))


def get_shodan_info(domain):
    try:
        
        print(f'\n{greenx}[++] Getting Shodan info...')
        print(f'{green}={reset}' * 50)
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
        print(f'\n{greenx}[++] Extracting Email Addresses...')
        print(f'{green}={reset}' * 50)
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        emails = set()
        for email in soup.find_all('a', href=True):
            if 'mailto:' in email['href']:
                emails.add(email['href'].replace('mailto:', ''))
        if emails:
            for email in emails:
                print('{}[*]{} Email: {}'.format(yellow,reset,email))
        else:
            print(f'{red}[-]{yellow} No email addresses found on the webpage.')
    except Exception as e:
        print('{}[-]{} Error extracting email addresses: {}'.format(red,reset,e))






# Function to get website title


def get_website_title(url):
    try:
        print(f'\n{greenx}[++] Getting Website Title...')
        print(f'{green}={reset}' * 50)
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        title = soup.title.string.strip() if soup.title else 'N/A'
        print('{}[*]{} Website Title: {}'.format(yellow,reset,title))
    except Exception as e:
        print('{}[-]{} Error getting website title: {}'.format(red,reset,e))


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
