#!/usr/bin/env python3
# This line tells Linux to run the script using Python 3 using Python 3 when executed directly.

import requests
# Imports the library which lets us make HTTP requests to APIs.

import sys
# Imports the sys module so we can access command-line arguments (sys.argv)
# Imported so we do not have to ask the user for the IP in our script, we can take it directly on the command line.

import os
import argparse
import json

API_KEY = "[YOUR API KEY HERE]"
# This stores the Virustotal API key.
# This key authenticates you to the Virustotal API.

# Define some ANSI codes
RESET = "\033[0m"
BOLD = "\033[1m"
BLUE = "\033[34m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"

def enrich_ip(ip_address):
        # We create a function called "enrich_ip"
        # It takes one argument: the IP address we want to look up.

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        # This builds the API request URL.
        # The f-string inserts the IP address into the URL.

        headers = {
                "accept": "application/json",
                # Tells the API we want the response in JSON format.

                "x-apikey": API_KEY
                # Sends your VirusTotal API key in the request header
                # This authenticates your request.
        }

        try:
           # Try block catches errors that may happen during the request.

           response = requests.get(url, headers=headers)
           # Sends an HTTP GET request to the VirusTotal API.
           # headers=headers includes our API key.

           response.raise_for_status()
           # If the request failed (404, 403, etc), this raises an exception.


           return response.json()
           # Converts the API response from JSON text into a Python dictionary.

        except requests.exceptions.RequestException as e:
           # If any network/API error occurs, it will be caught here.

           print(f"Error: {e}")
           # Print the error message

           return None
           # Return none to indicate failure.


if __name__ == "__main__":
        # This ensures the code below only runs if the script is executed directly (not imported as a module)
    if len(sys.argv) > 1:
        # sys.argv contains command-line arguments.
        # sys.argv[0] is the script name.
        # sys.argv[1] would be the IP address.


        ip = sys.argv[1]
        # Store the IP address provided by the user

        result = enrich_ip(ip)
        # Call our function and pass the IP address

        if result:
             #print(json.dumps(result, indent=2))
#             print("Keys:", result.keys())
#             print("Keys inside 'data':", result['data'].keys())
#             print(result['data']['id'].keys())
#             print(result['data']['type'].keys())
#             print(result['data']['links'].keys())
#             print(result['data']['attributes'].keys())

## Basic Information

             ip_address = result.get('data', {}).get('id', 'Not found')
             ip_country = result.get('data', {}).get('attributes', {}).get('country', 'Not found')
             ip_asn = result.get('data', {}).get('attributes', {}).get('asn', 'Not found')
             ip_as_owner = result.get('data', {}).get('attributes', {}).get('as_owner', 'Not found')
             ip_network = result.get('data', {}).get('attributes', {}).get('network', 'Not found')

##  Reputation & Detection

             ip_reputation = result.get('data', {}).get('attributes', {}).get('reputation', 'Not found')
             ip_las = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', 'Not found') 
             ip_lar = result.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
             priority_vendors = ['Kaspersky', 'Sophos', 'ESET', 'BitDefender', 'AlienVault']

## Additional Context

             ip_tags = result.get('data', {}).get('attributes', {}).get('tags', 'Not found')
             ip_whois = result.get('data', {}).get('attributes', {}).get('whois', 'Not found')
             ip_lhc = result.get('data', {}).get('attributes', {}).get('last_https_certificate', 'Not found')


## When & How Often

             ip_lad = result.get('data', {}).get('attributes', {}).get('last_analysis_date', 'Not found')
             ip_lmd = result.get('data', {}).get('attributes', {}).get('last_analysis_modification_date', 'Not found')


#             ip_whois = result.get('data', {}).get('attributes', {}).get('whois', 'Not found')
#             ip_type = result.get('data', {}).get('type', 'Not found')
#             ip_links = result.get('data', {}).get('links', 'Not found')
#             ip_attribute = result.get('data', {}).get('attributes', 'Not found')

             print("")
             print("----------------")
             print(f"{BOLD}IntelScout v0.1{RESET}")
             print("----------------")
             print("")
             print("")
             print("Basic Information")
             print("-----------------")
             print("")
             print(f"{BOLD}{BLUE}IP Address:{RESET}", ip_address)
             print(f"{BOLD}{BLUE}Country code:{RESET}", ip_country)
             print(f"{BOLD}{BLUE}Autonomous System Number:{RESET}", ip_asn)
             print(f"{BOLD}{BLUE}Organization:{RESET}", ip_as_owner)
             print(f"{BOLD}{BLUE}CIDR Range:{RESET}", ip_network)
             print("")
             print("")
             print("Reputation & Detection")
             print("-----------------")
             print("")
             print(f"{BOLD}{BLUE}IP Reputation:{RESET}", ip_reputation)
             print(f"{BOLD}{BLUE}Last Analysis Stats:{RESET}", ip_las)
#            print(f"{BOLD}{BLUE}Last Analysis Results:{RESET}", ip_lar)
             if result:
             # Summary stats
                 stats = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                 print(f"Malicious: {stats.get('malicious', 0)}, Suspicious: {stats.get('suspicious', 0)}, Harmless: {stats.get('harmless', 0)}")

                 # Priority vendor details
                 analysis = result.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
                 priority_vendors = ['Kaspersky', 'Sophos', 'ESET', 'BitDefender', 'AlienVault']
                 print("\nPriority Vendor Verdicts:")
                 for vendor in priority_vendors:
                     if vendor in analysis:
                        data = analysis[vendor]
                        print(f"  {vendor}: {data.get('category', '?')} ({data.get('result', '?')})")
                 else:
                        print(f"  {vendor}: not present")
             print("")
             print("")
             print("Additional Context")
             print("-----------------")
             print("")
             print(f"{BOLD}{BLUE}Tags:{RESET}", ip_tags)
             print(f"{BOLD}{BLUE}WHOIS:{RESET}", ip_whois)
             print(f"{BOLD}{BLUE}Last HTTPS Certificate:{RESET}", ip_lhc)
             print("")
             print("")
             print("When & How Often")
             print("-----------------")
             print("")
             print(f"{BOLD}{BLUE}Last Analysis Date:{RESET}", ip_lad)
             print(f"{BOLD}{BLUE}Last Modification Date:{RESET}", ip_lmd)

#             print(ip_whois)
             #print(ip_type)
             #print(ip_links)
             #print(ip_attribute)
        # Print the raw JSON response
        # TO DO: FORMAT THIS NICELY
    else:
        # If the user didn't provide an IP
        print("Usage: python script.py <IP_ADDRESS>")
        # Print instructions for correct usage
 
