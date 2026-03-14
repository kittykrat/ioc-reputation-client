#!/usr/bin/env python3
# This line tells Linux to run the script using Python 3 using Python 3 when executed directly.

import requests
#Imports the library which lets us make HTTP requests to APIs.

import sys
#Imports the sys module so we can access command-line arguments (sys.argv)

API_KEY = "INSERT_YOUR_API_KEY_HERE"
#This stores the Virustotal API key.
#This key authenticates you to the Virustotal API.

def enrich_ip(ip_address):
        # We create a function called "enrich_ip"
        # It takes one argument: the IP address we want to look up.

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        #This builds the API request URL.
        #The f-string inserts the IP address into the URL.

        headers = {
                "accept": "application/json",
                # Tells the API we want the response in JSON format.

                "x-apikey": API_KEY
                # Sends your VirusTotal API key in the request header
                # This authenticates your request.
        }

        try:
           response = requests.get(url, headers=headers)
           response.raise_for_status() # Raises an error for bad status codes
           return response.json()
        except requests.exceptions.RequestException as e:
           print(f"Error: {e}")
           return None

if __name__ == "__main__":
    # For CLI, you could take the IP as a command-line argument
    if len(sys.argv) > 1:
        ip = sys.argv[1]
        result = enrich_ip(ip)
        if result:
            print(result)  # You'll want to format this nicely for your CLI
    else:
        print("Usage: python script.py <IP_ADDRESS>")

