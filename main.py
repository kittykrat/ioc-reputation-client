#!/usr/bin/env python3
# This line tells Linux to run the script using Python 3 using Python 3 when executed directly.

import requests
# Imports the library which lets us make HTTP requests to APIs.

import sys
# Imports the sys module so we can access command-line arguments (sys.argv)
# Imported so we do not have to ask the user for the IP in our script, we can take it directly on the command line.

API_KEY = "INSERT_YOUR_API_KEY_HERE"
# This stores the Virustotal API key.
# This key authenticates you to the Virustotal API.

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
            print(result)
        # Print the raw JSON response
        # TO DO: FORMAT THIS NICELY
    else:
        # If the user didn't provide an IP
        print("Usage: python script.py <IP_ADDRESS>")
        # Print instructions for correct usage
