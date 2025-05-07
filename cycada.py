import os
import xml.etree.ElementTree as ET
from termcolor import colored

# Define the colors
def colorize_port_state(port_state):
    if port_state == 'open':
        return colored(port_state, 'green')
    elif port_state == 'closed':
        return colored(port_state, 'red')
    else:
        return colored(port_state, 'yellow')

def colorize_service(service):
    if 'http' in service:
        return colored(service, 'yellow')
    elif 'ftp' in service:
        return colored(service, 'blue')
    elif 'ssh' in service:
        return colored(service, 'cyan')
    else:
        return colored(service, 'white')

# Load nmap scan result XML
def parse_nmap_output(nmap_output_file):
    try:
        tree = ET.parse(nmap_output_file)
        root = tree.getroot()
        for host in root.findall('host'):
            # Extract IP address
            ip_address = host.find('address').get('addr')
            print(f"\n{colored('Scanning IP:', 'cyan')} {colored(ip_address, 'yellow')}")
            for port in host.findall('ports/port'):
                port_id = port.get('portid')
                state = port.find('state').get('state')
                service = port.find('service').get('name')
                print(f"  {colored('Port:', 'green')} {port_id} - {colorize_port_state(state)} - {colorize_service(service)}")
    except Exception as e:
        print(f"Error parsing the nmap output: {str(e)}")

# Run the script with an example nmap output
nmap_output = 'scan_result.xml'  # Ensure you have a valid nmap output XML file
parse_nmap_output(nmap_output)
