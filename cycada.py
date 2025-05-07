import os
import json
import xml.etree.ElementTree as ET
from colorama import init, Fore
from jinja2 import Template

# Initialize colorama for shell output
init()

# Function to parse nmap XML output
def parse_nmap_xml(file):
    tree = ET.parse(file)
    root = tree.getroot()

    hosts = []
    
    for host in root.findall('host'):
        ip = host.find('address').attrib['addr']
        hostname = host.find('hostnames').text if host.find('hostnames') is not None else "Unknown"
        ports = []

        for port in host.findall('ports/port'):
            port_num = port.attrib['portid']
            state = port.find('state').attrib['state']
            protocol = port.attrib['protocol']
            service = port.find('service').attrib['name'] if port.find('service') is not None else "Unknown"
            vuln = None  # You can extend with CVE vulnerability fetching here

            ports.append({'port': port_num, 'state': state, 'protocol': protocol, 'service': service, 'vuln': vuln})

        hosts.append({'ip': ip, 'hostname': hostname, 'ports': ports})

    return hosts

# Function to parse EyeWitness JSON reports
def parse_eyewitness_report(eyewitness_dir):
    eyewitness_data = []

    for root, dirs, files in os.walk(eyewitness_dir):
        for file in files:
            if file.endswith(".json"):
                with open(os.path.join(root, file), "r") as f:
                    data = json.load(f)
                    eyewitness_data.append(data)

    return eyewitness_data

# Function to combine nmap and EyeWitness data
def combine_data(nmap_data, eyewitness_data):
    for host in nmap_data:
        for port in host['ports']:
            if port['service'] in ['http', 'https']:  # We care about web services
                screenshot = None
                for ew in eyewitness_data:
                    if ew['host'] == host['ip'] and str(port['port']) in ew['screenshot']:
                        screenshot = ew['screenshot']
                        break
                port['screenshot'] = screenshot

    return nmap_data

# Function to print shell output (color-coded)
def print_shell_report(nmap_data):
    for host in nmap_data:
        print(f"{Fore.CYAN}{host['hostname']} ({host['ip']}){Fore.RESET}")
        
        for port in host['ports']:
            print(f"  {Fore.GREEN}[+] Port: {port['port']}/{port['protocol']} - {port['service']}{Fore.RESET}")
            
            if port['state'] == 'open':
                print(f"    {Fore.GREEN}[+] Status: Open{Fore.RESET}")
            else:
                print(f"    {Fore.RED}[-] Status: Closed{Fore.RESET}")
                
            if port.get('screenshot'):
                print(f"    {Fore.YELLOW}[!] Screenshot available: {port['screenshot']}{Fore.RESET}")
            
            if port.get('vuln'):
                print(f"    {Fore.RED}[!] Vulnerability: {port['vuln']}{Fore.RESET}")
        
        print("\n" + "-"*50)

# Function to generate HTML report using Jinja2
def generate_html_report(nmap_data):
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Recon Report</title>
        <style>
            body { font-family: Arial, sans-serif; }
            .open { color: green; }
            .closed { color: red; }
            .vulnerable { color: yellow; }
            .screenshot { margin-top: 10px; }
            .screenshot img { width: 300px; }
        </style>
    </head>
    <body>
        <h1>Recon Report</h1>
        {% for host in data %}
        <div>
            <h2>{{ host.hostname }} ({{ host.ip }})</h2>
            <ul>
                {% for port in host.ports %}
                    <li class="{{ 'open' if port.state == 'open' else 'closed' }}">
                        Port: {{ port.port }}/{{ port.protocol }} - {{ port.service }}
                        {% if port.screenshot %}
                            <div class="screenshot">
                                <img src="{{ port.screenshot }}" alt="Screenshot of {{ port.service }}"/>
                            </div>
                        {% endif %}
                    </li>
                {% endfor %}
            </ul>
        </div>
        {% endfor %}
    </body>
    </html>
    """
    template = Template(html_template)
    html_content = template.render(data=nmap_data)

    with open("recon_report.html", "w") as f:
        f.write(html_content)
    print(f"{Fore.GREEN}HTML report generated: recon_report.html{Fore.RESET}")

# Main function to run nmap, EyeWitness, and generate reports
def generate_report(target):
    # Step 1: Run nmap and EyeWitness (shell commands)
    print(f"{Fore.YELLOW}Running nmap scan...{Fore.RESET}")
    os.system(f"nmap -sV -O -T4 -oX scan.xml {target}")

    print(f"{Fore.YELLOW}Running EyeWitness...{Fore.RESET}")
    os.system(f"EyeWitness --web -f {target}_http_services.txt --no-prompt -d eyewitness_report")

    # Step 2: Parse nmap and EyeWitness
    print(f"{Fore.YELLOW}Parsing nmap and EyeWitness reports...{Fore.RESET}")
    nmap_data = parse_nmap_xml('scan.xml')
    eyewitness_data = parse_eyewitness_report('eyewitness_report')

    # Step 3: Combine the data
    print(f"{Fore.YELLOW}Combining nmap and EyeWitness data...{Fore.RESET}")
    combined_data = combine_data(nmap_data, eyewitness_data)

    # Step 4: Generate shell output
    print(f"{Fore.YELLOW}Generating shell output...{Fore.RESET}")
    print_shell_report(combined_data)

    # Step 5: Generate HTML report
    print(f"{Fore.YELLOW}Generating HTML report...{Fore.RESET}")
    generate_html_report(combined_data)

# Run the report generation on a given target
if __name__ == "__main__":
    target = input("Enter target IP or domain: ")
    generate_report(target)
