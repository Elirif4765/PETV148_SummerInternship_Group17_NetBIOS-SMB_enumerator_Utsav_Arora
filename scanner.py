import subprocess
import ipaddress
import socket
from datetime import datetime

#using datetime to make a filename with timestamp
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
filename = f"report_{timestamp}.txt"

#checks the host machine for its cidr notation, then from that, grabs the subnet/network range to scan.
def get_local_subnet():
    command = "ip addr show eth0 | grep 'inet '"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    cidr_string = result.stdout.strip().split()[1]
    subnet = ipaddress.ip_network(cidr_string, strict=False)
    return subnet

#scans the whole network range that was grabbed in get_local_subnet(), while also calling other functions to perform the main heavy lifting of the program
def scan_network(subnet):
    count = 0
    start_time = datetime.now()
    print(f"==[Scanning {str(subnet)} for SMB shares and live hosts]==\n")
    with open(filename, "w") as log:
        for ip in subnet.hosts():
            ip = str(ip)
            port_status = scan_ports(ip)
            if port_status[139] == 'Filtered' and port_status[445] == 'Filtered':
                continue
            count += 1
            nbts_data = run_nbtscan(ip)
            if port_status[139] == 'Open' or port_status[445] == 'Open':
                share_data = run_smbclient(ip)
            else:
                share_data = None
            print_output(ip, port_status, nbts_data, share_data, log)
    elapsed = (datetime.now()-start_time).seconds
    print(f"==[Scan completed in {elapsed}s]==\n==[Live Hosts found: {count}]==")

#called by scan_network to check status of ports 139 and 445 on individual IPs in the network. 
def scan_ports(ip):
    port_status = {}
    ports = [139,445]
    for port in ports:
        socks = None
        try:
            socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socks.settimeout(0.5)
            socks.connect((ip, port))
            port_status[port] = 'Open'
        except socket.timeout:
            port_status[port] = 'Filtered'
        except (ConnectionRefusedError, OSError):
            port_status[port] = 'Closed'
        finally:
            if socks:
                socks.close()
    return port_status

#called by scan_network, to print the data of the recon on the terminal and to also direct the output to an external log file
def print_output(ip, port_status, nbts_data, share_data, log):
    port_status_139 = port_status[139]
    port_status_445 = port_status[445]

    if nbts_data is None:
        hostname = 'Unknown'
        workgroup = 'Unknown'
    else:
        hostname = nbts_data["hostname"]
        workgroup = nbts_data["workgroup"]
    print(f"{ip} - Host:{hostname} Workgroup:{workgroup} - PORT 139: {port_status_139} | PORT 445: {port_status_445}")

    if share_data is None:
        if port_status_445=='Open' or port_status_139=='Open':
            print("     [+] SMB Security: Requires Authentication (Access Denied)")
    elif len(share_data) == 0:
        print("     [-] No anonymous custom shares found")
    else:
        print("     [!] WARNING: ANONYMOUS SHARES FOUND!")
        for share in share_data:
            print(f"      -> {share}")
    print()
    print("=" * 60, file=log)
    print(f"SECURITY AUDIT REPORT FOR TARGET: {ip}", file=log)
    print("=" * 60, file=log)
    print(f"[*] NetBIOS Hostname : {hostname}", file=log)
    print(f"[*] NetBIOS Workgroup: {workgroup}", file=log)
    print(f"[*] Port 139 Status  : {port_status_139}", file=log)
    print(f"[*] Port 445 Status  : {port_status_445}", file=log)
    print("-" * 60, file=log)

    if share_data is None:
        if port_status_445 == 'Open' or port_status_139 == 'Open':
            print("[+] SMB Security Assessment:", file=log)
            print("    Status: SECURE (Requires Authentication)", file=log)
            print("    Notice: Target rejected anonymous share listing requests.", file=log)

    elif len(share_data) == 0:
        print("[-] SMB Security Assessment:", file=log)
        print("    Status: POTENTIAL RISK (Anonymous Session Allowed)", file=log)
        print("    Notice: Connected successfully, but no custom disk shares were found.", file=log)
    else:
        print("[!] VULNERABILITY ALERT: Anonymous Share Enumeration Successful!", file=log)
        print("    Risk Level: HIGH", file=log)
        print("    The following custom file shares are readable without password verification:", file=log)
        for share in share_data:
            print(f"     -> {share}", file=log)
    print("\n\n", file=log)

#a wrapper that runs nbtscan on quiet mode on individual IPs, then grabs the hostname and workgroup (if returned by the command)
def run_nbtscan(ip):
    scan_results = {}
    command = ["nbtscan","-q",ip]
    result = subprocess.run(command, capture_output=True, text=True)
    result = result.stdout.strip()
    if result=='':
        return None
    nbtscan_parts = result.split()
    if(len(nbtscan_parts)>3):
        scan_results["hostname"]= nbtscan_parts[1]
        scan_results["workgroup"] = nbtscan_parts[3]
        return scan_results
    else:
        return None

#a wrapper that runs smbclient that uses -L to list all shares, and to also attempt anonymous login (-N), which means no password.
def run_smbclient(ip):
    shares = []
    command = ["smbclient","-L",ip,"-N"]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        return None
    result = result.stdout.splitlines()
    for line in result:
        if 'Disk' in line:
            indie_words = line.strip().split()
            share_name = indie_words[0]
            if share_name != 'print$':
                shares.append(share_name)
    return shares


subnet = get_local_subnet()
scan_network(subnet)