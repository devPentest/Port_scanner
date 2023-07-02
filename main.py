import scapy.all as scapy
import subprocess
import nmap


def scan_network(ip_range):
    # Scan network with Scapy
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered, _ = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)

    # Display active hosts
    print("Active hosts on the network:")
    print("IP\t\t\tMAC Address")
    print("-----------------------------------------")
    for result in answered:
        print(result[1].psrc + "\t\t" + result[1].hwsrc)

    # Return scan result
    return answered


def vulnerability_scan(ip):
    # Execute vulnerability scan with Nmap using subprocess
    print("Vulnerabilities detected on host {}: ".format(ip))
    command = f"nmap -p- --script vulners --script-args vulners.showall {ip}"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    output, _ = process.communicate()

    # Display scan result
    print(output.decode())


def scan_host(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments='-sV')

    if nm[ip].state() == 'up':
        print(f"Host {ip} is online.")
        print("Open ports:")
        for port in nm[ip]['tcp'].keys():
            service = nm[ip]['tcp'][port]['name']
            version = nm[ip]['tcp'][port]['version']
            print(f"Port {port}: Service {service}, Version {version}")

            if 'script_results' in nm[ip]['tcp'][port]:
                # If 'script_results' key exists, display script results
                script_results = nm[ip]['tcp'][port]['script_results']
                print("Script results:")
                for script_name, script_output in script_results.items():
                    print(f"{script_name}: {script_output}")
            else:
                print("No scripts were executed for this port.")
    else:
        print(f"Host {ip} is offline.")


# Example usage: Scan the local network (192.168.1.0/24) and perform vulnerability scan for each active host
network_range = "192.168.1.0/24"
active_hosts = scan_network(network_range)
print("-----------------------------------------")
for result in active_hosts:
    vulnerability_scan(result[1].psrc)

# Example usage: Scan a specific host
host = "192.168.1.1"
scan_host(host)
