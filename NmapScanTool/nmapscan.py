import scapy.all as scapy
import argparse
import ipaddress

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def print_result(results_list):
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

def is_valid_ip_range(ip_range):
    try:
        ipaddress.ip_network(ip_range, strict=False)
        return True
    except ValueError:
        return False

def main():
    parser = argparse.ArgumentParser(description="Network Scanner")
    parser.add_argument("-t", "--target", dest="target", help="Target IP address or range (e.g., 192.168.1.0/24)")
    options = parser.parse_args()

    if not options.target:
        parser.print_help()
        exit()

    if not is_valid_ip_range(options.target):
        print("Invalid IP range. Please use CIDR notation (e.g., 192.168.1.0/24).")
        exit()

    scan_result = scan(options.target)
    print_result(scan_result)

if __name__ == "__main__":
    main()