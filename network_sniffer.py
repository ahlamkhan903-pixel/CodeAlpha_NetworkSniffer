
"""
  Project  : Basic Network Sniffer
  Author   : Ahlam 
  Intern   : CodeAlpha Cybersecurity Internship
  Date     : March 2026
  Purpose  : Capture and analyze live network packets
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime
import argparse
import sys

# these functions add color to the output
class Color:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def red(s):    return f"{Color.RED}{s}{Color.RESET}"
def green(s):  return f"{Color.GREEN}{s}{Color.RESET}"
def yellow(s): return f"{Color.YELLOW}{s}{Color.RESET}"
def cyan(s):   return f"{Color.CYAN}{s}{Color.RESET}"
def bold(s):   return f"{Color.BOLD}{s}{Color.RESET}"


# counts how many packets are captured
packet_count = 0

# this function runs every time a packet is captured
def process_packet(packet):
    """
    This function is automatically called by Scapy
    every time a new packet is captured.
    We inspect the packet and print useful details.
    """
    global packet_count
    packet_count += 1

    timestamp = datetime.now().strftime("%H:%M:%S")

# check if packet has an IP address
    if IP in packet:
        src_ip   = packet[IP].src      # sender's IP address
        dst_ip   = packet[IP].dst      # receiver's IP address
        protocol = packet[IP].proto    # protocol number (6=TCP, 17=UDP, 1=ICMP)

        print(bold(f"\n[Packet #{packet_count}]") + f"  {timestamp}")
        print(f"  {'Source IP':<16}: {green(src_ip)}")
        print(f"  {'Dest IP':<16}: {cyan(dst_ip)}")

    # Show if packet is TCP
        if TCP in packet:
            src_port = packet[TCP].sport   # source port number
            dst_port = packet[TCP].dport   # destination port number
            flags    = packet[TCP].flags   # TCP flags (SYN, ACK, FIN, etc.)
            print(f"  {'Protocol':<16}: {yellow('TCP')}")
            print(f"  {'Src Port':<16}: {src_port}")
            print(f"  {'Dst Port':<16}: {dst_port}")
            print(f"  {'TCP Flags':<16}: {flags}")
        # check what service is using this port
            print(f"  {'Service':<16}: {identify_service(dst_port)}")

    # Show if packet is UDP
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"  {'Protocol':<16}: {yellow('UDP')}")
            print(f"  {'Src Port':<16}: {src_port}")
            print(f"  {'Dst Port':<16}: {dst_port}")
            print(f"  {'Service':<16}: {identify_service(dst_port)}")

    # Show if packet is ICMP (ping)
        elif ICMP in packet:
            icmp_type = packet[ICMP].type
            print(f"  {'Protocol':<16}: {red('ICMP')}")
            print(f"  {'ICMP Type':<16}: {icmp_type_name(icmp_type)}")

        #Other IP Protocols 
        else:
            print(f"  {'Protocol':<16}: Other (#{protocol})")

    # It will show the data inside the packet
        if Raw in packet:
            payload = packet[Raw].load
            # Show only first 80 bytes to keep output readable
            preview = payload[:80]
            try:
            # try to read the payload as text
                decoded = preview.decode("utf-8", errors="replace")
                print(f"  {'Payload':<16}: {decoded!r}")
            except Exception:
            # if not readable show as hex
                print(f"  {'Payload (hex)':<16}: {preview.hex()}")

        print("  " + "─" * 55)



# this function finds service name from port number
def identify_service(port):
    """Returns a human-readable service name for common port numbers."""
    services = {
        20:   "FTP Data",
        21:   "FTP Control",
        22:   "SSH",
        23:   "Telnet",
        25:   "SMTP (Email)",
        53:   "DNS",
        67:   "DHCP Server",
        68:   "DHCP Client",
        80:   "HTTP (Web)",
        110:  "POP3 (Email)",
        143:  "IMAP (Email)",
        443:  "HTTPS (Secure Web)",
        3306: "MySQL Database",
        3389: "RDP (Remote Desktop)",
        8080: "HTTP Alternate",
    }
    return services.get(port, f"Unknown (port {port})")


# this function explains ICMP type numbers
def icmp_type_name(icmp_type):
    types = {
        0: "Echo Reply (ping response)",
        3: "Destination Unreachable",
        8: "Echo Request (ping)",
        11: "Time Exceeded",
    }
    return types.get(icmp_type, f"Type {icmp_type}")

# This will show summary when user press Ctrl+C
def print_summary():
    print("\n")
    print(bold("=" * 55))
    print(bold(" CAPTURE SUMMARY"))
    print(bold("=" * 55))
    print(f"  Total packets captured : {green(str(packet_count))}")
    print(bold("=" * 55))
    print("  Sniffer stopped. Goodbye!")
    print()

# This is main function to start the program
def main():
  # take input from user in command line
    parser = argparse.ArgumentParser(
        description="CodeAlpha Basic Network Sniffer — captures live network packets"
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Number of packets to capture (0 = unlimited, press Ctrl+C to stop)"
    )
    parser.add_argument(
        "-f", "--filter",
        type=str,
        default="ip",
        help='BPF filter string (e.g. "tcp", "udp", "icmp", "port 80"). Default: "ip"'
    )
    args = parser.parse_args()

    # show title on the screen at the start
    print(bold(cyan("""
      CodeAlpha — Basic Network Sniffer           
      Cybersecurity Internship Task 1             
""")))
    print(f"  Filter   : {yellow(args.filter)}")
    print(f"  Count    : {yellow(str(args.count) if args.count else 'Unlimited')}")
    print(f"  Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("  Press Ctrl+C to stop capturing.\n")
    print("─" * 57)

    try:
       # sniff() captures live packets from the network
       # prn    : function to call for each captured packet
       # filter : what type of packets to capture
       # count  : how many packets to capture (0 = no limit)
       # store  : False = don't save packets in memory save in RAM
        sniff(
            prn=process_packet,
            filter=args.filter,
            count=args.count,
            store=False
        )
    except KeyboardInterrupt:
        # user stopped the program
        pass
    finally:
        print_summary()


# Run the program
if __name__ == "__main__":
    main()
