#!/usr/bin/env python3
"""
packet_sniffer.py — Educational packet sniffer using Scapy.

Usage examples:
  sudo python3 packet_sniffer.py --iface eth0 --filter "tcp port 80" --outfile captured.pcap
  python3 packet_sniffer.py --count 50 --verbose

Requirements:
  pip install scapy

Notes:
  - Run as root/Administrator.
  - Only sniff networks you are authorized to.
"""

import argparse
from datetime import datetime
import sys
import textwrap
from binascii import hexlify

from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, Raw, wrpcap, PcapWriter

# Size of payload preview (bytes)
PAYLOAD_PREVIEW = 64

def printable_ascii(b: bytes, max_len=64):
    """Return printable ASCII subset of bytes (non-printable shown as '.')"""
    b = b[:max_len]
    return ''.join((chr(x) if 32 <= x <= 126 else '.') for x in b)

def format_payload(raw_bytes: bytes, preview=PAYLOAD_PREVIEW):
    if not raw_bytes:
        return ""
    h = hexlify(raw_bytes[:preview]).decode()
    ascii_preview = printable_ascii(raw_bytes, preview)
    more = "..." if len(raw_bytes) > preview else ""
    return f"hex={h}{more} | ascii='{ascii_preview}'{more}"

def detect_protocol(pkt):
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(IP) or pkt.haslayer(IPv6):
        return "IP"
    return pkt.__class__.__name__

def summarize_packet(pkt, verbose=False):
    ts = datetime.utcfromtimestamp(pkt.time).isoformat() + "Z"
    src = pkt[IP].src if pkt.haslayer(IP) else (pkt[IPv6].src if pkt.haslayer(IPv6) else "N/A")
    dst = pkt[IP].dst if pkt.haslayer(IP) else (pkt[IPv6].dst if pkt.haslayer(IPv6) else "N/A")
    proto = detect_protocol(pkt)
    length = len(pkt)
    sport = dport = ""
    if pkt.haslayer(TCP):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport

    # payload (Raw layer)
    payload = b""
    if pkt.haslayer(Raw):
        try:
            payload = bytes(pkt[Raw].load)
        except Exception:
            payload = b""

    base = f"{ts}\t{src}:{sport}\t->\t{dst}:{dport}\t{proto}\tlen={length}"
    if verbose:
        pl = format_payload(payload)
        return f"{base}\n    payload: {pl}"
    else:
        return base

def make_packet_handler(writer=None, verbose=False):
    def handle(pkt):
        try:
            print(summarize_packet(pkt, verbose=verbose))
        except Exception as e:
            print(f"[!] Error summarizing packet: {e}", file=sys.stderr)

        # write to pcap if writer provided
        if writer:
            try:
                writer.write(pkt)
            except Exception as e:
                print(f"[!] Error writing packet to pcap: {e}", file=sys.stderr)

    return handle

def parse_args():
    ap = argparse.ArgumentParser(
        description="Educational packet sniffer (Scapy). Use responsibly.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""Examples:
  sudo python3 packet_sniffer.py --iface eth0 --filter "tcp port 80" --outfile out.pcap
  python3 packet_sniffer.py --count 100 --verbose
""")
    )
    ap.add_argument("--iface", "-i", help="Interface to capture on (default: scapy chooses)", default=None)
    ap.add_argument("--count", "-c", type=int, help="Number of packets to capture (0 = unlimited)", default=0)
    ap.add_argument("--filter", "-f", help="BPF filter (libpcap syntax), e.g. 'tcp port 80'", default=None)
    ap.add_argument("--outfile", "-o", help="Write captured packets to pcap file", default=None)
    ap.add_argument("--promisc", action="store_true", help="Enable promiscuous mode (OS dependent). You still need permissions.")
    ap.add_argument("--verbose", "-v", action="store_true", help="Show payload preview and extra details")
    return ap.parse_args()

def main():
    args = parse_args()

    print("[*] Packet Sniffer (educational). Make sure you have permission to capture on this network.")
    if args.outfile:
        print(f"[*] Packets will be saved to: {args.outfile}")
        pcap_writer = PcapWriter(args.outfile, append=True, sync=True)
    else:
        pcap_writer = None

    # Start sniffing
    try:
        sniff_kwargs = {
            "prn": make_packet_handler(writer=pcap_writer, verbose=args.verbose),
            "store": False
        }
        if args.iface:
            sniff_kwargs["iface"] = args.iface
        if args.filter:
            sniff_kwargs["filter"] = args.filter
        if args.count and args.count > 0:
            sniff_kwargs["count"] = args.count
        # Note: promiscuous is often default; scapy doesn't expose a direct param to toggle on all platforms
        print(f"[*] Starting capture (iface={args.iface}, filter={args.filter}, count={args.count or 'unlimited'})")
        sniff(**sniff_kwargs)
    except PermissionError:
        print("[!] Permission denied — run the script as root/Administrator.", file=sys.stderr)
    except KeyboardInterrupt:
        print("\n[*] Capture interrupted by user.")
    except Exception as e:
        print(f"[!] Error while sniffing: {e}", file=sys.stderr)
    finally:
        if pcap_writer:
            try:
                pcap_writer.close()
                print(f"[*] PCAP saved to {args.outfile}")
            except Exception:
                pass

if __name__ == "__main__":
    main()
    from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        if TCP in packet:
            proto_name = "TCP"
        elif UDP in packet:
            proto_name = "UDP"
        else:
            proto_name = str(protocol)

        print(f"Source: {src_ip} → Destination: {dst_ip} | Protocol: {proto_name}")

print("Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=packet_callback, count=10)  # Capture 10 packets


# output

# python -m venv venv
# Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
# venv\Scripts\Activate.ps1
# pip install scapy
# python packet_sniffer.py
# ctrl+c to stop
