
from scapy.all import sniff, IP
from nids_engine import detect_packet

def handle_packet(packet):
    if IP in packet:
        detect_packet(packet)

if __name__ == "__main__":
    print("=" * 55)
    print("NETWORK INTRUSION DETECTION SYSTEM")
    print("=" * 55)
    print("Live packet monitoring started.")
    print("Monitoring IP traffic for suspicious TCP patterns.")
    print("Alerts will be saved to alerts.json.")
    print("Press Ctrl+C to stop monitoring.")
    print()

    try:
        sniff(
            prn=handle_packet,
            store=False
        )
    except PermissionError:
        print("Permission denied. Run the terminal with appropriate privileges.")
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")
