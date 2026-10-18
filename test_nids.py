
import json
from pathlib import Path

from scapy.all import IP, TCP
from nids_engine import detect_packet, get_events

# Clear previous test alerts.
alerts_file = Path(__file__).resolve().parent / "alerts.json"
alerts_file.write_text("[]", encoding="utf-8")

print("Testing NIDS detection rules with simulated packets...")

# Simulate TCP SYN packets to 12 different destination ports.
for port in range(80, 92):
    packet = (
        IP(src="192.0.2.10", dst="192.0.2.20")
        / TCP(sport=45000, dport=port, flags="S")
    )
    detect_packet(packet)
# Simulate a high rate of TCP connection attempts.
for _ in range(25):
    packet = (
        IP(src="192.0.2.30", dst="192.0.2.40")
        / TCP(sport=45001, dport=443, flags="S")
    )
    detect_packet(packet)

print("\nDetected events:")

events = get_events()

for event in events:
    print(
        f"{event['severity']} | {event['event_type']} | "
        f"{event['source_ip']} -> {event['destination_ip']} | "
        f"{event['details']}"
    )


port_scan_pass = any(
    event["event_type"] == "Possible TCP port scan"
    for event in events
)

connection_rate_pass = any(
    event["event_type"] == "High connection rate"
    for event in events
)

if port_scan_pass:
    print("PASS: Port scan detection rule triggered.")
else:
    print("FAIL: Port scan detection rule did not trigger.")

if connection_rate_pass:
    print("PASS: High connection-rate rule triggered.")
else:
    print("FAIL: High connection-rate rule did not trigger.")

if port_scan_pass and connection_rate_pass:
    print("\nALL TESTS PASSED.")
else:
    print("\nSOME TESTS FAILED.")

if events:
    print("PASS: Alerts saved to alerts.json.")

