
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from threading import Lock
import json

from scapy.all import IP, TCP, UDP

BASE_DIR = Path(__file__).resolve().parent
ALERTS_FILE = BASE_DIR / "alerts.json"

PORT_SCAN_THRESHOLD = 10
CONNECTION_THRESHOLD = 20
WINDOW_SECONDS = 10

recent_ports = defaultdict(deque)
recent_connections = defaultdict(deque)
alert_keys = {}
events_lock = Lock()


def get_events():
    """Read alerts shared between the detector and dashboard."""
    try:
        with events_lock:
            with ALERTS_FILE.open("r", encoding="utf-8") as file:
                data = json.load(file)
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def record_event(source_ip, destination_ip, event_type, severity, details):
    """Save an alert to the shared JSON file."""
    event = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "event_type": event_type,
        "severity": severity,
        "details": details,
    }

    with events_lock:
        existing = get_events_unlocked()
        existing.append(event)
        existing = existing[-1000:]

        with ALERTS_FILE.open("w", encoding="utf-8") as file:
            json.dump(existing, file, indent=2)

    print(f"[{severity}] {event_type}: {source_ip} -> {destination_ip}")


def get_events_unlocked():
    """Read the JSON file while the caller holds events_lock."""
    try:
        with ALERTS_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def detect_packet(packet):
    """Inspect packets and identify suspicious TCP connection patterns."""
    if IP not in packet:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    now = datetime.now().timestamp()

    if TCP not in packet:
        if UDP in packet:
            return
        return

    destination_port = int(packet[TCP].dport)
    flags = packet[TCP].flags

    # Only count initial TCP SYN packets.
    if "S" not in flags or "A" in flags:
        return

    ports = recent_ports[source_ip]
    connections = recent_connections[source_ip]

    ports.append((now, destination_port))
    connections.append(now)

    while ports and now - ports[0][0] > WINDOW_SECONDS:
        ports.popleft()

    while connections and now - connections[0] > WINDOW_SECONDS:
        connections.popleft()

    unique_ports = len({port for _, port in ports})
    connection_count = len(connections)

    if unique_ports >= PORT_SCAN_THRESHOLD:
        key = (source_ip, "Possible TCP port scan")
        if now - alert_keys.get(key, 0) > WINDOW_SECONDS:
            alert_keys[key] = now
            record_event(
                source_ip,
                destination_ip,
                "Possible TCP port scan",
                "High",
                f"{unique_ports} unique destination ports in "
                f"{WINDOW_SECONDS} seconds",
            )

    if connection_count >= CONNECTION_THRESHOLD:
        key = (source_ip, "High connection rate")
        if now - alert_keys.get(key, 0) > WINDOW_SECONDS:
            alert_keys[key] = now
            record_event(
                source_ip,
                destination_ip,
                "High connection rate",
                "Medium",
                f"{connection_count} TCP SYN packets in "
                f"{WINDOW_SECONDS} seconds",
            )
