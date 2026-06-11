import logging
from scapy.all import IP, UDP, ICMP, DNS, DNSQR, sr1


# Protocol-specific UDP probes
UDP_PROBES = {
    53:  "dns",
    123: "ntp",
    161: "snmp",
    137: "netbios",
}


def _dns_probe(target: str, timeout: float):
    """Fix #4: Use scapy DNS layer for proper DNS query — gets real reply."""
    pkt = IP(dst=target) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="google.com"))
    return sr1(pkt, timeout=timeout, verbose=False)


def _ntp_probe(target: str, timeout: float):
    """NTP client request packet."""
    payload = b"\x1b" + b"\x00" * 47
    pkt = IP(dst=target) / UDP(dport=123) / payload
    return sr1(pkt, timeout=timeout, verbose=False)


def _snmp_probe(target: str, timeout: float):
    """SNMP v1 GetRequest for sysDescr OID."""
    payload = bytes.fromhex(
        "302602010004067075626c6963a019020400"
        "0000000201000201003011300f060b2b0601"
        "020101010100000500"
    )
    pkt = IP(dst=target) / UDP(dport=161) / payload
    return sr1(pkt, timeout=timeout, verbose=False)


def _netbios_probe(target: str, timeout: float):
    """NetBIOS Name Service query."""
    payload = (
        b"\xaa\xbb"
        b"\x00\x00"
        b"\x00\x01"
        b"\x00\x00\x00\x00\x00\x00"
        b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
        b"\x00\x21\x00\x01"
    )
    pkt = IP(dst=target) / UDP(dport=137) / payload
    return sr1(pkt, timeout=timeout, verbose=False)


def _generic_probe(target: str, port: int, timeout: float):
    """Empty UDP packet for ports with no specific probe."""
    pkt = IP(dst=target) / UDP(dport=port)
    return sr1(pkt, timeout=timeout, verbose=False)


def _send_probe(target: str, port: int, timeout: float):
    """Dispatch to the right probe function."""
    probe_type = UDP_PROBES.get(port)
    if probe_type == "dns":
        return _dns_probe(target, timeout)
    elif probe_type == "ntp":
        return _ntp_probe(target, timeout)
    elif probe_type == "snmp":
        return _snmp_probe(target, timeout)
    elif probe_type == "netbios":
        return _netbios_probe(target, timeout)
    else:
        return _generic_probe(target, port, timeout)


def scan_udp_port(target: str, port: int, timeout: float = 2.0) -> dict:
    """
    Scan a single UDP port using scapy.
    Returns dict with status: 'open', 'closed', 'open|filtered', or 'error'
    """
    result = {
        "target": target,
        "port": port,
        "protocol": "udp",
        "status": "open|filtered",
        "service": get_udp_service(port),
        "response": "N/A"
    }

    try:
        response = _send_probe(target, port, timeout)

        if response is None:
            result["status"] = "open|filtered"

        elif response.haslayer(DNS):
            # Fix #4: DNS layer reply = confirmed open
            result["status"] = "open"
            result["response"] = f"DNS reply (answers={response[DNS].ancount})"

        elif response.haslayer(UDP):
            # Any UDP reply = confirmed open
            result["status"] = "open"
            result["response"] = repr(bytes(response[UDP].payload)[:50])

        elif response.haslayer(ICMP):
            icmp = response[ICMP]
            if int(icmp.type) == 3 and int(icmp.code) == 3:
                result["status"] = "closed"
            else:
                result["status"] = "filtered"

    except Exception as e:
        logging.error(f"UDP scan error on {target}:{port} → {e}")
        result["status"] = "error"

    return result


def get_udp_service(port: int) -> str:
    udp_services = {
        53:   "DNS",
        67:   "DHCP",
        68:   "DHCP-Client",
        69:   "TFTP",
        123:  "NTP",
        137:  "NetBIOS-NS",
        138:  "NetBIOS-DGM",
        161:  "SNMP",
        162:  "SNMP-Trap",
        500:  "IKE/VPN",
        514:  "Syslog",
        520:  "RIP",
        1194: "OpenVPN",
        1900: "UPnP",
        4500: "IPSec-NAT",
        5353: "mDNS",
    }
    return udp_services.get(port, "Unknown")


# Top UDP ports to scan by default (most commonly exploited)
TOP_UDP_PORTS = [
    53, 67, 68, 69, 123, 137, 138, 161, 162,
    500, 514, 520, 1194, 1900, 4500, 5353
]
