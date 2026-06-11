import scapy.all as scapy
import logging


# TTL-based OS fingerprinting reference table
# Real-world TTL values decay hop-by-hop, so we use ranges
TTL_OS_MAP = [
    (range(0, 65),   "Linux / Android"),
    (range(65, 129), "Windows"),
    (range(129, 193), "Cisco / Network Device"),
    (range(193, 256), "Solaris / AIX"),
]


def get_os_from_ttl(ttl: int) -> str:
    """Map a TTL value to a probable OS."""
    for ttl_range, os_name in TTL_OS_MAP:
        if ttl in ttl_range:
            return os_name
    return "Unknown"


def fingerprint_os(ip: str, timeout: int = 2) -> dict:
    """
    Send an ICMP ping to the target and analyze the TTL
    in the response to guess the operating system.

    Returns a dict with keys: ttl, os_guess, confidence
    """
    result = {
        "ttl": None,
        "os_guess": "Unknown",
        "confidence": "low"
    }

    try:
        # Craft ICMP echo request
        pkt = scapy.IP(dst=ip) / scapy.ICMP()
        response = scapy.sr1(pkt, timeout=timeout, verbose=False)

        if response is None:
            logging.warning(f"No ICMP response from {ip} — host may be blocking pings")
            return result

        ttl = response.ttl
        result["ttl"] = ttl
        result["os_guess"] = get_os_from_ttl(ttl)

        # Confidence: TTL values far from boundaries are more reliable
        # e.g. TTL=64 or TTL=128 are textbook values → high confidence
        if ttl in (64, 128, 255):
            result["confidence"] = "high"
        elif ttl > 100 or ttl < 70:
            result["confidence"] = "medium"
        else:
            result["confidence"] = "low"

    except Exception as e:
        logging.error(f"OS fingerprint failed for {ip}: {e}")

    return result
