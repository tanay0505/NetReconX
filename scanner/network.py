import scapy.all as scapy
from scanner.os_detect import fingerprint_os


def scan_network_once(ip_range, timeout=5):
    """
    Performs a single ARP scan.
    """
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(
        arp_request_broadcast,
        timeout=timeout,
        verbose=False
    )[0]

    devices = []
    for element in answered_list:
        device_info = {
            "ip": element[1].psrc,
            "mac": element[1].hwsrc
        }
        devices.append(device_info)
    return devices


def scan_network(ip_range, attempts=3, os_detect=True):
    """
    Performs multiple ARP scans, merges results,
    and optionally fingerprints the OS of each device.
    """
    all_devices = {}

    for i in range(attempts):
        print(f"[+] Scan attempt {i+1}/{attempts}...")
        devices = scan_network_once(ip_range)
        for d in devices:
            all_devices[d["ip"]] = d  # deduplicate by IP

    final_devices = list(all_devices.values())
    print(f"\n[+] Found {len(final_devices)} unique devices\n")

    # ✅ OS fingerprinting pass
    if os_detect:
        print("[*] Running OS fingerprinting...\n")
        for device in final_devices:
            ip = device["ip"]
            fp = fingerprint_os(ip)
            device["os_guess"] = fp["os_guess"]
            device["ttl"] = fp["ttl"]
            device["os_confidence"] = fp["confidence"]
            print(f"    {ip} → {fp['os_guess']} (TTL={fp['ttl']}, confidence={fp['confidence']})")
        print()

    return final_devices
