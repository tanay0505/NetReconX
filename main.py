import argparse
import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from tqdm import tqdm
from datetime import datetime
from scanner.core import scan_port
from scanner.banner import grab_banner
from scanner.utils import get_service
from scanner.logger import setup_logger
from scanner.network import scan_network
from scanner.os_detect import fingerprint_os
from scanner.udp import scan_udp_port, TOP_UDP_PORTS
from scanner.cve import extract_product_version, lookup_cves

results = []
lock = Lock()
progress = None


def worker(target_ip, mac, port):
    global progress
    try:
        if scan_port(target_ip, port):
            banner = grab_banner(target_ip, port)
            service = get_service(port)
            result = {
                "target": target_ip,
                "mac": mac,
                "port": port,
                "protocol": "tcp",
                "status": "open",
                "service": service,
                "banner": banner if banner else "N/A"
            }
            tqdm.write(f"[+] {target_ip}:{port}/tcp OPEN ({service})")
            logging.info(f"TCP port {port} open on {target_ip}")

            with lock:
                results.append(result)

    except Exception as e:
        logging.error(f"Error scanning {target_ip}:{port}: {e}")
    finally:
        with lock:
            progress.update(1)


def run_cve_lookups(scan_results, max_results=5):
    """
    Post-scan pass: extract product/version from each TCP result's banner,
    deduplicate, and query the NVD API for known CVEs.
    Mutates scan_results in place, adding a 'cves' key where applicable.
    """
    # 1. Build a deduplicated list of (product, version) to look up
    lookups = {}  # (product, version) -> list of result dicts to update

    for r in scan_results:
        if r.get("protocol") != "tcp":
            continue
        pv = extract_product_version(r.get("banner", ""))
        if not pv:
            continue
        key = (pv[0].lower(), (pv[1] or "").lower())
        lookups.setdefault(key, []).append(r)

    if not lookups:
        print("[*] No identifiable service/version strings found for CVE lookup.\n")
        return

    print(f"\n[*] Running CVE lookups for {len(lookups)} unique service/version combo(s)...")
    print("    (NVD public API is rate-limited to ~5 requests / 30s)\n")

    cve_progress = tqdm(total=len(lookups), desc="CVE lookup", ncols=80)

    for (product, version), target_results in lookups.items():
        cves = lookup_cves(product, version if version else None, max_results=max_results)

        if cves:
            tqdm.write(f"[!] {product} {version or ''} → {len(cves)} CVE(s) found")
            for c in cves:
                tqdm.write(f"      {c['id']}  [{c['severity']}]  score={c['score']}")
        else:
            tqdm.write(f"[ ] {product} {version or ''} → no known CVEs found")

        for r in target_results:
            r["detected_product"] = product
            r["detected_version"] = version or "N/A"
            r["cves"] = cves

        cve_progress.update(1)

    cve_progress.close()
    print()


def main():
    parser = argparse.ArgumentParser(description="Network Reconnaissance Tool")
    parser.add_argument("--target", help="Target IP or domain")
    parser.add_argument("--network", help="Network range (e.g. 192.168.1.0/24)")
    parser.add_argument("--start", type=int, default=1, help="Start port (TCP)")
    parser.add_argument("--end", type=int, default=1000, help="End port (TCP)")
    parser.add_argument("--timestamp", action="store_true", help="Add timestamp to output file")
    parser.add_argument("--threads", type=int, default=100, help="Max concurrent threads (default: 100)")
    parser.add_argument("--no-os-detect", action="store_true", help="Skip OS fingerprinting")
    parser.add_argument("--udp", action="store_true", help="Also run UDP scan on top common ports")
    parser.add_argument("--udp-ports", help="Custom UDP ports to scan (e.g. 53,161,123)", default=None)
    parser.add_argument("--udp-timeout", type=float, default=2.0, help="UDP probe timeout in seconds (default: 2.0)")
    parser.add_argument("--cve", action="store_true", help="Look up known CVEs for detected service banners (uses NVD API)")
    parser.add_argument("--cve-results", type=int, default=5, help="Max CVEs to fetch per service/version (default: 5)")
    args = parser.parse_args()

    setup_logger()
    logging.info("Scan started")

    targets = []
    os_detect = not args.no_os_detect

    # 🟣 network mode
    if args.network:
        print(f"\n🔍 Scanning network: {args.network}\n")
        devices = scan_network(args.network, os_detect=os_detect)
        targets = devices

    # 🟢 single target mode
    elif args.target:
        target_entry = {"ip": args.target, "mac": "N/A"}

        if os_detect:
            print(f"[*] Fingerprinting OS for {args.target}...")
            fp = fingerprint_os(args.target)
            target_entry["os_guess"] = fp["os_guess"]
            target_entry["ttl"] = fp["ttl"]
            target_entry["os_confidence"] = fp["confidence"]
            print(f"    → {fp['os_guess']} (TTL={fp['ttl']}, confidence={fp['confidence']})\n")

        targets.append(target_entry)

    else:
        print("❌ Please provide --target or --network")
        return

    print(f"\n🎯 Targets: {[t['ip'] for t in targets]}\n")

    # Determine UDP ports to scan
    if args.udp_ports:
        udp_ports = [int(p.strip()) for p in args.udp_ports.split(",")]
    else:
        udp_ports = TOP_UDP_PORTS

    for target in targets:
        ip = target["ip"]
        mac = target["mac"]
        os_info = target.get("os_guess", "N/A")
        print(f"\n🚀 Scanning {ip} ({mac}) — OS: {os_info}\n")

        # --- TCP Scan ---
        total_ports = args.end - args.start + 1
        global progress
        progress = tqdm(total=total_ports, desc=f"{ip} TCP", ncols=80)

        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {
                executor.submit(worker, ip, mac, port): port
                for port in range(args.start, args.end + 1)
            }
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logging.error(f"Thread error on port {futures[future]}: {e}")

        progress.close()

        # --- UDP Scan ---
        if args.udp:
            print(f"\n[*] Running UDP scan on {ip} ({len(udp_ports)} ports)...\n")

            udp_progress = tqdm(total=len(udp_ports), desc=f"{ip} UDP", ncols=80)

            with ThreadPoolExecutor(max_workers=min(args.threads, len(udp_ports))) as executor:
                futures = {
                    executor.submit(scan_udp_port, ip, port, args.udp_timeout): port
                    for port in udp_ports
                }
                for future in as_completed(futures):
                    try:
                        r = future.result()
                        if r["status"] != "closed":
                            r["mac"] = mac
                            tqdm.write(f"[+] {ip}:{r['port']}/udp {r['status'].upper()} ({r['service']})")
                            logging.info(f"UDP port {r['port']} {r['status']} on {ip}")
                            with lock:
                                results.append(r)
                    except Exception as e:
                        logging.error(f"UDP thread error on port {futures[future]}: {e}")
                    finally:
                        udp_progress.update(1)

            udp_progress.close()

    # --- CVE Lookup (post-scan pass) ---
    if args.cve:
        run_cve_lookups(results, max_results=args.cve_results)

    # filename handling
    if args.network:
        safe_target = args.network.replace(".", "_").replace("/", "_")
    else:
        safe_target = args.target.replace(".", "_")

    if args.timestamp:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"results/{safe_target}_{timestamp}.json"
    else:
        output_file = f"results/{safe_target}.json"

    os.makedirs("results", exist_ok=True)

    output = {
        "targets": targets,
        "open_ports": results
    }

    with open(output_file, "w") as f:
        json.dump(output, f, indent=4)

    logging.info("Scan finished")
    print("\n✅ Scan complete!")
    print(f"📄 JSON saved to: {output_file}")


if __name__ == "__main__":
    main()
