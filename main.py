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
                "status": "open",
                "service": service,
                "banner": banner if banner else "N/A"
            }
            tqdm.write(f"[+] {target_ip}:{port} OPEN ({service})")
            logging.info(f"Port {port} open on {target_ip}")

            with lock:
                results.append(result)

    except Exception as e:
        logging.error(f"Error scanning {target_ip}:{port}: {e}")
    finally:
        with lock:
            progress.update(1)


def main():
    parser = argparse.ArgumentParser(description="Custom Port Scanner with Banner Detection")
    parser.add_argument("--target", help="Target IP or domain")
    parser.add_argument("--network", help="Network range (e.g. 192.168.1.0/24)")
    parser.add_argument("--start", type=int, default=1, help="Start port")
    parser.add_argument("--end", type=int, default=1000, help="End port")
    parser.add_argument("--timestamp", action="store_true", help="Add timestamp to output file")
    parser.add_argument("--threads", type=int, default=100, help="Max concurrent threads (default: 100)")
    parser.add_argument("--no-os-detect", action="store_true", help="Skip OS fingerprinting")
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

    for target in targets:
        ip = target["ip"]
        mac = target["mac"]
        os_info = target.get("os_guess", "N/A")
        print(f"\n🚀 Scanning {ip} ({mac}) — OS: {os_info}\n")

        total_ports = args.end - args.start + 1

        global progress
        progress = tqdm(total=total_ports, desc=f"{ip}", ncols=80)

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

    # ✅ Include OS fingerprint data in final JSON
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
