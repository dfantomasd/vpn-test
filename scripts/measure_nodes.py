"""Bounded HTTP latency/download probes through each eligible proxy.

Requires a trusted Mihomo binary and curl. Does not alter system VPN settings.
"""
import argparse
import concurrent.futures
import datetime
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import statistics
from pathlib import Path

try:
    from . import build_clients as clients
except ImportError:
    import build_clients as clients

DOWNLOAD_BYTES = 262144
PING_URL = "https://www.gstatic.com/generate_204"
SPEED_URL = f"https://speed.cloudflare.com/__down?bytes={DOWNLOAD_BYTES}"


def curl_probe(port, url, size_limit):
    command = ["curl", "--silent", "--show-error", "--proxy", f"socks5h://127.0.0.1:{port}",
               "--noproxy", "", "--connect-timeout", "5", "--max-time", "12",
               "--max-filesize", str(size_limit), "--output", os.devnull,
               "--write-out", "%{json}", url]
    result = subprocess.run(command, capture_output=True, text=True, timeout=15)
    try:
        data = json.loads(result.stdout)
    except ValueError:
        data = {}
    data["curl_exit"] = result.returncode
    return data


def measure(item, binary):
    name, outbound = item
    key = clients.node_key(outbound)
    result = {"name": name, "status": "unavailable"}
    try:
        _, proxy = clients.connection(name, outbound)
    except (ValueError, KeyError, TypeError, IndexError):
        result["reason"] = "unsupported_conversion"
        return key, result
    if proxy is None:
        result["reason"] = "unsupported_advanced_xhttp"
        return key, result
    proxy["name"] = "probe"
    with tempfile.TemporaryDirectory(prefix="vpn-best-probe-") as directory:
        with socket.socket() as available:
            available.bind(("127.0.0.1", 0))
            port = available.getsockname()[1]
        config = {"mixed-port": port, "bind-address": "127.0.0.1", "allow-lan": False,
                  "mode": "rule", "log-level": "silent", "proxies": [proxy],
                  "rules": ["MATCH,probe"]}
        path = Path(directory) / "probe.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        process = subprocess.Popen([binary, "-d", directory, "-f", str(path)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 5
            ready = False
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.15):
                        ready = True
                        break
                except OSError:
                    time.sleep(0.1)
            if not ready:
                result["reason"] = "proxy_core_not_ready"
                return key, result
            ping = curl_probe(port, PING_URL, 4096)
            if ping.get("curl_exit") or ping.get("http_code") != 204:
                result["reason"] = "latency_probe_failed"
                return key, result
            result["latency_ms"] = round(ping["time_starttransfer"] * 1000)
            samples = [curl_probe(port, SPEED_URL, DOWNLOAD_BYTES) for _ in range(3)]
            speeds = [s["speed_download"] * 8 / 1_000_000 for s in samples
                      if not s.get("curl_exit") and s.get("http_code") == 200
                      and s.get("size_download") == DOWNLOAD_BYTES and s.get("speed_download", 0) > 0]
            if len(speeds) < 2:
                result["reason"] = "speed_probe_failed"
                return key, result
            result.update({"status": "ok", "speed_mbps": round(statistics.median(speeds), 2),
                           "sample_bytes": DOWNLOAD_BYTES, "successful_samples": len(speeds), "samples_mbps": speeds})
        except (OSError, subprocess.TimeoutExpired, KeyError) as exc:
            result["reason"] = type(exc).__name__
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    return key, result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mihomo", default="mihomo")
    parser.add_argument("--workers", type=int, choices=range(1, 5), default=2)
    args = parser.parse_args()
    binary = shutil.which(args.mihomo)
    if not binary:
        raise SystemExit("Mihomo binary not found")
    catalog = clients.read_json(clients.ROOT / "whitelist_configs_combined.json")
    selected, _ = clients.foreign_nodes(catalog)
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(measure, item, binary) for item in selected]
        for future in concurrent.futures.as_completed(futures):
            key, result = future.result()
            results[key] = result
            print(result["name"], result["status"], flush=True)
    report = {"measured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "vantage": "GitHub Actions" if os.environ.get("GITHUB_ACTIONS") else "local machine",
              "download_bytes_per_node": DOWNLOAD_BYTES * 3,
              "latency_method": "HTTPS time to first byte through proxy (not ICMP)",
              "speed_method": "Median of 3 bounded 256 KiB HTTPS samples; minimum 2 successes",
              "nodes": results}
    (clients.ROOT / "measurements.json").write_text(clients.json_text(report), encoding="utf-8")


if __name__ == "__main__":
    main()
