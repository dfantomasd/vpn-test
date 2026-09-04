"""Generate native Happ JSON and Karing Clash YAML from one catalog.

No VPN connections are made. --refresh-rules downloads public classification data.
"""
import argparse
import copy
import datetime
import hashlib
import ipaddress
import json
import re
import socket
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = "https://raw.githubusercontent.com/dfantomasd/vpn-test/main/"
GEO_BASE = "https://raw.githubusercontent.com/KaringX/karing-ruleset/sing/geo/"
RULE_SOURCES = {
    "category-ru.json": GEO_BASE + "geosite/category-ru.json",
    "geoip-ru.json": GEO_BASE + "geoip/ru.json",
}
# These legacy exceptions are not Russian services. Do not leak their traffic.
REMOVE_DIRECT = {
    "whatismyipaddress.com", "ifconfig.me", "ipinfo.io", "browserleaks.com",
    "ipleak.net", "faceit.com", "api.faceit.com", "cdn.faceit.com",
    "steampowered.com", "steamcommunity.com", "steamstatic.com", "steamcontent.com",
    "www.hltv.org",
}
PRIVATE_CIDRS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                 "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10"]


def json_text(value):
    return json.dumps(value, ensure_ascii=False, indent=2) + "\n"


def node_key(outbound):
    data = json.dumps({k: v for k, v in outbound.items() if k != "tag"}, sort_keys=True)
    return hashlib.sha256(data.encode()).hexdigest()


def fresh_metrics(as_of):
    path = ROOT / "measurements.json"
    report = read_json(path) if path.exists() else {}
    return report.get("nodes", {}) if measurements_fresh(report, as_of) else {}


def ranked_nodes(selected, as_of=None):
    measurements = fresh_metrics(as_of or build_time())
    def score(item):
        metric = measurements.get(node_key(item[1]), {})
        if metric.get("status") != "ok":
            return -1
        return metric["speed_mbps"] / (1 + metric["latency_ms"] / 200)
    ranked = sorted(selected, key=score, reverse=True)
    decorated = []
    for index, (name, outbound) in enumerate(ranked):
        metric = measurements.get(node_key(outbound), {})
        if metric.get("status") == "ok":
            label = f"тест GitHub: ≈{metric['speed_mbps']:.2f} Мбит/с · {metric['latency_ms']} мс"
        else:
            label = "тест GitHub: нет замера"
        decorated.append((name + " | " + label, outbound))
    return decorated


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def refresh_rules():
    downloaded = {}
    for filename, url in RULE_SOURCES.items():
        with urllib.request.urlopen(url, timeout=40) as response:
            data = response.read()
        value = json.loads(data)
        if not value.get("rules"):
            raise ValueError("Empty geodata: " + filename)
        downloaded[filename] = data
    directory = ROOT / "rules"
    directory.mkdir(exist_ok=True)
    for filename, data in downloaded.items():
        (directory / filename).write_bytes(data)
    (directory / "sources.json").write_text(json_text({
        filename: {"url": RULE_SOURCES[filename], "sha256": hashlib.sha256(data).hexdigest()}
        for filename, data in downloaded.items()
    }), encoding="utf-8")


def routing_policy(catalog):
    domains = set()
    for config in catalog:
        for rule in config.get("routing", {}).get("rules", []):
            if rule.get("outboundTag") == "direct":
                domains.update(rule.get("domain", []))
    domains -= {"domain:" + name for name in REMOVE_DIRECT}
    domains.discard("regexp:.*\\.by$")
    domains.update({"domain:ru", "domain:su", "domain:xn--p1ai",
                    "geosite:category-ru", "geosite:private",
                    "domain:nspk.ru", "domain:sbp.nspk.ru"})
    return {
        "Name": "Russia", "GlobalProxy": "true",
        "RemoteDNSType": "DoH", "RemoteDNSDomain": "https://cloudflare-dns.com/dns-query",
        "RemoteDNSIP": "1.1.1.1", "DomesticDNSType": "DoU",
        "DomesticDNSDomain": "", "DomesticDNSIP": "77.88.8.8",
        "Geoipurl": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
        "Geositeurl": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
        "DnsHosts": {"cloudflare-dns.com": "1.1.1.1"},
        "DirectSites": sorted(domains), "DirectIp": ["geoip:private", "geoip:ru"] + PRIVATE_CIDRS,
        "ProxySites": [], "ProxyIp": [], "BlockSites": [], "BlockIp": [],
        "DomainStrategy": "IPIfNonMatch", "FakeDNS": "false",
    }


def nodes(catalog):
    """Export VLESS only, including during DNS checks and hourly measurements."""
    result, seen = [], set()
    ordered = sorted(catalog, key=lambda c: sum(o.get("protocol") == "vless"
                                              for o in c["outbounds"]) != 1)
    for config in ordered:
        proxies = [o for o in config["outbounds"] if o.get("protocol") == "vless"]
        for number, outbound in enumerate(proxies, 1):
            signature = json.dumps({k: v for k, v in outbound.items() if k != "tag"}, sort_keys=True)
            if signature in seen:
                continue
            seen.add(signature)
            name = config["remarks"]
            if len(proxies) > 1:
                name += f" / endpoint {number}"
            result.append((name, outbound))
    if not result:
        raise ValueError("No VLESS nodes")
    return result


def authority(host, port):
    if ":" in host:
        host = "[" + host + "]"
    return f"{host}:{port}"


def server_host(outbound):
    settings = outbound["settings"]
    return settings["vnext"][0]["address"] if "vnext" in settings else settings["address"]


def resolve_server_names():
    resolved = {}
    for _, outbound in nodes(read_json(ROOT / "whitelist_configs_combined.json")):
        host = server_host(outbound)
        try:
            ipaddress.ip_address(host)
            continue
        except ValueError:
            pass
        if host not in resolved:
            try:
                resolved[host] = sorted({item[4][0] for item in socket.getaddrinfo(
                    host, None, type=socket.SOCK_STREAM)})
            except socket.gaierror:
                resolved[host] = []  # Unknown location: exclude, do not guess.
    (ROOT / "rules/server_dns.json").write_text(json_text(resolved), encoding="utf-8")
    addresses = set()
    for _, outbound in nodes(read_json(ROOT / "whitelist_configs_combined.json")):
        host = server_host(outbound)
        try:
            addresses.add(str(ipaddress.ip_address(host)))
        except ValueError:
            addresses.update(resolved.get(host, []))
    def registration(address):
        url = "https://rdap.db.ripe.net/ip/" + address
        try:
            with urllib.request.urlopen(url, timeout=20) as response:
                value = json.load(response)
            return address, {"country": value.get("country"), "name": value.get("name"), "url": url}
        except Exception:
            return address, {"country": None, "url": url, "lookup_failed": True}
    with ThreadPoolExecutor(max_workers=4) as pool:
        registrations = dict(pool.map(registration, sorted(addresses)))
    (ROOT / "rules/server_registration.json").write_text(json_text(registrations), encoding="utf-8")


def foreign_nodes(catalog):
    networks = [ipaddress.ip_network(cidr) for rule in read_json(ROOT / "rules/geoip-ru.json")["rules"]
                for cidr in rule["ip_cidr"]]
    dns = read_json(ROOT / "rules/server_dns.json")
    registrations = read_json(ROOT / "rules/server_registration.json")
    accepted, excluded = [], []
    for name, outbound in nodes(catalog):
        host = server_host(outbound)
        reason = None
        if "🇷🇺" in name or re.search(r"россия|russia", name, re.IGNORECASE):
            reason = "Russian server label"
        try:
            addresses = [ipaddress.ip_address(host)]
        except ValueError:
            addresses = [ipaddress.ip_address(ip) for ip in dns.get(host, [])]
        if not addresses:
            reason = reason or "Unresolved server hostname; location unknown"
        elif any(ip.version == net.version and ip in net for ip in addresses for net in networks):
            reason = reason or "Russian entry IP (GeoIP RU)"
        if any(registrations.get(str(ip), {}).get("country") == "RU" for ip in addresses):
            reason = reason or "Russian network registration (RDAP RU)"
        if any(not registrations.get(str(ip), {}).get("country") or
               registrations.get(str(ip), {}).get("lookup_failed") for ip in addresses):
            reason = reason or "Unknown network registration country"
        if reason:
            excluded.append({"name": name, "server": host, "reason": reason})
        else:
            accepted.append((name, outbound))
    if not accepted:
        raise ValueError("No non-Russian nodes remain")
    return accepted, excluded


def happ_json_configs(catalog, as_of=None):
    """Preserve native Happ/Xray configs; filter whole profiles fail-closed.

    Removing an outbound from a balancer or whitelist chain can change semantics,
    so a profile is excluded if any of its VLESS endpoints is Russian/unknown.
    """
    accepted_nodes, excluded_nodes = foreign_nodes(catalog)
    accepted_keys = {node_key(outbound) for _, outbound in accepted_nodes}
    excluded_by_key = {node_key(outbound) for _, outbound in nodes(catalog)
                       if node_key(outbound) not in accepted_keys}
    result, excluded_profiles = [], []
    for config in catalog:
        proxy_outbounds = [outbound for outbound in config.get("outbounds", [])
                           if outbound.get("protocol") not in ("freedom", "blackhole")]
        reason = None
        if not proxy_outbounds:
            reason = "No proxy outbound"
        elif any(outbound.get("protocol") != "vless" for outbound in proxy_outbounds):
            reason = "Contains non-VLESS outbound"
        elif any(node_key(outbound) in excluded_by_key for outbound in proxy_outbounds):
            reason = "Contains Russian or location-unknown VLESS endpoint"
        if reason:
            excluded_profiles.append({"name": config.get("remarks", ""), "reason": reason})
        else:
            result.append(config)
    if not result:
        raise ValueError("No safe native Happ profiles remain")
    singles = []
    for config in result:
        proxies = [o for o in config['outbounds'] if o.get('protocol') == 'vless']
        if (len(proxies) == 1 and not config['routing'].get('balancers')
                and not proxies[0].get('proxySettings')
                and not proxies[0].get('streamSettings', {}).get('sockopt', {}).get('dialerProxy')):
            singles.append(copy.deepcopy(config))
    if len(singles) < 2:
        raise ValueError('At least two safe standalone VLESS profiles required for real auto-selection')
    policy = routing_policy(catalog)
    for config in singles:
        proxy = next(o for o in config['outbounds'] if o['protocol'] == 'vless')
        config['routing'] = happ_routing(policy, {'outboundTag': proxy['tag']})
    auto = copy.deepcopy(singles[0])
    auto['remarks'] = '🔄 Авто'
    proxies = []
    for index, config in enumerate(singles):
        outbound = copy.deepcopy(next(o for o in config['outbounds'] if o['protocol'] == 'vless'))
        outbound['tag'] = f'auto-node-{index:03d}'
        proxies.append(outbound)
    auto['outbounds'] = proxies + [o for o in auto['outbounds'] if o['protocol'] != 'vless']
    auto['routing'] = happ_routing(policy, {'balancerTag': 'Auto_Balancer'})
    auto['routing']['balancers'] = [{
        'tag': 'Auto_Balancer', 'selector': ['auto-node-'],
        'strategy': {'type': 'leastLoad', 'settings': {'expected': 1, 'maxRTT': '3s'}},
        'fallbackTag': proxies[0]['tag'],
    }]
    auto.pop('observatory', None)
    auto['burstObservatory'] = {
        'subjectSelector': ['auto-node-'],
        'pingConfig': {'destination': 'https://www.gstatic.com/generate_204',
                       'interval': '1m', 'timeout': '3s', 'sampling': 2},
    }
    return [auto] + singles, excluded_profiles


def happ_routing(policy, target):
    """Telegram takes priority over RU lists; default traffic stays in VPN."""
    return {'domainStrategy': 'IPIfNonMatch', 'rules': [
        {'type': 'field', 'domain': ['geosite:telegram', 'domain:t.me', 'domain:telegram.org'], **target},
        {'type': 'field', 'ip': ['geoip:telegram'], **target},
        {'type': 'field', 'domain': policy['DirectSites'], 'outboundTag': 'direct'},
        {'type': 'field', 'ip': policy['DirectIp'], 'outboundTag': 'direct'},
        {'type': 'field', 'network': 'tcp,udp', **target},
    ]}


def build_time():
    path = ROOT / "build_report.json"
    return (read_json(path).get("generated_at") if path.exists() else None) or datetime.datetime.now(datetime.timezone.utc).isoformat()


def measurements_fresh(report, as_of):
    try:
        age = (datetime.datetime.fromisoformat(as_of) -
               datetime.datetime.fromisoformat(report["measured_at"])).total_seconds()
        return 0 <= age <= 6 * 3600
    except (KeyError, TypeError, ValueError):
        return False


def karing_connections(selected):
    converted, excluded = [], []
    for name, outbound in selected:
        try:
            value = connection(name, outbound)
        except (ValueError, KeyError, TypeError, IndexError) as exc:
            excluded.append({"name": name, "reason": "Unsupported conversion: " + type(exc).__name__})
            continue
        converted.append(value)
    return converted, excluded


def connection(name, outbound):
    stream = outbound.get("streamSettings", {})
    if outbound.get("proxySettings") or stream.get("sockopt", {}).get("dialerProxy"):
        raise ValueError("Chained outbound requires explicit conversion: " + name)
    network = stream.get("network", "tcp")
    security = stream.get("security", "none")
    tls = stream.get("realitySettings" if security == "reality" else "tlsSettings", {})
    if tls.get("allowInsecure"):
        raise ValueError("Refusing insecure TLS: " + name)
    query = {"sni": tls.get("serverName", "")}
    clash = {"name": name, "udp": True}
    if outbound["protocol"] == "vless":
        peers = outbound["settings"]["vnext"]
        if len(peers) != 1 or len(peers[0]["users"]) != 1:
            raise ValueError("Ambiguous VLESS credentials")
        peer, user = peers[0], peers[0]["users"][0]
        host, port, secret = peer["address"], peer["port"], user["id"]
        if user.get("encryption", "none") != "none":
            raise ValueError("Unsupported VLESS encryption")
        query.update({"encryption": "none", "security": security, "type": network,
                      "flow": user.get("flow", ""), "fp": tls.get("fingerprint", "chrome")})
        clash.update({"type": "vless", "server": host, "port": port, "uuid": secret,
                      "network": network, "tls": security != "none",
                      "servername": tls.get("serverName", ""),
                      "client-fingerprint": tls.get("fingerprint", "chrome")})
        if user.get("flow"):
            clash["flow"] = user["flow"]
        if security == "reality":
            query.update({"pbk": tls["publicKey"], "sid": tls.get("shortId", "")})
            clash["reality-opts"] = {"public-key": tls["publicKey"], "short-id": tls.get("shortId", "")}
        elif security not in ("tls", "none"):
            raise ValueError("Unsupported security: " + security)
        if network == "xhttp":
            xhttp = stream["xhttpSettings"]
            query.update({"path": xhttp.get("path", "/"), "host": xhttp.get("host", ""),
                          "mode": xhttp.get("mode", "auto")})
            if xhttp.get("extra"):
                query["extra"] = json.dumps(xhttp["extra"], separators=(",", ":"))
            # Clash/Mihomo representation. Karing support depends on the app version.
            opts = {k: xhttp[k] for k in ("path", "host", "mode") if k in xhttp}
            extra = xhttp.get("extra", {})
            if "xPaddingBytes" in extra:
                opts["x-padding-bytes"] = extra["xPaddingBytes"]
            if "xmux" in extra:
                names = {"cMaxReuseTimes": "c-max-reuse-times", "maxConcurrency": "max-concurrency",
                         "maxConnections": "max-connections", "hKeepAlivePeriod": "h-keep-alive-period",
                         "hMaxRequestTimes": "h-max-request-times", "hMaxReusableSecs": "h-max-reusable-secs"}
                opts["reuse-settings"] = {names[k]: v for k, v in extra["xmux"].items()}
            clash["xhttp-opts"] = opts
            if set(extra) - {"xmux", "xPaddingBytes"}:
                # Preserve the complete URI for Happ, but do not silently lose
                # advanced parameters in Karing's partially compatible importer.
                clash = None
        elif network != "tcp":
            raise ValueError("Unsupported transport: " + network)
        scheme = "vless"
    elif outbound["protocol"] == "hysteria" and outbound["settings"].get("version") == 2:
        host, port = outbound["settings"]["address"], outbound["settings"]["port"]
        secret = stream["hysteriaSettings"]["auth"]
        clash.update({"type": "hysteria2", "server": host, "port": port, "password": secret,
                      "sni": tls.get("serverName", ""), "skip-cert-verify": False})
        scheme = "hysteria2"
    else:
        raise ValueError("Unsupported protocol: " + outbound["protocol"])
    if tls.get("alpn"):
        query["alpn"] = ",".join(tls["alpn"])
        if clash is not None:
            clash["alpn"] = tls["alpn"]
    link = (scheme + "://" + urllib.parse.quote(secret, safe="") + "@" + authority(host, port)
            + "?" + urllib.parse.urlencode(query, quote_via=urllib.parse.quote)
            + "#" + urllib.parse.quote(name, safe=""))
    return link, clash


def expanded_rules(policy, geo_sites, geo_ips):
    exact, suffix, regex = set(), set(), set()
    for site in policy["DirectSites"]:
        kind, value = site.split(":", 1)
        if kind == "domain":
            suffix.add(value)
        elif kind == "full":
            exact.add(value)
        elif kind == "regexp":
            regex.add(value)
        elif kind != "geosite":
            raise ValueError("Unknown rule " + site)
    for rule in geo_sites["rules"]:
        if set(rule) - {"domain", "domain_suffix"}:
            raise ValueError("New geosite schema; review before publishing")
        exact.update(rule.get("domain", []))
        suffix.update(s.lstrip(".") for s in rule.get("domain_suffix", []))
    suffix -= REMOVE_DIRECT
    exact -= REMOVE_DIRECT
    # .ru/.su/.рф suffix rules cover all legacy regexes for these zones.
    # Remaining regexes are retained as explicit rules in Happ; Karing domain
    # lists cover these banks/services without relying on unsupported regex rules.
    ips = set(PRIVATE_CIDRS)
    for rule in geo_ips["rules"]:
        if set(rule) != {"ip_cidr"}:
            raise ValueError("Unexpected GeoIP schema")
        ips.update(rule["ip_cidr"])
    rules = ["DOMAIN," + d + ",DIRECT" for d in sorted(exact)]
    rules += ["DOMAIN-SUFFIX," + d + ",DIRECT" for d in sorted(suffix)]
    for cidr in sorted(ips):
        version = ipaddress.ip_network(cidr).version
        rules.append(("IP-CIDR6," if version == 6 else "IP-CIDR,") + cidr + ",DIRECT")
    rules.append("MATCH,VPN_BEST")
    return rules


def yaml_document(config):
    # JSON flow values are YAML-compatible. Keep top-level YAML keys so the
    # client's format detection recognizes Clash rather than sing-box JSON.
    lines = []
    for key, value in config.items():
        if isinstance(value, list):
            lines.append(key + ":")
            lines.extend("  - " + json.dumps(item, ensure_ascii=False) for item in value)
        else:
            lines.append(key + ": " + json.dumps(value, ensure_ascii=False))
    return "\n".join(lines) + "\n"


def build(as_of=None):
    as_of = as_of or build_time()
    catalog = read_json(ROOT / "whitelist_configs_combined.json")
    policy = routing_policy(catalog)
    selected, russian_excluded = foreign_nodes(catalog)
    happ_configs, happ_excluded = happ_json_configs(catalog, as_of)
    selected = ranked_nodes(selected, as_of)
    converted, conversion_excluded = karing_connections(selected)
    happ = json_text(happ_configs)
    proxies = [proxy for _, proxy in converted if proxy is not None]
    names = [p["name"] for p in proxies]
    choices = names  # Measured best stays first in both the list and selector.
    auto = "🏆 Автовыбор на устройстве"
    config = {"mode": "rule", "proxies": proxies,
              "proxy-groups": [{"name": "VPN_BEST", "type": "select", "proxies": [auto] + choices},
                               {"name": auto, "type": "url-test", "proxies": choices,
                                "url": "https://www.gstatic.com/generate_204", "interval": 600,
                                "tolerance": 50}],
              "rules": expanded_rules(policy, read_json(ROOT / "rules/category-ru.json"),
                                      read_json(ROOT / "rules/geoip-ru.json"))}
    excluded = [urllib.parse.unquote(urllib.parse.urlsplit(link).fragment)
                for link, proxy in converted if proxy is None]
    report = {"generated_at": as_of, "happ_mode": "one device-side auto profile plus manual servers",
              "karing_conversion_excluded": conversion_excluded,
              "allowed_protocols": ["vless"], "happ_format": "native Xray JSON array",
              "happ_profiles": len(happ_configs), "happ_excluded_profiles": happ_excluded,
              "karing_nodes": len(proxies),
              "karing_rules": len(config["rules"]), "karing_excluded_advanced_xhttp": excluded,
              "excluded_russian_or_unknown_servers": russian_excluded,
              "measurements_available": (ROOT / "measurements.json").exists(),
              "note": "URI exports expand balancers into individual nodes; Karing XHTTP requires device testing."}
    karing_text = yaml_document(config)
    report["karing_publication"] = "generated"
    if not proxies:
        # Never replace a usable subscription with an empty proxy selector.
        previous = ROOT / "subscription_karing.txt"
        if not previous.exists():
            raise ValueError("No supported Karing nodes and no previous subscription to preserve")
        karing_text = previous.read_text(encoding="utf-8")
        report["karing_publication"] = "previous subscription retained: no supported nodes"
    return {"subscription.txt": happ, "subscription_karing.txt": karing_text,
            "routing_russia.json": json_text(policy), "build_report.json": json_text(report)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--refresh-rules", action="store_true")
    parser.add_argument("--resolve-servers", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.refresh_rules:
        if args.check:
            parser.error("--check does not allow --refresh-rules")
        refresh_rules()
    if args.resolve_servers or args.refresh_rules:
        if args.check:
            parser.error("--check does not allow --resolve-servers")
        resolve_server_names()
    outputs = build(None if args.check else datetime.datetime.now(datetime.timezone.utc).isoformat())
    for filename, content in outputs.items():
        path = ROOT / filename
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                raise SystemExit("Generated file is stale: " + filename)
        else:
            path.write_text(content, encoding="utf-8")
    if not args.check:
        readme = ROOT / "README.md"
        measured = read_json(ROOT / "measurements.json").get("measured_at", "нет")
        status = ("<!-- refresh-status:start -->\nПоследняя сборка (UTC): "
                  + json.loads(outputs["build_report.json"])["generated_at"]
                  + ". Последний замер: " + measured + ".\n<!-- refresh-status:end -->")
        readme.write_text(re.sub(r'<!-- refresh-status:start -->.*?<!-- refresh-status:end -->',
                                lambda _: status, readme.read_text(), flags=re.S), encoding="utf-8")
    print("Client subscriptions validated" if args.check else "Client subscriptions generated")


if __name__ == "__main__":
    main()
