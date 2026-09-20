import copy
import html
import json
import os
import sys
import time
import urllib.request
import math
from pathlib import Path


CATALOG_PATH = Path("whitelist_configs_combined.json")
CONFIG_KEYS = {"remarks", "outbounds", "routing"}
MIN_SOURCE_RETAIN_RATIO = 0.5

CANONICAL_DIRECT_OUTBOUND = {
    "protocol": "freedom",
    "settings": {"domainStrategy": "UseIP"},
    "tag": "direct",
}


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def fetch_subscription_text():
    source_file = os.environ.get("SUBSCRIPTION_SOURCE_FILE")
    if source_file:
        return Path(source_file).read_text(encoding="utf-8-sig", errors="replace")

    source_url = os.environ.get("SUBSCRIPTION_URL", "").strip()
    if not source_url.startswith("https://"):
        raise RuntimeError("Set SUBSCRIPTION_URL to your authorized HTTPS source, or use SUBSCRIPTION_SOURCE_FILE")

    request = urllib.request.Request(
        source_url,
        headers={
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/127.0.0.0 Safari/537.36"
            ),
            "Accept": "application/json,text/plain,*/*",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        },
    )
    last_error = None
    for attempt in range(1, 4):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.read().decode("utf-8-sig")
        except Exception as exc:
            last_error = exc
            if attempt < 3:
                time.sleep(5 * attempt)

    raise RuntimeError(f"Could not fetch subscription after retries: {last_error}") from last_error


def looks_like_config(value):
    return isinstance(value, dict) and CONFIG_KEYS <= set(value.keys())


def extract_configs(raw_text):
    # Connliberty may return a saved HTML page where each JSON config is
    # HTML-escaped inside an attribute. Decode it before JSON extraction.
    raw_text = html.unescape(raw_text)

    try:
        value = json.loads(raw_text)
    except json.JSONDecodeError:
        value = None

    if isinstance(value, list) and value and all(looks_like_config(item) for item in value):
        return value

    decoder = json.JSONDecoder()
    configs = []
    for index, char in enumerate(raw_text):
        if char != "{":
            continue
        try:
            value, _ = decoder.raw_decode(raw_text[index:])
        except json.JSONDecodeError:
            continue
        if looks_like_config(value):
            configs.append(value)

    if not configs:
        raise RuntimeError("Could not extract subscription configs from source response")

    remarks_markers = raw_text.count('"remarks"')
    if remarks_markers and len(configs) != remarks_markers:
        raise RuntimeError(
            f"Extracted {len(configs)} configs, but source contains {remarks_markers} remarks markers"
        )

    return configs


def deduplicate_configs(configs):
    """Keep one source config per remarks, preserving the page order."""
    unique = []
    positions = {}
    for config in configs:
        remarks = config.get("remarks")
        if remarks in positions:
            # Repeated cards are rendered copies of the same source entry.
            # Keep the latest copy while retaining the first position.
            unique[positions[remarks]] = config
            continue
        positions[remarks] = len(unique)
        unique.append(config)
    return unique


def current_direct_domains(configs):
    for config in configs:
        for rule in config.get("routing", {}).get("rules", []):
            if rule.get("outboundTag") == "direct" and isinstance(rule.get("domain"), list):
                return list(rule["domain"])
    raise RuntimeError("Could not find the approved direct domain list in the current catalog")


def configured_extra_direct_domains():
    raw_value = os.environ.get("DIRECT_EXTRA_DOMAINS", "")
    return [line.strip() for line in raw_value.splitlines() if line.strip()]


def extend_direct_domains(direct_domains):
    result = list(direct_domains)
    for domain in configured_extra_direct_domains():
        if domain not in result:
            result.append(domain)
    return result


def normalize_direct(config, direct_domains):
    outbounds = [
        outbound for outbound in config.get("outbounds", []) if outbound.get("tag") != "direct"
    ]
    outbounds.append(copy.deepcopy(CANONICAL_DIRECT_OUTBOUND))
    config["outbounds"] = outbounds

    routing = config.setdefault("routing", {})
    rules = routing.setdefault("rules", [])

    domain_rule = None
    for rule in rules:
        if rule.get("outboundTag") == "direct" and "domain" in rule:
            domain_rule = rule
            break

    if domain_rule is None:
        domain_rule = {"type": "field", "outboundTag": "direct", "domain": []}
        rules.insert(0, domain_rule)

    domain_rule.clear()
    domain_rule.update(
        {"type": "field", "outboundTag": "direct", "domain": list(direct_domains)}
    )

    if not any(rule.get("outboundTag") == "direct" and "protocol" in rule for rule in rules):
        rules.append({"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"})


def validate(configs, source_count, direct_domains, previous_count=None):
    if not configs:
        raise RuntimeError("Refusing to publish an empty catalog")
    if len(configs) != source_count:
        raise RuntimeError(f"Final config count {len(configs)} != source count {source_count}")
    if previous_count:
        minimum = max(2, math.ceil(previous_count * MIN_SOURCE_RETAIN_RATIO))
        if len(configs) < minimum:
            raise RuntimeError(
                f"Refusing suspicious catalog shrink: {previous_count} -> {len(configs)} "
                f"(minimum allowed {minimum})"
            )

    for config in configs:
        remarks = config.get("remarks", "<no remarks>")
        direct_outbounds = [
            outbound for outbound in config.get("outbounds", []) if outbound.get("tag") == "direct"
        ]
        if direct_outbounds != [CANONICAL_DIRECT_OUTBOUND]:
            raise RuntimeError(f"{remarks}: direct outbound is not canonical or is duplicated")

        domain_rules = [
            rule
            for rule in config.get("routing", {}).get("rules", [])
            if rule.get("outboundTag") == "direct" and "domain" in rule
        ]
        if not domain_rules or any(rule.get("domain") != direct_domains for rule in domain_rules):
            raise RuntimeError(f"{remarks}: direct domain rule does not match approved list")

        if not any(
            str(outbound.get("tag", "")).startswith("proxy") or outbound.get("tag") == "proxy"
            for outbound in config.get("outbounds", [])
        ):
            raise RuntimeError(f"{remarks}: proxy outbound is missing")


def main():
    current_configs = load_json(CATALOG_PATH)
    direct_domains = extend_direct_domains(current_direct_domains(current_configs))

    extracted_configs = extract_configs(fetch_subscription_text())
    source_configs = deduplicate_configs(extracted_configs)
    final_configs = [copy.deepcopy(config) for config in source_configs]
    for config in final_configs:
        normalize_direct(config, direct_domains)

    validate(final_configs, len(source_configs), direct_domains, len(current_configs))
    CATALOG_PATH.write_text(
        json.dumps(final_configs, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"extracted_configs={len(extracted_configs)}")
    print(f"source_configs={len(source_configs)}")
    print(f"final_configs={len(final_configs)}")
    print(f"direct_domains={len(direct_domains)}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"refresh_subscription.py failed: {exc}", file=sys.stderr)
        raise
