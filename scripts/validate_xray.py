"""Validate each native Happ profile without starting a VPN connection."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--xray', required=True)
    parser.add_argument('--assets', required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    configs = json.loads((root / 'subscription.txt').read_text())
    env = dict(os.environ, XRAY_LOCATION_ASSET=str(Path(args.assets).resolve()))
    with tempfile.TemporaryDirectory(prefix='vpn-test-xray-') as directory:
        for index, config in enumerate(configs):
            path = Path(directory) / 'config.json'
            path.write_text(json.dumps(config))
            result = subprocess.run([args.xray, 'run', '-test', '-c', str(path)],
                                    env=env, capture_output=True, text=True, timeout=30)
            if result.returncode:
                # Errors may contain credentials from the config; do not publish them in CI logs.
                raise SystemExit(f'Xray rejected profile #{index + 1}; inspect locally')
    print(f'Xray validated {len(configs)} profiles; no VPN connections started')


if __name__ == '__main__':
    main()
