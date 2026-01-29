#!/usr/bin/env python3
"""
Fail2Bunny - Bunny CDN Edge IP Whitelist for Fail2ban

Periodically downloads Bunny CDN edge IP lists and ensures those networks
are whitelisted in Fail2ban to prevent edge proxies from getting banned.

No external dependencies - uses only Python standard library.
"""

import argparse
import hashlib
import ipaddress
import json
import logging
import os
import ssl
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Optional

# Constants
DEFAULT_CONFIG_PATH = "/etc/fail2bunny/config.json"
BUNNY_IPV4_URL = "https://bunnycdn.com/api/system/edgeserverlist/"
BUNNY_IPV6_URL = "https://bunnycdn.com/api/system/edgeserverlist/IPv6"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def load_config(config_path: str) -> dict:
    """Load configuration from JSON file."""
    path = Path(config_path)
    
    if not path.exists():
        logger.error(f"Config file not found: {config_path}")
        sys.exit(1)
    
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    
    try:
        config = json.loads(content)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse config file: {e}")
        sys.exit(1)
    
    # Validate required fields
    if not config:
        config = {}
    
    # Set defaults
    defaults = {
        "target_file": "/etc/fail2ban/jail.d/bunny-edges.local",
        "baseline_ignoreip": ["127.0.0.1/8", "::1"],
        "timeout_seconds": 30,
        "reload_method": "auto",
        "interval_hint": "6h",
    }
    
    for key, value in defaults.items():
        if key not in config:
            config[key] = value
    
    return config


def fetch_ip_list(url: str, timeout: int) -> list[str]:
    """Fetch IP list from Bunny API endpoint using standard library."""
    logger.info(f"Fetching IP list from: {url}")
    
    # Create SSL context with verification
    ssl_context = ssl.create_default_context()
    
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "bunny-fail2ban-sync/1.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_context) as response:
            data = response.read().decode("utf-8")
    except urllib.error.URLError as e:
        logger.error(f"Failed to fetch {url}: {e}")
        raise
    except TimeoutError:
        logger.error(f"Timeout fetching {url}")
        raise
    
    # Try to parse as JSON
    try:
        parsed = json.loads(data)
        # Handle different response formats
        if isinstance(parsed, list):
            return parsed
        elif isinstance(parsed, dict):
            # Try common keys
            for key in ["ips", "addresses", "data", "items"]:
                if key in parsed and isinstance(parsed[key], list):
                    return parsed[key]
            # Return all string values
            return [v for v in parsed.values() if isinstance(v, str)]
    except json.JSONDecodeError:
        # Fall back to plain text (one IP per line)
        return [line.strip() for line in data.splitlines() if line.strip()]


def validate_ip_or_cidr(ip_str: str) -> Optional[str]:
    """Validate and normalize an IP address or CIDR network."""
    ip_str = ip_str.strip()
    if not ip_str:
        return None
    
    try:
        # Try as network (CIDR)
        network = ipaddress.ip_network(ip_str, strict=False)
        return str(network)
    except ValueError:
        pass
    
    try:
        # Try as single IP
        ip = ipaddress.ip_address(ip_str)
        return str(ip)
    except ValueError:
        pass
    
    logger.warning(f"Invalid IP/CIDR skipped: {ip_str}")
    return None


def process_ip_lists(ipv4_list: list[str], ipv6_list: list[str]) -> tuple[list[str], list[str]]:
    """Validate, deduplicate, and sort IP lists."""
    ipv4_validated = set()
    ipv6_validated = set()
    
    for ip_str in ipv4_list + ipv6_list:
        validated = validate_ip_or_cidr(ip_str)
        if validated:
            try:
                network = ipaddress.ip_network(validated, strict=False)
                if network.version == 4:
                    ipv4_validated.add(validated)
                else:
                    ipv6_validated.add(validated)
            except ValueError:
                ip = ipaddress.ip_address(validated)
                if ip.version == 4:
                    ipv4_validated.add(validated)
                else:
                    ipv6_validated.add(validated)
    
    # Sort for stable output
    def sort_key(ip_str):
        try:
            return ipaddress.ip_network(ip_str, strict=False).network_address
        except ValueError:
            return ipaddress.ip_address(ip_str)
    
    return sorted(ipv4_validated, key=sort_key), sorted(ipv6_validated, key=sort_key)


def generate_fail2ban_config(baseline_ips: list[str], bunny_ipv4: list[str], bunny_ipv6: list[str]) -> str:
    """Generate the Fail2ban jail.d config content."""
    all_ips = []
    
    # Add baseline IPs first
    for ip in baseline_ips:
        validated = validate_ip_or_cidr(ip)
        if validated:
            all_ips.append(validated)
    
    # Add Bunny IPs
    all_ips.extend(bunny_ipv4)
    all_ips.extend(bunny_ipv6)
    
    # Deduplicate while preserving order
    seen = set()
    unique_ips = []
    for ip in all_ips:
        if ip not in seen:
            seen.add(ip)
            unique_ips.append(ip)
    
    # Build config content
    lines = [
        "# Bunny CDN Edge IP Whitelist for Fail2ban",
        "# Auto-generated by fail2bunny - DO NOT EDIT MANUALLY",
        "#",
        f"# IPv4 entries: {len(bunny_ipv4)}",
        f"# IPv6 entries: {len(bunny_ipv6)}",
        f"# Baseline entries: {len(baseline_ips)}",
        "",
        "[DEFAULT]",
        f"ignoreip = {' '.join(unique_ips)}",
        "",
    ]
    
    return "\n".join(lines)


def get_file_hash(filepath: Path) -> Optional[str]:
    """Get MD5 hash of file contents, or None if file doesn't exist."""
    if not filepath.exists():
        return None
    
    with open(filepath, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def atomic_write(filepath: Path, content: str) -> None:
    """Write content to file atomically using temp file + rename."""
    # Ensure parent directory exists
    filepath.parent.mkdir(parents=True, exist_ok=True)
    
    # Write to temp file in same directory (for atomic rename)
    fd, temp_path = tempfile.mkstemp(
        dir=filepath.parent,
        prefix=f".{filepath.name}.",
        suffix=".tmp"
    )
    
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        
        # Atomic rename
        os.replace(temp_path, filepath)
        logger.info(f"Wrote config to: {filepath}")
    except Exception:
        # Clean up temp file on failure
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        raise


def reload_fail2ban(method: str) -> bool:
    """Reload Fail2ban configuration."""
    commands = {
        "auto": ["fail2ban-client", "reload"],
        "systemctl": ["systemctl", "reload", "fail2ban"],
        "service": ["service", "fail2ban", "reload"],
        "client": ["fail2ban-client", "reload"],
    }
    
    if method not in commands:
        logger.error(f"Unknown reload method: {method}")
        return False
    
    cmd = commands[method]
    logger.info(f"Reloading Fail2ban using: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        
        if result.returncode == 0:
            logger.info("Fail2ban reloaded successfully")
            return True
        else:
            logger.error(f"Fail2ban reload failed: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        logger.error("Fail2ban reload timed out")
        return False
    except FileNotFoundError:
        logger.error(f"Command not found: {cmd[0]}")
        return False


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Sync Bunny CDN edge IPs to Fail2ban whitelist"
    )
    parser.add_argument(
        "-c", "--config",
        default=DEFAULT_CONFIG_PATH,
        help=f"Path to config file (default: {DEFAULT_CONFIG_PATH})"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would change without writing or reloading"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Load config
    logger.info(f"Loading config from: {args.config}")
    config = load_config(args.config)
    
    target_file = Path(config["target_file"])
    baseline_ips = config["baseline_ignoreip"]
    timeout = config["timeout_seconds"]
    reload_method = config["reload_method"]
    
    logger.info(f"Target file: {target_file}")
    logger.info(f"Baseline IPs: {len(baseline_ips)}")
    logger.info(f"Timeout: {timeout}s")
    
    # Fetch IP lists
    try:
        ipv4_raw = fetch_ip_list(BUNNY_IPV4_URL, timeout)
        ipv6_raw = fetch_ip_list(BUNNY_IPV6_URL, timeout)
    except Exception as e:
        logger.error(f"Failed to fetch IP lists: {e}")
        logger.error("Keeping existing whitelist unchanged")
        sys.exit(1)
    
    logger.info(f"Fetched {len(ipv4_raw)} IPv4 and {len(ipv6_raw)} IPv6 entries")
    
    # Process and validate
    ipv4_validated, ipv6_validated = process_ip_lists(ipv4_raw, ipv6_raw)
    logger.info(f"Validated {len(ipv4_validated)} IPv4 and {len(ipv6_validated)} IPv6 entries")
    
    # Generate config
    new_content = generate_fail2ban_config(baseline_ips, ipv4_validated, ipv6_validated)
    new_hash = hashlib.md5(new_content.encode()).hexdigest()
    old_hash = get_file_hash(target_file)
    
    changed = new_hash != old_hash
    
    if args.dry_run:
        logger.info("=== DRY RUN MODE ===")
        logger.info(f"Content changed: {changed}")
        if changed:
            logger.info("New config content:")
            print(new_content)
        else:
            logger.info("No changes detected")
        return
    
    if not changed:
        logger.info("No changes detected, skipping write and reload")
        return
    
    logger.info("Changes detected, updating whitelist")
    
    # Write new config
    try:
        atomic_write(target_file, new_content)
    except Exception as e:
        logger.error(f"Failed to write config: {e}")
        sys.exit(1)
    
    # Reload Fail2ban
    if not reload_fail2ban(reload_method):
        logger.error("Failed to reload Fail2ban")
        sys.exit(1)
    
    logger.info("Sync completed successfully")


if __name__ == "__main__":
    main()
