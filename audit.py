#!/usr/bin/env python3
"""Android Signage Audit Tool
Scans a network for Android devices with ADB exposed, checks for root access,
identifies digital signage applications, and reports security findings.

This tool is for authorized network administrators to audit their own networks.
Do not use on networks you do not own or have explicit authorization to test.

Usage:
    python3 audit.py --subnet 192.168.1.0/24
    python3 audit.py --host 192.168.1.50
    python3 audit.py --subnet 10.0.0.0/24 --port 5555 --output report.json

Requires: adb (Android Debug Bridge) installed and in PATH

https://github.com/tsali/android-signage-audit
"""

import argparse
import json
import os
import subprocess
import socket
import sys
import time
from datetime import datetime


SIGNAGE_PACKAGES = {
    "com.novisign.android.player": "NoviSign Digital Signage",
    "com.risevision.player": "Rise Vision",
    "com.screencloud.player": "ScreenCloud",
    "com.yodeck.player": "Yodeck",
    "com.signagelive.player": "Signagelive",
    "com.enplug.android": "Enplug",
    "tv.optiSigns": "OptiSigns",
    "com.posterbooking.player": "PosterBooking",
    "com.viewneo.player": "Viewneo",
    "com.kitcast.tv": "Kitcast",
    "com.broadsign.xpress": "Broadsign Xpress",
    "com.scala.content.manager": "Scala",
    "com.four.winds.interactive": "Four Winds Interactive",
    "com.mvix.player": "Mvix",
    "com.wallboard.player": "Wallboard",
}

REMOTE_ACCESS_PACKAGES = {
    "com.teamviewer.host.market": "TeamViewer Host",
    "com.teamviewer.host.samsung": "TeamViewer Host (Samsung)",
    "com.anydesk.anydeskandroid": "AnyDesk",
    "com.realvnc.viewer.android": "RealVNC Viewer",
}


def log(msg, level="INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [{level}] {msg}")


def scan_port(host, port, timeout=2):
    """Check if a TCP port is open."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return True
    except:
        return False


def scan_subnet(subnet, port=5555, timeout=1):
    """Scan a subnet for open ADB ports."""
    import ipaddress
    network = ipaddress.ip_network(subnet, strict=False)
    found = []
    total = sum(1 for _ in network.hosts())
    log(f"Scanning {total} hosts on {subnet} for port {port}...")

    for i, host in enumerate(network.hosts()):
        ip = str(host)
        if scan_port(ip, port, timeout):
            log(f"FOUND: {ip}:{port} OPEN", "WARN")
            found.append(ip)
        if (i + 1) % 50 == 0:
            log(f"  Progress: {i + 1}/{total}")

    return found


def adb_cmd(host, port, cmd, timeout=15):
    """Run an ADB command against a target."""
    target = f"{host}:{port}"
    try:
        result = subprocess.run(
            ["adb", "-s", target] + cmd,
            capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", -1
    except FileNotFoundError:
        log("ERROR: 'adb' not found in PATH. Install Android platform-tools.", "ERROR")
        sys.exit(1)


def connect_adb(host, port=5555):
    """Connect ADB to a target."""
    target = f"{host}:{port}"
    try:
        result = subprocess.run(
            ["adb", "connect", target],
            capture_output=True, text=True, timeout=10
        )
        return "connected" in result.stdout.lower()
    except:
        return False


def disconnect_adb(host, port=5555):
    """Disconnect ADB from a target."""
    target = f"{host}:{port}"
    subprocess.run(["adb", "disconnect", target], capture_output=True, timeout=5)


def audit_device(host, port=5555):
    """Perform a full security audit of an Android device."""
    findings = {
        "host": host,
        "port": port,
        "timestamp": datetime.now().isoformat(),
        "adb_open": False,
        "adb_authenticated": False,
        "device_info": {},
        "root_access": False,
        "root_method": None,
        "signage_apps": [],
        "remote_access_apps": [],
        "open_ports": [],
        "security_issues": [],
        "severity": "LOW",
    }

    # Step 1: ADB Connection
    log(f"Connecting to {host}:{port}...")
    if not connect_adb(host, port):
        log(f"Cannot connect to {host}:{port}", "WARN")
        findings["adb_open"] = True  # Port was open but auth failed
        findings["security_issues"].append("ADB port open but requires authorization")
        return findings

    findings["adb_open"] = True
    findings["adb_authenticated"] = True
    findings["security_issues"].append("ADB port exposed with no authentication required")
    findings["severity"] = "HIGH"

    # Step 2: Device Info
    log("Gathering device information...")
    info_props = {
        "model": "ro.product.model",
        "brand": "ro.product.brand",
        "device": "ro.product.device",
        "android_version": "ro.build.version.release",
        "sdk_version": "ro.build.version.sdk",
        "build_id": "ro.build.display.id",
        "build_type": "ro.build.type",
        "build_keys": "ro.build.tags",
        "cpu_abi": "ro.product.cpu.abi",
        "serial": "ro.serialno",
    }

    for key, prop in info_props.items():
        out, rc = adb_cmd(host, port, ["shell", f"getprop {prop}"])
        if out:
            findings["device_info"][key] = out

    # Check for debug/test builds
    build_type = findings["device_info"].get("build_type", "")
    build_keys = findings["device_info"].get("build_keys", "")
    if "userdebug" in build_type or "eng" in build_type:
        findings["security_issues"].append(f"Device running DEBUG build ({build_type})")
        findings["severity"] = "CRITICAL"
    if "test-keys" in build_keys:
        findings["security_issues"].append("Device signed with TEST KEYS (not production)")
        findings["severity"] = "CRITICAL"

    # Step 3: Root Access
    log("Checking root access...")
    out, rc = adb_cmd(host, port, ["shell", "su -c id"])
    if "uid=0(root)" in out:
        findings["root_access"] = True
        findings["root_method"] = "su binary"
        findings["security_issues"].append("Full root access available via 'su' binary")
        findings["severity"] = "CRITICAL"
    else:
        out, rc = adb_cmd(host, port, ["shell", "id"])
        if "uid=0" in out:
            findings["root_access"] = True
            findings["root_method"] = "adb runs as root"
            findings["security_issues"].append("ADB shell runs as root by default")
            findings["severity"] = "CRITICAL"

    # Step 4: Signage Applications
    log("Checking for digital signage applications...")
    out, rc = adb_cmd(host, port, ["shell", "pm list packages -3"])
    if out:
        installed = [line.replace("package:", "") for line in out.split("\n")]
        for pkg, name in SIGNAGE_PACKAGES.items():
            if pkg in installed:
                findings["signage_apps"].append({"package": pkg, "name": name})
                log(f"  Found: {name} ({pkg})")

    # Step 5: Remote Access Applications
    for pkg, name in REMOTE_ACCESS_PACKAGES.items():
        if pkg in installed:
            findings["remote_access_apps"].append({"package": pkg, "name": name})
            log(f"  Found remote access: {name}")

    # Step 6: Network Exposure
    log("Checking open network ports...")
    if findings["root_access"]:
        out, rc = adb_cmd(host, port, ["shell", "su -c 'cat /proc/net/tcp'"])
    else:
        out, rc = adb_cmd(host, port, ["shell", "cat /proc/net/tcp"])

    if out:
        for line in out.split("\n"):
            parts = line.split()
            if len(parts) > 3 and parts[3] == "0A":  # LISTEN state
                try:
                    lport = int(parts[1].split(":")[1], 16)
                    if lport > 1024:
                        findings["open_ports"].append(lport)
                except:
                    pass

    if 5555 in findings["open_ports"]:
        findings["security_issues"].append("ADB TCP port 5555 persists across reboots")

    # Step 7: ADB Persistence
    out, rc = adb_cmd(host, port, ["shell", "getprop persist.adb.tcp.port"])
    if out and out.strip():
        findings["security_issues"].append(f"ADB TCP port set to persist: {out.strip()}")

    out, rc = adb_cmd(host, port, ["shell", "getprop service.adb.tcp.port"])
    if out and out.strip():
        findings["security_issues"].append(f"ADB TCP service port active: {out.strip()}")

    # Step 8: Storage Check
    log("Checking storage...")
    out, rc = adb_cmd(host, port, ["shell", "df /data"])
    if out:
        findings["device_info"]["storage"] = out

    # Step 9: Firmware Age
    out, rc = adb_cmd(host, port, ["shell", "cat /proc/version"])
    if out:
        findings["device_info"]["kernel"] = out

    # Disconnect
    disconnect_adb(host, port)

    return findings


def print_report(findings):
    """Print a human-readable report."""
    print("\n" + "=" * 70)
    print("  ANDROID SIGNAGE SECURITY AUDIT REPORT")
    print("=" * 70)
    print(f"  Target:    {findings['host']}:{findings['port']}")
    print(f"  Timestamp: {findings['timestamp']}")
    print(f"  Severity:  {findings['severity']}")
    print("=" * 70)

    info = findings.get("device_info", {})
    if info:
        print("\n--- Device Information ---")
        print(f"  Model:       {info.get('model', 'Unknown')}")
        print(f"  Brand:       {info.get('brand', 'Unknown')}")
        print(f"  Android:     {info.get('android_version', 'Unknown')} (SDK {info.get('sdk_version', '?')})")
        print(f"  Build:       {info.get('build_id', 'Unknown')}")
        print(f"  Build Type:  {info.get('build_type', 'Unknown')}")
        print(f"  Build Keys:  {info.get('build_keys', 'Unknown')}")
        print(f"  CPU:         {info.get('cpu_abi', 'Unknown')}")

    if findings.get("signage_apps"):
        print("\n--- Digital Signage Applications ---")
        for app in findings["signage_apps"]:
            print(f"  [!] {app['name']} ({app['package']})")

    if findings.get("remote_access_apps"):
        print("\n--- Remote Access Applications ---")
        for app in findings["remote_access_apps"]:
            print(f"  [!] {app['name']} ({app['package']})")

    if findings.get("open_ports"):
        print(f"\n--- Open Ports ({len(findings['open_ports'])}) ---")
        for port in sorted(findings["open_ports"]):
            label = ""
            if port == 5555:
                label = " (ADB)"
            elif port == 5900 or port == 5901:
                label = " (VNC)"
            elif port == 5800 or port == 5801:
                label = " (VNC HTTP)"
            print(f"  {port}{label}")

    print(f"\n--- Security Findings ({len(findings['security_issues'])}) ---")
    for i, issue in enumerate(findings["security_issues"], 1):
        print(f"  [{findings['severity']}] {i}. {issue}")

    print("\n--- Access Summary ---")
    print(f"  ADB Open:          {'YES' if findings['adb_open'] else 'No'}")
    print(f"  ADB No Auth:       {'YES' if findings['adb_authenticated'] else 'No'}")
    print(f"  Root Access:       {'YES' if findings['root_access'] else 'No'}")
    if findings["root_method"]:
        print(f"  Root Method:       {findings['root_method']}")

    if findings["severity"] == "CRITICAL":
        print("\n" + "!" * 70)
        print("  CRITICAL: This device has NO authentication and FULL root access.")
        print("  Anyone on this network can:")
        print("    - Install malware or cryptominers")
        print("    - Use the device as a network pivot point")
        print("    - Replace signage content with arbitrary media")
        print("    - Exfiltrate data from the local network")
        print("    - Brick the device remotely")
        print("  RECOMMENDATION: Disable ADB over TCP immediately or isolate")
        print("  the device on a restricted VLAN with no internet access.")
        print("!" * 70)

    print()


def main():
    parser = argparse.ArgumentParser(
        description="Android Signage Security Audit Tool",
        epilog="For authorized network administrators only."
    )
    parser.add_argument("--host", help="Single host to audit")
    parser.add_argument("--subnet", help="Subnet to scan (e.g. 192.168.1.0/24)")
    parser.add_argument("--port", type=int, default=5555, help="ADB port (default: 5555)")
    parser.add_argument("--output", help="Save report as JSON file")
    parser.add_argument("--timeout", type=int, default=2, help="Port scan timeout in seconds")
    args = parser.parse_args()

    if not args.host and not args.subnet:
        parser.print_help()
        print("\nError: Specify --host or --subnet")
        sys.exit(1)

    targets = []
    if args.host:
        if scan_port(args.host, args.port, args.timeout):
            targets.append(args.host)
        else:
            log(f"{args.host}:{args.port} is not open", "WARN")
            sys.exit(1)
    elif args.subnet:
        targets = scan_subnet(args.subnet, args.port, args.timeout)

    if not targets:
        log("No devices found with open ADB ports")
        sys.exit(0)

    log(f"Found {len(targets)} device(s) with ADB exposed")
    all_findings = []

    for host in targets:
        findings = audit_device(host, args.port)
        print_report(findings)
        all_findings.append(findings)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(all_findings, f, indent=2)
        log(f"Report saved to {args.output}")


if __name__ == "__main__":
    main()
