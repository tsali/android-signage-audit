# Android Signage Security Audit

A security audit tool for network administrators to identify exposed Android digital signage devices on their networks.

**Blog post**: [The $30 Security Hole in Your Lobby](https://cultofjames.org/the-30-security-hole-in-your-lobby/) — the full story behind this tool.

## The Problem

Cheap Android TV boxes are widely deployed as digital signage players in businesses — dance studios, restaurants, lobbies, churches, retail stores. These devices often ship with:

- **ADB (Android Debug Bridge) enabled over TCP on port 5555** — no authentication
- **Root access via `su`** — full device control
- **Debug/test firmware builds** — `userdebug` with `test-keys`, never meant for production
- **Android 6.0 or older** — years of unpatched vulnerabilities
- **No device management** — nobody monitors or updates them

This means anyone on the same network can:

- Install malware, cryptominers, or botnet agents
- Replace signage content with arbitrary images or video
- Use the device as a pivot point to attack other devices on the network
- Exfiltrate data through the device's internet connection
- Brick the device remotely
- Access cameras, microphones, or other hardware

## Real-World Finding

During a routine network audit for a client, we discovered a Novisign digital signage player with:

| Finding | Detail |
|---------|--------|
| Device | X10-MINI (Rockchip RK3368) |
| Android | 6.0.1 Marshmallow |
| Build | `userdebug` with `test-keys` |
| Firmware | August 2019 (6+ years old) |
| ADB | Port 5555, open, no authentication |
| Root | Full root via `su` binary |
| Network | Connected to WiFi on a shared VLAN with cameras, TVs, and staff devices |
| Management | None — device was deployed and forgotten |

With ADB access we could:
- Take screenshots of what's displayed on the TV
- Install and uninstall applications
- Access the full filesystem
- Execute commands as root
- Reboot the device
- Push arbitrary content

The device was running a single app (Novisign) and had TeamViewer Host installed but unconfigured. The signage content included photos of children at a dance studio.

## This Tool

`audit.py` scans your network for Android devices with exposed ADB ports and performs a security assessment.

### What It Checks

1. **ADB Exposure** — Is port 5555 (or custom) open and accepting unauthenticated connections?
2. **Device Information** — Model, Android version, build type, signing keys
3. **Root Access** — Can `su` escalate to root? Does ADB run as root by default?
4. **Build Security** — Is this a `userdebug` or `eng` build? Signed with `test-keys`?
5. **Signage Applications** — Identifies 15+ common digital signage platforms
6. **Remote Access** — Checks for TeamViewer, AnyDesk, VNC installations
7. **Open Ports** — Lists all listening TCP ports on the device
8. **ADB Persistence** — Will ADB survive a reboot?

### Supported Signage Platforms Detected

NoviSign, Rise Vision, ScreenCloud, Yodeck, Signagelive, Enplug, OptiSigns, PosterBooking, Viewneo, Kitcast, Broadsign, Scala, Four Winds Interactive, Mvix, Wallboard

## Usage

### Requirements

- Python 3.6+
- `adb` (Android Debug Bridge) in PATH
  - Ubuntu/Debian: `sudo apt install android-tools-adb`
  - Fedora: `sudo dnf install android-tools`
  - macOS: `brew install android-platform-tools`

### Scan a Single Device

```bash
python3 audit.py --host 192.168.1.50
```

### Scan a Subnet

```bash
python3 audit.py --subnet 192.168.1.0/24
```

### Save Report as JSON

```bash
python3 audit.py --subnet 10.0.0.0/24 --output report.json
```

### Custom ADB Port

```bash
python3 audit.py --host 192.168.1.50 --port 5556
```

## Sample Output

```
======================================================================
  ANDROID SIGNAGE SECURITY AUDIT REPORT
======================================================================
  Target:    192.168.1.50:5555
  Timestamp: 2026-05-08T11:00:00
  Severity:  CRITICAL
======================================================================

--- Device Information ---
  Model:       X10-MINI
  Brand:       Android
  Android:     6.0.1 (SDK 23)
  Build:       rk3368_box-userdebug 6.0.1 MXC89K test-keys
  Build Type:  userdebug
  Build Keys:  test-keys
  CPU:         arm64-v8a

--- Digital Signage Applications ---
  [!] NoviSign Digital Signage (com.novisign.android.player)

--- Remote Access Applications ---
  [!] TeamViewer Host (com.teamviewer.host.market)

--- Security Findings (6) ---
  [CRITICAL] 1. ADB port exposed with no authentication required
  [CRITICAL] 2. Device running DEBUG build (userdebug)
  [CRITICAL] 3. Device signed with TEST KEYS (not production)
  [CRITICAL] 4. Full root access available via 'su' binary
  [CRITICAL] 5. ADB TCP port 5555 persists across reboots
  [CRITICAL] 6. ADB TCP service port active: 5555

--- Access Summary ---
  ADB Open:          YES
  ADB No Auth:       YES
  Root Access:       YES
  Root Method:       su binary

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  CRITICAL: This device has NO authentication and FULL root access.
  Anyone on this network can:
    - Install malware or cryptominers
    - Use the device as a network pivot point
    - Replace signage content with arbitrary media
    - Exfiltrate data from the local network
    - Brick the device remotely
  RECOMMENDATION: Disable ADB over TCP immediately or isolate
  the device on a restricted VLAN with no internet access.
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

## Remediation

### Immediate Actions

1. **Disable ADB over TCP**: Connect via USB and run `adb tcpip -1` or `adb shell setprop persist.adb.tcp.port ""`
2. **Isolate the device**: Move to a dedicated VLAN with no access to other network segments
3. **Block port 5555**: Add a firewall rule blocking TCP 5555 on the signage VLAN

### Long-Term Recommendations

1. **Replace cheap Android boxes** with managed signage devices or Chromebox/ChromeOS devices
2. **Use an MDM solution** (Mobile Device Management) to manage and monitor signage devices
3. **Regular firmware updates** — if the manufacturer doesn't provide them, replace the device
4. **Network segmentation** — signage devices should never share a VLAN with cameras, POS systems, or staff WiFi
5. **Periodic audits** — run this tool monthly to catch new devices

## IoT Security and VLAN Segmentation

Digital signage boxes are IoT devices. So are smart TVs, IP cameras, Chromecast dongles, Sonos speakers, smart light bulbs, and every other "smart" device on your network. They all share the same problems:

- Rarely updated firmware
- Default or no credentials
- Unnecessary services running (ADB, Telnet, UPnP)
- No monitoring or alerting
- Deployed and forgotten

**The fundamental mistake is putting IoT devices on the same network as everything else.**

When a signage box sits on the same VLAN as your security cameras, your NVR, your staff computers, and your POS system, a compromise of that $30 box is a compromise of your entire network. The attacker doesn't need to hack your firewall — they just need to hack the cheapest device on your WiFi.

### Recommended VLAN Architecture for Small Business

| VLAN | Purpose | Devices | Internet | Cross-VLAN Access |
|------|---------|---------|----------|-------------------|
| Management | Network infrastructure | Router, switches, APs, firewall | Yes | Admin only |
| Staff | Employee devices | Laptops, phones, desktops | Yes | None |
| Cameras | Surveillance | IP cameras, NVR | Limited (cloud upload only) | NVR only |
| Signage/IoT | Smart devices | Signage boxes, smart TVs, speakers, Chromecast | Limited (content only) | None |
| Guest | Public WiFi | Customer/visitor devices | Yes (throttled) | None |

### Key Principles

1. **IoT devices get their own VLAN.** Period. No exceptions. If it has firmware you can't audit, it goes on the IoT VLAN.

2. **Default deny between VLANs.** An IoT device should never be able to reach your cameras, your POS, or your staff network. Create explicit firewall rules for the specific traffic that needs to cross (e.g., signage cloud sync on port 443 outbound only).

3. **No inbound from IoT.** The IoT VLAN should not be able to initiate connections to any other VLAN. If you need to manage a signage box, connect FROM the management VLAN TO the device — not the other way around.

4. **Restrict internet access.** Signage boxes need HTTPS to their cloud provider and nothing else. Block everything else outbound. A compromised signage box that can't call home to a C2 server is significantly less dangerous.

5. **Monitor IoT VLANs separately.** Alert on unusual traffic — a signage box shouldn't be port scanning, making DNS requests to unusual domains, or transferring large amounts of data.

6. **Inventory everything.** Know every device on every VLAN. If you can't name it, it shouldn't be there. Run periodic ARP scans and compare against your inventory.

### Why This Gets Missed

Network administrators — even good ones — often overlook IoT segmentation because:

- The client adds devices AFTER the network is built — smart TVs, signage boxes, speakers get plugged in without telling the network engineer
- The client says "it's just a TV" and connects it to whatever WiFi network they know the password to
- The signage vendor says "connect it to WiFi" with no security guidance
- Small businesses don't have enterprise network gear (though UniFi and similar prosumer equipment makes VLANs accessible and affordable now)
- Nobody thinks of a signage box as an attack surface until it is one
- If IoT devices didn't exist when the network was built, there's no IoT VLAN waiting for them

In this case, the network was originally built with proper segmentation. Security cameras were already on a dedicated VLAN — isolated so they can't reach anything outside their network. The employee VLAN can access the camera VLAN for viewing, but not the other way around. That part was done right from day one.

What happened next: the client added signage boxes, smart TVs, Sonos speakers, and other IoT devices on their own — connecting them to the employee WiFi because that's the network they had the password to. Now the employee VLAN had a compromised signage box with root access sitting alongside devices that had firewall permissions to reach the camera network. A pivot from the signage box to any employee device to the camera VLAN is a three-hop attack that bypasses the camera isolation entirely.

**This is the most common scenario.** Networks don't start insecure — they drift there as clients add devices without involving their network engineer. The segmentation you built only works if new devices go on the right VLAN.

**Treat every IoT device as hostile until proven otherwise.** Segment first, ask questions later.

## Responsible Disclosure

This tool is for authorized network administrators auditing their own infrastructure. If you discover vulnerable devices on a network you manage, follow responsible disclosure:

1. Document the finding
2. Notify the device owner
3. Recommend remediation
4. Verify the fix

Do not use this tool on networks you do not own or have explicit written authorization to test.

## Credits

Built by Amy 3.0 for RAI during a real-world network audit. Pensacola, FL.

## License

MIT
