# OVW Network Security Audit

## Overview

Security audit of a live production venue (wrestling arena) network. Flat consumer network with no segmentation, sharing bandwidth and access between production equipment, security cameras, staff devices, and audience WiFi during live events.

## Environment

- **Router**: Consumer-grade ASUS GT-AC5300 (no VLANs, no remote management)
- **Network**: Flat 192.168.x.0/24 — all devices on same subnet
- **Switch**: UniFi USW-16-PoE (42W PoE budget, 23W used)
- **Secondary Switch**: Netgear GS308EP (unmanaged, no visibility)
- **WiFi**: Consumer WiFi from ASUS router — no band steering, no client management
- **Internet**: Spectrum cable

## Devices Discovered

20 devices identified on the network via ping sweep and port scanning.

### Infrastructure
| IP | Ports | Device | Risk |
|----|-------|--------|------|
| .1 | 53, 80, 8443 | ASUS Router | HIGH — Admin UI exposed to entire LAN |
| .249 | 22 | USW-16-PoE Switch | LOW — expected |
| .30 | 22, 80 | CompanionPi (Bitfocus) | LOW — expected |

### Cameras — CRITICAL
| IP | Ports | Device | Risk |
|----|-------|--------|------|
| .11 | 22, 80, 443, 554, **5555** | PTZOptics F64.HI (PTZ 1) | **CRITICAL** — See PTZ-OPTICS-AUDIT.md |
| .12 | 22, 80, 443, 554, **5555** | PTZOptics F64.HI (PTZ 2) | **CRITICAL** — See PTZ-OPTICS-AUDIT.md |
| .2 | 80, 554 | IP Camera | MED — RTSP + web UI |
| .3 | 80, 554 | IP Camera | MED — RTSP + web UI |
| .4 | 80, 554 | IP Camera | MED — RTSP + web UI |
| .5 | 80, 554 | IP Camera | MED — RTSP + web UI |

### Security/NVR
| IP | Ports | Device | Risk |
|----|-------|--------|------|
| .19 | 135, 139, 445, **3389** | Windows NVR (Blue Iris) | **HIGH** — RDP exposed to flat network |

### Production Equipment
| IP | Ports | Device | Risk |
|----|-------|--------|------|
| .6 | **21**, 80, 445 | Unknown (FTP + SMB) | **HIGH** — FTP is never secure |
| .18 | 135, 139, 445 | Windows PC | MED — SMB/NetBIOS |
| .198 | 135, 139, 445 | Windows PC | MED — SMB/NetBIOS |

### Storage
| IP | Ports | Device | Risk |
|----|-------|--------|------|
| .25 | 80, 139, 445 | EVO SNS NAS | MED — SMB exposed, was at 0 bytes free |

### Other
| IP | Ports | Device | Risk |
|----|-------|--------|------|
| .7 | 80 | Unknown | LOW |
| .10 | 80 | Unknown | LOW |
| .110 | 80 | Unknown | LOW |
| .43 | (none) | Unknown | LOW |
| .108 | (none) | Unknown | LOW |
| .220 | (none) | Unknown | LOW |

## Critical Findings

### 1. PTZOptics Cameras — CVE-2024-8956 Auth Bypass (CONFIRMED)
Two $1,500 professional PTZ cameras with:
- Full configuration dump without authentication
- RTSP video feeds with auth disabled
- ONVIF PTZ control with auth disabled — cameras can be moved by anyone on WiFi
- ADB port 5555 open (requires key auth)
- SSH port 22 open with hardcoded credentials (CVE-2025-35451)
- Full details: [PTZ-OPTICS-AUDIT.md](PTZ-OPTICS-AUDIT.md)

### 2. NVR with RDP Exposed
The Blue Iris camera NVR has Remote Desktop Protocol (3389) open on the flat network. During live events, audience members on WiFi can attempt RDP connections to the camera system.

### 3. FTP on Production Device
Device at .6 has FTP (port 21) open. FTP transmits credentials in cleartext. Combined with SMB (445), this device is a dual file sharing vulnerability.

### 4. Flat Network — No Segmentation
Production equipment (ATEM, VideoHub, X32 mixer), security cameras, NVR, NAS storage, staff devices, and **audience WiFi during live events** all share one subnet. No VLANs, no firewall rules between device types.

### 5. Consumer Router
The ASUS GT-AC5300 provides no:
- VLAN support
- Remote management capability
- Network segmentation
- Proper firewall rules between device types
- Band steering or client management for high-density events

### 6. NAS Storage at Capacity
EVO SNS NAS (NAS2) was found at 0 bytes free, with 1,993 old security camera backup files consuming the entire 5.5TB volume. Files were from March 2026, 2+ months old.

## Attack Scenarios

### During Live Event
1. Audience member connects to venue WiFi
2. Scans network — finds PTZ cameras on .11 and .12
3. Accesses `http://.11/cgi-bin/param.cgi?get_device_conf` — full config dump, no auth
4. Controls camera pan/tilt/zoom via ONVIF — points cameras away from ring
5. Views all RTSP camera feeds without credentials
6. Attempts RDP to NVR at .19
7. Accesses production files via SMB on .6, .18, .198
8. All from a phone on the audience WiFi

### Persistent Access
1. Attacker identifies PTZ camera SSH (CVE-2025-35451)
2. Gains root shell on camera
3. Uses camera as persistent network foothold
4. Pivots to NVR, NAS, production equipment
5. Exfiltrates video archives from EVO SNS
6. Installs backdoor that survives camera reboots

## Remediation

### Immediate ($0)
1. Enable RTSP authentication on PTZ cameras
2. Enable ONVIF authentication on PTZ cameras
3. Update PTZ camera firmware (patches CVE-2024-8956/8957)
4. Disable FTP on .6 — use SFTP or SMB instead
5. Restrict RDP access on NVR (Windows Firewall)
6. Set up automated cleanup for NAS backup files

### Short-Term ($1,437 — Option B)
1. Replace ASUS router with UniFi Cloud Gateway Ultra
2. Add 2x U7-Pro WiFi 7 access points
3. Replace USW-16-PoE with USW-24-PoE
4. Implement VLAN segmentation:
   - Production VLAN (ATEM, VideoHub, X32, PTZ cameras, CompanionPi)
   - Camera VLAN (fixed cameras, NVR)
   - Staff WiFi VLAN
   - Guest/Audience WiFi VLAN (isolated, throttled)
5. Full proposal: OVW-Network-Proposal-2026.pdf

## References

- [PTZOptics Camera Audit](PTZ-OPTICS-AUDIT.md) — detailed camera vulnerability assessment
- [Android Signage Audit Tool](audit.py) — network scanner for exposed Android devices
- [PTZOptics Known Vulnerabilities](https://ptzoptics.com/known-vulnerabilities-and-fixes/)
- [CISA Advisory ICSA-25-162-10](https://www.cisa.gov/news-events/ics-advisories/icsa-25-162-10)
- [The $30 Security Hole in Your Lobby](https://cultofjames.org/the-30-security-hole-in-your-lobby/) — related IoT security blog post

## Audit Conducted By

Amy 3.0 for RAI | May 8, 2026 | Authorized network security assessment
