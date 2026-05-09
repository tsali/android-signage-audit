# Dad-KY Network Security Audit

## Overview

Security audit of a residential network managed with enterprise UniFi equipment. This network serves as a baseline comparison against the venue networks audited alongside it.

## Environment

- **Gateway**: UniFi Fiber Gateway (192.168.0.1)
- **Switch**: USW-Pro-24-PoE (24 ports, PoE)
- **Access Points**: U6-LR (hallway), UK-Ultra
- **Network**: 192.168.0.0/23
- **Internet**: Spectrum
- **Remote Access**: WireGuard VPN to primary site

## Devices Discovered

45 devices identified (26 on .0.x subnet, 19 on .1.x subnet).

### Infrastructure
| IP (NAT) | Ports | Device | Risk |
|----------|-------|--------|------|
| .204.1 | 22, 53, 80, 443, 8080, 8443 | UniFi Fiber Gateway | LOW — managed, expected |
| .204.184 | 22 | UK-Ultra AP | LOW — managed, expected |

### Cameras (10 devices)
| IP Range | Ports | Type | Risk |
|----------|-------|------|------|
| .204.20-.32 | 80, 554 | IP Cameras (Chinese OEM) | MED — RTSP exposed, auth status unverified |

Web interfaces on cameras with port 80 return jQuery-based UIs with Chinese comments, indicating OEM hardware. ONVIF and CGI probes returned empty or 404 — cameras may require authentication (positive finding compared to PTZOptics at OVW).

### Smart TV
| IP (NAT) | Ports | Device | Risk |
|----------|-------|--------|------|
| .204.191 | 80, 8008, 8009, 8443 | Sony XR-65A95K Bravia OLED | MED — Chromecast ports open, standard for Cast-enabled TV |

### Other
| IP (NAT) | Ports | Device | Risk |
|----------|-------|--------|------|
| .204.41 | 80, 443 | Canon device (printer/camera) | LOW |
| .204.72 | 80 | Unknown | LOW |
| 11 WiFi clients | (none) | Phones, laptops, tablets | LOW |

## Findings

### POSITIVE: No Critical Vulnerabilities Found

Unlike the OVW venue network:
- **No ADB (5555) exposed** on any device
- **No RDP (3389) exposed**
- **No FTP (21) exposed**
- **No SMB/NetBIOS exposed** to general network
- **No authentication bypass confirmed** on cameras
- **Enterprise-grade UniFi equipment** with proper management

### MEDIUM: Camera RTSP Exposure
10 IP cameras expose RTSP (554) and web interfaces (80) on the local network. Authentication status was not fully verified — CGI probes returned empty, suggesting auth may be enabled. Recommend verifying RTSP authentication is enabled on all cameras.

### MEDIUM: Sony TV Cast Ports
The Sony Bravia TV exposes Chromecast ports (8008, 8009) without authentication. This is standard for Cast-enabled devices and expected on a home network. Any device on the WiFi can cast content to the TV.

### LOW: Network Segmentation
The network operates on a single /23 subnet without VLANs. For a residential network with managed UniFi equipment, this is acceptable but could be improved by isolating IoT devices (cameras, TV) from personal devices.

## Comparison to OVW

| Category | Dad-KY | OVW |
|----------|--------|-----|
| Router | UniFi Gateway (enterprise) | ASUS GT-AC5300 (consumer) |
| VLANs | None (single /23) | None (flat /24) |
| Critical vulns | 0 | 5+ |
| ADB exposed | 0 devices | 2 devices |
| RDP exposed | 0 devices | 1 device |
| FTP exposed | 0 devices | 1 device |
| Auth bypass | None confirmed | CVE-2024-8956 confirmed |
| Management | UniFi Cloud | None (physical only) |
| Overall | Clean | Critical |

## Recommendations

1. **Verify camera RTSP authentication** — test with VLC to confirm feeds require credentials
2. **Consider IoT VLAN** — separate cameras and TV from personal devices (optional for home use)
3. **Keep firmware updated** — UniFi gateway and APs should be on latest stable

## Audit Conducted By

Amy 3.0 for RAI | May 8, 2026 | Authorized network security assessment
