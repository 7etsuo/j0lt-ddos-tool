# j0lt.c DNS Amplification Tool
<img src="https://github.com/7etsuo/j0lt-ddos-tool/assets/90065760/6609a809-d34a-487f-8f69-b960445b376e" alt="Cyber Security Expert" width="600" height="400">

------------------------------------------------------------

**WARNING: This tool is for educational purposes only. It should only be used in controlled, authorized environments.**

------------------------------------------------------------
## Author
> * 7etsuo 
> * [X](https://x.com/7etsuo)
> * [GitHub](https://github.com/7etsuo)

------------------------------------------------------------
## Overview
This repository contains `j0lt`, a command-line tool designed to demonstrate the mechanics and impact of DNS amplification attacks—a common type of Distributed Denial of Service (DDoS) attack. It is intended for educational purposes within cybersecurity labs to prevent real-world harm.

## Key Features:
- **Enables IP Spoofing:** Specifies a source IP to simulate attacks from different origins.
- **Targets Specific Ports:** Demonstrates exploitation of UDP-based services.
- **Controls Attack Magnitude:** Tests system resilience against various loads.
- **Debug Mode:** Offers detailed packet content outputs for educational purposes.
- **Hex Dump:** Provides optional hex dumps of packet headers for analysis.
- **No Resolv List Mode:** Allows use of a pre-existing DNS server list instead of downloading a new one.

## Usage Warning
The use of `j0lt` for any unauthorized DDoS attacks is illegal and unethical. Ensure you have explicit permission from network administrators.

## Resources
* [RFC 1700 - Assigned Numbers](https://datatracker.ietf.org/doc/html/rfc1700)
* [RFC 1035 - DNS](https://datatracker.ietf.org/doc/html/rfc1035)
* [RFC 1071 - Checksum](https://datatracker.ietf.org/doc/html/rfc1071)
* [RFC 768 - UDP](https://www.rfc-editor.org/rfc/rfc768.html)
* [RFC 760 - IP](https://www.rfc-editor.org/rfc/rfc760.html)

------------------------------------------------------------
## Usage
```bash
$ sudo ./j0lt -t <target> -p <port> -m <magnitude>
$ gcc j0lt.c -o j0lt
$ sudo ./j0lt -t 127.0.0.1 -p 80 -m 1337
```
 ------------------------------------------------------------
 ## Options
 - `[-x]` will print a hexdump of the packet headers
 - `[-d]` puts j0lt into debug mode, no packets are sent
 - `[-r list]` will not fetch a resolv list, if one is provided.
 ------------------------------------------------------------
## Understanding DNS Amplification Attacks
DNS amplification attacks involve attackers using open DNS servers to flood a target with DNS response traffic. This is achieved by spoofing the target's address in DNS lookup requests, causing the server's response to overwhelm the target.


