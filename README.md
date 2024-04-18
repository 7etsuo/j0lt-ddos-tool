# j0lt.c DNS amplification tool

_This tool is not weaponized, it is for educational purposes only._

> This repository contains the source code for j0lt, a command-line tool designed to simulate DNS amplification attacks for educational purposes. j0lt generates and sends UDP packets with forged IP headers to demonstrate the potential impact and operation of DNS amplification, a common type of Distributed Denial of Service (DDoS) attack. The tool is intended strictly for use in controlled, authorized environments such as cybersecurity labs where the effects of DDoS can be studied without causing actual harm.

## Key Features:
- IP Spoofing: Allows the specification of a source IP address to simulate the attack coming from different origins.
- Port Targeting: Targets specific ports on the recipient system to demonstrate how UDP-based services can be exploited.
- Magnitude Control: Users can define the scale of the attack to test system resilience against varying loads.
- Debug Mode: Provides a detailed output of the packet contents for educational insight into how network data is structured and transmitted.
- Hex Dump: Optionally outputs a hex dump of the packet headers for further analysis.
- No Resolv List Mode: Optionally avoids downloading a new list of DNS servers, allowing users to specify a custom path to a pre-existing list.

## Usage Warning:
> The tool is designed for educational use only, under strict conditions with explicit permission from the network administrators. Unauthorized use of this tool to perform actual DDoS attacks is illegal and unethical.

------------------------------------------------------------
## Author
> * 7etsuo
> * https://x.com/7etsuo
> * https://github.com/7etsuo
 ------------------------------------------------------------
 ## Resources:
 * https://datatracker.ietf.org/doc/html/rfc1700    (NUMBERS)
 * https://datatracker.ietf.org/doc/html/rfc1035    (DNS)
 * https://datatracker.ietf.org/doc/html/rfc1071    (CHECKSUM)
 * https://www.rfc-editor.org/rfc/rfc768.html       (UDP)
 * https://www.rfc-editor.org/rfc/rfc760            (IP)
 ------------------------------------------------------------
 ## Usage
 - `$ sudo ./j0lt -t <target> -p <port> -m <magnitude>`
 - `$ gcc j0lt.c -o j0lt`
 - `$ sudo ./j0lt -t 127.0.0.1 -p 80 -m 1337`
 ------------------------------------------------------------
 ## Options
 - `[-x]` will print a hexdump of the packet headers
 - `[-d]` puts j0lt into debug mode, no packets are sent
 - `[-r list]` will not fetch a resolv list, if one is provided.
 ------------------------------------------------------------
## What is DNS a amplification attack
 _A type of DDoS attack in which attackers use publicly
 accessible open DNS servers to flood a target with DNS
 response traffic. An attacker sends a DNS lookup request
 to an open DNS server with the source address spoofed to
 be the target’s address. When the DNS server sends the
 record response, it is sent to the target instead._
