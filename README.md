# j0lt.c DNS amplification tool

_This tool is not weaponized, it is for educational purposes only._

------------------------------------------------------------
## Author
> * snowcrash
> * snowcra5h@icloud.com
> * https://github.com/snowcra5h/
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
