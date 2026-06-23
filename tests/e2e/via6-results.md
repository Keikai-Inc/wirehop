# 4via6 overlapping-subnet e2e

- Date: 2026-06-23
- Result: PASS
- ICMPv6 echo over via6: 3/3 received, 0% loss, rtt avg 4.8ms, ttl=63 (one
  forwarding hop through the gateway — confirms SIIT + kernel NAT path)
- Overlap: client LAN and site-B LAN both `192.168.1.0/24`; device `192.168.1.50`
- Gateway site id: `99272260`
- via6 address tested: `fd68:6f70:7669:6136:05ea:c644:c0a8:0132`
- Local v4 collision present on client: yes (`192.168.1.50` on collision0)
- Assertion: `ping -6 fd68:6f70:7669:6136:05ea:c644:c0a8:0132` from the client succeeds → reached the REMOTE device
  (the fd68::/64 via6 address can only route through the tunnel+gateway+SIIT,
   so a reply proves disambiguation from the local collision).
