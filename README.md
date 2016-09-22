


THIS SOFTWARE IS DEPRECATED.   PLEASE USE SLIMSHIM INSTEAD.


Documentation is available at https://mkirby.org/mkblog/?p=328

QUICK OVERVIEW/TL;DR

1. This allows you to get past NAC (as long as you shim a trusted device)
2. This allows you to MITM any host connecting through the shimbox
3. This allows you to spoof as any device connected to the Eth1
4. Everything is transparent to the network

The shimbox is a dual-nic device that plugs into the network between a pc and the switch or between a switch uplink port and the router.  The shimbox will spoof the IPs and MACs of the IPs on the LAN, and the router on it’s opposite interfaces.  It creates spoofed IPs/MACs of every device in the LAN on the shimbox’s outside interface and creates spoofed IPs/MACs of the router(s) on the shimbox’s inside interface. This allows the shimbox to share the same IP and MAC with all devices connected to it’s internal interface. The shimbox can then pivot through any of those LAN IPs to attack the network or to MITM attack the devices on the switch. A single device can also be shimmed with the use of a crossover cable. This is particularly useful on networks that have NAC (Network Access Control) where a rogue device is incapable of joining the network.


The goals of this project were as follows:

1. The LAN devices must not perceive any manipulation to the router IP and MAC.
2. The LAN devices must not detect any changes to it’s network configuration, otherwise the user will get a popup to classify the network as home, work, or public.
3. The LAN devices must be able to connect to other IPs on the same LAN, even if they are on a separate bridged-switch.
4. The LAN devices must not see a duplicate IP/MAC.
5. The router(s) must not see a duplicate IP/MAC.
6. The LAN devices must be able to connect to the shim box, but only when I allow it.  This is for when I shim my own PC to do pentesting.
7. The LAN IPs and MACs cannot be manipulated.  The surrounding network cannot see any changes to any device on the LAN.
8. NAC cannot see any changes and must trust the shimbox and LAN.
9. The shimbox must forward any inbound connections to the IPs on the LAN.  (In case any services such as RDP, NAC agents, etc.).
10. The shimbox must be able to connect to the network using the IP of any IP on the shimmed LAN.
11. The shimbox must be able to be removed with only a short disconnect for shimmed devices as the cables are restored to prior configuration.
12. A network scanner must not be able to detect the shimbox.

The only caveat is broadcast packets, which netbios is notorious for.  IPTables is not capable of forwarding broadcast packets.  This should only be a problem for “network neighborhood” discovery on the LAN.  Connecting directly to a CIFS/SMB server will work just fine and very entertaining with MITM attacks to steal password hashes.

As anyone with network skills knows, you cannot just plug in a new device, spoof the IP/MAC without first unplugging the PC you are mimicking.   I toyed with the idea of using a bridge and arptables to spoof the MAC, but realized that TCP would break when either the shimbox or PC would reply with RST packets for a connection was intended for the other.  The solution was to use network namespaces. Linux network namespaces are similar to Cisco VRFs. It’s a container for a virtualized network stack. Think of a chroot for networking, or a virtual machine without an OS. A network namespace contains it’s own arp tables, firewall rules, routes, interfaces, and IPs. My current version can only do IPv4, but I have plans for IPv6. It can shim dhcp or static IPs. I have a separate script called dhcptail.pl to watch for dhcp requests and auto-run shim.pl with it’s MAC.  For static IPs, you’ll have to sniff and watch, and run shim.pl manually with the appropriate IP and MAC flags.  The shimbox will create up to 2 namespaces for each device you want to shim. The router-side namespace will be re-used if multiple devices are using the same router.

For my shimbox hardware, I chose a Zotac MI542. It has dual-core i5, 16gb ram, 500gb ssd, wifi, and 2 gigabit nics. It is running Kali 2. There is no hardware manipulation. Any hardware with 2 nics will work. A usb nic adapter would work if your hardware has only 1 nic. I am currently experimenting on porting Shim.pl to OpenWRT, which will require a custom kernel.

The shimbox has 2 physical NICs.  ETH0 is external, facing the router, and an empty bridge is created called BR0. ETH1 is internal, facing the LAN on the uplink port, or an individual device, and has an empty bridge called BR1.  A virtual interface, TAP0, is created as an internal bridge. Each device IP gets a dedicated namespace on the external bridge. The router(s) gets a dedicated namespace on the internal bridge, but will be re-used if more than 1 device is using that router. Two TAP interfaces are created in each namespace. TAP1 is the spoofed IP/MAC and TAP2 links to the internal TAP0 bridge. The TAP2 interfaces are assigned an IP from the 169.254.0.0/16 space. IPTables and ARPTables are used to SNAT and DNAT the traffic through the shimbox.


Here is breakdown of how shim.pl works
- If shim.pl is ran with –shimmac=, it will use dhcp to spoof a dhclient on the outside and a dhcpd server on the inside. Otherwise flags for router/shim IPs/MACs must be supplied.
- A namespace is created for the device to be shimmed and the 2 tap interfaces are created. Tap1 is the device IP/MAC and Tap2 is the link to the internal bridge.
- tshark is ran during dhclient, if dhcp is used, to gather dhcp info and also create the dhcpd server on the inside.
- A namespace is created for the router, unless it already exists for a previously shimmed device in which case a new IP is added to Tap2 along with a PBR for the shimmed IP. Tap1 is the router IP/MAC and Tap2 is the link to the internal bridge.
- IPTables will DNAT any inbound traffic to the device IP as the Tap2 IP of it’s respective router namespace, which is then DNAT’d again to the actual device IP. And vice versa.
- IPTables will increment the TTL on outbound packets so that the shimmed devices cannot see the shimbox in a traceroute
- Proxy arp is enable on the router namespace and routes are added/updated to route for other IPs on the same subnet. This allows and shimmed device to connect to other IPs on the same subnet. If multiple shimmed devices exist, their IP is removed from the routes. Each shimmed device is assigned an individual PBR table.
- Appropriate ARPTables rules are added to prevent collisions in the event that someone swaps the cables and interfaces.
- Additional IPTables can be ran to forward ports to the shimbox or redirect any other ports. For example, I can redirect port 2222 to the shimbox ssh so I can connect to it from the inside or outside. Very useful when you need to forward ports for reverse-bind exploits.

The shim.pl script will fork after getting enough information so that the bulk of the program is executed in the background. The whole process can take 10-60 seconds per shim with dhcp, but it can run multiple shims in parallel. The internal network utilizes the 169.254.0.0/16, which allows shim.pl to shim up to 32,766 devices since 2 internal IPs are used per shimmed device. When I want to pivot shimbox to mimic a device, I simply add the shim’s linked bridge IP(tap2) as my default route on the shimbox.

Here is the output of shim.pl –showshims with 2 active shims:
```
SHIMNS: S080027db4f52
ROUTERNS: R6805ca325e85
HOSTNAME: win7
OUTSIDE eth0/br0
|	brS080027db4f52/tap1/192.168.1.232
|_	lnS080027db4f52/tap2/169.254.0.4
	|_	CORE BRIDGE tap0/169.254.0.1
		|	lnR6805ca325e85/tap2/169.254.0.5
		|_	brR6805ca325e85/tap1/192.168.1.1
			|_	INSIDE eth1/br1

SHIMNS: Sac87a30a4362
ROUTERNS: R6805ca325e85
HOSTNAME: agent86
OUTSIDE eth0/br0
|	brSac87a30a4362/tap1/192.168.1.19
|_	lnSac87a30a4362/tap2/169.254.0.2
	|_	CORE BRIDGE tap0/169.254.0.1
		|	lnR6805ca325e85/tap2/169.254.0.3
		|_	brR6805ca325e85/tap1/192.168.1.1
			|_	INSIDE eth1/br1

```
 

After a shim is built, you can view it’s settings through ‘ip netns exec’.

Here is an example of ‘ip netns exec Sac87a30a4362 iptables-save’ to view the shim netns (external namespace)
```
*mangle
:PREROUTING ACCEPT [377:154569]
:INPUT ACCEPT [74:10684]
:FORWARD ACCEPT [279:140040]
:OUTPUT ACCEPT [1:40]
:POSTROUTING ACCEPT [280:140080]
COMMIT
*filter
:INPUT ACCEPT [74:10684]
:FORWARD ACCEPT [279:140040]
:OUTPUT ACCEPT [1:40]
COMMIT
*nat
:PREROUTING ACCEPT [66:9704]
:INPUT ACCEPT [54:7824]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [2:156]
-A PREROUTING -d 192.168.1.19/32 -p udp -m udp --dport 2222 -j DNAT --to-destination 169.254.0.1:22
-A PREROUTING -d 192.168.1.19/32 -p tcp -m tcp --dport 2222 -j DNAT --to-destination 169.254.0.1:22
-A PREROUTING -d 192.168.1.19/32 -p udp -m udp -m multiport --dports 4444 -j DNAT --to-destination 169.254.0.1
-A PREROUTING -d 192.168.1.19/32 -p tcp -m tcp -m multiport --dports 4444 -j DNAT --to-destination 169.254.0.1
-A PREROUTING -d 192.168.1.19/32 ! -p icmp -j DNAT --to-destination 169.254.0.3
-A PREROUTING -d 169.254.0.2/32 ! -p icmp -j DNAT --to-destination 192.168.1.1
-A POSTROUTING -d 169.254.0.1/32 -o tap2 -p udp -m udp --dport 22 -j SNAT --to-source 169.254.0.2
-A POSTROUTING -d 169.254.0.1/32 -o tap2 -p tcp -m tcp --dport 22 -j SNAT --to-source 169.254.0.2
-A POSTROUTING -d 169.254.0.1/32 -o tap2 -p udp -m udp -m multiport --dports 4444 -j SNAT --to-source 169.254.0.2
-A POSTROUTING -d 169.254.0.1/32 -o tap2 -p tcp -m tcp -m multiport --dports 4444 -j SNAT --to-source 169.254.0.2
-A POSTROUTING ! -d 169.254.0.0/16 -o tap1 -j SNAT --to-source 192.168.1.19
COMMIT
```
Here is an example of ‘ip netns exec R6805ca325e85 iptables-save’ to view the spoofed router netns (internal namespace)
```
*mangle
:PREROUTING ACCEPT [1428:1143012]
:INPUT ACCEPT [138:20976]
:FORWARD ACCEPT [1276:1117304]
:OUTPUT ACCEPT [14:4676]
:POSTROUTING ACCEPT [1290:1121980]
-A PREROUTING -m ttl --ttl-gt 1 -j TTL --ttl-inc 2
COMMIT
*filter
:INPUT ACCEPT [161:26760]
:FORWARD ACCEPT [1342:1128970]
:OUTPUT ACCEPT [16:5388]
COMMIT
*nat
:PREROUTING ACCEPT [143:21296]
:INPUT ACCEPT [138:20976]
:OUTPUT ACCEPT [9:3006]
:POSTROUTING ACCEPT [23:4098]
-A PREROUTING -s 192.168.1.232/32 -p udp -m udp --dport 2222 -j DNAT --to-destination 169.254.0.1:22
-A PREROUTING -s 192.168.1.232/32 -p tcp -m tcp --dport 2222 -j DNAT --to-destination 169.254.0.1:22
-A PREROUTING -s 192.168.1.232/32 -d 192.168.1.1/32 -p udp -m udp -m multiport --dports 4444 -j DNAT --to-destination 169.254.0.1
-A PREROUTING -s 192.168.1.232/32 -d 192.168.1.1/32 -p tcp -m tcp -m multiport --dports 4444 -j DNAT --to-destination 169.254.0.1
-A PREROUTING -s 192.168.1.19/32 -p udp -m udp --dport 2222 -j DNAT --to-destination 169.254.0.1:22
-A PREROUTING -s 192.168.1.19/32 -p tcp -m tcp --dport 2222 -j DNAT --to-destination 169.254.0.1:22
-A PREROUTING -s 192.168.1.19/32 -d 192.168.1.1/32 -p udp -m udp -m multiport --dports 4444 -j DNAT --to-destination 169.254.0.1
-A PREROUTING -s 192.168.1.19/32 -d 192.168.1.1/32 -p tcp -m tcp -m multiport --dports 4444 -j DNAT --to-destination 169.254.0.1
-A PREROUTING -d 192.168.1.1/32 ! -p icmp -j DNAT --to-destination 169.254.0.2
-A PREROUTING -d 169.254.0.3/32 ! -p icmp -j DNAT --to-destination 192.168.1.19
-A PREROUTING -d 192.168.1.1/32 ! -p icmp -j DNAT --to-destination 169.254.0.4
-A PREROUTING -d 169.254.0.5/32 ! -p icmp -j DNAT --to-destination 192.168.1.232
-A POSTROUTING -d 169.254.0.1/32 -o tap2 -p udp -m udp --dport 22 -j SNAT --to-source 169.254.0.5
-A POSTROUTING -d 169.254.0.1/32 -o tap2 -p tcp -m tcp --dport 22 -j SNAT --to-source 169.254.0.5
-A POSTROUTING -d 169.254.0.1/32 -o tap2 -p udp -m udp -m multiport --dports 4444 -j SNAT --to-source 169.254.0.5
-A POSTROUTING -d 169.254.0.1/32 -o tap2 -p tcp -m tcp -m multiport --dports 4444 -j SNAT --to-source 169.254.0.5
-A POSTROUTING -d 169.254.0.1/32 -o tap2 -p udp -m udp --dport 22 -j SNAT --to-source 169.254.0.3
-A POSTROUTING -d 169.254.0.1/32 -o tap2 -p tcp -m tcp --dport 22 -j SNAT --to-source 169.254.0.3
-A POSTROUTING -d 169.254.0.1/32 -o tap2 -p udp -m udp -m multiport --dports 4444 -j SNAT --to-source 169.254.0.3
-A POSTROUTING -d 169.254.0.1/32 -o tap2 -p tcp -m tcp -m multiport --dports 4444 -j SNAT --to-source 169.254.0.3
-A POSTROUTING -s 192.168.1.19/32 -j SNAT --to-source 169.254.0.3
-A POSTROUTING -s 192.168.1.232/32 -j SNAT --to-source 169.254.0.5
COMMIT
```
