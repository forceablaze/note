title: "OSI Model"
date: 2015-05-25 14:07:38
tags: Network
---
### OSI level
+ Layer 1 (Physical)
	+ USB, DSL...
+ Layer 2 (Data Link)
	+ L2TP, IEEE 802.2...
+ Layer 3 (Network Layer)
	+ IPv4, IPv6, ICMP, 
+ Layer 4 (Transport Layer)
	+ TCP, UDP
+ Layer 5 (Session Layer)
	+ RPC, PAP
+ Layer 6 (Presentation Layer)
	+ ASCII, JPEG, ...
+ Layer 7 (Application Layer)
	+ HTTP, FTP, telnet

### ARP
每個網卡都有個 48-bits 的 MAC address，區別各個網卡，但是上層的協定都是用 IP 來區別，因此需要一套方法對應 MAC 位址與 IP 位址。

``` bash
Address        HWtype    HWaddress           Flags Mask    Iface
10.1.9.43      ether     10:c3:7b:b6:4f:38   C             enp0s25
10.1.9.130     ether     00:18:1a:f0:bf:e1   C             enp0s25
192.168.0.1    ether     f4:ec:38:e0:03:92   C             enp0s25
10.1.9.73      ether     90:2b:34:b7:10:97   C             enp0s25
10.1.9.254     ether     00:00:0c:07:ac:09   C             enp0s25
10.1.9.2       ether     00:24:8c:a6:67:67   C             enp0s25
```