title: "Software switches in Linux"
date: 2015-09-22 16:51:12
tags: Linux,Network,KVM
---

## Linux has 3 types of software switches
+ bridge
+ macvlan
+ Open vSwitch

http://www.linuxfoundation.org/collaborate/workgroups/networking/

### bridge (IEEE 802.1D)

+ fdb (Forwarding DB)
	+ Each Bridge instance has its own forwarding database used regardless whether STP is run or not.
	+ The Forwarding database is placed in the net_bridge data structure and defined as hash table.
	+ An instance of the net_bridge_fdb_entry data structure is added to the database for each MAC address learnt on the bridge ports.

http://bitwisertraining.com/8021DSTD/Introduction.htm
http://bitwisertraining.com/8021DSTD/M1L2P1.htm

http://blog.xuite.net/ivan1193/blog/7801194-Spanning+Tree+Protocol+

+ Using **promiscuous mode** that allows to receive all packets
	+ Common NIC filters unicast whose dst is not its mac address
without promiscuous mode
	+ Many NICs also filter multicast / vlan-tagged packets by default

http://kernelnewbies.org/Bridging_and_Forwarding

### macvlan
VLAN using not 802.1Q tag but **mac address**

+ 4 types of mode
	+ bridge
	+ vepa (Virtual Ethernet Port Aggregator)
	+ private
	+ passthrough

+ Using **unicast filtering** if supported, instead of promiscuous mode (except for passthrough)

http://virt.kernelnewbies.org/MacVTap
http://www.kernelchina.org/node/214

### Open vSwitch

### Hardware Switch

+ SR-IOV (single root I/O virtualization)

SR-IOV allows a device, such as a network adapter, to separate access to its resources among various PCIe hardware functions. These functions consist of the following types:
+ PF (Physical Function)
+ VF (Virtual Function)

PF 與 VF 之間的溝通透過 Layer2 的 classifier/sorter switch 處理。

Example
1. packet arrived
2. send to L2 sorter
3. sorted based upon mac/vlan, placed into queue/pool
4. DMA action initiated (by Intel chipset )
5. VT-d re-maps DMA address

Removes CPU from the process of moving data to and from a VM. Data is DMA'd directly to and from a VM without the software switch in the VMM ever 'touching' it.

https://msdn.microsoft.com/en-us/library/windows/hardware/hh440148(v=vs.85).aspx

	