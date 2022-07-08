# ArpSpoof
ArpSpoof is a program written in rust that demonstrates how an arp spoof attack works against a local network device.

## How to build and run
The command ``cargo run`` is enough to compile and run the program. The only inputs needed for performing the attack are the gateway ip address and the victim ip address. They can both be changed in the main function.

## How it works
General explanation of how the program works. For more information on the arp protocol [click here](https://en.wikipedia.org/wiki/Address_Resolution_Protocol). For a more in depth knowledge of how the packets are structured see the file [arp_packets.rs](https://github.com/EdoardoLuciani/ArpSpoof/blob/main/src/arp_packets.rs).

### Gathering the mac address of both the gateway and victim
This step is not required as the mac addresses of both can be found using external programs, but it is easier for the user to specify ip addresses. An arp request is sent to both ip addresses and their response is read. Now both mac addresses are known!

### Getting in the middle of the communication
The next step is to send an arp reply to the gateway saying that the victim ip address corresponds to our mac address.\
Next another arp reply is sent to the victim saying that the gateway ip address corresponds to our mac address.\
In this way our device will be in the middle of the communication between the gateway and the victim.\
\
Yes, you read it correctly a reply. But who asked? Nobody. Apparently operating systems are on constant lookout for arp replies and will update their arp cache on every arp reply directed to them. It does not matter if they requested it or not. Plus arp replies are targeted which means that they do not disturb other devices in the network. Such things could not be said for arp announcements.

### Sniffing and forwarding the traffic
Now that we are in the middle, unless we want to DoS, traffic needs to be forwarded:\
Packets that come from the gateway with the victim destination ip will be sent to us due to them containing our mac as a destination, these will be forwarded to the victim by changing the source mac to ours, and the destination mac to the victim's.
Packets that come from the victim with the gateway destination ip will be sent to us due to them containing our mac as a destination, these will be forwarded to the gateway by changing the source mac to ours, and the destination mac will be the gateway's.
The communication is restored now and the victim will not notice any problem in their connection.

### Replying to arp requests
While we listen to the network, it may happen that:\
the victim sends an arp request for the gateway\
the gateway sends an arp request for the victim\
\
We have to answer it, and we arp reply to both with our mac address.

License
See [LICENSE](https://github.com/EdoardoLuciani/ArpSpoof/blob/main/LICENSE)
