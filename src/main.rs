extern crate core;

use std::net::{IpAddr, Ipv4Addr};
use pnet_datalink;
use pnet::packet::{self, MutablePacket, Packet};
use pnet::packet::ethernet::{EtherType, EtherTypes};
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4;
use pnet::packet::PacketSize;
use pnet_datalink::Channel;

fn get_gateway_address() {
    let interface_name = "wlp3s0";
    let interface = {
        pnet_datalink::interfaces().iter().find(|interface| {
            interface.name.eq(interface_name)
        }).expect(&format!("Interface {} could not be found", interface_name)).clone()
    };

    let interface_ipv4_address = {
        let ip = interface.ips.iter().find(|ip | {
            ip.ip().is_ipv4()
        }).expect("Interface has no valid ipv4 address");

        match ip.ip() {
            IpAddr::V4(ipv4) => ipv4,
            IpAddr::V6(_) => unreachable!()
        }
    };

    let packet = {
        let mut icmp_packet = packet::icmp::MutableIcmpPacket::owned(vec![0u8; packet::icmp::IcmpPacket::minimum_packet_size() + 4]).unwrap();
        icmp_packet.set_icmp_type(IcmpTypes::Traceroute);
        icmp_packet.set_icmp_code(packet::icmp::IcmpCode::new(0));
        icmp_packet.set_checksum(pnet::packet::icmp::checksum(&icmp_packet.to_immutable()));

        let mut ipv4_packet_data = vec![0u8; packet::ipv4::Ipv4Packet::minimum_packet_size() + icmp_packet.packet_size() + 4];
        let ipv4_packet_len = ipv4_packet_data.len() as u16;
        let mut ipv4_packet = packet::ipv4::MutableIpv4Packet::new(&mut ipv4_packet_data).unwrap();
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length(5);
        ipv4_packet.set_ttl(1);
        ipv4_packet.set_total_length(ipv4_packet_len);
        ipv4_packet.set_flags(0x40);
        ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        ipv4_packet.set_source(interface_ipv4_address);
        ipv4_packet.set_destination(Ipv4Addr::new(224,0,0,2));
        ipv4_packet.set_payload(icmp_packet.packet_mut());

        let ethernet_packet_data = vec![0u8; packet::ethernet::EthernetPacket::minimum_packet_size() + ipv4_packet.packet_size()];
        let mut ethernet_packet = packet::ethernet::MutableEthernetPacket::owned(ethernet_packet_data).unwrap();
        ethernet_packet.set_destination(pnet_datalink::MacAddr::broadcast());
        ethernet_packet.set_source(interface.mac.unwrap());
        ethernet_packet.set_ethertype(packet::ethernet::EtherTypes::Ipv4);
        ethernet_packet.set_payload(ipv4_packet.packet_mut());

        ethernet_packet.packet().to_owned()
    };

    let (mut tx, mut rx) = match pnet_datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(rx, tx)) => (rx, tx),
        Ok(_) => panic!("unhandled channel type"),
        Err(e) => panic!("unable to create channel: {}", e),
    };

    tx.send_to(&packet, None).expect("Could not send packet").expect("Packet sending failed");

    loop {
        let incoming_packet = rx.next();
        if let Ok(packet_data) = incoming_packet {
            if let Some(ethernet_packet) = packet::ethernet::EthernetPacket::new(packet_data) {
                if ethernet_packet.get_ethertype() == EtherTypes::Ipv4 {
                   if let Some(ipv4_packet) = packet::ipv4::Ipv4Packet::new(ethernet_packet.payload()) {
                        if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
                            if let Some(icmp_packet) = packet::icmp::IcmpPacket::new(ipv4_packet.payload()) {
                                dbg!(icmp_packet);
                            }
                        }
                   }
                }
            }
        }
    }
}

fn main() {
    get_gateway_address();
}
