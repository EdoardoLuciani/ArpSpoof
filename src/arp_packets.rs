use std::net::Ipv4Addr;
use pnet::packet::{self, MutablePacket, Packet};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations};
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::PacketSize;
use pnet::util::MacAddr;

// Who has [target_ip]? Tell [sender_ip] at [sender_mac]
pub fn arp_request(sender_mac: MacAddr, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
    let mut arp_packet = packet::arp::MutableArpPacket::owned(vec![0u8; packet::arp::ArpPacket::minimum_packet_size()]).unwrap();
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(sender_mac);
    arp_packet.set_sender_proto_addr(sender_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    let ethernet_packet_data = vec![0u8; packet::ethernet::EthernetPacket::minimum_packet_size() + arp_packet.packet_size()];
    let mut ethernet_packet = packet::ethernet::MutableEthernetPacket::owned(ethernet_packet_data).unwrap();
    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(sender_mac);
    ethernet_packet.set_ethertype(packet::ethernet::EtherTypes::Arp);
    ethernet_packet.set_payload(arp_packet.packet_mut());
    ethernet_packet.packet().to_owned()
}

// [sender_target_ip] now has mac address [sender_mac]
pub fn arp_announcement(sender_mac: MacAddr, sender_target_ip: Ipv4Addr) -> Vec<u8> {
    let mut arp_packet = packet::arp::MutableArpPacket::owned(vec![0u8; packet::arp::ArpPacket::minimum_packet_size()]).unwrap();
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(sender_mac);
    arp_packet.set_sender_proto_addr(sender_target_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(sender_target_ip);

    let ethernet_packet_data = vec![0u8; packet::ethernet::EthernetPacket::minimum_packet_size() + arp_packet.packet_size()];
    let mut ethernet_packet = packet::ethernet::MutableEthernetPacket::owned(ethernet_packet_data).unwrap();
    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(sender_mac);
    ethernet_packet.set_ethertype(packet::ethernet::EtherTypes::Arp);
    ethernet_packet.set_payload(arp_packet.packet_mut());
    ethernet_packet.packet().to_owned()
}

// [target_ip] at [target_mac] sent an arp request for [sender_ip].
// [sender_ip] is [sender_mac]
pub fn arp_reply(sender_mac: MacAddr, sender_ip: Ipv4Addr, target_mac: MacAddr, target_ip: Ipv4Addr) -> Vec<u8> {
    let mut arp_packet = packet::arp::MutableArpPacket::owned(vec![0u8; packet::arp::ArpPacket::minimum_packet_size()]).unwrap();
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Reply);
    arp_packet.set_sender_hw_addr(sender_mac);
    arp_packet.set_sender_proto_addr(sender_ip);
    arp_packet.set_target_hw_addr(target_mac);
    arp_packet.set_target_proto_addr(target_ip);

    let ethernet_packet_data = vec![0u8; packet::ethernet::EthernetPacket::minimum_packet_size() + arp_packet.packet_size()];
    let mut ethernet_packet = packet::ethernet::MutableEthernetPacket::owned(ethernet_packet_data).unwrap();
    ethernet_packet.set_destination(target_mac);
    ethernet_packet.set_source(sender_mac);
    ethernet_packet.set_ethertype(packet::ethernet::EtherTypes::Arp);
    ethernet_packet.set_payload(arp_packet.packet_mut());
    ethernet_packet.packet().to_owned()
}