// SPDX-License-Identifier: MIT
use std::net::{IpAddr, Ipv4Addr};

use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_generic::GenlMessage;
use netlink_packet_ipvs::ctrl::nlas::destination::Destination;
use netlink_packet_ipvs::ctrl::nlas::service::Service;
use netlink_packet_ipvs::ctrl::nlas::{
    destination, service, AddressFamily, IpvsCtrlAttrs,
};
use netlink_packet_ipvs::ctrl::IpvsServiceCtrl;
use netlink_sys::{protocols::NETLINK_GENERIC, Socket, SocketAddr};

fn main() {
    let d = Destination {
        address: IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
        fwd_method: destination::ForwardTypeFull::Masquerade,
        weight: 1,
        upper_threshold: None,
        lower_threshold: None,
        port: 5555,
        family: AddressFamily::IPv4,
    };

    let mut d2 = d.clone();
    d2.weight = 1234;

    let s = Service {
        address: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        netmask: service::Netmask(16, AddressFamily::IPv4), // 255.255.0.0 is a /16 netmask
        scheduler: service::Scheduler::RoundRobin, // "rr" in the command
        flags: service::Flags(0),                  // Assuming no flags are set
        port: Some(9999),
        fw_mark: None,             // Not specified in the command
        persistence_timeout: None, // Not specified in the command
        family: AddressFamily::IPv4,
        protocol: service::Protocol::TCP, // '-t' in the command indicates TCP
    };
    let txbuf = d.serialize_set(&s, &d2);
    let txbuf = Service::serialize_get();
    let r = send_buf(&txbuf).unwrap();
    for entry in r {
        match entry {
            IpvsCtrlAttrs::Service(nlas) => {
                println!("{:?}", Service::from_nlas(&nlas))
            }
            IpvsCtrlAttrs::Destination(nlas) => {
                println!("{:?}", Destination::from_nlas(&nlas))
            }
        }
    }
}
fn send_buf(buf: &[u8]) -> Result<Vec<IpvsCtrlAttrs>, std::io::Error> {
    let mut socket = Socket::new(NETLINK_GENERIC).unwrap();
    socket.bind_auto().unwrap();
    socket.connect(&SocketAddr::new(0, 0)).unwrap();
    let mut offset = 0;
    socket.send(&buf, 0).unwrap();

    let (rxbuf, _) = socket.recv_from_full().unwrap();

    let mut ret = Vec::new();
    loop {
        let buf = &rxbuf[offset..];
        let msg =
            <NetlinkMessage<GenlMessage<IpvsServiceCtrl>>>::deserialize(buf)
                .unwrap();

        match msg.payload {
            NetlinkPayload::Done(_) => break,
            NetlinkPayload::InnerMessage(genlmsg) => {
                ret.extend_from_slice(&genlmsg.payload.nlas);
            }
            NetlinkPayload::Error(err) => {
                if err.code.is_some() {
                    let e = std::io::Error::from_raw_os_error(
                        err.code.unwrap().get().abs(),
                    );
                    return Err(e);
                }
            }
            other => {
                println!("{:?}", other)
            }
        }

        offset += msg.header.length as usize;
        if offset >= rxbuf.len() || msg.header.length == 0 {
            break;
        }
    }
    Ok(ret)
}
