// SPDX-License-Identifier: MIT
use std::net::{IpAddr, Ipv4Addr};

use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST,
};
use netlink_packet_generic::GenlMessage;
use netlink_packet_ipvs::ctrl::nlas::destination::Destination;
use netlink_packet_ipvs::ctrl::nlas::{
    self, destination, service, AddressFamily,
};
use netlink_packet_ipvs::ctrl::{IpvsCtrlCmd, IpvsServiceCtrl};
use netlink_sys::{protocols::NETLINK_GENERIC, Socket, SocketAddr};

fn main() {
    let mut socket = Socket::new(NETLINK_GENERIC).unwrap();
    socket.bind_auto().unwrap();
    socket.connect(&SocketAddr::new(0, 0)).unwrap();

    let d = destination::Destination {
        address: IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
        fwd_method: destination::ForwardTypeFull::Masquerade,
        weight: 1,
        upper_threshold: None,
        lower_threshold: None,
        port: 5555,
        family: AddressFamily::IPv4,
    };

    let s = service::Service {
        address: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        netmask: service::Netmask(16, AddressFamily::IPv4), // 255.255.0.0 is a /16 netmask
        scheduler: service::Scheduler::RoundRobin, // "rr" in the command
        flags: service::Flags(0),                  // Assuming no flags are set
        port: Some(9999),
        fw_mark: None,             // Not specified in the command
        persistence_timeout: None, // Not specified in the command
        family: AddressFamily::IPv4,
        protocol: service::Protocol::TCP, // '-t' in the command indicates TCP
        stats: service::Stats,            // Assuming default Stats
        stats64: service::Stats64,        // Assuming default Stats64
    };
    //*
    let mut genlmsg = GenlMessage::from_payload(IpvsServiceCtrl {
        cmd: IpvsCtrlCmd::NewDest,
        nlas: vec![
            nlas::IpvsCtrlAttrs::Service(s.create_nlas()),
            nlas::IpvsCtrlAttrs::Destination(d.create_nlas()),
        ],
        //nlas: vec![],
    });
    //*/
    /*
    let mut genlmsg = GenlMessage::from_payload(IpvsServiceCtrl {
        cmd: IpvsCtrlCmd::NewDest,
        nlas: d.create_nlas() + s.create_nlas(),
    });
    */
    //println!("{:?}", s.create_nlas());
    genlmsg.finalize();
    let mut nlmsg = NetlinkMessage::from(genlmsg);
    // TODO: DUMP for GET, remove DUMP for SET
    nlmsg.header.flags = NLM_F_REQUEST | NLM_F_ACK;
    nlmsg.finalize();

    println!("{:?}", nlmsg);
    println!("{}", nlmsg.buffer_len());
    // header?
    let mut txbuf = vec![0u8; nlmsg.buffer_len()];
    println!("{:?}", txbuf);
    nlmsg.serialize(&mut txbuf);
    println!("{:?}", txbuf);

    socket.send(&txbuf, 0).unwrap();

    let mut offset = 0;

    println!("Waiting for a new message");
    let (rxbuf, _) = socket.recv_from_full().unwrap();

    loop {
        let buf = &rxbuf[offset..];
        // Parse the message
        let msg =
            <NetlinkMessage<GenlMessage<IpvsServiceCtrl>>>::deserialize(buf)
                .unwrap();

        match msg.payload {
            NetlinkPayload::Done(_) => break,
            NetlinkPayload::InnerMessage(genlmsg) => {
                println!("got {:?}", genlmsg.payload.cmd);
                print_entry(genlmsg.payload.nlas);
            }
            NetlinkPayload::Error(err) => {
                println!("{:?}", err);
                if err.code.is_some() {
                    let e = std::io::Error::from_raw_os_error(
                        err.code.unwrap().get().abs(),
                    );
                    eprintln!(
                        "Received a netlink error message: {err:?} = {}",
                        e
                    );
                    return;
                }
            }
            other => {
                println!("{:?}", other)
            }
        }

        offset += msg.header.length as usize;
        println!("{} {} {}", offset, rxbuf.len(), msg.header.length);
        if offset >= rxbuf.len() || msg.header.length == 0 {
            break;
        }
    }
}

fn print_entry(entries: Vec<nlas::IpvsCtrlAttrs>) {
    for entry in entries {
        match entry {
            nlas::IpvsCtrlAttrs::Service(s) => println!("{:?}", s),
            nlas::IpvsCtrlAttrs::Destination(s) => {
                println!("{:?}", Destination::from_nlas(&s))
            }
        }
    }
}
