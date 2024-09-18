// SPDX-License-Identifier: MIT
use std::net::{IpAddr, Ipv4Addr};

use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST,
};
use netlink_packet_generic::GenlMessage;
use netlink_packet_ipvs::ctrl::{nlas, IpvsCtrl, IpvsCtrlCmd};
use netlink_sys::{protocols::NETLINK_GENERIC, Socket, SocketAddr};

fn main() {
    let mut socket = Socket::new(NETLINK_GENERIC).unwrap();
    socket.bind_auto().unwrap();
    socket.connect(&SocketAddr::new(0, 0)).unwrap();

    let s = nlas::Service {
        address: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        netmask: nlas::Netmask(16, nlas::AddressFamily::IPv4), // 255.255.0.0 is a /16 netmask
        scheduler: nlas::Scheduler::RoundRobin, // "rr" in the command
        flags: nlas::Flags(0),                  // Assuming no flags are set
        port: Some(9999),
        fw_mark: None,             // Not specified in the command
        persistence_timeout: None, // Not specified in the command
        family: nlas::AddressFamily::IPv4,
        protocol: nlas::Protocol::TCP, // '-t' in the command indicates TCP
        stats: nlas::Stats,            // Assuming default Stats
        stats64: nlas::Stats64,        // Assuming default Stats64
    };
    let mut genlmsg = GenlMessage::from_payload(IpvsCtrl {
        //cmd: IpvsCtrlCmd::GetService,
        //nlas: vec![],
        cmd: IpvsCtrlCmd::NewService,
        nlas: s.create_nlas(),
    });
    println!("{:?}", s.create_nlas());
    genlmsg.finalize();
    let mut nlmsg = NetlinkMessage::from(genlmsg);
    // TODO: DUMP for GET, remove DUMP for SET
    //nlmsg.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlmsg.header.flags = NLM_F_REQUEST;
    nlmsg.finalize();

    let mut txbuf = vec![0u8; nlmsg.buffer_len()];
    nlmsg.serialize(&mut txbuf);
    println!("{:?}", txbuf);

    socket.send(&txbuf, 0).unwrap();

    let mut offset = 0;

    'outer: loop {
        let (rxbuf, _) = socket.recv_from_full().unwrap();

        loop {
            let buf = &rxbuf[offset..];
            // Parse the message
            let msg = <NetlinkMessage<GenlMessage<IpvsCtrl>>>::deserialize(buf)
                .unwrap();

            match msg.payload {
                NetlinkPayload::Done(_) => break 'outer,
                NetlinkPayload::InnerMessage(genlmsg) => {
                    if IpvsCtrlCmd::NewService == genlmsg.payload.cmd {
                        print_entry(genlmsg.payload.nlas);
                    }
                }
                NetlinkPayload::Error(err) => {
                    let e = std::io::Error::from_raw_os_error(
                        err.code.unwrap().get().abs(),
                    );
                    eprintln!(
                        "Received a netlink error message: {err:?} = {}",
                        e
                    );
                    return;
                }
                _ => {}
            }

            offset += msg.header.length as usize;
            if offset >= rxbuf.len() || msg.header.length == 0 {
                offset = 0;
                break;
            }
        }
    }
}

fn print_entry(entry: Vec<nlas::IpvsCtrlAttrs>) {
    println!("todo {entry:?}");
}
