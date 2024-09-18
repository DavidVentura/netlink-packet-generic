// SPDX-License-Identifier: MIT
use std::net::{IpAddr, Ipv4Addr};

use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST,
};
use netlink_packet_generic::{GenlHeader, GenlMessage};
use netlink_packet_ipvs::{
    constants::IPVS_CMD_ATTR_SERVICE,
    ctrl::{nlas, IpvsCtrl, IpvsCtrlCmd},
};
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
    /*
         * for ipvsadm -A -t  1.2.3.4:9999 -M 255.255.0.0

         first 20 bytes are netlink header =
         command=1
         fam=1
         len=104
         flags=5
    0000   68 00 00 00 27 00 05 00 02 12 eb 66 9f 70 0f 4c   h...'......f.p.L
    0010   01 01 00 00 54 00 01 80 06 00 01 00 02 00 00 00   ....T...........
    0020   06 00 02 00 06 00 00 00 14 00 03 00 01 02 03 04   ................
    0030   00 00 00 00 00 00 00 00 00 00 00 00 06 00 04 00   ................
    0040   27 0f 00 00 08 00 06 00 77 6c 63 00 0c 00 07 00   '.......wlc.....
    0050   00 00 00 00 ff ff ff ff 08 00 08 00 00 00 00 00   ................
    0060   08 00 09 00 ff ff 00 00                           ........

        54 00 01 80 06 00 01 00 02 00 00 00 06 00 02 00 T...............
        06 00 00 00 14 00 03 00 01 02 03 04 00 00 00 00 ................
        00 00 00 00 00 00 00 00 06 00 04 00 27 0f 00 00 ............'...
        08 00 06 00 77 6c 63 00 0c 00 07 00 00 00 00 00 ....wlc.........
        ff ff ff ff 08 00 08 00 00 00 00 00 08 00 09 00 ................
        ff ff 00 00                                     ....

        06 00 01 00 02 00 00 00 07 00 06 00 72 72 00 00 ............rr..
        08 00 07 00 00 00 00 00 08 00 09 00 ff ff 00 00 ................
        06 00 02 00 06 00 00 00 08 00 03 00 01 02 03 04 ................
        06 00 04 00 27 0f 00 00                         ....'...

         */
    // inner-layer = IPVS_CMD_ATTR_SERVICE + packed service
    // outer-layer = IpvsCtrlCmd::NewService + inner-layer
    let mut genlmsg = GenlMessage::from_payload(IpvsCtrl {
        //cmd: IpvsCtrlCmd::GetService,
        //nlas: vec![],
        cmd: IpvsCtrlCmd::NewService,
        // nlas: [ServiceNla(s.create_nlas)]
        nlas: s.create_nlas(),
    });
    println!("{:?}", s.create_nlas());
    genlmsg.finalize();
    let mut nlmsg = NetlinkMessage::from(genlmsg);
    // TODO: DUMP for GET, remove DUMP for SET
    //nlmsg.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlmsg.header.flags = NLM_F_REQUEST | NLM_F_ACK;
    nlmsg.finalize();

    let mut txbuf = vec![0u8; nlmsg.buffer_len()];
    nlmsg.serialize(&mut txbuf);
    println!("{:?}", txbuf);
    let mut hardcoded_vec = vec![0x54, 0x00, 0x01, 0x80];
    //it's wrapped in another NLA with len 0x54 and type 0x8001, but what's that??
    let (left, right) = txbuf.split_at(20);
    let mut left = left.to_vec();
    let mut right = right.to_vec();
    left.append(&mut hardcoded_vec);
    left.append(&mut right);
    socket.send(&left, 0).unwrap();
    println!("{left:?}");

    //socket.send(&txbuf, 0).unwrap();

    let mut offset = 0;

    println!("Waiting for a new message");
    let (rxbuf, _) = socket.recv_from_full().unwrap();

    loop {
        let buf = &rxbuf[offset..];
        // Parse the message
        let msg =
            <NetlinkMessage<GenlMessage<IpvsCtrl>>>::deserialize(buf).unwrap();

        match msg.payload {
            NetlinkPayload::Done(_) => break,
            NetlinkPayload::InnerMessage(genlmsg) => {
                if IpvsCtrlCmd::NewService == genlmsg.payload.cmd {
                    print_entry(genlmsg.payload.nlas);
                }
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
            offset = 0;
            break;
        }
    }
}

fn print_entry(entry: Vec<nlas::IpvsCtrlAttrs>) {
    println!("todo {entry:?}");
}
