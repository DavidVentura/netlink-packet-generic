// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST,
};
use netlink_packet_generic::GenlMessage;
use netlink_packet_ipvs::ctrl::{nlas::IpvsCtrlAttrs, IpvsCtrl, IpvsCtrlCmd};
use netlink_sys::{protocols::NETLINK_GENERIC, Socket, SocketAddr};

fn main() {
    let mut socket = Socket::new(NETLINK_GENERIC).unwrap();
    socket.bind_auto().unwrap();
    socket.connect(&SocketAddr::new(0, 0)).unwrap();

    let mut genlmsg = GenlMessage::from_payload(IpvsCtrl {
        cmd: IpvsCtrlCmd::GetService,
        nlas: vec![],
    });
    genlmsg.finalize();
    let mut nlmsg = NetlinkMessage::from(genlmsg);
    nlmsg.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlmsg.finalize();

    let mut txbuf = vec![0u8; nlmsg.buffer_len()];
    nlmsg.serialize(&mut txbuf);

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

fn print_entry(entry: Vec<IpvsCtrlAttrs>) {
    println!("todo {entry:?}");
}
