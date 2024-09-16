// SPDX-License-Identifier: MIT

use crate::constants::*;
use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_generic::constants::CTRL_ATTR_OP_FLAGS;
use netlink_packet_utils::{
    nla::{Nla, NlaBuffer, NlasIterator},
    parsers::*,
    traits::*,
    DecodeError,
};
use std::mem::size_of_val;
use std::net::IpAddr;

/*
mod mcast;
mod oppolicy;
mod ops;
mod policy;

pub use mcast::*;
pub use oppolicy::*;
pub use ops::*;
pub use policy::*;
*/

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Service {
    address: IpAddr,
    netmask: Netmask,
    scheduler: Scheduler,
    flags: Flags,
    port: Option<u16>,
    fw_mark: Option<u32>,
    persistence_timeout: Option<u32>,
    family: AddressFamily,
    protocol: Protocol,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Netmask(u8);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Flags(u32);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scheduler {
    RoundRobin,
    WeightedRoundRobin,
    LeastConnection,
    WeightedLeastConnection,
    LocalityBasedLeastConnection,
    LocalityBasedLeastConnectionWithReplication,
    DestinationHashing,
    SourceHashing,
    ShortestExpectedDelay,
    NeverQueue,
    WeightedFailover,
    WeightedOverflow,
    MaglevHashing,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddressFamily {
    IPv4,
    IPv6,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Protocol {
    TCP,
    UDP,
    SCTP,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpvsCtrlAttrs {
    AddressFamily(AddressFamily),
    Protocol(Protocol),
    Addr(IpAddr),
    Port(u16),
    Flags(Flags),
    // TODO: Fwmark
    Scheduler(Scheduler),
    Timeout(Option<u32>),
    Netmask(Netmask),
    // TODO: stats / stats64
}

impl Nla for IpvsCtrlAttrs {
    fn value_len(&self) -> usize {
        println!("value len 333");
        // TODO
        //match self {}
        return 333;
    }

    // u16?? same with constants
    fn kind(&self) -> u16 {
        match self {
            IpvsCtrlAttrs::AddressFamily(_) => IPVS_SVC_ATTR_AF,
            IpvsCtrlAttrs::Protocol(_) => IPVS_SVC_ATTR_PROTOCOL,
            IpvsCtrlAttrs::Addr(_) => IPVS_SVC_ATTR_ADDR,
            IpvsCtrlAttrs::Port(_) => IPVS_SVC_ATTR_PORT,
            IpvsCtrlAttrs::Flags(_) => IPVS_SVC_ATTR_FLAGS,
            IpvsCtrlAttrs::Scheduler(_) => IPVS_SVC_ATTR_SCHED_NAME,
            IpvsCtrlAttrs::Timeout(_) => IPVS_SVC_ATTR_TIMEOUT,
            IpvsCtrlAttrs::Netmask(_) => IPVS_SVC_ATTR_NETMASK,
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        println!("not emitting value");
        /*
            use IpvsCtrlAttrs::*;
            match self {
                FamilyId(v) => NativeEndian::write_u16(buffer, *v),
                FamilyName(s) => {
                    buffer[..s.len()].copy_from_slice(s.as_bytes());
                    buffer[s.len()] = 0;
                }
                Version(v) => NativeEndian::write_u32(buffer, *v),
                HdrSize(v) => NativeEndian::write_u32(buffer, *v),
                MaxAttr(v) => NativeEndian::write_u32(buffer, *v),
                Ops(nlas) => {
                    OpList::from(nlas).as_slice().emit(buffer);
                }
                McastGroups(nlas) => {
                    McastGroupList::from(nlas).as_slice().emit(buffer);
                }
                Policy(nla) => nla.emit_value(buffer),
                OpPolicy(nla) => nla.emit_value(buffer),
                Op(v) => NativeEndian::write_u32(buffer, *v),
            }
        */
        // TODO
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for IpvsCtrlAttrs
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        println!("Kind is {} and payload is {:?}", buf.kind(), payload);
        Ok(Self::AddressFamily(AddressFamily::IPv4))
        /*
        Ok(match buf.kind() {
            IPVS_SVC_ATTR_AF => Self::AddressFamily(
                parse_u16(payload)
                    .context("invalid CTRL_ATTR_FAMILY_ID value")?,
            ),
            CTRL_ATTR_FAMILY_NAME => Self::FamilyName(
                parse_string(payload)
                    .context("invalid CTRL_ATTR_FAMILY_NAME value")?,
            ),
            CTRL_ATTR_VERSION => Self::Version(
                parse_u32(payload)
                    .context("invalid CTRL_ATTR_VERSION value")?,
            ),
            CTRL_ATTR_HDRSIZE => Self::HdrSize(
                parse_u32(payload)
                    .context("invalid CTRL_ATTR_HDRSIZE value")?,
            ),
            CTRL_ATTR_MAXATTR => Self::MaxAttr(
                parse_u32(payload)
                    .context("invalid CTRL_ATTR_MAXATTR value")?,
            ),
            CTRL_ATTR_OPS => {
                let ops = NlasIterator::new(payload)
                    .map(|nlas| {
                        nlas.and_then(|nlas| {
                            NlasIterator::new(nlas.value())
                                .map(|nla| {
                                    nla.and_then(|nla| OpAttrs::parse(&nla))
                                })
                                .collect::<Result<Vec<_>, _>>()
                        })
                    })
                    .collect::<Result<Vec<Vec<_>>, _>>()
                    .context("failed to parse CTRL_ATTR_OPS")?;
                Self::Ops(ops)
            }
            CTRL_ATTR_MCAST_GROUPS => {
                let groups = NlasIterator::new(payload)
                    .map(|nlas| {
                        nlas.and_then(|nlas| {
                            NlasIterator::new(nlas.value())
                                .map(|nla| {
                                    nla.and_then(|nla| {
                                        McastGrpAttrs::parse(&nla)
                                    })
                                })
                                .collect::<Result<Vec<_>, _>>()
                        })
                    })
                    .collect::<Result<Vec<Vec<_>>, _>>()
                    .context("failed to parse CTRL_ATTR_MCAST_GROUPS")?;
                Self::McastGroups(groups)
            }
            CTRL_ATTR_POLICY => Self::Policy(
                PolicyAttr::parse(&NlaBuffer::new(payload))
                    .context("failed to parse CTRL_ATTR_POLICY")?,
            ),
            CTRL_ATTR_OP_POLICY => Self::OpPolicy(
                OppolicyAttr::parse(&NlaBuffer::new(payload))
                    .context("failed to parse CTRL_ATTR_OP_POLICY")?,
            ),
            CTRL_ATTR_OP => Self::Op(parse_u32(payload)?),
            kind => {
                return Err(DecodeError::from(format!(
                    "Unknown NLA type: {kind}"
                )))
            }
        })
        */
    }
}

/*
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcast_groups_parse() {
        let mcast_bytes: [u8; 24] = [
            24, 0, // Netlink header length
            7, 0, // Netlink header kind (Mcast groups)
            20, 0, // Mcast group nested NLA length
            1, 0, // Mcast group kind
            8, 0, // Id length
            2, 0, // Id kind
            1, 0, 0, 0, // Id
            8, 0, // Name length
            1, 0, // Name kind
            b't', b'e', b's', b't', // Name
        ];
        let nla_buffer = NlaBuffer::new_checked(&mcast_bytes[..])
            .expect("Failed to create NlaBuffer");
        let result_attr = GenlCtrlAttrs::parse(&nla_buffer)
            .expect("Failed to parse encoded McastGroups");
        let expected_attr = GenlCtrlAttrs::McastGroups(vec![vec![
            McastGrpAttrs::Id(1),
            McastGrpAttrs::Name("test".to_string()),
        ]]);
        assert_eq!(expected_attr, result_attr);
    }

    #[test]
    fn mcast_groups_emit() {
        let mcast_attr = GenlCtrlAttrs::McastGroups(vec![
            vec![
                McastGrpAttrs::Id(7),
                McastGrpAttrs::Name("group1".to_string()),
            ],
            vec![
                McastGrpAttrs::Id(8),
                McastGrpAttrs::Name("group2".to_string()),
            ],
        ]);
        let expected_bytes: [u8; 52] = [
            52, 0, // Netlink header length
            7, 0, // Netlink header kind (Mcast groups)
            24, 0, // Mcast group nested NLA length
            1, 0, // Mcast group kind (index 1)
            8, 0, // Id length
            2, 0, // Id kind
            7, 0, 0, 0, // Id
            11, 0, // Name length
            1, 0, // Name kind
            b'g', b'r', b'o', b'u', b'p', b'1', 0, // Name
            0, // mcast group padding
            24, 0, // Mcast group nested NLA length
            2, 0, // Mcast group kind (index 2)
            8, 0, // Id length
            2, 0, // Id kind
            8, 0, 0, 0, // Id
            11, 0, // Name length
            1, 0, // Name kind
            b'g', b'r', b'o', b'u', b'p', b'2', 0, // Name
            0, // padding
        ];
        let mut buf = vec![0u8; 100];
        mcast_attr.emit(&mut buf);

        assert_eq!(&expected_bytes[..], &buf[..expected_bytes.len()]);
    }

    #[test]
    fn ops_parse() {
        let ops_bytes: [u8; 24] = [
            24, 0, // Netlink header length
            6, 0, // Netlink header kind (Ops)
            20, 0, // Op nested NLA length
            0, 0, // Op kind
            8, 0, // Id length
            1, 0, // Id kind
            1, 0, 0, 0, // Id
            8, 0, // Flags length
            2, 0, // Flags kind
            123, 0, 0, 0, // Flags
        ];
        let nla_buffer = NlaBuffer::new_checked(&ops_bytes[..])
            .expect("Failed to create NlaBuffer");
        let result_attr = GenlCtrlAttrs::parse(&nla_buffer)
            .expect("Failed to parse encoded McastGroups");
        let expected_attr =
            GenlCtrlAttrs::Ops(vec![vec![OpAttrs::Id(1), OpAttrs::Flags(123)]]);
        assert_eq!(expected_attr, result_attr);
    }

    #[test]
    fn ops_emit() {
        let ops = GenlCtrlAttrs::Ops(vec![
            vec![OpAttrs::Id(1), OpAttrs::Flags(11)],
            vec![OpAttrs::Id(3), OpAttrs::Flags(33)],
        ]);
        let expected_bytes: [u8; 44] = [
            44, 0, // Netlink header length
            6, 0, // Netlink header kind (Ops)
            20, 0, // Op nested NLA length
            1, 0, // Op kind
            8, 0, // Id length
            1, 0, // Id kind
            1, 0, 0, 0, // Id
            8, 0, // Flags length
            2, 0, // Flags kind
            11, 0, 0, 0, // Flags
            20, 0, // Op nested NLA length
            2, 0, // Op kind
            8, 0, // Id length
            1, 0, // Id kind
            3, 0, 0, 0, // Id
            8, 0, // Flags length
            2, 0, // Flags kind
            33, 0, 0, 0, // Flags
        ];
        let mut buf = vec![0u8; 100];
        ops.emit(&mut buf);

        assert_eq!(&expected_bytes[..], &buf[..expected_bytes.len()]);
    }
}
*/
