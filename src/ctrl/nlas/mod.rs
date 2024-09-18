// SPDX-License-Identifier: MIT

use crate::constants::*;
use anyhow::Context;
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use core::str;
use netlink_packet_utils::{
    nla::{Nla, NlaBuffer},
    parsers::*,
    traits::*,
    DecodeError,
};
use std::convert::TryInto;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
    stats: Stats,
    stats64: Stats64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stats;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stats64;

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

impl From<&str> for Scheduler {
    fn from(s: &str) -> Self {
        match s.as_ref() {
            "rr" => Scheduler::RoundRobin,
            "wrr" => Scheduler::WeightedRoundRobin,
            "lc" => Scheduler::LeastConnection,
            "wlc" => Scheduler::WeightedLeastConnection,
            "lblc" => Scheduler::LocalityBasedLeastConnection,
            "lblcr" => Scheduler::LocalityBasedLeastConnectionWithReplication,
            "dh" => Scheduler::DestinationHashing,
            "sh" => Scheduler::SourceHashing,
            "sed" => Scheduler::ShortestExpectedDelay,
            "nq" => Scheduler::NeverQueue,
            "fo" | "fail" => Scheduler::WeightedFailover,
            "ovf" | "flow" => Scheduler::WeightedOverflow,
            "mh" => Scheduler::MaglevHashing,
            other => panic!("Unknown scheduler: '{}'", other),
        }
    }
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
pub struct MaskBytes(Vec<u8>);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddrBytes(Vec<u8>);

impl AddrBytes {
    pub fn as_ipaddr(&self, family: AddressFamily) -> IpAddr {
        match family {
            AddressFamily::IPv4 => IpAddr::V4(Ipv4Addr::new(
                self.0[0], self.0[1], self.0[2], self.0[3],
            )),
            AddressFamily::IPv6 => {
                let arr: [u8; 16] = self.0.as_slice().try_into().unwrap();
                IpAddr::V6(Ipv6Addr::from(arr))
            }
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpvsCtrlAttrs {
    AddressFamily(AddressFamily),
    Protocol(Protocol),
    AddrBytes(AddrBytes),
    Port(u16),
    Flags(Flags),
    Fwmark(u32),
    Scheduler(Scheduler),
    Timeout(u32),
    Netmask(Netmask),
    Stats(Stats),
    Stats64(Stats64),
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
            IpvsCtrlAttrs::AddrBytes(_) => IPVS_SVC_ATTR_ADDR,
            IpvsCtrlAttrs::Port(_) => IPVS_SVC_ATTR_PORT,
            IpvsCtrlAttrs::Flags(_) => IPVS_SVC_ATTR_FLAGS,
            IpvsCtrlAttrs::Fwmark(_) => IPVS_SVC_ATTR_FWMARK,
            IpvsCtrlAttrs::Scheduler(_) => IPVS_SVC_ATTR_SCHED_NAME,
            IpvsCtrlAttrs::Timeout(_) => IPVS_SVC_ATTR_TIMEOUT,
            IpvsCtrlAttrs::Netmask(_) => IPVS_SVC_ATTR_NETMASK,
            IpvsCtrlAttrs::Stats(_) => IPVS_SVC_ATTR_STATS,
            IpvsCtrlAttrs::Stats64(_) => IPVS_SVC_ATTR_STATS64,
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

        Ok(match buf.kind() {
            IPVS_SVC_ATTR_AF => {
                let val = parse_u16(payload)?;
                let af = match val {
                    // FIXME constants
                    2 => AddressFamily::IPv4,
                    10 => AddressFamily::IPv6,
                    other => {
                        return Err(DecodeError::from(format!(
                            "unknown addr family {other}",
                        )))
                    }
                };
                Self::AddressFamily(af)
            }
            IPVS_SVC_ATTR_ADDR => Self::AddrBytes(AddrBytes(payload.to_vec())),
            IPVS_SVC_ATTR_PROTOCOL => {
                let val = parse_u16(payload)?;
                Self::Protocol(match val {
                    0x06 => Protocol::TCP,
                    0x11 => Protocol::UDP,
                    0x84 => Protocol::SCTP,
                    other => panic!("Protocol {} is not supported", other),
                })
            }
            IPVS_SVC_ATTR_PORT => {
                let val = LittleEndian::read_u16(payload);
                Self::Port(u16::from_be(val))
            }
            IPVS_SVC_ATTR_FLAGS => {
                let val = LittleEndian::read_u32(payload);
                Self::Flags(Flags(val))
            }
            IPVS_SVC_ATTR_FWMARK => {
                let val = BigEndian::read_u32(payload);
                Self::Fwmark(val)
            }
            IPVS_SVC_ATTR_SCHED_NAME => {
                let name = str::from_utf8(payload)
                    .context("Scheduler name invalid utf-8")?;
                let name = name.trim_end_matches('\0');
                Self::Scheduler(Scheduler::from(name))
            }
            IPVS_SVC_ATTR_TIMEOUT => {
                let val = BigEndian::read_u32(payload);
                Self::Timeout(val)
            }
            IPVS_SVC_ATTR_NETMASK => {
                let ones: u32 =
                    payload.into_iter().map(|octet| octet.count_ones()).sum();
                assert!(ones <= 128); // an ipv6 address is 16 bytes
                Self::Netmask(Netmask(ones as u8))
            }
            // TODO
            IPVS_SVC_ATTR_STATS => Self::Stats(Stats),
            IPVS_SVC_ATTR_STATS64 => Self::Stats64(Stats64),
            _ => {
                panic!("Unhandled {}", buf.kind());
            }
        })
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
