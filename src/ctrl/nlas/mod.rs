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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::{convert::TryInto, num::NonZero};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Service {
    pub address: IpAddr,
    pub netmask: Netmask,
    pub scheduler: Scheduler,
    pub flags: Flags,
    pub port: Option<u16>,
    pub fw_mark: Option<u32>,
    pub persistence_timeout: Option<NonZero<u32>>,
    pub family: AddressFamily,
    pub protocol: Protocol,
    pub stats: Stats,
    pub stats64: Stats64,
}

impl Service {
    pub fn create_nlas(&self) -> Vec<IpvsCtrlAttrs> {
        let mut ret = Vec::new();
        ret.push(IpvsCtrlAttrs::AddressFamily(self.family.clone()));
        ret.push(IpvsCtrlAttrs::Protocol(self.protocol.clone()));
        let octets = match self.address {
            // apparently it's always a 16-vec
            IpAddr::V4(v) => {
                let mut o = v.octets().to_vec();
                o.append(&mut vec![0u8; 12]);
                o
            }
            IpAddr::V6(v) => v.octets().to_vec(),
        };
        ret.push(IpvsCtrlAttrs::AddrBytes(AddrBytes(octets)));
        if let Some(port) = self.port {
            ret.push(IpvsCtrlAttrs::Port(port));
        }
        if let Some(fw_mark) = self.fw_mark {
            ret.push(IpvsCtrlAttrs::Fwmark(fw_mark));
        }
        ret.push(IpvsCtrlAttrs::Scheduler(self.scheduler.clone()));
        //// apparently flags should have 0xff x4 ?
        ret.push(IpvsCtrlAttrs::Flags(self.flags));
        if let Some(timeout) = self.persistence_timeout {
            ret.push(IpvsCtrlAttrs::Timeout(timeout.get()));
        } else {
            ret.push(IpvsCtrlAttrs::Timeout(0));
        }
        ret.push(IpvsCtrlAttrs::Netmask(self.netmask.clone()));

        ret
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stats;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stats64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Netmask(pub u8, pub AddressFamily);

impl Netmask {
    pub fn gen_netmask(&self, buf: &mut [u8]) {
        let bytes = match self.1 {
            AddressFamily::IPv4 => 4,
            AddressFamily::IPv6 => 16,
        };
        let full_bytes = self.0 as usize / 8;
        let remaining_bits = self.0 % 8;

        // Fill full bytes with 1s
        for i in 0..full_bytes {
            if i < bytes {
                buf[i] = 0xFF;
            }
        }

        // Fill the partial byte
        if full_bytes < bytes && remaining_bits > 0 {
            buf[full_bytes] = 0xFF << (8 - remaining_bits);
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Flags(pub u32);

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
impl Scheduler {
    fn to_string(&self) -> String {
        match self {
            Scheduler::RoundRobin => "rr",
            Scheduler::WeightedRoundRobin => "wrr",
            Scheduler::LeastConnection => "lc",
            Scheduler::WeightedLeastConnection => "wlc",
            Scheduler::LocalityBasedLeastConnection => "lblc",
            Scheduler::LocalityBasedLeastConnectionWithReplication => "lblcr",
            Scheduler::DestinationHashing => "dh",
            Scheduler::SourceHashing => "sh",
            Scheduler::ShortestExpectedDelay => "sed",
            Scheduler::NeverQueue => "nq",
            Scheduler::WeightedFailover => "fo",
            Scheduler::WeightedOverflow => "ovf",
            Scheduler::MaglevHashing => "mh",
        }
        .to_string()
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
        let res = match self {
            Self::AddressFamily(_) => 2,
            Self::AddrBytes(AddrBytes(bytes)) => bytes.len(),
            Self::Protocol(_) => 2,
            Self::Port(_) => 2,
            Self::Flags(_) => 4 + 4, // not sure why, but padded with 4x 0xFF
            Self::Fwmark(_) => 4,
            Self::Scheduler(scheduler) => scheduler.to_string().len() + 1, // +1 for null terminator
            Self::Timeout(_) => 4,
            Self::Netmask(Netmask(_, addr_family)) => match addr_family {
                AddressFamily::IPv4 => 4,
                AddressFamily::IPv6 => 16,
            },
            Self::Stats(_) | Self::Stats64(_) => {
                // TODO: Return correct size when Stats and Stats64 are defined
                0
            }
        };
        res
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
        match self {
            //TODO constants
            Self::AddressFamily(af) => {
                let val = match af {
                    AddressFamily::IPv4 => 2,
                    AddressFamily::IPv6 => 10,
                };
                LittleEndian::write_u16(buffer, val);
            }
            Self::AddrBytes(AddrBytes(bytes)) => {
                buffer[..bytes.len()].copy_from_slice(bytes);
            }
            //TODO constants
            Self::Protocol(protocol) => {
                let val = match protocol {
                    Protocol::TCP => 0x06,
                    Protocol::UDP => 0x11,
                    Protocol::SCTP => 0x84,
                };
                LittleEndian::write_u16(buffer, val);
            }
            Self::Port(port) => {
                BigEndian::write_u16(buffer, *port);
            }
            Self::Flags(Flags(flags)) => {
                LittleEndian::write_u32(buffer, *flags);
                buffer[4] = 0xff;
                buffer[5] = 0xff;
                buffer[6] = 0xff;
                buffer[7] = 0xff;
            }
            Self::Fwmark(fwmark) => {
                LittleEndian::write_u32(buffer, *fwmark);
            }
            Self::Scheduler(scheduler) => {
                let name = scheduler.to_string();
                buffer[..name.len()].copy_from_slice(name.as_bytes());
                if name.len() < buffer.len() {
                    buffer[name.len()] = b'\0';
                }
            }
            Self::Timeout(timeout) => {
                LittleEndian::write_u32(buffer, *timeout);
            }
            Self::Netmask(nm) => {
                nm.gen_netmask(buffer);
            }
            Self::Stats(_) | Self::Stats64(_) => {
                // TODO: Implement when Stats and Stats64 are defined
            }
        }
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

                // This is WRONG but needs to be corrected outside
                Self::Netmask(Netmask(ones as u8, AddressFamily::IPv4))
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
