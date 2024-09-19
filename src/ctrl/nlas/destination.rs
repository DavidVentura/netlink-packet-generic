use crate::constants::*;
use crate::ctrl::nlas::AddressFamily;
use byteorder::{ByteOrder, NativeEndian, NetworkEndian};
use netlink_packet_utils::{
    nla::{Nla, NlaBuffer},
    parsers::*,
    traits::*,
    DecodeError,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;
use std::{convert::TryFrom, error::Error};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Destination {
    pub address: IpAddr,
    pub fwd_method: ForwardTypeFull,
    pub weight: u32,
    pub upper_threshold: Option<NonZeroU32>,
    pub lower_threshold: Option<NonZeroU32>,
    pub port: u16,
    pub family: AddressFamily,
}

impl Destination {
    pub fn from_nlas(
        nlas: &[DestinationCtrlAttrs],
    ) -> Result<Destination, Box<dyn Error>> {
        let mut address = None;
        let mut fwd_method = None;
        let mut weight = None;
        let mut upper_threshold = None;
        let mut lower_threshold = None;
        let mut port = None;
        let mut family = None;
        let mut tunnel_type = None;
        let mut tunnel_port = None;
        let mut tunnel_flags = None;

        for nla in nlas {
            match nla {
                DestinationCtrlAttrs::Addr(addr) => address = Some(addr),
                DestinationCtrlAttrs::FwdMethod(method) => {
                    fwd_method = Some(method.clone())
                }
                DestinationCtrlAttrs::Weight(w) => weight = Some(*w),
                DestinationCtrlAttrs::UpperThreshold(t) => {
                    upper_threshold = NonZeroU32::new(*t)
                }
                DestinationCtrlAttrs::LowerThreshold(t) => {
                    lower_threshold = NonZeroU32::new(*t)
                }
                DestinationCtrlAttrs::Port(p) => port = Some(*p),
                DestinationCtrlAttrs::AddrFamily(f) => family = Some(f.clone()),
                DestinationCtrlAttrs::TunType(t) => {
                    tunnel_type = Some(t.clone())
                }
                DestinationCtrlAttrs::TunPort(p) => tunnel_port = Some(*p),
                DestinationCtrlAttrs::TunFlags(f) => {
                    tunnel_flags = Some(f.clone())
                }
                _ => {} // Ignore other attributes
            }
        }

        let _fam = family.ok_or("Address family is required")?;
        let __addr = address.ok_or("Address is required")?;
        let _addr = match _fam {
            AddressFamily::IPv4 => IpAddr::V4(Ipv4Addr::new(
                __addr[0], __addr[1], __addr[2], __addr[3],
            )),
            AddressFamily::IPv6 => todo!(), //IpAddr::V6(Ipv6Addr::try_from(__addr)),
        };

        let __fwd = fwd_method.ok_or("Forward method is required")?;
        let _fwd = match __fwd {
            ForwardType::Tunnel => ForwardTypeFull::Tunnel {
                tunnel_type: tunnel_type.ok_or("")?,
                tunnel_port: tunnel_port.ok_or("")?,
                tunnel_flags: tunnel_flags.ok_or("")?,
            },
            ForwardType::Masquerade => ForwardTypeFull::Masquerade,
            ForwardType::Direct => ForwardTypeFull::Direct,
        };

        Ok(Destination {
            address: _addr,
            fwd_method: _fwd,
            weight: weight.ok_or("Weight is required")?,
            port: port.ok_or("Port is required")?,
            upper_threshold,
            lower_threshold,
            family: _fam,
        })
    }
}
impl Destination {
    pub fn create_nlas(&self) -> Vec<DestinationCtrlAttrs> {
        Vec::new()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DestinationExtended {
    pub destination: Destination,
    pub active_connections: u32,
    pub inactive_connections: u32,
    pub persistent_connections: u32,
    pub stats: Stats,
    pub stats64: Stats,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stats {
    pub connections: u64,
    pub incoming_packets: u64,
    pub outgoing_packets: u64,
    pub incoming_bytes: u64,
    pub outgoing_bytes: u64,
    pub connection_rate: u64,
    pub incoming_packet_rate: u64,
    pub outgoing_packet_rate: u64,
    pub incoming_byte_rate: u64,
    pub outgoing_byte_rate: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForwardTypeFull {
    Masquerade, // NAT
    Tunnel {
        tunnel_type: TunnelType,
        tunnel_port: u16,
        tunnel_flags: TunnelFlags,
    },
    Direct,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForwardType {
    Masquerade, // NAT
    Tunnel,
    Direct,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TunnelType {
    // TODO / not supported
    None,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelFlags(pub u16);

// Implement necessary traits (e.g., From, TryFrom) for conversions
impl From<u16> for TunnelFlags {
    fn from(value: u16) -> Self {
        TunnelFlags(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DestinationCtrlAttrs {
    Addr(Vec<u8>),
    Port(u16),
    FwdMethod(ForwardType),
    Weight(u32),
    UpperThreshold(u32),
    LowerThreshold(u32),
    ActiveConns(u32),
    InactiveConns(u32),
    PersistConns(u32),
    Stats(Stats),
    AddrFamily(AddressFamily),
    Stats64(Stats),
    TunType(TunnelType),
    TunPort(u16),
    TunFlags(TunnelFlags),
}

impl Nla for DestinationCtrlAttrs {
    fn is_nested(&self) -> bool {
        true
    }
    fn value_len(&self) -> usize {
        match self {
            Self::Addr(_) => 16,
            Self::Port(_) | Self::TunPort(_) => 2,
            Self::FwdMethod(_)
            | Self::Weight(_)
            | Self::UpperThreshold(_)
            | Self::LowerThreshold(_)
            | Self::ActiveConns(_)
            | Self::InactiveConns(_)
            | Self::PersistConns(_) => 4,
            Self::Stats(_) | Self::Stats64(_) => 0, // never write stats over the wire
            Self::AddrFamily(_) => 2,
            Self::TunType(_) => 1,
            Self::TunFlags(_) => 2,
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Addr(_) => IPVS_DEST_ATTR_ADDR,
            Self::Port(_) => IPVS_DEST_ATTR_PORT,
            Self::FwdMethod(_) => IPVS_DEST_ATTR_FWD_METHOD,
            Self::Weight(_) => IPVS_DEST_ATTR_WEIGHT,
            Self::UpperThreshold(_) => IPVS_DEST_ATTR_U_THRESH,
            Self::LowerThreshold(_) => IPVS_DEST_ATTR_L_THRESH,
            Self::ActiveConns(_) => IPVS_DEST_ATTR_ACTIVE_CONNS,
            Self::InactiveConns(_) => IPVS_DEST_ATTR_INACT_CONNS,
            Self::PersistConns(_) => IPVS_DEST_ATTR_PERSIST_CONNS,
            Self::Stats(_) => IPVS_DEST_ATTR_STATS,
            Self::AddrFamily(_) => IPVS_DEST_ATTR_ADDR_FAMILY,
            Self::Stats64(_) => IPVS_DEST_ATTR_STATS64,
            Self::TunType(_) => IPVS_DEST_ATTR_TUN_TYPE,
            Self::TunPort(_) => IPVS_DEST_ATTR_TUN_PORT,
            Self::TunFlags(_) => IPVS_DEST_ATTR_TUN_FLAGS,
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Addr(addr) => buffer.copy_from_slice(&addr),
            Self::Port(port) => NativeEndian::write_u16(buffer, *port),
            Self::TunPort(port) => NativeEndian::write_u16(buffer, *port),
            Self::FwdMethod(method) => {
                NativeEndian::write_u32(buffer, method.into())
            }
            Self::Weight(weight) => NativeEndian::write_u32(buffer, *weight),
            Self::UpperThreshold(thresh) => {
                NativeEndian::write_u32(buffer, *thresh)
            }
            Self::LowerThreshold(thresh) => {
                NativeEndian::write_u32(buffer, *thresh)
            }
            Self::ActiveConns(conns) => NativeEndian::write_u32(buffer, *conns),
            Self::InactiveConns(conns) => {
                NativeEndian::write_u32(buffer, *conns)
            }
            Self::PersistConns(conns) => {
                NativeEndian::write_u32(buffer, *conns)
            }
            Self::Stats(_) | Self::Stats64(_) => {
                // we never write the stats over the wire
            }
            Self::AddrFamily(family) => {
                //TODO constants
                let val = match family {
                    AddressFamily::IPv4 => 2,
                    AddressFamily::IPv6 => 10,
                };
                NativeEndian::write_u16(buffer, val);
            }
            Self::TunType(tun_type) => buffer[0] = tun_type.into(),
            Self::TunFlags(flags) => NativeEndian::write_u16(buffer, flags.0),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for DestinationCtrlAttrs
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();

        Ok(match buf.kind() {
            IPVS_DEST_ATTR_ADDR => Self::Addr(payload.to_vec()),
            IPVS_DEST_ATTR_PORT => Self::Port(NetworkEndian::read_u16(payload)),
            IPVS_DEST_ATTR_FWD_METHOD => {
                Self::FwdMethod(ForwardType::try_from(parse_u32(payload)?)?)
            }
            IPVS_DEST_ATTR_WEIGHT => Self::Weight(parse_u32(payload)?),
            IPVS_DEST_ATTR_U_THRESH => {
                Self::UpperThreshold(parse_u32(payload)?)
            }
            IPVS_DEST_ATTR_L_THRESH => {
                Self::LowerThreshold(parse_u32(payload)?)
            }
            IPVS_DEST_ATTR_ACTIVE_CONNS => {
                Self::ActiveConns(parse_u32(payload)?)
            }
            IPVS_DEST_ATTR_INACT_CONNS => {
                Self::InactiveConns(parse_u32(payload)?)
            }
            IPVS_DEST_ATTR_PERSIST_CONNS => {
                Self::PersistConns(parse_u32(payload)?)
            }
            IPVS_DEST_ATTR_STATS | IPVS_DEST_ATTR_STATS64 => {
                let stats = Stats {
                    connections: NativeEndian::read_u64(&payload[0..8]),
                    incoming_packets: NativeEndian::read_u64(&payload[8..16]),
                    outgoing_packets: NativeEndian::read_u64(&payload[16..24]),
                    incoming_bytes: NativeEndian::read_u64(&payload[24..32]),
                    outgoing_bytes: NativeEndian::read_u64(&payload[32..40]),
                    connection_rate: NativeEndian::read_u64(&payload[40..48]),
                    incoming_packet_rate: NativeEndian::read_u64(
                        &payload[48..56],
                    ),
                    outgoing_packet_rate: NativeEndian::read_u64(
                        &payload[56..64],
                    ),
                    incoming_byte_rate: NativeEndian::read_u64(
                        &payload[64..72],
                    ),
                    outgoing_byte_rate: NativeEndian::read_u64(
                        &payload[72..80],
                    ),
                };
                if buf.kind() == IPVS_DEST_ATTR_STATS {
                    Self::Stats(stats)
                } else {
                    Self::Stats64(stats)
                }
            }
            IPVS_DEST_ATTR_ADDR_FAMILY => {
                Self::AddrFamily(AddressFamily::try_from(parse_u16(payload)?)?)
            }
            IPVS_DEST_ATTR_TUN_TYPE => {
                Self::TunType(TunnelType::try_from(payload[0])?)
            }
            IPVS_DEST_ATTR_TUN_PORT => Self::TunPort(parse_u16(payload)?),
            IPVS_DEST_ATTR_TUN_FLAGS => {
                Self::TunFlags(TunnelFlags(parse_u16(payload)?))
            }
            _ => {
                return Err(DecodeError::from(format!(
                    "Unknown DestinationCtrlAttrs kind: {}",
                    buf.kind()
                )))
            }
        })
    }
}

impl TryFrom<u32> for ForwardType {
    type Error = DecodeError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            // TODO is this right
            0 => Ok(ForwardType::Masquerade),
            _ => panic!("not sure what to do with {}", value),
        }
    }
}

impl From<&ForwardType> for u32 {
    fn from(ft: &ForwardType) -> u32 {
        match ft {
            // TODO is this right
            ForwardType::Masquerade => 0,
            _ => todo!("impl non-nat forwardtype"),
        }
    }
}

impl TryFrom<u16> for AddressFamily {
    type Error = DecodeError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            2 => Ok(AddressFamily::IPv4),
            10 => Ok(AddressFamily::IPv6),
            _ => Err(DecodeError::from(format!(
                "Unknown AddressFamily value: {}",
                value
            ))),
        }
    }
}

impl TryFrom<u8> for TunnelType {
    type Error = DecodeError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        //TODO is this right
        match value {
            0 => Ok(TunnelType::None),
            other => panic!("not sure what to do with tunnel {}", other),
        }
    }
}
impl From<&TunnelType> for u8 {
    fn from(t: &TunnelType) -> u8 {
        match t {
            TunnelType::None => 0,
        }
    }
}
