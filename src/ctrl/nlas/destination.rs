use crate::constants::*;
use crate::ctrl::nlas::AddressFamily;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{Nla, NlaBuffer},
    parsers::*,
    traits::*,
    DecodeError,
};
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Destination {
    pub address: IpAddr,
    pub fwd_method: ForwardType,
    pub weight: u32,
    pub upper_threshold: Option<NonZeroU32>,
    pub lower_threshold: Option<NonZeroU32>,
    pub port: u16,
    pub family: AddressFamily,
    pub tunnel_type: Option<TunnelType>,
    pub tunnel_port: Option<u16>,
    pub tunnel_flags: Option<TunnelFlags>,
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
pub enum ForwardType {
    Masquerade,
    // TODO / not supported
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TunnelType {
    // TODO / not supported
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
    Addr(IpAddr),
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
            Self::Addr(addr) => match addr {
                IpAddr::V4(_) => 4,
                IpAddr::V6(_) => 16,
            },
            Self::Port(_) | Self::TunPort(_) => 2,
            Self::FwdMethod(_)
            | Self::Weight(_)
            | Self::UpperThreshold(_)
            | Self::LowerThreshold(_)
            | Self::ActiveConns(_)
            | Self::InactiveConns(_)
            | Self::PersistConns(_) => 4,
            Self::Stats(_) | Self::Stats64(_) => 80, // Assuming 10 u64 fields in Stats
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
            Self::Addr(addr) => match addr {
                IpAddr::V4(v4) => buffer.copy_from_slice(&v4.octets()),
                IpAddr::V6(v6) => buffer.copy_from_slice(&v6.octets()),
            },
            Self::Port(port) | Self::TunPort(port) => {
                NativeEndian::write_u16(buffer, *port)
            }
            Self::FwdMethod(method) => {
                // FIXME
                //NativeEndian::write_u32(buffer, *method as u32)
                NativeEndian::write_u32(buffer, 1)
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
            Self::Stats(stats) | Self::Stats64(stats) => {
                let mut offset = 0;
                NativeEndian::write_u64(
                    &mut buffer[offset..],
                    stats.connections,
                );
                offset += 8;
                NativeEndian::write_u64(
                    &mut buffer[offset..],
                    stats.incoming_packets,
                );
                offset += 8;
                NativeEndian::write_u64(
                    &mut buffer[offset..],
                    stats.outgoing_packets,
                );
                offset += 8;
                NativeEndian::write_u64(
                    &mut buffer[offset..],
                    stats.incoming_bytes,
                );
                offset += 8;
                NativeEndian::write_u64(
                    &mut buffer[offset..],
                    stats.outgoing_bytes,
                );
                offset += 8;
                NativeEndian::write_u64(
                    &mut buffer[offset..],
                    stats.connection_rate,
                );
                offset += 8;
                NativeEndian::write_u64(
                    &mut buffer[offset..],
                    stats.incoming_packet_rate,
                );
                offset += 8;
                NativeEndian::write_u64(
                    &mut buffer[offset..],
                    stats.outgoing_packet_rate,
                );
                offset += 8;
                NativeEndian::write_u64(
                    &mut buffer[offset..],
                    stats.incoming_byte_rate,
                );
                offset += 8;
                NativeEndian::write_u64(
                    &mut buffer[offset..],
                    stats.outgoing_byte_rate,
                );
            }
            Self::AddrFamily(family) => {
                //TODO constants
                let val = match family {
                    AddressFamily::IPv4 => 2,
                    AddressFamily::IPv6 => 10,
                };
                NativeEndian::write_u16(buffer, val);
            }
            //Self::TunType(tun_type) => buffer[0] = *tun_type as u8,
            // FIXME
            Self::TunType(tun_type) => buffer[0] = 1,
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
            IPVS_DEST_ATTR_ADDR => {
                let addr = if payload.len() == 4 {
                    IpAddr::V4(Ipv4Addr::from(parse_u32(payload)?))
                } else if payload.len() == 16 {
                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(payload);
                    IpAddr::V6(Ipv6Addr::from(bytes))
                } else {
                    return Err(DecodeError::from(format!(
                        "Invalid IP address length: {}",
                        payload.len()
                    )));
                };
                Self::Addr(addr)
            }
            IPVS_DEST_ATTR_PORT => Self::Port(parse_u16(payload)?),
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

// Implement necessary conversion traits for ForwardType, AddressFamily, and TunnelType
impl TryFrom<u32> for ForwardType {
    type Error = DecodeError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        // Implement the conversion logic here
        unimplemented!()
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
        // Implement the conversion logic here
        unimplemented!()
    }
}
