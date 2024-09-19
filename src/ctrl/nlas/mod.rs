// SPDX-License-Identifier: MIT

use crate::constants::*;
use destination::DestinationCtrlAttrs;
use netlink_packet_utils::{
    nla::{Nla, NlaBuffer},
    traits::*,
    DecodeError,
};
use service::SvcCtrlAttrs;

pub mod destination;
pub mod service;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddressFamily {
    IPv4,
    IPv6,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpvsCtrlAttrs {
    Service(service::SvcCtrlAttrs),
    Destination(destination::DestinationCtrlAttrs),
}

impl Nla for IpvsCtrlAttrs {
    fn value_len(&self) -> usize {
        match self {
            IpvsCtrlAttrs::Service(nla) => nla.buffer_len(),
            IpvsCtrlAttrs::Destination(nla) => nla.buffer_len(),
        }
    }
    fn kind(&self) -> u16 {
        match self {
            IpvsCtrlAttrs::Service(_) => IPVS_CMD_ATTR_SERVICE,
            IpvsCtrlAttrs::Destination(_) => IPVS_CMD_ATTR_DEST,
        }
    }
    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            IpvsCtrlAttrs::Service(nla) => nla.emit_value(buffer),
            IpvsCtrlAttrs::Destination(nla) => nla.emit_value(buffer),
        }
    }
}
impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for IpvsCtrlAttrs
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            IPVS_CMD_ATTR_SERVICE => {
                Self::Service(SvcCtrlAttrs::parse(&NlaBuffer::new(payload))?)
            }
            IPVS_CMD_ATTR_DEST => Self::Destination(
                DestinationCtrlAttrs::parse(&NlaBuffer::new(payload))?,
            ),
            other => {
                panic!("Don't know how to parse with type {}", other);
            }
        })
    }
}
