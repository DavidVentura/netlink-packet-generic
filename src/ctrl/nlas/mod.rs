// SPDX-License-Identifier: MIT

use crate::constants::*;
use destination::DestinationCtrlAttrs;
use netlink_packet_utils::{
    nla::{Nla, NlaBuffer, NlasIterator},
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
    Service(Vec<service::SvcCtrlAttrs>),
    Destination(Vec<destination::DestinationCtrlAttrs>),
}

impl Nla for IpvsCtrlAttrs {
    fn is_nested(&self) -> bool {
        true
    }
    fn value_len(&self) -> usize {
        match self {
            IpvsCtrlAttrs::Service(nla) => nla.as_slice().buffer_len(),
            IpvsCtrlAttrs::Destination(nla) => nla.as_slice().buffer_len(),
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
            // TODO emit_value => emit
            IpvsCtrlAttrs::Service(nla) => nla.as_slice().emit(buffer),
            IpvsCtrlAttrs::Destination(nla) => nla.as_slice().emit(buffer),
        }
    }
}
impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for IpvsCtrlAttrs
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        println!("{}", buf.kind());
        println!("payload for svc {:?}", payload);

        Ok(match buf.kind() {
            IPVS_CMD_ATTR_SERVICE => {
                let nlas = NlasIterator::new(payload)
                    .map(|nla| SvcCtrlAttrs::parse(&nla?))
                    .collect::<Result<Vec<_>, _>>()?;
                Self::Service(nlas)
            }
            IPVS_CMD_ATTR_DEST => Self::Destination(
                NlasIterator::new(payload)
                    .map(|nla| DestinationCtrlAttrs::parse(&nla?))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            other => {
                panic!("Don't know how to parse with type {}", other);
            }
        })
    }
}
