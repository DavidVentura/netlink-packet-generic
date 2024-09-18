// SPDX-License-Identifier: MIT

//! Generic netlink controller implementation
//!
//! This module provides the definition of the controller packet.
//! It also serves as an example for creating a generic family.

use self::nlas::*;
use crate::constants::*;
use anyhow::Context;
use netlink_packet_generic::{traits::*, GenlHeader};
use netlink_packet_utils::{nla::NlasIterator, traits::*, DecodeError};
use std::convert::{TryFrom, TryInto};

/// Netlink attributes for this family
pub mod nlas;

/// Command code definition of Netlink controller (nlctrl) family
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpvsCtrlCmd {
    Unspec,
    NewService, /* add service */
    SetService, /* modify service */
    DelService, /* delete service */
    GetService, /* get service info */

    NewDest, /* add destination */
    SetDest, /* modify destination */
    DelDest, /* delete destination */
    GetDest, /* get destination info */
}

impl From<IpvsCtrlCmd> for u8 {
    fn from(cmd: IpvsCtrlCmd) -> u8 {
        use IpvsCtrlCmd::*;
        match cmd {
            NewService => IPVS_CMD_NEW_SERVICE,
            SetService => IPVS_CMD_SET_SERVICE,
            DelService => IPVS_CMD_DEL_SERVICE,
            GetService => IPVS_CMD_GET_SERVICE,

            NewDest => IPVS_CMD_NEW_DEST,
            SetDest => IPVS_CMD_SET_DEST,
            DelDest => IPVS_CMD_DEL_DEST,
            GetDest => IPVS_CMD_GET_DEST,
            Unspec => IPVS_CMD_UNSPEC,
        }
    }
}

impl TryFrom<u8> for IpvsCtrlCmd {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use IpvsCtrlCmd::*;
        Ok(match value {
            IPVS_CMD_NEW_SERVICE => NewService,
            IPVS_CMD_SET_SERVICE => SetService,
            IPVS_CMD_DEL_SERVICE => DelService,
            IPVS_CMD_GET_SERVICE => GetService,

            IPVS_CMD_NEW_DEST => NewDest,
            IPVS_CMD_SET_DEST => SetDest,
            IPVS_CMD_DEL_DEST => DelDest,
            IPVS_CMD_GET_DEST => GetDest,
            IPVS_CMD_UNSPEC => Unspec,
            cmd => {
                return Err(DecodeError::from(format!(
                    "Unknown control command: {cmd}"
                )))
            }
        })
    }
}

/// Payload of generic netlink controller
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpvsCtrl {
    /// Command code of this message
    pub cmd: IpvsCtrlCmd,
    /// Netlink attributes in this message
    pub nlas: Vec<IpvsCtrlAttrs>,
}

impl GenlFamily for IpvsCtrl {
    fn family_name() -> &'static str {
        "IPVS"
    }

    fn family_id(&self) -> u16 {
        0x27
    }

    fn command(&self) -> u8 {
        self.cmd.into()
    }

    fn version(&self) -> u8 {
        1
    }
}

impl Emitable for IpvsCtrl {
    fn emit(&self, buffer: &mut [u8]) {
        self.nlas.as_slice().emit(buffer)
    }

    fn buffer_len(&self) -> usize {
        self.nlas.as_slice().buffer_len()
    }
}

impl ParseableParametrized<[u8], GenlHeader> for IpvsCtrl {
    fn parse_with_param(
        buf: &[u8],
        header: GenlHeader,
    ) -> Result<Self, DecodeError> {
        Ok(Self {
            cmd: header.cmd.try_into()?,
            // skip header
            nlas: parse_ctrlnlas(&buf[4..])?,
        })
    }
}

fn parse_ctrlnlas(buf: &[u8]) -> Result<Vec<IpvsCtrlAttrs>, DecodeError> {
    let nlas = NlasIterator::new(buf)
        .map(|nla| nla.and_then(|nla| IpvsCtrlAttrs::parse(&nla)))
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse control message attributes")?;

    Ok(nlas)
}
