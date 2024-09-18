// SPDX-License-Identifier: MIT

//! Define constants related to generic netlink
pub const GENL_ID_CTRL: u16 = 16;
pub const GENL_HDRLEN: usize = 4;

pub const IPVS_CMD_UNSPEC: u8 = 0;
pub const IPVS_CMD_NEW_SERVICE: u8 = 1; /* add service */
pub const IPVS_CMD_SET_SERVICE: u8 = 2; /* modify service */
pub const IPVS_CMD_DEL_SERVICE: u8 = 3; /* delete service */
pub const IPVS_CMD_GET_SERVICE: u8 = 4; /* get service info */
pub const IPVS_CMD_NEW_DEST: u8 = 5; /* add destination */
pub const IPVS_CMD_SET_DEST: u8 = 6; /* modify destination */
pub const IPVS_CMD_DEL_DEST: u8 = 7; /* delete destination */
pub const IPVS_CMD_GET_DEST: u8 = 8; /* get destination info */

pub const IPVS_CMD_ATTR_UNSPEC: u8 = 0;
/* nested service attribute */
pub const IPVS_CMD_ATTR_SERVICE: u8 = 1;
/* nested destination attribute */
pub const IPVS_CMD_ATTR_DEST: u8 = 2;
/* nested sync daemon attribute */
pub const IPVS_CMD_ATTR_DAEMON: u8 = 3;
/* TCP connection timeout */
pub const IPVS_CMD_ATTR_TIMEOUT_TCP: u8 = 4;
/* TCP FIN wait timeout */
pub const IPVS_CMD_ATTR_TIMEOUT_TCP_FIN: u8 = 5;
/* UDP timeout */
pub const IPVS_CMD_ATTR_TIMEOUT_UDP: u8 = 6;

pub const IPVS_SVC_ATTR_UNSPEC: u16 = 0;
pub const IPVS_SVC_ATTR_AF: u16 = 1;
pub const IPVS_SVC_ATTR_PROTOCOL: u16 = 2;
pub const IPVS_SVC_ATTR_ADDR: u16 = 3;
pub const IPVS_SVC_ATTR_PORT: u16 = 4;
pub const IPVS_SVC_ATTR_FWMARK: u16 = 5;
pub const IPVS_SVC_ATTR_SCHED_NAME: u16 = 6;
pub const IPVS_SVC_ATTR_FLAGS: u16 = 7;
pub const IPVS_SVC_ATTR_TIMEOUT: u16 = 8;
pub const IPVS_SVC_ATTR_NETMASK: u16 = 9;
pub const IPVS_SVC_ATTR_STATS: u16 = 10;
pub const IPVS_SVC_ATTR_PE_NAME: u16 = 11;
pub const IPVS_SVC_ATTR_STATS64: u16 = 12;
