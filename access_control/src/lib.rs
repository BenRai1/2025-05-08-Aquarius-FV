#![no_std]
pub mod access;
pub mod constants;
pub mod emergency;
pub mod errors;
pub mod events;
pub mod interface;
pub mod management;
pub mod role;
pub mod storage; //@audit changed to public?
pub mod transfer;
pub mod utils;
pub static mut GHOST_TRANSFER_DELAYED_COUNTER: u32 = 0;
pub static mut GHOST_HAS_MANY_USERS_COUNTER: u32 = 0;
pub static mut GHOST_TRANSFER_DEADLINE_COUNTER: u32 = 0;
pub static mut GHOST_EVENT_COUNTER: u32 = 0;
pub static mut GHOST_FROM_SYMBOL_COUNTER: u32 = 0;
pub static mut GHOST_GET_KEY_COUNTER: u32 = 0;


