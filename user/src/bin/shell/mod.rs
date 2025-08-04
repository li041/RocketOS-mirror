#![allow(unused)]
pub mod command;
pub mod environment;

pub const LF: u8 = 0x0au8;
pub const CR: u8 = 0x0du8;
pub const DL: u8 = 0x7fu8;
pub const BS: u8 = 0x08u8;

pub const UP_ARROW: &str = "\x1B[A";
pub const DOWN_ARROW: &str = "\x1B[B";
pub const RIGHT_ARROW: &str = "\x1B[C";
pub const LEFT_ARROW: &str = "\x1B[D";

pub const ESC: u8 = 0x1bu8;
pub const TAB: u8 = 0x09u8;

// Arona OS theme color
pub const THEME_COLOR: &str = "\u{1B}[38;5;14m";
pub const RESET_COLOR: &str = "\u{1B}[0m";
