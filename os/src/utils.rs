use alloc::string::String;

/// 由caller保证ptr的合法性
/// Convert C-style string(end with '\0') to rust string
pub fn c_str_to_string(ptr: *const u8) -> String {
    let mut ptr = ptr as usize;
    let mut ret = String::new();
    // trace!("[c_str_to_string] convert ptr at {:#x} to string", ptr);
    loop {
        let ch: u8 = unsafe { *(ptr as *const u8) };
        if ch == 0 {
            break;
        }
        ret.push(ch as char);
        ptr += 1;
    }
    ret
}
