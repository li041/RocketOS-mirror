//! Loading user applications into memory

/// Get the total number of applications.
use alloc::{string::{String, ToString}, vec::Vec};
use lazy_static::*;
use log::info;
use xmas_elf::ElfFile;
use crate::{config::PAGE_SIZE, task::aux::*};


///get app number
pub fn get_num_app() -> usize {
    extern "C" {
        fn _num_app();
    }
    unsafe { (_num_app as usize as *const usize).read_volatile() }
}
/// get applications data
pub fn get_app_data(app_id: usize) -> &'static [u8] {
    extern "C" {
        fn _num_app();
    }
    let num_app_ptr = _num_app as usize as *const usize;
    let num_app = get_num_app();
    let app_start = unsafe { core::slice::from_raw_parts(num_app_ptr.add(1), num_app + 1) };
    assert!(app_id < num_app);
    unsafe {
        core::slice::from_raw_parts(
            app_start[app_id] as *const u8,
            app_start[app_id + 1] - app_start[app_id],
        )
    }
}

lazy_static! {
    ///All of app's name
    static ref APP_NAMES: Vec<&'static str> = {
        let num_app = get_num_app();
        extern "C" {
            fn _app_names();
        }
        let mut start = _app_names as usize as *const u8;
        let mut v = Vec::new();
        unsafe {
            for _ in 0..num_app {
                let mut end = start;
                while end.read_volatile() != b'\0' {
                    end = end.add(1);
                }
                let slice = core::slice::from_raw_parts(start, end as usize - start as usize);
                let str = core::str::from_utf8(slice).unwrap();
                v.push(str);
                start = end.add(1);
            }
        }
        v
    };
}

#[allow(unused)]
///get app data from name
pub fn get_app_data_by_name(name: &str) -> Option<&'static [u8]> {
    let num_app = get_num_app();
    (0..num_app)
        .find(|&i| APP_NAMES[i] == name)
        .map(get_app_data)
}

pub fn load_dl_interp_if_needed(elf: &ElfFile) -> Option<usize> {
    let elf_header = elf.header;
    let ph_count = elf_header.pt2.ph_count();

    let mut is_dynamic_link = false;

    // check if the elf is dynamic link
    for i in 0..ph_count {
        let ph = elf.program_header(i).unwrap();
        if ph.get_type().unwrap() == xmas_elf::program::Type::Interp {
            is_dynamic_link = true;
            break;
        }
    }
    if is_dynamic_link {
        // load dynamic link interpreter
        let section = elf.find_section_by_name(".interp").unwrap();
        let mut interp = String::from_utf8(section.raw_data(&elf).to_vec()).unwrap();
        interp = interp.trim_end_matches('\0').to_string();
        info!("[load_dl] interp: {}", interp);
        // load interp
        // Todo: dynamic interpreter
        let interp_data = get_app_data_by_name(&interp).unwrap();
        let interp_entry = read_elf(interp_data).0;
        return Some(interp_entry);
    }
    Some(0)
}

/// returns (entry_point, aux_vec)
pub fn read_elf(elf_data: &[u8]) -> (usize, Vec<AuxHeader>) {
    let elf = xmas_elf::ElfFile::new(elf_data).unwrap();
    let elf_header = elf.header;
    let magic = elf_header.pt1.magic;
    assert_eq!(magic, [0x7f, 0x45, 0x4c, 0x46], "invalid elf file"); 
    let ph_count = elf_header.pt2.ph_count();
    let mut entry_point = elf_header.pt2.entry_point() as usize;
    //auxv
    let mut aux_vec: Vec<AuxHeader> = Vec::with_capacity(64);
    
    aux_vec.push(AuxHeader {
        aux_type: AT_PHENT,
        value: elf.header.pt2.ph_entry_size() as usize,
    }); // ELF64 header 64bytes
    aux_vec.push(AuxHeader {
        aux_type: AT_PHNUM,
        value: ph_count as usize,
    });
    aux_vec.push(AuxHeader {
        aux_type: AT_PAGESZ,
        value: PAGE_SIZE,
    });

    // Todo: dynamic interpreter
    aux_vec.push(AuxHeader {
        aux_type: AT_BASE,
        value: 0,
    });
    aux_vec.push(AuxHeader {
        aux_type: AT_FLAGS,
        value: 0 as usize,
    });
    aux_vec.push(AuxHeader {
        aux_type: AT_ENTRY,
        value: elf.header.pt2.entry_point() as usize,
    });
    aux_vec.push(AuxHeader {
        aux_type: AT_UID,
        value: 0 as usize,
    });
    aux_vec.push(AuxHeader {
        aux_type: AT_EUID,
        value: 0 as usize,
    });
    aux_vec.push(AuxHeader {
        aux_type: AT_GID,
        value: 0 as usize,
    });
    aux_vec.push(AuxHeader {
        aux_type: AT_EGID,
        value: 0 as usize,
    });
    aux_vec.push(AuxHeader {
        aux_type: AT_PLATFORM,
        value: 0 as usize,
    });
    aux_vec.push(AuxHeader {
        aux_type: AT_HWCAP,
        value: 0 as usize,
    });
    aux_vec.push(AuxHeader {
        aux_type: AT_CLKTCK,
        value: 100 as usize,
    });
    aux_vec.push(AuxHeader {
        aux_type: AT_SECURE,
        value: 0 as usize,
    });
    aux_vec.push(AuxHeader {
        aux_type: AT_NOTELF,
        value: 0x112d as usize,
    });
    // Todo: 
    (entry_point, aux_vec)
}

///list all apps
pub fn list_apps() {
    // println!("/**** LINKED APPS ****");
    println!("[kernel] LINKED APPS >>>");
    for app in APP_NAMES.iter() {
        print!("{} \t", app);
    }
    println!("");
    // println!("**************/");
}
