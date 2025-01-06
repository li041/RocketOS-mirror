// //!Stdin & Stdout
// use alloc::boxed::Box;

// use super::tty::TTY;
// use super::{File, FileMeta};
// use crate::config::AsyncResult;
// // use crate::mm::UserBuffer;
// // use crate::sbi::console_getchar;
// // use crate::task::yield_task;
// use crate::utils::SyscallErr;
// ///Standard input
// pub struct Stdin {
//     pub meta: FileMeta,
// }
// ///Standard output
// pub struct Stdout {
//     pub meta: FileMeta,
// }

// impl File for Stdin {
//     // fn readable(&self) -> bool {
//     //     true
//     // }
//     // fn writable(&self) -> bool {
//     //     false
//     // }
//     fn read<'a>(&'a self, buf: &'a mut [u8]) -> AsyncResult<usize> {
//         // Box::pin(async move {
//         //     // assert_eq!(buf.len(), 1);
//         //     // busy loop
//         //     let mut c: usize;
//         //     loop {
//         //         c = console_getchar();
//         //         // opensbi returns usize::MAX if no char available
//         //         if c == usize::MAX {
//         //             yield_task().await;
//         //             continue;
//         //         } else {
//         //             break;
//         //         }
//         //     }
//         //     let ch = c as u8;
//         //     unsafe {
//         //         // buf.buffers[0].as_mut_ptr().write_volatile(ch);
//         //         buf.as_mut_ptr().write_volatile(ch);
//         //     }
//         //     Ok(1)
//         // })
//         TTY.read(buf)
//     }
//     fn write(&self, _buf: &[u8]) -> AsyncResult<usize> {
//         // panic!("Cannot write to stdin!");
//         Box::pin(async move { Err(SyscallErr::EBADF.into()) })
//     }
//     fn get_meta(&self) -> &FileMeta {
//         // FileMeta::new(None, 0)
//         // &FileMeta {
//         //     inode: None,
//         //     offset: 0,
//         //     dentry_index: 0,
//         // }
//         // &FileMeta::new(None, 0, 0)
//         &self.meta
//     }
//     fn seek(&self, _offset: usize) -> Option<usize> {
//         None
//     }
// }

// impl File for Stdout {
//     // fn readable(&self) -> bool {
//     //     false
//     // }
//     // fn writable(&self) -> bool {
//     //     true
//     // }
//     fn read(&self, _buf: &mut [u8]) -> AsyncResult<usize> {
//         Box::pin(async move { Err(SyscallErr::EBADF.into()) })
//         // panic!("Cannot read from stdout!");
//     }
//     fn write<'a>(&'a self, buf: &'a [u8]) -> AsyncResult<usize> {
//         // Box::pin(async move {
//         //     // for buffer in user_buf.buffers.iter() {
//         //     //     print!("{}", core::str::from_utf8(*buffer).unwrap());
//         //     // }
//         //     print!("{}", core::str::from_utf8(buf).unwrap());
//         //     Ok(buf.len())
//         // })
//         TTY.write(buf)
//     }
//     fn get_meta(&self) -> &FileMeta {
//         // FileMeta::new(None, 0)
//         // &FileMeta {
//         //     inode: None,
//         //     offset: 0,
//         //     dentry_index: 0,
//         // }
//         // &FileMeta::new(None, 0, 0)
//         &self.meta
//     }
//     fn seek(&self, _offset: usize) -> Option<usize> {
//         None
//     }
// }
