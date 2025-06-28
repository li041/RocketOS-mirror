use crate::arch::config::MAX_HARTS;

extern "C" {
    fn _start();
}

pub fn start_other_harts(hart_id: usize) {
    for i in 0..MAX_HARTS {
        if i == hart_id {
            continue;
        }
        println!("Starting hart {}", i);
        loongArch64::ipi::csr_mail_send(0x90000000, i, 0);
        loongArch64::ipi::send_ipi_single(i, 1);
    }
}
