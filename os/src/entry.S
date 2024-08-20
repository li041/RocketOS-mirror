     .section .text.entry
     .globl _start
 _start:
    la sp, boot_stack_top
    call rust_main


    .section .bss.stack

    .globl boot_stack_lower_bound
boot_stack_lower_bound:

    .space 4096 * 16 # * 8  # 8 CPUS at most

    .globl boot_stack_top
boot_stack_top: