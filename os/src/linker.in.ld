#ifdef la2k1000
BASE_ADDRESS = 0x0000000090000000;
#endif

#if defined(fu740) || defined(qemu)
BASE_ADDRESS = 0x80200000;
#endif

#ifdef k210
BASE_ADDRESS = 0x80020000;
#endif

/*
*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
*
*
*   THIS FILE WILL BE SENT TO 
*              THE  
*       GNU C PRE-PROCESSOR
*
*VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV
*>DO NOT USE THE # SYMBOL FOR COMMENTS<
*^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
*
*
*
*
*
*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
*/

/*==========ARCHITECTURE===========*/
#ifdef RISCV
OUTPUT_ARCH(riscv)
#endif
#ifdef LOONGARCH64
OUTPUT_ARCH( "loongarch64" )
#endif
/*==================================*/

ENTRY(_start)
SECTIONS
{
    . = BASE_ADDRESS;
    skernel = .;

    stext = .;
    .text : {
        *(.text.entry)
        . = ALIGN(4K);
        strampoline = .;
        *(.text.trampoline);
        . = ALIGN(4K);
        etrampoline = .;
#ifdef ARCH_LOONGARCH64
        . = ALIGN(4K);
        srfill = .;
        KEEP(*(.text.__rfill));
        . = ALIGN(4K);
        strap_handler = .;
        KEEP(*(.text.trap_handler));
        . = ALIGN(4K);
        skern_trap = .;
        KEEP(*(.text.kern_trap));
        . = ALIGN(4K);
#endif
        *(.text .text.*)
    }

    . = ALIGN(4K);
    etext = .;
    srodata = .;
    .rodata : {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
    }
    
    . = ALIGN(4K);
    erodata = .;

#ifdef EH_ENABLED
    seh_frame_hdr = .;
    .eh_frame_hdr : {
        KEEP(*(.eh_frame_hdr .eh_frame_hdr.*))
    } 
    . = ALIGN(4K);

    eeh_frame_hdr = .;
    seh_frame = .;
    .eh_frame : {
        KEEP(*(.eh_frame .eh_frame.*))
    }
    . = ALIGN(4K);
    eeh_frame =.;
#endif

    sdata = .;
    .data : {
        *(.data .data.*)
        *(.sdata .sdata.*)
    }

    . = ALIGN(4K);
    edata = .;
    sbss_with_stack = .;
    .bss : {
        *(.bss.stack)
        sbss = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
    }

    . = ALIGN(4K);
    ebss = .;
    ekernel = .;

#ifndef EH_ENABLED
    /DISCARD/ : {
        *(.eh_frame)
    }
#endif
}
