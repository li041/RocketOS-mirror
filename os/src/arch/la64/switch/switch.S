.altmacro
.macro SAVE_SN n
    st.d $s\n, $a0, (\n+2)*8
.endm
.macro LOAD_SN n
    ld.d $s\n, $a1, (\n+2)*8
.endm
    .section .text
    .globl __switch
.equ CSR_PGDL, 0x19
__switch:
    # __swtich(
    #   next_task_kernel_stack: *const usize,
    #)
    # a0 -> next_task_kernel_stack
    # 硬编码, 这里在现任务的内核栈中分配一块空间大小为`TaskContext`的空间
    addi.d $sp, $sp, -16*8
    # 保存 ra, tp 与 s0~s11
    st.d $ra, $sp, 0
    st.d $tp, $sp, 8
    .set n, 0
    .rept 9
        SAVE_SN %n
        .set n, n+1
    .endr
    # 保存fp到s[9]
    st.d $fp, $sp, (9+2)*8
    # 保存pgdl
    csrrd $t0, CSR_PGDL
    st.d $t0, $sp, 14*8
    # 重新保存当前任务的内核栈指针
    st.d $sp, $tp, 0

    # a0指向的是下一个任务的内核栈
    # 恢复 ra, tp 与 s0~s8, fp
    ld.d $ra, $a0, 0
    ld.d $tp, $a0, 8
    .set n, 0
    .rept 9
        LOAD_SN %n
        .set n, n+1
    .endr
    ld.d $fp, $a0, (9+2)*8
    # 恢复pgdl
    ld.d $t0, $a0, 14*8
    csrwr $t0, CSR_PGDL
    # 刷新tlb
    invtlb 0x3, $zero, $zero
    # return to next execution, 硬编码
    addi.d $a0, $a0, 16*8
    addi.d $sp, $a0, 0
    # 现在sp指向的是下一个任务的内核栈
    jr $ra
