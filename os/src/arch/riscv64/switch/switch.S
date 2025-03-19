.altmacro
.macro SAVE_CALLEE n
    sd s\n, (\n+2)*8(sp)
.endm
.macro LOAD_CALLEE n
    ld s\n, (\n+2)*8(a0)
.endm
    .section .text
    .globl __switch
__switch:
    # __swtich(
    #    next_task_kernel_stack: *const usize,
    # )
    # a0 -> next_task_kernel_stack
    # 硬编码, 这里在现任务的内核栈中分配一块空间大小为`TaskContext`的空间
    addi sp, sp, -16*8
    # 保存 ra, tp 与 s0~s11 
    sd ra, 0(sp)
    sd tp, 8(sp)
    .set n, 0
    .rept 12
        SAVE_CALLEE %n
        .set n, n+1
    .endr
    # 保存satp
    csrr t0, satp
    sd t0, 14*8(sp)
    # 重新保存当前任务的内核栈指针
    sd sp, 0(tp)

    # a0指向的是下一个任务的内核栈
    # restore ra, tp and s0~s11 of next execution
    ld ra, 0(a0) 
    ld tp, 8(a0)
    # 之后tp指向的是下一个任务的TCB
    .set n, 0
    .rept 12
        LOAD_CALLEE %n
        .set n, n+1
    .endr
    # restore satp
    ld t0, 14*8(a0)
    csrw satp, t0
    # 刷新tlb
    sfence.vma
    # return to next execution, 硬编码
    addi a0, a0, 16*8
    # Todo: 检验, 好像不需要修改next task TCB中的sp
    # sd a0, 0(tp)
    mv sp, a0
    # # 现在sp指向的是下一个任务的内核栈
    ret

