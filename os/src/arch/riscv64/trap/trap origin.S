# sscratch 寄存器 在用户态时保存用户的内核栈指针, 在内核态时保存内核的用户栈指针  
# 在trap中不需要修改TCB中的sp, 因为在__switch中当前任务的内核栈是根据现在的sp来确定的, 这个sp的值已经减去了TrapContext的大小
# 但在__swtich中, 需要修改当前TCB中的sp, 因为在__switch中下个任务的内核栈位置是通过TCB中的sp来确定的

.altmacro
.macro SAVE_GP n
    sd x\n, \n*8(sp)
.endm
.macro LOAD_GP n
    ld x\n, \n*8(sp)
.endm
    .section .text
    .globl __trap_from_user
    .globl __return_to_user
    .globl __trap_from_kernel
    .globl __trap_from_signal
    .align 2
# 在trap进入内核态时, 将用户态的上下文保存到内核栈上, 然后调用trap_handler
__trap_from_user:
    # 交换sp和sscratch的值
    csrrw sp, sscratch, sp
    # now sp->kernel stack, sscratch->user stack
    # 在内核栈上保存用户的上下文 
    addi sp, sp, -34*8
    # save general-purpose registers
    sd x1, 1*8(sp)
    # skip sp(x2), we will save it later
    sd x3, 3*8(sp)
    # skip tp(x4), application does not use it 
    sd x4, 4*8(sp)
    # save x5~x31
    .set n, 5
    .rept 27
        SAVE_GP %n
        .set n, n+1
    .endr
    # we can use t0/t1/t2 freely, because they were saved on kernel stack
    csrr t0, sstatus
    csrr t1, sepc
    sd t0, 32*8(sp)
    sd t1, 33*8(sp)
    # read user stack from sscratch and save it on the kernel stack
    csrr t2, sscratch
    sd t2, 2*8(sp)
    # 第一个参数是TrapContext在内核栈上的地址, 通过a0传递
    mv a0, sp
    # 注意要在保存上下文后设置stvec
    # 设置stvec为Mode(0~1 bits) Direct, 基地址为__trap_from_kernel
    la t0, __trap_from_user
    csrw stvec, t0
    # 设置sstatus的SPP位为1, 表示进入内核态, 实际并没有作用
    csrs sstatus, 8
    call trap_handler
    j __return_to_user

# 该trap仅由sigreturn_trampoline进行调用，作为信号的处理程序入口
__trap_from_signal:
    csrrw sp, sscratch, sp
    mv a0, sp
    # 恢复stvec设置
    la t0, __trap_from_user
    csrw stvec, t0
    # 设置sstatus的SPP位为1, 表示进入内核态, 实际并没有作用
    csrs sstatus, 8
    call trap_handler
    j __return_to_user

# 在trap_handler返回时, 将内核栈上的上下文恢复到用户态, 然后返回到用户态
# 注意这个`__return_to_user`与TrapContext结构体强相关, 且是硬编码的
# 预期：进入该函数时sp指向该内核栈的TrapContext的位置
__return_to_user:
    # 设置stvec为Mode(0~1 bits) Direct, 基地址为__trap_from_user
    # 注意要在恢复上下文之前设置, 因为恢复上下文时会用到stvec
    la t0, __trap_from_user
    csrw stvec, t0 
    # now sp->kernel stack(after allocated)
    ld t0, 32*8(sp)
    # `__return_to_user` sstatus/sepc
    ld t1, 33*8(sp)
    ld t2, 2*8(sp)
    csrw sstatus, t0
    csrw sepc, t1
    csrw sscratch, t2
    # 现在sscarch指向的是用户栈
    # `return_to_user` general-purpuse registers except sp/tp
    ld x1, 1*8(sp)
    ld x3, 3*8(sp)
    # skip tp(x4), application does not use it
    ld x4, 4*8(sp)
    .set n, 5
    .rept 27
        LOAD_GP %n
        .set n, n+1
    .endr
    # release TrapContext on kernel stack
    addi sp, sp, 34*8
    csrrw sp, sscratch, sp
    # 现在sp指向的是用户栈, sscratch指向的是内核栈, 然后返回到用户态
    # 置sstatus的SPP位为0, 表示返回到用户态
    csrc sstatus, 8 
    sret

# Todo: 这个在使用内核栈保存信息的情况, 是可以做到的, 详细可能
__trap_from_kernel:
    # # 交换sp和sscratch的值
    # csrrw sp, sscratch, sp
    # 相较于__trap_from_user, 这里不用换栈, 因为本身就在内核
    # allocate another TrapContext on kernel stack
    addi sp, sp, -34*8
    # save general-purpose registers
    sd x1, 1*8(sp)
    # skip sp(x2), we will save it later
    # save x3~x31
    .set n, 3
    .rept 29
        SAVE_GP %n
        .set n, n+1
    .endr
    # we can use t0/t1/t2 freely, because they were saved on kernel stack
    csrr t0, sstatus
    csrr t1, sepc
    sd t0, 32*8(sp)
    sd t1, 33*8(sp)
    sd sp, 2*8(sp)
    call kernel_trap_handler
    # 内核态的trap_handler返回后, 恢复内核态的上下文
    ld t0, 32*8(sp)
    ld t1, 33*8(sp)
    # Todo: 这里是不是不用保存和恢复sstatus
    csrw sstatus, t0
    csrw sepc, t1
    # sp
    ld x1, 1*8(sp)
    # restore x3~x31
    .set n, 3
    .rept 29
        LOAD_GP %n
        .set n, n+1
    .endr
    # release TrapContext on kernel stack
    addi sp, sp, 34*8
    sret


