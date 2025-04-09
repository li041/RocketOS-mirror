# SAVE数据保存寄存器在用户态时保存用户的内核栈指针


.altmacro
.macro SAVE_GP n
    st.d $r\n, $sp, \n*8
.endm
.macro LOAD_GP n
    ld.d $r\n, $sp, \n*8
.endm

    .section .text
    .globl __trap_from_user
    .globl __return_to_user
    .globl __trap_from_kernel
.equ CSR_SAVE0, 0x30
.equ CSR_PRMD, 0x1
.equ CSR_ERA, 0x6
.equ CSR_EENTRY, 0xc

# 根据Eentry的语义, 保持页对齐
    .align 12
__trap_from_user:
    # 交换sp和SAVE0的值
    csrwr $sp, CSR_SAVE0
    # 此时sp->内核栈, SAVE0->用户栈
    # 在内核栈上保存用户的上下文
    # todo: 这里TrapContext还没确定好, 先用32GR+sstaus+sepc
    addi.d $sp, $sp, -34*8
    # 保存通用寄存器
    st.d $r1, $sp, 1*8
    # skip tp(r2), 应用程序不使用它
    # skip sp(r3), 我们稍后保存它
    .set n, 4
    .rept 28
        SAVE_GP %n
        .set n, n+1
    .endr
    # Todo: 保存浮点寄存器

    # 我们可以自由使用t0/t1/t2, 因为它们已经保存在内核栈上
    csrrd $t0, CSR_PRMD
    csrrd $t1, CSR_ERA
    st.d $t0, $sp, 32*8
    st.d $t1, $sp, 33*8

    # 从SAVE0读取内核栈并保存到内核栈
    csrrd $t2, CSR_SAVE0
    st.d $t2, $sp, 3*8
    # trap_handler第一个参数是TrapContext在内核栈上的地址, 通过a0传递
    add.d $a0, $sp, $zero

    # 设置例外入口地址
    la $t0, __trap_from_user
    csrwr $t0, CSR_EENTRY
    bl trap_handler
    b __return_to_user


# 在trap_handler返回时, 将内核栈上的上下文恢复到用户态, 然后返回到用户态
# 注意这个`__return_to_user`与TrapContext结构体强相关, 且是硬编码的
# 预期：进入该函数时sp指向该内核栈的TrapContext的位置
__return_to_user:
    # 设置EEntry为__trap_from_user
    la $t0, __trap_from_user
    csrwr $t0, CSR_EENTRY

    # 恢复上下文
    ld.d $t0, $sp, 32*8
    ld.d $t1, $sp, 33*8
    ld.d $t2, $sp, 3*8
    csrwr $t0, CSR_PRMD
    csrwr $t1, CSR_ERA
    csrwr $t2, CSR_SAVE0
    # 现在SAVE0指向用户栈
    ld.d $r1, $sp, 1*8
    # skip tp(r2), 应用程序不使用它
    # skip sp(r3), 我们稍后load它
    .set n, 4
    .rept 28
        LOAD_GP %n
        .set n, n+1 
    .endr
    # release TrapContext on kernel stack
    addi.d $sp, $sp, 34*8
    # 交换sp和SAVE0的值
    csrwr $sp, CSR_SAVE0
    # 现在sp指向的是用户栈, SAVE0指向的是内核栈, 然后返回到用户态
    ertn 

.align 12
__trap_from_kernel:
    addi.d $sp, $sp, -34*8
    # 保存通用寄存器
    st.d $r1, $sp, 1*8
    st.d $r2, $sp, 2*8
    # skip sp(r3), 稍后保存它
    .set n, 4
    .rept 28
        SAVE_GP %n
        .set n, n+1
    .endr
    # Todo: 保存浮点寄存器

    # 我们可以自由使用t0/t1/t2, 因为它们已经保存在内核栈上
    csrrd $t0, CSR_PRMD
    csrrd $t1, CSR_ERA
    st.d $t0, $sp, 32*8
    st.d $t1, $sp, 33*8

    # 保存sp
    st.d $r3, $sp, 3*8 
    bl kernel_trap_handler
    # 内核态的trap_handler返回时, 恢复内核态的上下文
    ld.d $t0, $sp, 32*8
    ld.d $t1, $sp, 33*8
    # Todo: 这里是不是不用保存和恢复sstatus
    csrwr $t0, CSR_PRMD
    csrwr $t1, CSR_ERA
    # sp
    ld.d $r1, $sp, 1*8
    .set n, 3
    .rept 29
        LOAD_GP %n
        .set n, n+1
    .endr
    # 释放内核栈上的TrapContext
    addi.d $sp, $sp, 34*8
    ertn
