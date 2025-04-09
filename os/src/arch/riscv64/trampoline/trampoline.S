    .section .text.trampoline
    .align 12
    .globl sigreturn_trampoline

# 在用户注册了信号处理程序并执行结束后，用户的信号处理程序会返回到该函数来调用sigreturn回到内核态
sigreturn_trampoline:
    li	a7,139
    ecall