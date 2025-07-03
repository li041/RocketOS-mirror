    .section .text.__rfill
    .globl __rfill
.equ TLBRSAVE, 0x8b
# PGD是当前上下文中出错虚地址对应的全局目录基址
.equ PGD, 0x1b
.equ TLBRELO0, 0x8c
.equ TLBRELO1, 0x8d
.equ TLBREHI, 0x8e
.equ CRMD, 0x0
# 触发TLB重填例外的出错虚地址
.equ TLBRBADV, 0x89
.equ TLBIDX, 0x10
.equ TLBEHI, 0x11
.equ TLBELO0, 0x12
.equ TLBELO1, 0x13
# __rfill在遍历过程中会检查页表项的有效性, 如果无效则会调用错误处理
__rfill:
    # 使用TLB重填例外数据保存, 保存t0
    csrwr $t0, TLBRSAVE
    # 加载发生TLB重填例外的页表
    csrrd $t0, PGD

    # 第一次lddir - 获取二级页目录
    lddir $t0, $t0, 2
    # 如果lddir失败, 跳转到构造无效页表项
    beqz $t0, construct_invalid
    # 过往的错误认知: 出来最低位为1, 需要减去
    # addi.d $t0, $t0, -1
    # 7.13 查出来带flags, 需要去除
    # 右移12位, 再左移12位, 清除flags
    srli.d $t0, $t0, 12
    slli.d $t0, $t0, 12

    # 第二次lddir - 获取一级页目录
    lddir $t0, $t0, 1
    # 如果lddir失败, 跳转到构造无效页表项
    beqz $t0, construct_invalid
    # addi.d $t0, $t0, -1
    srli.d $t0, $t0, 12
    slli.d $t0, $t0, 12
    ldpte $t0, 0
    ldpte $t0, 1
    tlbfill
    b restore_t0

construct_invalid: 
    csrrd $t0, TLBREHI
    ori $t0, $t0, 0xC
    csrwr $t0, TLBEHI

    rotri.d $t0, $t0, 61
    ori $t0, $t0, 3
    rotri.d $t0, $t0, 3

    csrwr $t0, TLBRELO0
    csrrd $t0, TLBRELO0
    csrwr $t0, TLBRELO1
    tlbfill


restore_t0: 
    # 恢复t0
    csrrd $t0, TLBRSAVE
    # 异常返回(返回地址是TLBBADV)
    ertn