.section .text.entry
.global _start

.equ CSR_CRMD, 0x0
.equ CSR_DMW0, 0x180
.equ CSR_DMW1, 0x181

_start:
0:
    # 先读CSR.CRMD看看内存映射模式
    # CRMD的csr_num是0x0
    csrrd $t1, 0x0
    # CRMD是0x8, 直接地址映射模式 

    # li.d  $t0, 0x1fe20000  # 加载 uart_addr 到临时寄存器 $t0
    # li.w $t2, 0x48 # 加载字符'H'到临时寄存器 $t2
    # st.b $t2, $t0, 0 # 将字符'H'写入串口
    # 这个down掉了

    # li.d $t0, 0x90000000
    # li.w $t2, 0x48
    # st.b $t2, $t0, 0 
    # 这个是可以的

    #设置映射窗口
    # addi.d    $t0, $zero,0x11
    # csrwr     $t0, 0x180  #设置LOONGARCH_CSR_DMWIN0

    # copy from Impact
    pcaddi      $t0,    0x0
    srli.d      $t0,    $t0,    0x30
    slli.d      $t0,    $t0,    0x30
    addi.d      $t0,    $t0,    0x11
    csrwr       $t0,    CSR_DMW1   # Make sure the window remains the same after the switch.
    sub.d       $t0,    $t0,    $t0
    addi.d      $t0,    $t0,    0x11
    csrwr       $t0,    CSR_DMW0
    pcaddi      $t0,    0x0
    slli.d      $t0,    $t0,    0x10
    srli.d      $t0,    $t0,    0x10
    jirl        $t0,    $t0,    0x10    # 跳0段的下一条指令
    # The barrier
    sub.d       $t0,    $t0,    $t0
    csrwr       $t0,    0x181
    sub.d       $t0,    $t0,    $t0
    # IMPACT END, 实际上就是设置了下DMW0, 中间好像倒腾了下DMW1, 最后是置回去, 目前还不理解
    la.global $sp, boot_stack_top
    bl rust_main
1:
    b 1b
    .section .bss.stack
    .globl boot_stack
boot_stack:
    .space 4096 * 32
    .globl boot_stack_top
boot_stack_top: