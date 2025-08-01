.section .text.entry
.global _start

.equ CSR_CRMD, 0x0
.equ CSR_CPUID, 0x20
.equ CSR_DMW0, 0x180
.equ CSR_DMW1, 0x181

_start:
0:
    # 获取当前 CPU ID 并放入 a0
    csrrd $a0, CSR_CPUID

    # 为每个核设置栈
    li.d $t0, 4096 * 16
    mul.d $t1, $a0, $t0
    la.global $sp, boot_stack_top
    sub.d $sp, $sp, $t1

    # 先读CSR.CRMD看看内存映射模式
    # CRMD的csr_num是0x0
    # csrrd $t1, 0x0
    # CRMD是0x8, 直接地址映射模式 

    # li.d  $t0, 0x800000001fe20000  # 加载 uart_addr 到临时寄存器 $t0
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
    csrwr       $t0,    0x181   # Make sure the window remains the same after the switch.
    sub.d       $t0,    $t0,    $t0
    addi.d      $t1,    $t0,    0x11
    # li.d  $t0, 0x800000001fe20000  # 加载 uart_addr 到临时寄存器 $t0
    # li.w $t2, 0x48 # 加载字符'H'到临时寄存器 $t2
    # st.b $t2, $t0, 0 # 将字符'H'写入串口
    csrwr       $t1,    0x180      #00->00
    pcaddi      $t0,    0x0
    slli.d      $t0,    $t0,    0x10
    srli.d      $t0,    $t0,    0x10
    jirl        $t0,    $t0,    0x10    # 跳0段的下一条指令180
    # The barrier
    sub.d       $t2,    $t1,    $t1
    addi.d      $t2,    $t2,    0x11
    csrwr       $t2,    0x181  #00->00
    csrwr       $t1,    0x180  #recover uart
    #can use uart
    # li.d  $t0, 0x800000001fe20000  # 加载 uart_addr 到临时寄存器 $t0
    # li.w $t2, 0x48 # 加载字符'H'到临时寄存器 $t2
    # st.b $t2, $t0, 0 # 将字符'H'写入串口
    # la.global $sp, boot_stack_top
    bl rust_main

    .section .bss.stack
    .globl boot_stack
boot_stack:
    .space 4096 * 16 * 4
    .globl boot_stack_top
boot_stack_top: