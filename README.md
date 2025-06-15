# 🚀 RocketOS
RocketOS 是一个支持 **RISC-V** 与 **LoongArch** 架构的宏内核操作系统项目，支持基本内核功能、用户态程序运行、文件系统、VirtIO 设备等内容。

## 📦 项目结构

```
.
├── LICENSE
├── Makefile
├── README.md
├── bootloader
│   ├── opensbi-qemu
│   └── opensbi-qemu.bin
├── img
├── os
│   ├── src
│   └── vendor
└── user
    ├── src
    └── vendor
```

## 🛠️ 构建方式

默认会同时构建 RISC-V 和 LoongArch 的内核和用户程序：

```bash
make all
```

构建过程将：

* 解压磁盘镜像
* 构建 RISC-V 和 LoongArch 架构的用户态与内核程序
* 生成 `kernel-rv` 和 `kernel-la` 两个内核镜像

## 🚀 启动系统

### 启动 RISC-V 模拟器：

```bash
make run-riscv
```

### 启动 LoongArch 模拟器：

```bash
make run-loongarch
```

## 🐞 调试支持
支持通过 gdb 进行调试：

```bash
make gdbserver    # 启动 QEMU 并开启 GDB 服务
make gdbclient    # 启动 GDB 客户端
```

## 🧹 清理构建文件

```bash
make clean
```

---

## ✨ 注意事项

* 需要安装 QEMU，且支持 `qemu-system-riscv64` 和 `qemu-system-loongarch64`。
* 使用了 `virtio` 设备和多磁盘模拟，请确保 QEMU 版本足够新。
* 需要支持交叉编译工具链，如 `riscv64-linux-musl-gcc` 与 `loongarch64-linux-musl-gcc`。

---

欢迎学习和修改本项目，用于教学、研究和实验操作系统开发 🚀

---

