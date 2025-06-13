# Makefile args:
# - `MODE`: Run with `Mode=debug` to build in debug mode.
#  		By default, rros will run in debug mode.
# - `FEATURES`: Features to enable when build
#		["test", ] 
# - `ARCH`: Architecture to build
#		["riscv64", "loongarch64"]
# - `FS`: disk image to use

# Building
# ARCH ?= loongarch64
ARCH ?= riscv64
MODE := debug
FEATURES := default
#ip option not unspecified
IP ?= 10.0.2.15
GW ?= 10.0.2.2
# Target, Binutils(Objcopy), FS
ifeq ($(ARCH), riscv64)
	TARGET := riscv64gc-unknown-none-elf
	OBJCOPY := rust-objcopy --binary-architecture=riscv64
    # FS := ../img/ext4_prev.img
    FS := ../img/sdcard-rv.img
    FS2 := ../img/disk.img
else ifeq ($(ARCH), loongarch64)
	TARGET := loongarch64-unknown-none
	OBJCOPY := loongarch64-linux-gnu-objcopy 
    FS := ../img/sdcard-la.img
    FS2 := ../img/disk-la.img
else
	$(error "Unsupported architecture: $(ARCH), Use riscv64 or loongarch64")
endif

export ROCKET_IP=$(IP)
export ROCKET_GW=$(GW)
# User
USER_TARGET_PATH := ../user/target/$(TARGET)/$(MODE)/

KERNEL_ELF := target/$(TARGET)/$(MODE)/os
KERNEL_BIN := $(KERNEL_ELF).bin

# BOARD
BOARD := qemu
# riscv64使用opensbi, loongarch64目前没有
ifeq ($(ARCH), riscv64)
    SBI ?= opensbi
    BOOTLOADER := ../bootloader/$(SBI)-$(BOARD).bin
    BOOTLOADER_ELF := ../bootloader/$(SBI)-$(BOARD)
endif

# Configs
MEM_SIZE = 1024M
LOG :=  
ifeq ($(MODE), release)
	MODE_ARG := --release
endif

# QEMU
# 添加一块虚拟硬盘, 命名为`x0`, 将`sdcard.img`挂载到这块硬盘上, VirtIO总线通过MMIO进行控制, 且该块设备在总线中的编号为0
# 查看设备树 -machine virt,dumpdtb=out.dtb 
# 默认ipv4,ipv6均已经on，需要注意qemu官方的slirp中的hostfwd仍然只适配ipv4映射,将宿主机的5556 映射到5555
ifeq ($(ARCH), riscv64)
    QEMU_CMD := qemu-system-riscv64
    QEMU_ARGS := 	-machine virt\
                    -m $(MEM_SIZE) \
                    -kernel $(KERNEL_BIN) \
                    -nographic \
                    -smp 2\
                    -bios default\
                    -drive file=$(FS),if=none,format=raw,id=x0 \
                    -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0\
                    -device virtio-net-device,netdev=net -netdev user,id=net,hostfwd=tcp::5555-:5555,hostfwd=udp::5555-:5555\
                    -drive file=$(FS2),if=none,format=raw,id=x1\
                    -device virtio-blk-device,drive=x1,bus=virtio-mmio-bus.1
else ifeq ($(ARCH), loongarch64)
    QEMU_CMD := qemu-system-loongarch64
    QEMU_ARGS = 	-kernel $(KERNEL_ELF) -m $(MEM_SIZE) -nographic \
                    -smp 1\
                    -machine virt \
                    -no-reboot \
                    -drive file=$(FS),if=none,format=raw,id=x0 \
                    -device virtio-blk-pci,drive=x0 \
                    -device virtio-net-pci,netdev=net -netdev user,id=net,hostfwd=tcp::5556-:5555,hostfwd=udp::5556-:5555 \
                    -nographic\
                    -drive file=$(FS2),if=none,format=raw,id=x1\
                    -device virtio-blk-pci,drive=x1
else
	$(error "Unsupported architecture: $(ARCH), Use riscv64 or loongarch64")
endif

# gdb
ifeq ($(ARCH), riscv64)
    GDB_CLIENT := riscv64-unknown-elf-gdb
    GDB_ARGS := -ex 'file target/riscv64gc-unknown-none-elf/$(MODE)/os' \
        		-ex 'set arch riscv:rv64' \
			    -ex 'target remote localhost:1234'
else ifeq ($(ARCH), loongarch64)
    GDB_CLIENT := loongarch64-linux-gnu-gdb
    GDB_ARGS := -ex 'file target/loongarch64-unknown-none/$(MODE)/os' \
                -ex 'target remote localhost:1234'
else
    $(error "Unsupported architecture: $(ARCH), Use riscv64 or loongarch64")
endif

gdbserver: build
	$(QEMU_CMD) $(QEMU_ARGS) -s -S 

gdbclient: 
	@echo "Using GDB: $(GDB_CLIENT)"
	$(GDB_CLIENT) $(GDB_ARGS)

# build-offline: 
# 	cargo build $(MODE_ARG) --features $(FEATURES) --offline 
# 	@$(OBJCOPY) $(KERNEL_ELF) --strip-all -O binary $(KERNEL_BIN)

build: move-cargo
	USER_TARGET_PATH=$(USER_TARGET_PATH) LOG=$(LOG) cargo build $(MODE_ARG) --features $(FEATURES) --target $(TARGET)
	@$(OBJCOPY) $(KERNEL_ELF) --strip-all -O binary $(KERNEL_BIN)
	
run: build 
	$(QEMU_CMD) $(QEMU_ARGS)

clean:
	@$(shell which cargo)  clean

move-cargo:
	@rm -rf .cargo
	@mkdir .cargo
	cp cargo/config_$(ARCH).toml .cargo/config.toml

make-user:
	@cd ../user && make ARCH=$(ARCH)
	@./build

all: move-cargo make-user build-offline move-bin

.PHONY: make-user build 
