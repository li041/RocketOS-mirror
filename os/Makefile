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

# Target, Binutils(Objcopy), FS
ifeq ($(ARCH), riscv64)
	TARGET := riscv64gc-unknown-none-elf
	OBJCOPY := rust-objcopy --binary-architecture=riscv64
    FS := ../img/ext4_prev.img
else ifeq ($(ARCH), loongarch64)
	TARGET := loongarch64-unknown-none
	OBJCOPY := loongarch64-linux-gnu-objcopy 
    FS := ../img/ext4_prev-la.img
else
	$(error "Unsupported architecture: $(ARCH), Use riscv64 or loongarch64")
endif

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
LOG := error
QEMU_NET_PORT ?= 5555

ifeq ($(MODE), release)
	MODE_ARG := --release
endif

# QEMU
# 添加一块虚拟硬盘, 命名为`x0`, 将`sdcard.img`挂载到这块硬盘上, VirtIO总线通过MMIO进行控制, 且该块设备在总线中的编号为0
# 查看设备树 -machine virt,dumpdtb=out.dtb 
ifeq ($(ARCH), riscv64)
    QEMU_CMD := qemu-system-riscv64
    QEMU_ARGS := 	-machine virt\
                    -m $(MEM_SIZE) \
                    -kernel $(KERNEL_BIN) \
                    -nographic \
                    -smp 2\
                    -bios default \
                    -drive file=$(FS),if=none,format=raw,id=x0 \
                    -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0\
                    -device virtio-net-device,netdev=net -netdev user,id=net
else ifeq ($(ARCH), loongarch64)

                    # -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0
    QEMU_CMD := qemu-system-loongarch64
    QEMU_ARGS = 	-kernel $(KERNEL_ELF) -m $(MEM_SIZE) -nographic \
                    -smp 1\
                    -machine virt \
                    -no-reboot \
                    -drive file=$(FS),if=none,format=raw,id=disk0 \
                    -device virtio-blk-pci,drive=disk0 \
                    -nographic 
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
	@cargo clean

move-cargo:
	@rm -rf .cargo
	@mkdir .cargo
	cp cargo/config_$(ARCH).toml .cargo/config.toml

make-user:
	@cd ../user && make ARCH=$(ARCH)
	@./build

all: move-cargo make-user build-offline move-bin

.PHONY: make-user build 
