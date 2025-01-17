# Makefile args:
# - `MODE`: Run with `Mode=debug` to build in debug mode.
#  		By default, rros will run in debug mode.
# - `FEATURES`: Features to enable when build
#		["test", ] 

# Building
TARGET := riscv64gc-unknown-none-elf
MODE := debug
KERNEL_ELF := target/$(TARGET)/$(MODE)/os
KERNEL_BIN := $(KERNEL_ELF).bin
FEATURES := default

# BOARD
BOARD := qemu
SBI ?= opensbi
BOOTLOADER := ../bootloader/$(SBI)-$(BOARD).bin
BOOTLOADER_ELF := ../bootloader/$(SBI)-$(BOARD)

# TEST
TEST_KERNEL_BIN = kernel-qemu
TEST_bios = sbi-qemu

# Configs
MEM_SIZE = 128M
LOG := error

# Binutils
OBJCOPY := rust-objcopy --binary-architecture=riscv64

ifeq ($(MODE), release)
	MODE_ARG := --release
endif

# File system
FS := ../img/sdcard-riscv.img


# QEMU
# 添加一块虚拟硬盘, 命名为`x0`, 将`sdcard.img`挂载到这块硬盘上, VirtIO总线通过MMIO进行控制, 且该块设备在总线中的编号为0
QEMU_ARGS := 	-machine virt \
				-m $(MEM_SIZE) \
				-kernel $(KERNEL_BIN) \
				-nographic \
				-smp 2\
				-bios $(BOOTLOADER_ELF)\
			    -drive file=$(FS),if=none,format=raw,id=x0 \
			 	-device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0\
				-device virtio-net-device,netdev=net -netdev user,id=net

TEST_QEMU_ARGS := 	-machine virt \
				-m $(MEM_SIZE) \
				-kernel $(TEST_KERNEL_BIN) \
				-nographic \
				-smp 2\
				-bios $(TEST_bios)\
			    -drive file=$(FS),if=none,format=raw,id=x0 \
			 	-device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0\
				-device virtio-net-device,netdev=net -netdev user,id=net


# gdb
GDB_CLIENT := riscv64-unknown-elf-gdb
GDB_ARGS := -ex 'file target/riscv64gc-unknown-none-elf/debug/os' \
    		-ex 'set arch riscv:rv64' \
			-ex 'target remote localhost:1234'

gdbserver: env build
	qemu-system-riscv64 $(QEMU_ARGS) -s -S 

gdbclient: 
	@echo "Using GDB: $(GDB_CLIENT)"
	$(GDB_CLIENT) $(GDB_ARGS)

env:
	(rustup target list | grep "riscv64gc-unknown-none-elf (installed)") || rustup target add $(TARGET)
	cargo install cargo-binutils
	rustup component add rust-src
	rustup component add llvm-tools-preview

gdbserver: env build
	qemu-system-riscv64 $(QEMU_ARGS) -s -S 

gdbclient: 
	@echo "Using GDB: $(GDB_CLIENT)"
	$(GDB_CLIENT) $(GDB_ARGS)

env:
	(rustup target list | grep "riscv64gc-unknown-none-elf (installed)") || rustup target add $(TARGET)
	cargo install cargo-binutils
	rustup component add rust-src
	rustup component add llvm-tools-preview

# # 检查是否存在 riscv64-unknown-elf-gdb
# ifeq ("$(shell command -v $(GDB_CLIENT))", "")
#     GDB_CLIENT := gdb-multiarch
# # 检查是否存在 gdb-multiarch
# else ifeq ("$(shell command -v $(GDB_CLIENT))", "")
#     $(error "No suitable GDB client found. Please install riscv64-unknown-elf-gdb or gdb-multiarch.")
# endif

build-offline: 
	cargo build $(MODE_ARG) --features $(FEATURES) --offline 
	@$(OBJCOPY) $(KERNEL_ELF) --strip-all -O binary $(KERNEL_BIN)

build:
	LOG=$(LOG) cargo build $(MODE_ARG) --features $(FEATURES)
	@$(OBJCOPY) $(KERNEL_ELF) --strip-all -O binary $(KERNEL_BIN)
	
run: build 
	qemu-system-riscv64 $(QEMU_ARGS)

run-test: make-user move-cargo build-offline move-bin
	qemu-system-riscv64 $(TEST_QEMU_ARGS)

clean:
	@cargo clean

move-cargo:
	@rm -rf .cargo
	@mkdir .cargo
	@cp cargo/* .cargo/

move-bin:
	@cp $(KERNEL_BIN) ../kernel-qemu
	@cp $(BOOTLOADER_ELF) ../sbi-qemu

make-user:
	@cd ../user && make
	@./build

all: move-cargo make-user build-offline move-bin

.PHONY: make-user build 
