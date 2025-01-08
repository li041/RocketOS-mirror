# Makefile args:
# - `MODE`: Run with `Mode=debug` to build in debug mode.
#  		By default, rros will run in debug mode.
# - `FEATURES`: Features to enable when build
#		["test", ] 

# Building
TARGET := riscv64gc-unknown-none-elf
MODE := release
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

# Binutils
OBJCOPY := rust-objcopy --binary-architecture=riscv64

ifeq ($(MODE), release)
	MODE_ARG := --release
endif

# File system
FS_IMG := ../img/sdcard.img

# QEMU
# 添加一块虚拟硬盘, 命名为`x0`, 将`sdcard.img`挂载到这块硬盘上, VirtIO总线通过MMIO进行控制, 且该块设备在总线中的编号为0
QEMU_ARGS := 	-machine virt \
				-m $(MEM_SIZE) \
				-kernel $(KERNEL_BIN) \
				-nographic \
				-smp 2\
				-bios $(BOOTLOADER_ELF)\
			    -drive file=$(FS_IMG),if=none,format=raw,id=x0 \
			 	-device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0\
				-device virtio-net-device,netdev=net -netdev user,id=net

TEST_QEMU_ARGS := 	-machine virt \
				-m $(MEM_SIZE) \
				-kernel $(TEST_KERNEL_BIN) \
				-nographic \
				-smp 2\
				-bios $(TEST_bios)\
			    -drive file=$(FS_IMG),if=none,format=raw,id=x0 \
			 	-device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0\
				-device virtio-net-device,netdev=net -netdev user,id=net


# gdb
GDB_CLIENT := riscv64-unknown-elf-gdb
GDB_ARGS := -ex 'file target/riscv64gc-unknown-none-elf/debug/os' \
    		-ex 'set arch riscv:rv64' \
			-ex 'target remote localhost:1234'

# # 检查是否存在 riscv64-unknown-elf-gdb
# ifeq ("$(shell command -v $(GDB_CLIENT))", "")
#     GDB_CLIENT := gdb-multiarch
# # 检查是否存在 gdb-multiarch
# else ifeq ("$(shell command -v $(GDB_CLIENT))", "")
#     $(error "No suitable GDB client found. Please install riscv64-unknown-elf-gdb or gdb-multiarch.")
# endif

build: 
	cargo build $(MODE_ARG) --features $(FEATURES) --offline 
	@$(OBJCOPY) $(KERNEL_ELF) --strip-all -O binary $(KERNEL_BIN)
	
run: build 
	qemu-system-riscv64 $(QEMU_ARGS)

run-test: build
	qemu-system-riscv64 $(TEST_QEMU_ARGS)

clean:
	@cargo clean

gdbserver: env build
	qemu-system-riscv64 $(QEMU_ARGS) -s -S 

gdbclient: 
	@echo "Using GDB: $(GDB_CLIENT)"
	$(GDB_CLIENT) $(GDB_ARGS)

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

all: move-cargo make-user build move-bin

.PHONY: move-cargo make-user build move-bin
