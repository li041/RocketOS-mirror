# qemu: all
# 	qemu-system-riscv64 \
# 	-machine virt \
# 	-kernel kernel-qemu \
# 	-m 128M -nographic \
# 	-smp 2 \
# 	-bios sbi-qemu \
# 	-drive file=sdcard.img,if=none,format=raw,id=x0 \
# 	-device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 \
# 	-device virtio-net-device,netdev=net -netdev user,id=net

# ARCH ?= loongarch64
ARCH ?= riscv64
MODE ?= debug

# all: clean run
all : 
	@cd ./img && make all
	@cp ./img/disk.img ./disk.img && cp ./img/disk-la.img ./disk-la.img
	@cd ./os && make build ARCH=riscv64 MODE=release && make build ARCH=loongarch64 MODE=release
	@cp ./os/target/riscv64gc-unknown-none-elf/release/os.bin ./kernel-rv && cp ./os/target/loongarch64-unknown-none/release/os ./kernel-la
	

pre2024: 
	@cd ./img && make pre2024
	make run

pre2025:
	@cd ./img && make pre2025
	make run

custom:
	@cd ./img && make custom
	make run

run: 
	@cd ./user && make build ARCH=$(ARCH) MODE=$(MODE)
	@cd ./os && make run ARCH=$(ARCH) MODE=$(MODE)

gdbserver: 
	@cd ./user && make build
	@cd ./os && make gdbserver

gdbclient:
	@cd ./user && make build
	@cd ./os && make gdbclient

clean:
	@cd ./os && make clean
	@cd ./user && make clean

.PHONY: all qemu