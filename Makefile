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

all: clean run

pre2024: 
	@cd ./img && make pre2024
	make run

pre2025:
	@cd ./img && make pre2025
	make run

custom:
	@cd ./img && make custom
	make run

run: clean
	@cd ./user && make build ARCH=$(ARCH)
	@cd ./os && make run ARCH=$(ARCH)

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