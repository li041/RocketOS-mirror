qemu: all
	qemu-system-riscv64 \
	-machine virt \
	-kernel kernel-qemu \
	-m 128M -nographic \
	-smp 2 \
	-bios sbi-qemu \
	-drive file=sdcard.img,if=none,format=raw,id=x0 \
	-device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 \
	-device virtio-net-device,netdev=net -netdev user,id=net

all: 
	@cd ./os && make all

clean:
	@cd ./os && make clean
	@cd ./user && make clean

.PHONY: all qemu