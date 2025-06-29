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
MODE ?= release

# all: clean run
all : 
	cd ./img && make unpack
	mkdir ./increment -p && mkdir ./oscamp -p 
	cp /coursegrader/testdata/sdcard-rv.img.gz . && gunzip sdcard-rv.img.gz
	cp /coursegrader/testdata/sdcard-la.img.gz . && gunzip sdcard-la.img.gz
	mount ./sdcard-rv.img ./oscamp && mount ./disk.img ./increment 
	./copy_tests.sh ./ltp_test.txt ./oscamp/musl/ltp/testcases/bin ./increment/musl/ltp/testcases/bin
	./copy_tests.sh ./ltp_test.txt ./oscamp/glibc/ltp/testcases/bin ./increment/glibc/ltp/testcases/bin
	umount ./oscamp && umount ./increment
	mount ./sdcard-la.img ./oscamp && mount ./disk-la.img ./increment 
	./copy_tests.sh ./ltp_test.txt ./oscamp/musl/ltp/testcases/bin ./increment/musl/ltp/testcases/bin
	./copy_tests.sh ./ltp_test.txt ./oscamp/glibc/ltp/testcases/bin ./increment/glibc/ltp/testcases/bin
	umount ./oscamp && umount ./increment
	rm -rf sdcard-rv.img sdcard-rv.img.gz    
	rm -rf sdcard-la.img sdcard-la.img.gz
	cd ./user && make build ARCH=riscv64 MODE=release
	cd ./os && make build ARCH=riscv64 MODE=release 
	cd ./user && make build ARCH=loongarch64 MODE=release
	cd ./os && make build ARCH=loongarch64 MODE=release
	cp ./os/target/riscv64gc-unknown-none-elf/release/os.bin ./kernel-rv && cp ./os/target/loongarch64-unknown-none/release/os ./kernel-la

kernel:
	@cd ./img && make pack
	@cd ./user && make build ARCH=riscv64 MODE=release
	@cd ./os && make build ARCH=riscv64 MODE=release 
	@cd ./user && make build ARCH=loongarch64 MODE=release
	@cd ./os && make build ARCH=loongarch64 MODE=release
	@cp ./os/target/riscv64gc-unknown-none-elf/release/os.bin ./kernel-rv && cp ./os/target/loongarch64-unknown-none/release/os ./kernel-la
	
run-riscv:
	qemu-system-riscv64 \
		-machine virt \
		-m 1024M \
		-kernel kernel-rv \
		-nographic \
		-smp 2 \
		-bios default \
		-drive file=./disk-la.img,if=none,format=raw,id=x0 \
		-device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 \
		-device virtio-net-device,netdev=net -netdev user,id=net,hostfwd=tcp::5555-:5555,hostfwd=udp::5555-:5555 \
		-drive file=disk.img,if=none,format=raw,id=x1 \
		-device virtio-blk-device,drive=x1,bus=virtio-mmio-bus.1

run-loongarch:
	qemu-system-loongarch64 \
		-kernel kernel-la \
		-m 1024M \
		-nographic \
		-smp 1 \
		-machine virt \
		-no-reboot \
		-drive file=disk.img,if=none,format=raw,id=x0 \
		-device virtio-blk-pci,drive=x0 \
		-drive file=disk-la.img,if=none,format=raw,id=x1 \
		-device virtio-blk-pci,drive=x1 \
        -device virtio-net-pci,netdev=net -netdev user,id=net,hostfwd=tcp::5556-:5555,hostfwd=udp::5556-:5555 \

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

bench: 
	@cd ./user && make build ARCH=$(ARCH) MODE=$(MODE)
	@cd ./os && make bench ARCH=$(ARCH) MODE=$(MODE)

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