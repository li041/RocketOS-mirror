IMG ?= pre2024
# ARCH ?= loongarch64
ARCH ?= riscv64
LIBC ?= musl

# Cross-compiler prefixes
riscv64_gnu = riscv64-linux-gnu-gcc
riscv64_musl = riscv64-linux-musl-gcc
loongarch64_gnu = loongarch64-linux-gnu-gcc
loongarch64_musl = loongarch64-linux-musl-gcc

IMG_FILE := $(IMG)$(if $(filter riscv64,$(ARCH)),,-la).img
EXT4_OUT := ext4_prev$(if $(filter riscv64,$(ARCH)),,-la).img
CUSTOM := custom$(if $(filter riscv64,$(ARCH)),,-la)

# Compiler flags
CFLAGS = 
LDFLAGS =

ifeq ($(ARCH), riscv64)
    ifeq ($(LIBC), gnu)
		CC := $(riscv64_gnu)
	else ifeq ($(LIBC), musl)
		CC := $(riscv64_musl)
	else
		$(error "Unsupported libc: $(LIBC), Use gnu or musl")
	endif
else ifeq ($(ARCH), loongarch64)
   	ifeq ($(LIBC), gnu)
		CC := $(loongarch64_gnu)
	else ifeq ($(LIBC), musl)
		CC := $(loongarch64_musl)
	else
		$(error "Unsupported libc: $(LIBC), Use gnu or musl")
	endif
else
    $(error "Unsupported architecture: $(ARCH), Use riscv64 or loongarch64")
endif

pre2024:
	$(MAKE) init_img IMG=pre2024 ARCH=$(ARCH)

pre2025:
	$(MAKE) init_img IMG=pre2025 ARCH=$(ARCH)

init_img:
	rm $(EXT4_OUT)
	dd if=/dev/zero of=$(EXT4_OUT) count=4096 bs=1M
	mkfs.ext4 $(EXT4_OUT)
	mkdir -p mnt_temp
	sudo mount $(EXT4_OUT) mnt_temp
	mkdir -p mnt
	sudo mount $(IMG_FILE) mnt
	sudo cp -r ./mnt/* mnt_temp
	sudo umount mnt
	sudo umount mnt_temp
	sudo rm -rf mnt_temp

custom: compile_custom
	rm $(EXT4_OUT)
	dd if=/dev/zero of=$(EXT4_OUT) count=2048 bs=1M
	mkfs.ext4 $(EXT4_OUT)
	mkdir -p mnt
	sudo mount $(EXT4_OUT) mnt
	sudo cp -r ./$(CUSTOM)/* mnt
	sudo umount mnt

compile_custom:
	mkdir -p $(CUSTOM)
	mkdir -p origin
	for file in origin/*.c; do \
		if [ -f "$$file" ]; then \
			$(CC) $(CFLAGS) $$file -o $(CUSTOM)/$$(basename $$file .c) $(LDFLAGS); \
		fi; \
	done

umount:
	sudo umount mnt

.PHONY: custom