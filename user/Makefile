
# Building
# ARCH ?= loongarch64
ARCH ?= riscv64
MODE := release

# Target, Binutils(Objcopy)
ifeq ($(ARCH), riscv64)
	TARGET := riscv64gc-unknown-none-elf
	OBJCOPY := rust-objcopy --binary-architecture=riscv64
	OBJDUMP := rust-objdump --arch-name=riscv64
else ifeq ($(ARCH), loongarch64)
	TARGET := loongarch64-unknown-none
	OBJCOPY := loongarch64-linux-gnu-objcopy 
	OBJDUMP := loongarch64-linux-gnu-objdump
else
	$(error "Unsupported architecture: $(ARCH), Use riscv64 or loongarch64")
endif
APP_DIR := src/bin
TARGET_DIR := target/$(TARGET)/$(MODE)
APPS := $(wildcard $(APP_DIR)/*.rs)
ELFS := $(patsubst $(APP_DIR)/%.rs, $(TARGET_DIR)/%, $(APPS))
BINS := $(patsubst $(APP_DIR)/%.rs, $(TARGET_DIR)/%.bin, $(APPS))

CP := cp 

TEST ?= 
SUBMIT :=

ifeq ($(MODE), release)
	MODE_ARG := --release
endif

elf: $(APPS) 
ifeq ($(SUBMIT), true)
	@cargo build --offline --release --target $(TARGET)
else
	@cargo build $(MODE_ARG) --target $(TARGET)
endif
ifeq ($(TEST), 1)
	@$(CP) $(TARGET_DIR)/usertests $(TARGET_DIR)/initproc
endif

binary: elf
	@$(foreach elf, $(ELFS), $(OBJCOPY) $(elf) --strip-all -O binary $(patsubst $(TARGET_DIR)/%, $(TARGET_DIR)/%.bin, $(elf));)

move-cargo:
	@rm -rf .cargo
	@mkdir .cargo
	cp cargo/config_$(ARCH).toml .cargo/config.toml

build: move-cargo binary

clean:
	@cargo clean

.PHONY: elf binary build clean
