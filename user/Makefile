TARGET := riscv64gc-unknown-none-elf
MODE := release
APP_DIR := src/bin
TARGET_DIR := target/$(TARGET)/$(MODE)
APPS := $(wildcard $(APP_DIR)/*.rs)
ELFS := $(patsubst $(APP_DIR)/%.rs, $(TARGET_DIR)/%, $(APPS))
BINS := $(patsubst $(APP_DIR)/%.rs, $(TARGET_DIR)/%.bin, $(APPS))

OBJDUMP := rust-objdump --arch-name=riscv64
OBJCOPY := rust-objcopy --binary-architecture=riscv64
CP := cp 

TEST ?= 
SUBMIT :=

ifeq ($(MODE), release)
	MODE_ARG := --release
endif

elf: $(APPS) 
ifeq ($(SUBMIT), true)
	@cargo build --offline --release
else
	@cargo build $(MODE_ARG)
endif
ifeq ($(TEST), 1)
	@$(CP) $(TARGET_DIR)/usertests $(TARGET_DIR)/initproc
endif

binary: elf
	@$(foreach elf, $(ELFS), $(OBJCOPY) $(elf) --strip-all -O binary $(patsubst $(TARGET_DIR)/%, $(TARGET_DIR)/%.bin, $(elf));)

move-cargo:
	@rm -rf .cargo
	@cp -r cargo .cargo

build: move-cargo binary

clean:
	@cargo clean

.PHONY: elf binary build clean
