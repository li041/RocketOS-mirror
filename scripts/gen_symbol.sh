#!/bin/bash

TARGET=$1
MODE=$2
ARCH=$3

RUSTFILT=rustfilt

# 检查参数是否提供
if [ -z "$TARGET" ] || [ -z "$MODE" ] || [ -z "$ARCH" ]; then
    echo "Usage: $0 <TARGET> <MODE> <ARCH>"
    echo "Example: $0 riscv64gc-unknown-none-elf release riscv64"
    exit 1
fi

# 根据架构选择对应的工具和输出路径
if [ "$ARCH" = "riscv64" ]; then
    NM=riscv64-linux-gnu-nm
    OUT_TXT=../os/src/arch/riscv64/backtrace/symbol.txt
elif [ "$ARCH" = "loongarch64" ]; then
    NM=loongarch64-linux-gnu-nm
    OUT_TXT=../os/src/arch/la64/backtrace/symbol.txt
else
    echo "Error: Unsupported architecture: $ARCH, Use riscv64 or loongarch64"
    exit 1
fi

# 检查输入文件是否存在
INPUT_FILE="target/${TARGET}/${MODE}/os"
if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: Input file $INPUT_FILE not found. Please build the project first."
    exit 1
fi

# 创建输出目录
mkdir -p "$(dirname "$OUT_TXT")"

# 生成纯净的文本版本
echo "Generating symbol table for $ARCH..."
echo "Input: $INPUT_FILE"
echo "Output: $OUT_TXT"

"$NM" -n "$INPUT_FILE" | grep ' [Tt] ' | awk '{print $1, $3}' | "$RUSTFILT" > "$OUT_TXT"

if [ $? -eq 0 ]; then
    echo "Symbol table generated successfully!"
    echo "Total symbols: $(wc -l < "$OUT_TXT")"
else
    echo "Error: Failed to generate symbol table"
    exit 1
fi