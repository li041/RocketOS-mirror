#!/bin/bash

# 用法提示
usage() {
    echo "Usage: $0 ARCH=[rv|la] CC=[musl|glibc]"
    exit 1
}

# 参数解析
for arg in "$@"; do
    case $arg in
        ARCH=*)
            ARCH="${arg#*=}"
            shift
            ;;
        CC=*)
            CC="${arg#*=}"
            shift
            ;;
        *)
            usage
            ;;
    esac
done

# 参数检查
if [[ -z "$ARCH" || -z "$CC" ]]; then
    usage
fi

# Todo: 现在用来clean_ltp的文件统一使用riscv-musl.log
LOG_FILE="./scripts/riscv-musl.log"

# 决定镜像文件与目标文件夹
if [[ "$ARCH" == "rv" ]]; then
    IMG_FILE="img/sdcard-rv.img"
    TARGET_DIR="ltp"
    # LOG_FILE="riscv-${CC}.log"
elif [[ "$ARCH" == "la" ]]; then
    IMG_FILE="img/sdcard-la.img"
    TARGET_DIR="ltp-la"
    # LOG_FILE="loongarch-${CC}.log"
else
    echo "Invalid ARCH: $ARCH (must be rv or la)"
    exit 1
fi

# 检查 CC 参数合法性
if [[ "$CC" != "musl" && "$CC" != "glibc" ]]; then
    echo "Invalid CC: $CC (must be musl or glibc)"
    exit 1
fi

# 设置路径
SRC_DIR="img/mnt/${CC}/ltp/testcases/bin"
DEST_DIR="img/${TARGET_DIR}/${CC}/ltp/testcases/bin"

# 挂载镜像
sudo mount "$IMG_FILE" img/mnt || { echo "Failed to mount $IMG_FILE"; exit 1; }

# 拷贝文件
mkdir -p "$DEST_DIR"
cp -a "$SRC_DIR/"* "$DEST_DIR/" || { echo "Copy failed"; sudo umount img/mnt; exit 1; }

# 卸载镜像
sudo umount img/mnt || { echo "Failed to umount"; exit 1; }

# 调用清理脚本
echo "Running clean_ltp.py with log file: $LOG_FILE"
python3 ./scripts/clean_ltp.py "$LOG_FILE" "$DEST_DIR" z || { echo "clean_ltp.py failed"; exit 1; }

echo "✅ Done."
