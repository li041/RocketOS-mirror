#!/bin/bash

# 检查参数数量
if [ "$#" -ne 3 ]; then
    echo "用法: $0 <ltp_test_file> <source_dir> <destination_dir>"
    echo "示例: $0 ./ltp_test.txt ./oscamp/musl/ltp/testcases/bin ./increment/musl/ltp/testcases/bin"
    exit 1
fi

# 参数赋值
TEST_FILE="$1"
SRC_DIR="$2"
DST_DIR="$3"

# 检查测试用例文件是否存在
if [ ! -f "$TEST_FILE" ]; then
    echo "错误: 测试文件 '$TEST_FILE' 未找到。"
    exit 1
fi

# 创建目标目录（如果不存在）
mkdir -p "$DST_DIR"

# 读取测试用例并复制文件
# 使用 cat 和管道读取文件
cat "$TEST_FILE" | while IFS= read -r testcase; do
    # 忽略空行和注释行
    [[ -z "$testcase" || "$testcase" == \#* ]] && continue

    src_file="$SRC_DIR/$testcase"
    dst_file="$DST_DIR/$testcase"

    if [ -f "$src_file" ]; then
        cp "$src_file" "$dst_file"
        # echo "已复制: $testcase"
    else
        echo "警告: $testcase 未在 $SRC_DIR 中找到"
    fi
done
