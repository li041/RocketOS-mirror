import re
import sys
import os

def process_ltp_log_flexible(input_file_path, output_file_path="passed_ltp_cases.txt"):
    """
    更灵活地处理 LTP 日志文件，主要关注 Summary: 下的 passed 值，
    并将其与最近遇到的 RUN LTP CASE 关联。

    参数:
        input_file_path (str): 输入 LTP 日志文件的路径。
        output_file_path (str): 存储通过测试用例的输出文件路径。
    """
    if not os.path.exists(input_file_path):
        print(f"错误: 输入文件 '{input_file_path}' 不存在。请检查路径是否正确。")
        return

    passed_test_cases = {}
    last_run_test_case = None # 用于存储最近遇到的 'RUN LTP CASE' 名称
    in_summary_block = False # 标志，表示我们当前是否在 'Summary:' 块中
    totol_count = 0 # 用于统计通过的测试用例总数

    try:
        with open(input_file_path, 'r', encoding='utf-8', errors='ignore') as f_in:
            for line in f_in:
                # 1. 捕捉最近的 'RUN LTP CASE'
                run_match = re.search(r"RUN LTP CASE (\w+)", line)
                if run_match:
                    last_run_test_case = run_match.group(1)
                    in_summary_block = False # 重置 Summary 块标志
                    # 如果是新测试用例，初始化其通过计数
                    if last_run_test_case not in passed_test_cases:
                        passed_test_cases[last_run_test_case] = 0
                    continue

                # 2. 检测 'Summary:' 块的开始
                if line.strip().startswith("Summary:"):
                    in_summary_block = True
                    continue # 跳过 'Summary:' 行本身

                # 3. 如果在 Summary 块中，且有 'passed' 行，则提取数值
                if in_summary_block:
                    passed_match = re.search(r"passed\s+(\d+)", line)
                    if passed_match:
                        passed_count = int(passed_match.group(1))
                        
                        # 只有当有最近的测试用例名称时才更新
                        if last_run_test_case:
                            # 记录该测试用例的最高通过次数
                            passed_test_cases[last_run_test_case] = max(
                                passed_test_cases.get(last_run_test_case, 0), passed_count
                            )
                            totol_count += passed_count # 累加总通过次数
                        # 找到 passed 统计后，认为 Summary 块结束
                        in_summary_block = False
                        # 找到通过计数后，清除最近运行的测试用例，因为它可能属于前一个测试的Summary
                        # 这样可以确保下一个Summary会关联到下一个RUN LTP CASE
                        last_run_test_case = None
                        continue

                    # 如果在 Summary 块中但不是 passed 行，且是空行或下一个 "Summary:" 开始，
                    # 也可以认为当前 Summary 块结束（防止误捕获）
                    if not line.strip() or line.strip().startswith("Summary:"):
                        in_summary_block = False
                        # 找到通过计数后，清除最近运行的测试用例，因为它可能属于前一个测试的Summary
                        last_run_test_case = None


    except Exception as e:
        print(f"处理文件时发生错误: {e}")
        return

    # 过滤掉最终通过计数为 0 的测试用例
    valid_passed_cases = {
        name: count for name, count in passed_test_cases.items() if count > 0
    }

    # 删除不要的测试用例
    # 本身能过，但占用时间过长，且得分少
    unwanted_cases = {
        "ebizzy"
        "open04", 
        "gettimeofday2"
    }

    for case in unwanted_cases:
        if case in valid_passed_cases:
            del valid_passed_cases[case]

    try:
        with open(output_file_path, 'w', encoding='utf-8') as f_out:
            for case_name in sorted(valid_passed_cases.keys()): # 按字母顺序排序输出
                f_out.write(f"{case_name}\n")
    except Exception as e:
        print(f"写入输出文件时发生错误: {e}")
        return

    print(f"\n--- 结果统计 ---")
    print(f"已将通过的测试用例名称写入 '{output_file_path}':")
    if valid_passed_cases:
        for case_name, count in sorted(valid_passed_cases.items()):
            print(f"- **{case_name}**: 通过 **{count}** 次")
        print(f"\n**总计通过的测试用例数量: {len(valid_passed_cases)} 个**")
        print(f"**总计通过次数: {totol_count} 次**")
    else:
        print("未找到任何通过的测试用例。")
    print(f"--- 统计结束 ---")

# --- 脚本执行入口 ---
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python your_script_name.py <输入日志文件路径> [输出文件路径]")
        print("  例如: python process_ltp.py ltp_results.log")
        print("  或者: python process_ltp.py ltp_results.log my_passed_tests.txt")
        sys.exit(1) # 退出程序，表示参数不足

    input_log_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "passed_ltp_cases.txt"

    process_ltp_log_flexible(input_log_file, output_file)