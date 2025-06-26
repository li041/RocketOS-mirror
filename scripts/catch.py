import re
import sys

def extract_zero_status_cases(input_file, output_file):
    zero_status_cases = []
    current_summary = None
    
    with open(input_file, 'r') as f:
        lines = f.readlines()
    
    for line in lines:
        line = line.strip()
        
        # 检查是否进入 Summary 部分
        if line.startswith("Summary:"):
            current_summary = line
            continue
        
        # 检查是否匹配 FAIL LTP CASE <测例名> : 0
        fail_match = re.search(r'FAIL LTP CASE (\w+) : 0', line)
        if fail_match and current_summary:
            zero_status_cases.append(fail_match.group(1))
            current_summary = None  # 避免重复匹配
    
    # 写入输出文件
    with open(output_file, 'w') as f:
        for case in zero_status_cases:
            f.write(case + "\n")
    
    return zero_status_cases

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python extract_zero_status_cases.py <input_file> <output_file>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    zero_cases = extract_zero_status_cases(input_file, output_file)
    print(f"Found {len(zero_cases)} test cases with status 0.")
    print(f"Results written to {output_file}")