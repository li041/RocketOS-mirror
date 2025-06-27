import os

def cleanup_files(input_file, target_dir, ch):
    # 读取输入文件中的保留文件名列表
    with open(input_file, 'r', encoding='utf-8') as f:
        keep_files = set(line.strip() for line in f if line.strip())

    # 遍历目标目录下的所有文件
    for filename in os.listdir(target_dir):
        full_path = os.path.join(target_dir, filename)
        
        # 只处理文件，忽略目录
        if not os.path.isfile(full_path):
            continue
        
        # 判断是否需要删除
        first_char = filename[0].lower()
        if first_char <= ch.lower() and filename not in keep_files:
            print(f"Deleting: {filename}")
            os.remove(full_path)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Cleanup files in directory")
    parser.add_argument("input_file", help="Input file with filenames to keep (one per line)")
    parser.add_argument("target_dir", help="Target directory to cleanup")
    parser.add_argument("ch", help="Character to compare first letter of filenames")

    args = parser.parse_args()

    cleanup_files(args.input_file, args.target_dir, args.ch)
