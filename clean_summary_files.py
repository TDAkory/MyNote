import os
import sys

def delete_summary_files(root_dir):
    deleted_count = 0
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # 忽略 .git 目录
        if '.git' in dirpath:
            continue
            
        for filename in filenames:
            if filename.endswith('SUMMARY.md'):
                file_path = os.path.join(dirpath, filename)
                try:
                    os.remove(file_path)
                    print(f"已删除: {file_path}")
                    deleted_count += 1
                except Exception as e:
                    print(f"删除失败: {file_path} - {e}")
    
    print(f"\n清理完成！共删除 {deleted_count} 个SUMMARY.md文件")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("用法: python clean_summary_files.py <根文件夹路径>")
        sys.exit(1)

    root_directory = sys.argv[1]
    delete_summary_files(root_directory)
