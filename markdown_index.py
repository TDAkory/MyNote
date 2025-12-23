import os
import sys

# 配置字典：为MyNote下的每个子目录指定生成深度
# 键：目录名，值：生成深度
# 如果没有配置，则使用默认深度
depth_config = {
    'AppFrameThoughts': 2,  # AppFrameThoughts目录生成2级深度
    'BlogSrc': 2,            # BlogSrc目录生成2级深度
    'CppLearn': 2,           # CppLearn目录生成2级深度
    'CSFundations': 3,       # CSFundations目录生成3级深度
    'GoLearn': 2,            # GoLearn目录生成2级深度
    'JavaLearn': 2,          # JavaLearn目录生成2级深度
    'LinuxLearn': 2,         # LinuxLearn目录生成2级深度
    'PythonLearn': 2,        # PythonLearn目录生成2级深度
    'Readings': 2,           # Readings目录生成2级深度
    'RustLearn': 2,          # RustLearn目录生成2级深度
    'ZImages': 1,            # ZImages目录生成1级深度
}

# 默认生成深度
default_depth = 1


def generate_markdown_tree(root_dir, max_depth=None):
    markdown = []

    # 检查当前目录是否有上级目录
    parent_dir = os.path.dirname(root_dir)
    if parent_dir and parent_dir != root_dir:
        # 获取父目录名
        parent_basename = os.path.basename(parent_dir)
        # 生成父目录的INDEX.md文件名（忽略下划线）
        parent_index_filename = parent_basename.replace('_', '') + 'INDEX.md'
        # 计算父目录INDEX.md的相对路径
        parent_index_path = os.path.relpath(os.path.join(parent_dir, parent_index_filename), root_dir)
        # 在列表开头添加指向父目录的链接
        markdown.append(f"* [../ ({parent_basename})]({parent_index_path})")

    def add_file_or_dir(path, level=0):
        # 忽略 .DS_Store、.git、.gitignore 和所有包含SUMMARY或INDEX的文件
        basename = os.path.basename(path)
        if basename in ['.DS_Store', '.git', '.gitignore'] or 'SUMMARY' in basename or 'INDEX' in basename:
            return

        indent = "  " * level
        if os.path.isfile(path):
            file_name = os.path.basename(path)
            relative_path = os.path.relpath(path, root_dir)
            markdown.append(f"{indent}* [{file_name}]({relative_path})")
        elif os.path.isdir(path):
            dir_name = os.path.basename(path)
            relative_path = os.path.relpath(path, root_dir)
            # 生成目标INDEX.md的文件名（忽略下划线）
            index_filename = dir_name.replace('_', '') + 'INDEX.md'
            # 检查是否存在INDEX.md文件
            if os.path.exists(os.path.join(path, index_filename)):
                markdown.append(f"{indent}* [{dir_name}]({relative_path}/{index_filename})")
            elif os.path.exists(os.path.join(path, 'README.md')):
                markdown.append(f"{indent}* [{dir_name}]({relative_path}/README.md)")
            else:
                markdown.append(f"{indent}* [{dir_name}]")
            
            # 如果设置了最大深度且当前层级已经达到或超过，就不再递归
            if max_depth is not None and level >= max_depth:
                return
                
            for item in sorted(os.listdir(path)):
                item_path = os.path.join(path, item)
                if os.path.isdir(item_path) and item.startswith('.'):  # 新增过滤条件
                    continue
                add_file_or_dir(item_path, level + 1)

    # 只处理当前目录下的内容，不包括目录本身
    for item in sorted(os.listdir(root_dir)):
        item_path = os.path.join(root_dir, item)
        if os.path.isdir(item_path) and item.startswith('.'):
            continue
        add_file_or_dir(item_path, 0)
    
    return "\n".join(markdown)


def traverse_directories(root_dir):
    """遍历所有目录并为每个目录生成仅包含下一级内容的INDEX文件"""
    # 遍历所有目录
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # 忽略 .git 目录
        if '.git' in dirpath:
            continue
            
        # 忽略以 . 开头的隐藏目录
        if os.path.basename(dirpath).startswith('.'):
            continue
            
        # 确定生成深度
        current_depth = default_depth
        
        # 检查当前目录是否是MyNote的直接子目录
        parent_dir = os.path.basename(os.path.dirname(dirpath))
        current_dir = os.path.basename(dirpath)
        
        # 如果父目录是MyNote，检查是否有深度配置
        if parent_dir == 'MyNote':
            current_depth = depth_config.get(current_dir, default_depth)
        # 如果当前目录是MyNote本身
        elif dirpath.endswith('MyNote') or dirpath.endswith('MyNote/'):
            current_depth = default_depth
        
        # 生成当前目录的Markdown树
        markdown_tree = generate_markdown_tree(dirpath, max_depth=current_depth)
        
        # 生成输出文件名：当前目录名（忽略下划线） + INDEX.md
        dir_name = os.path.basename(dirpath)
        output_filename = dir_name.replace('_', '') + 'INDEX.md'
        output_file = os.path.join(dirpath, output_filename)
        
        # 写入文件
        with open(output_file, 'w') as f:
            f.write("# Table of contents\n\n")
            f.write(markdown_tree)
            
        print(f"已生成: {output_file}")


def delete_index_files(root_dir):
    """遍历所有目录并删除所有INDEX.md文件"""
    deleted_count = 0
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # 忽略 .git 目录
        if '.git' in dirpath:
            continue
            
        for filename in filenames:
            if filename.endswith('INDEX.md'):
                file_path = os.path.join(dirpath, filename)
                try:
                    os.remove(file_path)
                    print(f"已删除: {file_path}")
                    deleted_count += 1
                except Exception as e:
                    print(f"删除失败: {file_path} - {e}")
    
    print(f"\n清理完成！共删除 {deleted_count} 个INDEX.md文件")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("用法:")
        print("  生成INDEX.md文件: python gen_markdown_index.py gen <根文件夹路径>")
        print("  清理INDEX.md文件: python gen_markdown_index.py clean <根文件夹路径>")
        sys.exit(1)

    command = sys.argv[1]
    root_directory = sys.argv[2]

    if command == "gen":
        traverse_directories(root_directory)
        print("\n所有INDEX.md文件已生成完成！")
    elif command == "clean":
        delete_index_files(root_directory)
    else:
        print("无效命令。可用命令: gen, clean")
        sys.exit(1)
