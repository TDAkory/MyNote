import argparse
import os
import re
import sys


DEFAULT_DEPTH = 0
IGNORED_DIR_NAMES = {
    '.git',
    '.obsidian',
    '.venv',
    '__pycache__',
    'docs',
}
GENERIC_INDEX_NAMES = {
    'Basics',
    'basics',
    'Packages',
    'Topics',
    'Framework',
    'Model',
    'test',
    'debug',
    'cache',
    'network',
    'Z-Books',
    'README',
}
INDEX_NAME_OVERRIDES = {
    'AppFrameThoughts/00_Foundations': 'FoundationsINDEX.md',
    'AppFrameThoughts/01_Computer': 'ComputerINDEX.md',
    'AppFrameThoughts/02_CompressionEncoding': 'CompressionEncodingINDEX.md',
    'AppFrameThoughts/03_Communication': 'CommunicationINDEX.md',
    'AppFrameThoughts/04_DistributedSystem': 'DistributedSystemINDEX.md',
    'AppFrameThoughts/05_Storage': 'StorageINDEX.md',
    'AppFrameThoughts/06_DataSystem': 'DataSystemINDEX.md',
    'AppFrameThoughts/07_CloudNative': 'CloudNativeINDEX.md',
    'AppFrameThoughts/08_Observability': 'ObservabilityINDEX.md',
    'AppFrameThoughts/09_AI': 'AIINDEX.md',
    'AppFrameThoughts/10_Engineering': 'EngineeringINDEX.md',
    'CppLearn/Topics': 'CppTopicsINDEX.md',
    'CppLearn/Framework': 'CppFrameworkINDEX.md',
    'GoLearn/Basics': 'GoBasicsINDEX.md',
    'RustLearn/Basics': 'RustBasicsINDEX.md',
    'JavaLearn/basics': 'JavaBasicsINDEX.md',
    'LinuxLearn/basics': 'LinuxBasicsINDEX.md',
    'GoLearn/Packages': 'GoPackagesINDEX.md',
    'PythonLearn/Packages': 'PythonPackagesINDEX.md',
    'CppLearn/Z-Books': 'CppZBooksINDEX.md',
    'LinuxLearn/Z-Books': 'LinuxZBooksINDEX.md',
    'LinuxLearn/basics/network': 'LinuxBasicsNetworkINDEX.md',
    'LinuxLearn/source_code/network': 'LinuxSourceNetworkINDEX.md',
    'CSFundations/algorithem/cache': 'AlgoCacheINDEX.md',
    'CSFundations/big_fundament/OS/cache': 'OSCacheINDEX.md',
    'ZImages/img/AppFrameThoughts/AI': 'ZImgAIINDEX.md',
    'ZImages/img/AppFrameThoughts/09_AI': 'ZImg09AIINDEX.md',
    'ZImages/img/AppFrameThoughts': 'ZImgAppFrameThoughtsINDEX.md',
    'ZImages/img/CSFundations': 'ZImgCSFundationsINDEX.md',
    'ZImages/img/CppLearn': 'ZImgCppLearnINDEX.md',
    'ZImages/img/GoLearn': 'ZImgGoLearnINDEX.md',
    'ZImages/img/AppFrameThoughts/09_AI/RecommenderSystem': 'ZImgRecommenderSystemINDEX.md',
    'ZImages/img/AppFrameThoughts/VectorSearch': 'ZImgVectorSearchINDEX.md',
}


def index_filename_for_dir(path, base_dir=None):
    existing = existing_index_filename(path)
    if existing:
        return existing
    return desired_index_filename_for_dir(path, base_dir)


def desired_index_filename_for_dir(path, base_dir=None):
    base = os.path.abspath(base_dir) if base_dir else os.path.abspath(os.getcwd())
    rel_path = os.path.relpath(os.path.abspath(path), base)
    rel_path = rel_path.replace(os.sep, '/')
    if rel_path in INDEX_NAME_OVERRIDES:
        return INDEX_NAME_OVERRIDES[rel_path]

    dir_name = os.path.basename(path)
    clean_name = clean_index_name_part(dir_name)
    if dir_name in GENERIC_INDEX_NAMES:
        parent_name = clean_index_name_part(os.path.basename(os.path.dirname(path)))
        if parent_name:
            clean_name = parent_name + clean_name
    return clean_name + 'INDEX.md'


def clean_index_name_part(name):
    name = re.sub(r'^\d+[_-]*', '', name)
    parts = re.split(r'[_\s-]+', name)
    return ''.join(part[:1].upper() + part[1:] for part in parts if part)


def existing_index_filename(path):
    if not os.path.isdir(path):
        return None
    matches = sorted(
        item for item in os.listdir(path)
        if item.endswith('INDEX.md') and os.path.isfile(os.path.join(path, item))
    )
    if not matches:
        return None
    return matches[0]


def should_ignore(path):
    basename = os.path.basename(path)
    if basename in ['.DS_Store']:
        return True
    if basename.startswith('.'):
        return True
    if os.path.isdir(path) and basename in IGNORED_DIR_NAMES:
        return True
    return 'SUMMARY' in basename or 'INDEX' in basename


def generate_markdown_tree(root_dir, max_depth=DEFAULT_DEPTH):
    markdown = []

    # 检查当前目录是否有上级目录
    parent_dir = os.path.dirname(root_dir)
    is_mynote_root = os.path.basename(os.path.abspath(root_dir)) == 'MyNote'
    if parent_dir and parent_dir != root_dir and not is_mynote_root:
        # 获取父目录名
        parent_basename = os.path.basename(parent_dir)
        parent_index_filename = index_filename_for_dir(parent_dir)
        # 计算父目录INDEX.md的相对路径
        parent_index_path = os.path.relpath(os.path.join(parent_dir, parent_index_filename), root_dir)
        # 在列表开头添加指向父目录的链接
        markdown.append(f"* [../ ({parent_basename})]({parent_index_path})")

    def add_file_or_dir(path, level=0):
        if should_ignore(path):
            return

        indent = "  " * level
        if os.path.isfile(path):
            file_name = os.path.basename(path)
            relative_path = os.path.relpath(path, root_dir)
            markdown.append(f"{indent}* [{file_name}]({relative_path})")
        elif os.path.isdir(path):
            dir_name = os.path.basename(path)
            relative_path = os.path.relpath(path, root_dir)
            index_filename = index_filename_for_dir(path, root_dir)
            if os.path.exists(os.path.join(path, index_filename)):
                markdown.append(f"{indent}* [{dir_name}]({relative_path}/{index_filename})")
            elif os.path.exists(os.path.join(path, 'README.md')):
                markdown.append(f"{indent}* [{dir_name}]({relative_path}/README.md)")
            else:
                markdown.append(f"{indent}* [{dir_name}]")
            
            if max_depth is not None and level >= max_depth:
                return
                
            for item in sorted(os.listdir(path)):
                item_path = os.path.join(path, item)
                if os.path.isdir(item_path) and item.startswith('.'):
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
    for dirpath, dirnames, filenames in os.walk(root_dir):
        if '.git' in dirpath:
            continue
            
        if os.path.basename(dirpath).startswith('.'):
            dirnames[:] = []
            continue

        dirnames[:] = [
            name for name in dirnames
            if not should_ignore(os.path.join(dirpath, name))
        ]

        if should_ignore(dirpath):
            dirnames[:] = []
            continue

        markdown_tree = generate_markdown_tree(dirpath, max_depth=DEFAULT_DEPTH)
        output_filename = index_filename_for_dir(dirpath, root_dir)
        output_file = os.path.join(dirpath, output_filename)
        
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


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Generate or clean MyNote INDEX.md files. Default generation follows INDEX_POLICY.md: one-level navigation only."
    )
    parser.add_argument("command", choices=["gen", "clean"])
    parser.add_argument("root_directory")
    args = parser.parse_args(argv)

    if args.command == "gen":
        traverse_directories(args.root_directory)
        print("\n所有INDEX.md文件已生成完成！")
        return 0
    elif args.command == "clean":
        delete_index_files(args.root_directory)
        return 0
    else:
        print("无效命令。可用命令: gen, clean")
        return 1


if __name__ == "__main__":
    sys.exit(main())
