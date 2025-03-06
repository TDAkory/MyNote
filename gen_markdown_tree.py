import os
import sys


def generate_markdown_tree(root_dir):
    markdown = []

    def add_file_or_dir(path, level=0):
        # 忽略 .DS_Store、.git 和 .gitignore
        if os.path.basename(path) in ['.DS_Store', '.git', '.gitignore']:
            return

        indent = "  " * level
        if os.path.isfile(path):
            file_name = os.path.basename(path)
            relative_path = os.path.relpath(path, root_dir)
            markdown.append(f"{indent}* [{file_name}]({relative_path})")
        elif os.path.isdir(path):
            dir_name = os.path.basename(path)
            relative_path = os.path.relpath(path, root_dir)
            if os.path.exists(os.path.join(path, 'README.md')):
                markdown.append(f"{indent}* [{dir_name}]({relative_path}/README.md)")
            else:
                markdown.append(f"{indent}* [{dir_name}]")
            for item in sorted(os.listdir(path)):
                item_path = os.path.join(path, item)
                add_file_or_dir(item_path, level + 1)

    add_file_or_dir(root_dir)
    return "\n".join(markdown)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("用法: python script.py <文件夹路径> <输出目标文件>")
        sys.exit(1)

    root_directory = sys.argv[1]
    output_file = sys.argv[2]

    markdown_tree = generate_markdown_tree(root_directory)

    # 输出到文件
    with open(output_file, 'w') as f:
        f.write("# Table of contents\n\n")
        f.write(markdown_tree)

    print(f"Markdown 目录树已更新到 {output_file}")