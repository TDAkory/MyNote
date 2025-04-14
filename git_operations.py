import os
import subprocess

# 直接设置需要遍历的子文件夹全局参数
subfolders = ['AppFrameThoughts', 'BlogSrc', 'CppLearn', 'CSFundations', 'GoLearn', 'LinuxLearn', 'PythonLearn', 'Readings', 'RustLearn', 'ZImages']

# 定义处理子文件夹的函数
def process_subfolder(subfolder, remote_branch='HEAD:master'):
    my_note_path = os.path.dirname(os.path.abspath(__file__))
    my_note_sub_path = os.path.join(my_note_path, subfolder)
    original_dir = os.getcwd()
    os.chdir(my_note_sub_path)
    print(f'当前目录: {os.getcwd()}')
    # 检查是否存在 diff
    result = subprocess.run(['git', 'diff', '--quiet'], capture_output=True)
    # 检查是否存在未跟踪文件
    status_result = subprocess.run(['git', 'status', '--porcelain'], capture_output=True, text=True)
    untracked_files = [line for line in status_result.stdout.split('\n') if line.startswith('?? ') or line.startswith('M ')]
    if result.returncode != 0 or untracked_files:
        # 使用 git add 添加更改
        subprocess.run(['git', 'add', '.'])
        # 展示 git status
        status_result = subprocess.run(['git', 'status'], capture_output=True, text=True)
        print(status_result.stdout)
        # 让用户输入 commit message
        commit_message = input('请输入 commit message: ')
        # 执行 git commit
        subprocess.run(['git', 'commit', '-m', commit_message])
        # 推送到 HEAD:master
        subprocess.run(['git', 'push', 'origin', remote_branch])
    os.chdir(original_dir)

# 遍历指定子文件夹
for subfolder in subfolders:
    process_subfolder(subfolder)
process_subfolder('', 'main')