import os
import subprocess

# 直接设置需要遍历的子文件夹全局参数
subfolders = ['AppFrameThoughts', 'BlogSrc', 'CppLearn', 'CSFundations', 'GoLearn', 'JavaLearn', 'LinuxLearn', 'PythonLearn', 'Readings', 'RustLearn', 'ZImages']

# 处理本地有修改的情况
def handle_local_changes(remote_branch='HEAD:master'):
    # 使用 git add 添加更改
    subprocess.run(['git', 'add', '.'])
    # 展示 git status
    status_result = subprocess.run(['git', 'status'], capture_output=True, text=True)
    print(status_result.stdout)
    # 让用户输入 commit message
    commit_message = input('请输入 commit message: ')
    # 执行 git commit
    subprocess.run(['git', 'commit', '-m', commit_message])
    
    # 获取所有remote配置
    remotes_result = subprocess.run(['git', 'remote'], capture_output=True, text=True)
    remotes = [remote.strip() for remote in remotes_result.stdout.split('\n') if remote.strip()]
    
    # 对每个remote执行push操作
    for remote in remotes:
        print(f'推送到 remote: {remote}')
        subprocess.run(['git', 'push', remote, remote_branch])

# 处理本地无修改但commit更多的情况
def handle_local_commits(remote_branch='HEAD:master'):
    # 检查是否有本地提交未推送到远程
    # 获取所有remote配置
    remotes_result = subprocess.run(['git', 'remote'], capture_output=True, text=True)
    remotes = [remote.strip() for remote in remotes_result.stdout.split('\n') if remote.strip()]
    
    # 对每个remote检查是否需要推送
    for remote in remotes:
        # 检查远程是否存在master分支
        remote_master_ref = f'refs/remotes/{remote}/master'
        check_remote = subprocess.run(['git', 'show-ref', '--verify', '--quiet', remote_master_ref], capture_output=True)
        
        if check_remote.returncode == 0:
            # 比较本地与远程的提交
            rev_list = subprocess.run(['git', 'rev-list', '--count', f'{remote_master_ref}..HEAD'], capture_output=True, text=True)
            ahead_count = int(rev_list.stdout.strip())
            
            if ahead_count > 0:
                print(f'本地比 remote {remote}/master 领先 {ahead_count} 个提交，执行推送...')
                subprocess.run(['git', 'push', remote, remote_branch])
        else:
            # 远程不存在master分支，执行推送以创建
            print(f'Remote {remote} 不存在 master 分支，执行推送以创建...')
            subprocess.run(['git', 'push', remote, remote_branch])

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
        handle_local_changes(remote_branch)
    else:
        handle_local_commits(remote_branch)
    os.chdir(original_dir)

# 遍历指定子文件夹
for subfolder in subfolders:
    process_subfolder(subfolder)
process_subfolder('')