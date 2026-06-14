import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


# 直接设置需要遍历的子文件夹全局参数
subfolders = [
    'AppFrameThoughts',
    'BlogSrc',
    'CppLearn',
    'CSFundations',
    'GoLearn',
    'JavaLearn',
    'LinuxLearn',
    'PythonLearn',
    'Readings',
    'RustLearn',
    'ZImages',
]

TEXT_EXTENSIONS = {
    '.adoc',
    '.c',
    '.cc',
    '.cfg',
    '.conf',
    '.cpp',
    '.css',
    '.csv',
    '.go',
    '.h',
    '.hpp',
    '.html',
    '.ini',
    '.java',
    '.js',
    '.json',
    '.kt',
    '.lua',
    '.m',
    '.md',
    '.mm',
    '.py',
    '.rs',
    '.sh',
    '.sql',
    '.swift',
    '.toml',
    '.ts',
    '.tsx',
    '.txt',
    '.xml',
    '.yaml',
    '.yml',
}

MAX_TEXT_FILE_BYTES = 2 * 1024 * 1024
SCAN_LOG_NAME = 'note_security_scan.log'
SCAN_CONFIG_NAME = 'note_security_scan_config.json'
SECURITY_RULES = []
SECURITY_CONFIG_PATH = None


@dataclass
class SecurityFinding:
    severity: str
    rule: str
    path: str
    line_number: int
    matched_text: str
    message: str


@dataclass
class SecurityRule:
    name: str
    severity: str
    pattern: re.Pattern
    message: str


def default_security_config():
    """Default config only contains generic patterns; private keywords live in .git/info config."""
    return {
        'literal_rules': [],
        'regex_rules': [
            {
                'name': 'credential-assignment',
                'severity': 'HIGH',
                'message': '疑似凭证、密钥或访问令牌赋值，请删除。',
                'patterns': [
                    r'(password|passwd|secret|auth[_-]?token|access[_-]?token|refresh[_-]?token|api[_-]?key|access[_-]?key|credential)\s*[:=]\s*[^\s`\]})>,;]+',
                ],
            },
            {
                'name': 'cloud-access-key',
                'severity': 'HIGH',
                'message': '疑似云服务访问密钥，请删除。',
                'patterns': [r'AKIA[0-9A-Z]{16}'],
            },
            {
                'name': 'private-key-block',
                'severity': 'HIGH',
                'message': '疑似私钥内容，请删除。',
                'patterns': [r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'],
            },
            {
                'name': 'local-absolute-path',
                'severity': 'MEDIUM',
                'message': '疑似本地绝对路径，不应同步到公开仓库；请改成泛化路径。',
                'patterns': [r'(?<![:\w])/(?:Users|home|opt|var|tmp|mnt|data|Volumes)/[^\s`)>,;]+'],
            },
            {
                'name': 'private-ip-address',
                'severity': 'HIGH',
                'message': '疑似私有网段 IP，请删除或泛化。',
                'patterns': [
                    r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3})\b',
                ],
            },
            {
                'name': 'email-address',
                'severity': 'MEDIUM',
                'message': '疑似邮箱地址，请确认是否为公开资料；非公开邮箱应删除。',
                'patterns': [r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'],
            },
        ],
    }


def my_note_root():
    return os.path.dirname(os.path.abspath(__file__))


def root_git_info_dir():
    result = subprocess.run(
        ['git', '-C', my_note_root(), 'rev-parse', '--git-dir'],
        capture_output=True,
        text=True,
        check=True,
    )
    git_dir = result.stdout.strip()
    if not os.path.isabs(git_dir):
        git_dir = os.path.abspath(os.path.join(my_note_root(), git_dir))
    info_dir = os.path.join(git_dir, 'info')
    os.makedirs(info_dir, exist_ok=True)
    return info_dir


def default_security_config_path():
    return os.path.join(root_git_info_dir(), SCAN_CONFIG_NAME)


def ensure_security_config(config_path):
    if os.path.exists(config_path):
        return False
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, 'w', encoding='utf-8') as file:
        json.dump(default_security_config(), file, ensure_ascii=False, indent=2)
        file.write('\n')
    return True


def load_security_rules_from_config(config_path):
    with open(config_path, 'r', encoding='utf-8') as file:
        config = json.load(file)

    rules = []
    for rule in config.get('literal_rules', []):
        keywords = [keyword for keyword in rule.get('keywords', []) if keyword]
        if not keywords:
            continue
        pattern = '|'.join(re.escape(keyword) for keyword in keywords)
        rules.append(
            SecurityRule(
                name=rule['name'],
                severity=rule.get('severity', 'HIGH'),
                pattern=re.compile(pattern, re.IGNORECASE),
                message=rule.get('message', '命中敏感关键词，请删除或泛化。'),
            )
        )

    for rule in config.get('regex_rules', []):
        for pattern_text in rule.get('patterns', []):
            if not pattern_text:
                continue
            rules.append(
                SecurityRule(
                    name=rule['name'],
                    severity=rule.get('severity', 'HIGH'),
                    pattern=re.compile(pattern_text, re.IGNORECASE),
                    message=rule.get('message', '命中敏感模式，请删除或泛化。'),
                )
            )

    if not rules:
        raise ValueError(f'安全扫描配置为空或无有效规则: {config_path}')
    return rules


def configure_security_rules(config_path=None, init_only=False):
    global SECURITY_RULES, SECURITY_CONFIG_PATH

    resolved_path = os.path.abspath(config_path) if config_path else default_security_config_path()
    created = ensure_security_config(resolved_path)
    SECURITY_CONFIG_PATH = resolved_path
    if created:
        print(f'已创建默认安全扫描配置: {resolved_path}')
    else:
        print(f'使用安全扫描配置: {resolved_path}')

    if init_only:
        return created

    SECURITY_RULES = load_security_rules_from_config(resolved_path)
    return created


def run_git(args, capture_output=True, check=False):
    return subprocess.run(['git', *args], capture_output=capture_output, text=True, check=check)


def normalize_git_path(path):
    return path.strip().strip('"')


def is_text_candidate(path):
    path_obj = Path(path)
    if any(part == '.git' for part in path_obj.parts):
        return False
    if path_obj.name == SCAN_LOG_NAME:
        return False
    if path_obj.suffix.lower() in TEXT_EXTENSIONS:
        return True
    return path_obj.suffix == ''


def read_text_file(path):
    try:
        if not os.path.isfile(path):
            return None
        if os.path.getsize(path) > MAX_TEXT_FILE_BYTES:
            return None
        with open(path, 'rb') as file:
            data = file.read()
        if b'\x00' in data:
            return None
        return data.decode('utf-8')
    except (OSError, UnicodeDecodeError):
        return None


def collect_staged_files():
    result = run_git(['diff', '--cached', '--name-only', '--diff-filter=ACMR'])
    return [normalize_git_path(line) for line in result.stdout.splitlines() if line.strip()]


def collect_worktree_changed_files():
    result = run_git(['status', '--porcelain'])
    files = []
    for line in result.stdout.splitlines():
        if not line:
            continue
        status = line[:2]
        raw_path = line[3:]
        if status.strip() == 'D':
            continue
        if ' -> ' in raw_path:
            raw_path = raw_path.split(' -> ', 1)[1]
        files.append(normalize_git_path(raw_path))
    return files


def collect_full_scan_files():
    result = run_git(['ls-files', '--cached', '--others', '--exclude-standard'])
    return [normalize_git_path(line) for line in result.stdout.splitlines() if line.strip()]


def collect_outgoing_files(remote_master_ref):
    result = run_git(['diff', '--name-only', '--diff-filter=ACMR', f'{remote_master_ref}..HEAD'])
    return [normalize_git_path(line) for line in result.stdout.splitlines() if line.strip()]


def unique_existing_text_files(paths):
    seen = set()
    selected = []
    for path in paths:
        if not path or path in seen:
            continue
        seen.add(path)
        if is_text_candidate(path) and os.path.isfile(path):
            selected.append(path)
    return selected


def scan_file(path):
    text = read_text_file(path)
    if text is None:
        return []

    findings = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule in SECURITY_RULES:
            for match in rule.pattern.finditer(line):
                matched_text = match.group(0).strip()
                if len(matched_text) > 120:
                    matched_text = matched_text[:117] + '...'
                findings.append(
                    SecurityFinding(
                        severity=rule.severity,
                        rule=rule.name,
                        path=path,
                        line_number=line_number,
                        matched_text=matched_text,
                        message=rule.message,
                    )
                )
    return findings


def get_scan_log_path():
    result = run_git(['rev-parse', '--git-dir'])
    git_dir = result.stdout.strip()
    if not os.path.isabs(git_dir):
        git_dir = os.path.abspath(git_dir)
    info_dir = os.path.join(git_dir, 'info')
    os.makedirs(info_dir, exist_ok=True)
    return os.path.join(info_dir, SCAN_LOG_NAME)


def write_scan_log(mode, scanned_files, findings, result_label):
    log_path = get_scan_log_path()
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    lines = [
        '=' * 80,
        f'time: {timestamp}',
        f'repository: {os.getcwd()}',
        f'config: {SECURITY_CONFIG_PATH or "not configured"}',
        f'mode: {mode}',
        f'scanned_files: {len(scanned_files)}',
        f'findings: {len(findings)}',
        f'result: {result_label}',
    ]
    for finding in findings:
        lines.extend(
            [
                '',
                f'[{finding.severity}] {finding.rule}',
                f'file: {finding.path}',
                f'line: {finding.line_number}',
                f'match: {finding.matched_text}',
                f'message: {finding.message}',
            ]
        )
    lines.append('')
    with open(log_path, 'a', encoding='utf-8') as file:
        file.write('\n'.join(lines))
    return log_path


def print_findings(mode, findings, log_path):
    print('\n安全扫描失败，已暂停同步。')
    print(f'当前目录: {os.getcwd()}')
    print(f'扫描模式: {mode}')
    print(f'日志文件: {log_path}')
    for finding in findings:
        print('')
        print(f'[{finding.severity}] {finding.rule}')
        print(f'文件: {finding.path}:{finding.line_number}')
        print(f'命中: {finding.matched_text}')
        print(f'说明: {finding.message}')
    print('\n请删除或泛化上述内容后重新运行同步脚本。')


def run_security_scan(mode, files):
    scanned_files = unique_existing_text_files(files)
    findings = []
    for path in scanned_files:
        findings.extend(scan_file(path))

    result_label = 'BLOCKED' if findings else 'PASS'
    log_path = write_scan_log(mode, scanned_files, findings, result_label)

    if findings:
        print_findings(mode, findings, log_path)
        return False

    print(f'安全扫描通过：mode={mode}, scanned_files={len(scanned_files)}, log={log_path}')
    return True


def get_remotes():
    remotes_result = run_git(['remote'])
    return [remote.strip() for remote in remotes_result.stdout.split('\n') if remote.strip()]


def remote_master_ref(remote):
    return f'refs/remotes/{remote}/master'


def has_remote_master(remote):
    check_remote = subprocess.run(
        ['git', 'show-ref', '--verify', '--quiet', remote_master_ref(remote)],
        capture_output=True,
        text=True,
    )
    return check_remote.returncode == 0


def outgoing_files_for_all_remotes():
    files = []
    for remote in get_remotes():
        ref = remote_master_ref(remote)
        if has_remote_master(remote):
            files.extend(collect_outgoing_files(ref))
    return files


# 处理本地有修改的情况
def handle_local_changes(remote_branch='HEAD:master', scan_only=False):
    if scan_only:
        files_to_scan = collect_worktree_changed_files() + outgoing_files_for_all_remotes()
        return run_security_scan('incremental-scan-only', files_to_scan)

    # 使用 git add 添加更改，随后扫描 staged 内容。
    subprocess.run(['git', 'add', '.'])
    staged_files = collect_staged_files()
    if not run_security_scan('incremental-staged', staged_files):
        return False

    # 展示 git status
    status_result = subprocess.run(['git', 'status'], capture_output=True, text=True)
    print(status_result.stdout)
    # 让用户输入 commit message
    commit_message = input('请输入 commit message: ')
    # 执行 git commit
    subprocess.run(['git', 'commit', '-m', commit_message], check=True)

    # 对每个remote执行push操作
    for remote in get_remotes():
        print(f'推送到 remote: {remote}')
        subprocess.run(['git', 'push', remote, remote_branch], check=True)
    return True


# 处理本地无修改但commit更多的情况
def handle_local_commits(remote_branch='HEAD:master', scan_only=False):
    ok = True
    remotes = get_remotes()

    if scan_only:
        files_to_scan = outgoing_files_for_all_remotes()
        return run_security_scan('incremental-scan-only', files_to_scan)

    # 对每个remote检查是否需要推送
    for remote in remotes:
        # 检查远程是否存在master分支
        ref = remote_master_ref(remote)

        if has_remote_master(remote):
            # 比较本地与远程的提交
            rev_list = run_git(['rev-list', '--count', f'{ref}..HEAD'])
            ahead_count = int(rev_list.stdout.strip())

            if ahead_count > 0:
                files_to_scan = collect_outgoing_files(ref)
                if not run_security_scan(f'incremental-outgoing:{remote}', files_to_scan):
                    ok = False
                    continue
                print(f'本地比 remote {remote}/master 领先 {ahead_count} 个提交，执行推送...')
                subprocess.run(['git', 'push', remote, remote_branch], check=True)
        else:
            files_to_scan = collect_full_scan_files()
            if not run_security_scan(f'incremental-new-remote:{remote}', files_to_scan):
                ok = False
                continue
            # 远程不存在master分支，执行推送以创建
            print(f'Remote {remote} 不存在 master 分支，执行推送以创建...')
            subprocess.run(['git', 'push', remote, remote_branch], check=True)
    return ok


def run_full_scan():
    files_to_scan = collect_full_scan_files()
    return run_security_scan('full', files_to_scan)


# 定义处理子文件夹的函数
def process_subfolder(subfolder, remote_branch='HEAD:master', full_scan=False, scan_only=False):
    my_note_path = os.path.dirname(os.path.abspath(__file__))
    my_note_sub_path = os.path.join(my_note_path, subfolder)
    if not os.path.isdir(my_note_sub_path):
        print(f'跳过不存在的目录: {my_note_sub_path}')
        return True

    original_dir = os.getcwd()
    os.chdir(my_note_sub_path)
    try:
        print(f'当前目录: {os.getcwd()}')

        if full_scan:
            return run_full_scan()

        # 检查是否存在 diff
        result = subprocess.run(['git', 'diff', '--quiet'], capture_output=True, text=True)
        # 检查是否存在未跟踪文件或工作区修改
        status_result = run_git(['status', '--porcelain'])
        changed_files = [line for line in status_result.stdout.split('\n') if line.strip()]
        if result.returncode != 0 or changed_files:
            return handle_local_changes(remote_branch, scan_only=scan_only)
        return handle_local_commits(remote_branch, scan_only=scan_only)
    finally:
        os.chdir(original_dir)


def parse_args():
    parser = argparse.ArgumentParser(description='同步笔记到 GitHub 前执行安全扫描。')
    parser.add_argument(
        '--init-security-config',
        action='store_true',
        help='初始化默认安全扫描配置到 .git/info，不执行扫描、提交或推送。',
    )
    parser.add_argument(
        '--security-config',
        help='指定安全扫描配置文件路径；默认使用 MyNote 根仓库 .git/info/note_security_scan_config.json。',
    )
    parser.add_argument(
        '--full-scan',
        action='store_true',
        help='全量扫描所有文本文件，只扫描不提交、不推送。',
    )
    parser.add_argument(
        '--scan-only',
        action='store_true',
        help='只进行增量扫描，不提交、不推送。',
    )
    parser.add_argument(
        '--subfolder',
        action='append',
        help='只处理指定子目录；可重复传入。传空字符串可表示 MyNote 根目录。',
    )
    parser.add_argument(
        '--remote-branch',
        default='HEAD:master',
        help='推送目标分支，默认 HEAD:master。',
    )
    return parser.parse_args()


def selected_subfolders(args):
    if args.subfolder is not None:
        return args.subfolder
    return [*subfolders, '']


def main():
    args = parse_args()
    if args.full_scan and args.scan_only:
        print('--full-scan 本身就是只扫描模式，不需要同时传 --scan-only。', file=sys.stderr)
        return 2

    try:
        configure_security_rules(args.security_config, init_only=args.init_security_config)
    except (OSError, json.JSONDecodeError, re.error, KeyError, ValueError) as error:
        print(f'安全扫描配置加载失败: {error}', file=sys.stderr)
        return 2

    if args.init_security_config:
        print('安全扫描配置初始化完成：未执行扫描、git add / commit / push。')
        return 0

    all_ok = True
    for subfolder in selected_subfolders(args):
        ok = process_subfolder(
            subfolder,
            remote_branch=args.remote_branch,
            full_scan=args.full_scan,
            scan_only=args.scan_only,
        )
        all_ok = all_ok and ok

    if args.full_scan:
        print('全量扫描完成：未执行 git add / commit / push。')
    elif args.scan_only:
        print('增量扫描完成：未执行 git add / commit / push。')
    return 0 if all_ok else 1


if __name__ == '__main__':
    sys.exit(main())
