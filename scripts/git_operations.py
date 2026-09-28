import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
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
SCAN_LOG_RELATIVE_DIR = ('.mynote', 'logs', 'security-scan')
SCAN_LOG_RETENTION = 20
SCAN_CONFIG_NAME = 'note_security_scan_config.json'
VERSIONED_SCAN_CONFIG_NAME = 'note_security_scan_config.json'
IGNORED_TEXT_CANDIDATE_NAMES = {SCAN_LOG_NAME, '.DS_Store'}
SECURITY_RULES = []
SECURITY_ALLOWLIST = []
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


@dataclass
class AllowlistEntry:
    """已知安全的例外：命中安全规则但符合此处描述的内容将被放过。"""

    name: str
    match_pattern: re.Pattern
    rules: set  # 为空表示对所有规则生效
    path_pattern: re.Pattern  # 为 None 表示对所有文件生效

    def allows(self, finding):
        if self.rules and finding.rule not in self.rules:
            return False
        if self.path_pattern is not None and not self.path_pattern.search(finding.path):
            return False
        return self.match_pattern.search(finding.matched_text) is not None


class SecurityScanError(RuntimeError):
    pass


def shutil_which(command):
    return shutil.which(command)


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
                'name': 'bearer-token',
                'severity': 'HIGH',
                'message': '疑似 Bearer/JWT 访问令牌，请删除。',
                'patterns': [
                    r'\bBearer\s+[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_.+/=-]+',
                ],
            },
            {
                'name': 'github-token',
                'severity': 'HIGH',
                'message': '疑似 GitHub 访问令牌，请删除。',
                'patterns': [r'\bgh[pousr]_[A-Za-z0-9_]{20,}\b'],
            },
            {
                'name': 'cloud-access-key',
                'severity': 'HIGH',
                'message': '疑似云服务访问密钥，请删除。',
                'patterns': [r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'],
            },
            {
                'name': 'private-key-block',
                'severity': 'HIGH',
                'message': '疑似私钥内容，请删除。',
                'patterns': [r'-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----'],
            },
            {
                'name': 'local-absolute-path',
                'severity': 'MEDIUM',
                'message': '疑似本地绝对路径，不应同步到公开仓库；请改成泛化路径。',
                'patterns': [r'(?<![:\w])/(?:Users|home|opt|var|data|Volumes)/[^\s`)>,;]+'],
            },
            {
                'name': 'private-ip-address',
                'severity': 'HIGH',
                'message': '疑似私有网段 IP，请删除或泛化。',
                'patterns': [
                    r'\b(?:10\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)|172\.(?:1[6-9]|2\d|3[0-1])\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)|192\.168\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d))\b',
                ],
            },
            {
                'name': 'email-address',
                'severity': 'MEDIUM',
                'message': '疑似邮箱地址，请确认是否为公开资料；非公开邮箱应删除。',
                'patterns': [r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'],
            },
        ],
        'allowlist': [
            {
                'name': 'gitmodules-ssh-url',
                'message': '.gitmodules 中的 SSH 远程 URL（git@host）是合法配置，非邮箱泄露。',
                'rules': ['email-address'],
                'path_pattern': r'(^|/)\.gitmodules$',
                'match_pattern': r'^git@[A-Za-z0-9.-]+(?::|$)',
            },
            {
                'name': 'documented-placeholder-secret',
                'message': '文档中的空值、示例值或环境变量占位符不是实际凭证。',
                'rules': ['credential-assignment'],
                'match_pattern': r'(?i)(password|passwd|secret|auth[_-]?token|access[_-]?token|refresh[_-]?token|api[_-]?key|access[_-]?key|credential)\s*[:=]\s*(""|\'\'|changeme|example|<[^>]+>|\$\{[A-Z0-9_]+\}?)',
            },
        ],
    }


def my_note_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


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


def versioned_security_config_path():
    return os.path.join(my_note_root(), 'scripts', VERSIONED_SCAN_CONFIG_NAME)


def base_security_config():
    config_path = versioned_security_config_path()
    if os.path.exists(config_path):
        with open(config_path, 'r', encoding='utf-8') as file:
            return json.load(file)
    return default_security_config()


def ensure_security_config(config_path):
    if os.path.exists(config_path):
        return False
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, 'w', encoding='utf-8') as file:
        json.dump(base_security_config(), file, ensure_ascii=False, indent=2)
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


def load_allowlist_from_config(config_path):
    with open(config_path, 'r', encoding='utf-8') as file:
        config = json.load(file)

    entries = []
    for entry in config.get('allowlist', []):
        match_text = entry.get('match_pattern')
        if not match_text:
            continue
        path_text = entry.get('path_pattern')
        entries.append(
            AllowlistEntry(
                name=entry.get('name', 'allowlist'),
                match_pattern=re.compile(match_text, re.IGNORECASE),
                rules=set(entry.get('rules', []) or []),
                path_pattern=re.compile(path_text) if path_text else None,
            )
        )
    return entries


def configure_security_rules(config_path=None, init_only=False):
    global SECURITY_RULES, SECURITY_ALLOWLIST, SECURITY_CONFIG_PATH

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
    SECURITY_ALLOWLIST = load_allowlist_from_config(resolved_path)
    return created


def run_git(args, capture_output=True, check=False):
    result = subprocess.run(['git', *args], capture_output=capture_output, text=True)
    if check and result.returncode != 0:
        stderr = (result.stderr or '').strip()
        raise SecurityScanError(f'git {" ".join(args)} failed: {stderr}')
    return result


def normalize_git_path(path):
    return path.strip().strip('"')


def is_text_candidate(path):
    path_obj = Path(path)
    if any(part == '.git' for part in path_obj.parts):
        return False
    if path_obj.name in IGNORED_TEXT_CANDIDATE_NAMES:
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
    result = run_git(['diff', '--cached', '--name-only', '--diff-filter=ACMR'], check=True)
    return [normalize_git_path(line) for line in result.stdout.splitlines() if line.strip()]


def collect_worktree_changed_files():
    result = run_git(['status', '--porcelain'], check=True)
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
    result = run_git(['ls-files', '--cached', '--others', '--exclude-standard'], check=True)
    return [normalize_git_path(line) for line in result.stdout.splitlines() if line.strip()]


def collect_outgoing_files(remote_master_ref):
    result = run_git(['diff', '--name-only', '--diff-filter=ACMR', f'{remote_master_ref}..HEAD'], check=True)
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


def scan_text(path, text):
    findings = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule in SECURITY_RULES:
            for match in rule.pattern.finditer(line):
                matched_text = match.group(0).strip()
                if len(matched_text) > 120:
                    matched_text = matched_text[:117] + '...'
                finding = SecurityFinding(
                    severity=rule.severity,
                    rule=rule.name,
                    path=path,
                    line_number=line_number,
                    matched_text=matched_text,
                    message=rule.message,
                )
                if is_allowlisted(finding):
                    continue
                findings.append(finding)
    return findings


def scan_file(path):
    text = read_text_file(path)
    if text is None:
        raise SecurityScanError(f'候选文本文件无法读取或超过大小限制: {path}')
    return scan_text(path, text)


def is_allowlisted(finding):
    return any(entry.allows(finding) for entry in SECURITY_ALLOWLIST)


def git_object_text(object_id):
    size_result = run_git(['cat-file', '-s', object_id], check=True)
    size = int(size_result.stdout.strip())
    if size > MAX_TEXT_FILE_BYTES:
        raise SecurityScanError(f'Git blob 超过扫描大小限制: {object_id} ({size} bytes)')

    data_result = subprocess.run(['git', 'cat-file', 'blob', object_id], capture_output=True)
    if data_result.returncode != 0:
        stderr = data_result.stderr.decode('utf-8', errors='replace').strip()
        raise SecurityScanError(f'读取 Git blob 失败: {object_id}: {stderr}')
    data = data_result.stdout
    if b'\x00' in data:
        return None
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError as error:
        raise SecurityScanError(f'Git blob 不是 UTF-8 文本: {object_id}: {error}')


def iter_git_blobs_for_ranges(ranges):
    seen = set()
    for rev_range in ranges:
        result = run_git(['rev-list', '--objects', rev_range], check=True)
        for line in result.stdout.splitlines():
            parts = line.split(' ', 1)
            object_id = parts[0]
            path = normalize_git_path(parts[1]) if len(parts) == 2 else object_id
            if object_id in seen:
                continue
            seen.add(object_id)
            type_result = run_git(['cat-file', '-t', object_id], check=True)
            if type_result.stdout.strip() != 'blob':
                continue
            if not is_text_candidate(path):
                continue
            yield object_id, path


def scan_log_directory():
    return os.path.join(my_note_root(), *SCAN_LOG_RELATIVE_DIR)


def sanitize_log_component(value, fallback):
    sanitized = re.sub(r'[^A-Za-z0-9._-]+', '-', str(value)).strip('._-')
    return sanitized or fallback


def scan_log_target(repository_path=None):
    root = os.path.realpath(my_note_root())
    repository = os.path.realpath(repository_path or os.getcwd())
    try:
        if os.path.commonpath([root, repository]) == root:
            relative = os.path.relpath(repository, root)
        else:
            relative = os.path.basename(repository)
    except ValueError:
        relative = os.path.basename(repository)
    if relative == '.':
        return 'root'
    return sanitize_log_component(relative, 'root')


def prune_scan_logs(log_dir, target, keep=SCAN_LOG_RETENTION):
    filename_pattern = re.compile(
        rf'^{re.escape(target)}_\d{{8}}-\d{{6}}-\d{{3}}_.+\.log$'
    )
    entries = []
    for entry in os.scandir(log_dir):
        if not entry.is_file() or filename_pattern.fullmatch(entry.name) is None:
            continue
        entries.append((entry.stat().st_mtime_ns, entry.name, entry.path))
    entries.sort()
    for _, _, path in entries[:-keep]:
        os.remove(path)


def publish_scan_log(temp_path, log_dir, base_name):
    suffix = 0
    while True:
        suffix_text = '' if suffix == 0 else f'_{suffix}'
        log_path = os.path.join(log_dir, f'{base_name}{suffix_text}.log')
        reservation_path = os.path.join(log_dir, f'.{base_name}{suffix_text}.lock')
        try:
            descriptor = os.open(
                reservation_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
            )
        except FileExistsError:
            suffix += 1
            continue
        os.close(descriptor)
        if os.path.exists(log_path):
            os.remove(reservation_path)
            suffix += 1
            continue
        try:
            os.replace(temp_path, log_path)
        finally:
            try:
                os.remove(reservation_path)
            except OSError as error:
                print(f'警告: 清理安全扫描日志预留文件失败: {error}', file=sys.stderr)
        break

    return log_path


def write_scan_log(mode, scanned_files, findings, result_label, errors=None):
    timestamp = datetime.now()
    display_timestamp = timestamp.strftime('%Y-%m-%d %H:%M:%S')
    filename_timestamp = timestamp.strftime('%Y%m%d-%H%M%S-%f')[:-3]
    target = scan_log_target()
    mode_component = sanitize_log_component(mode, 'scan')
    result_component = sanitize_log_component(result_label, 'UNKNOWN')
    log_dir = scan_log_directory()
    errors = errors or []
    lines = [
        '=' * 80,
        f'time: {display_timestamp}',
        f'repository: {os.getcwd()}',
        f'config: {SECURITY_CONFIG_PATH or "not configured"}',
        f'mode: {mode}',
        f'scanned_files: {len(scanned_files)}',
        f'findings: {len(findings)}',
        f'errors: {len(errors)}',
        f'result: {result_label}',
    ]
    for error in errors:
        lines.extend(['', '[ERROR] scan-error', f'message: {error}'])
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
    content = '\n'.join(lines)

    temp_path = None
    try:
        os.makedirs(log_dir, exist_ok=True)
        base_name = f'{target}_{filename_timestamp}_{mode_component}_{result_component}'
        with tempfile.NamedTemporaryFile(
            mode='w',
            encoding='utf-8',
            dir=log_dir,
            prefix=f'.{target}_',
            suffix='.tmp',
            delete=False,
        ) as file:
            temp_path = file.name
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        log_path = publish_scan_log(temp_path, log_dir, base_name)
        temp_path = None
    except OSError as error:
        if temp_path is not None:
            try:
                os.remove(temp_path)
            except OSError:
                pass
        raise SecurityScanError(f'写入安全扫描日志失败: {error}') from error

    try:
        prune_scan_logs(log_dir, target)
    except OSError as error:
        print(f'警告: 清理旧安全扫描日志失败: {error}', file=sys.stderr)
    return log_path


def print_findings(mode, findings, log_path, errors=None):
    errors = errors or []
    print('\n安全扫描失败，已暂停同步。')
    print(f'当前目录: {os.getcwd()}')
    print(f'扫描模式: {mode}')
    print(f'日志文件: {log_path or "未写入"}')
    for error in errors:
        print('')
        print('[ERROR] scan-error')
        print(f'说明: {error}')
    for finding in findings:
        print('')
        print(f'[{finding.severity}] {finding.rule}')
        print(f'文件: {finding.path}:{finding.line_number}')
        print(f'命中: {finding.matched_text}')
        print(f'说明: {finding.message}')
    print('\n请删除或泛化上述内容后重新运行同步脚本。')


def run_optional_gitleaks(mode, files):
    if shutil_which('gitleaks') is None:
        print('gitleaks 未安装：跳过可选增强扫描。')
        return []

    command = ['gitleaks', 'detect', '--no-banner', '--redact', '--exit-code', '1']
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode == 0:
        print('gitleaks 增强扫描通过。')
        return []
    if result.returncode == 1:
        return [
            SecurityFinding(
                severity='HIGH',
                rule='gitleaks',
                path='.',
                line_number=0,
                matched_text='gitleaks finding',
                message=(result.stdout or result.stderr or 'gitleaks detect reported leaks').strip()[:120],
            )
        ]
    print(f'gitleaks 执行失败，按可选增强跳过: {(result.stderr or result.stdout).strip()}')
    return []


def run_security_scan(mode, files):
    scanned_files = unique_existing_text_files(files)
    findings = []
    errors = []
    try:
        for path in scanned_files:
            findings.extend(scan_file(path))
        findings.extend(run_optional_gitleaks(mode, scanned_files))
    except SecurityScanError as error:
        errors.append(str(error))

    result_label = 'BLOCKED' if findings or errors else 'PASS'
    try:
        log_path = write_scan_log(mode, scanned_files, findings, result_label, errors=errors)
    except SecurityScanError as error:
        errors.append(str(error))
        print_findings(mode, findings, None, errors=errors)
        return False

    if findings or errors:
        print_findings(mode, findings, log_path, errors=errors)
        return False

    print(f'安全扫描通过：mode={mode}, scanned_files={len(scanned_files)}, log={log_path}')
    return True


def run_security_scan_for_git_objects(mode, ranges):
    scanned_files = []
    findings = []
    errors = []
    try:
        for object_id, path in iter_git_blobs_for_ranges(ranges):
            text = git_object_text(object_id)
            if text is None:
                continue
            scanned_path = f'{path}@{object_id[:12]}'
            scanned_files.append(scanned_path)
            findings.extend(scan_text(scanned_path, text))
        findings.extend(run_optional_gitleaks(mode, scanned_files))
    except SecurityScanError as error:
        errors.append(str(error))

    result_label = 'BLOCKED' if findings or errors else 'PASS'
    try:
        log_path = write_scan_log(mode, scanned_files, findings, result_label, errors=errors)
    except SecurityScanError as error:
        errors.append(str(error))
        print_findings(mode, findings, None, errors=errors)
        return False
    if findings or errors:
        print_findings(mode, findings, log_path, errors=errors)
        return False
    print(f'安全扫描通过：mode={mode}, scanned_git_blobs={len(scanned_files)}, log={log_path}')
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
                if not run_security_scan_for_git_objects(f'incremental-outgoing:{remote}', [f'{ref}..HEAD']):
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
    my_note_path = my_note_root()
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


def parse_args(argv=None):
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
    return parser.parse_args(argv)


def selected_subfolders(args):
    if args.subfolder is not None:
        return args.subfolder
    return [*subfolders, '']


def main(argv=None):
    args = parse_args(argv)
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
