#!/usr/bin/env python3
"""MyNote repository command entrypoint."""

import sys

from scripts import git_operations
from scripts import markdown_index


COMMANDS = {'index', 'sync'}


def print_usage():
    print('Usage:')
    print('  python3 mynote.py sync [git/sync options]')
    print('  python3 mynote.py index <gen|clean> <root-directory>')
    print('  python3 mynote.py [git/sync options]  # backward compatible')
    print('')
    print('Commands:')
    print('  index   Generate or clean MyNote index files.')
    print('  sync    Run MyNote git sync and security scan workflow.')


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print_usage()
        return 2

    command = args[0]
    if command == 'sync':
        return git_operations.main(args[1:])
    if command == 'index':
        return markdown_index.main(args[1:])

    if command.startswith('-'):
        return git_operations.main(args)

    print(f'Unknown command: {command}', file=sys.stderr)
    print_usage()
    return 2


if __name__ == '__main__':
    sys.exit(main())
