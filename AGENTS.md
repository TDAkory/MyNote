# AGENTS.md

This repository is a Markdown-first personal knowledge base. Treat code files here as repository maintenance tooling, not as the main product.

## Scope

- Keep note content in Markdown unless the user explicitly asks for supporting scripts or tooling.
- Put experiments, benchmarks, binaries, and build outputs outside this repository unless the user gives a specific path.
- Respect submodule boundaries. Many top-level folders, such as `CppLearn`, `AppFrameThoughts`, `CSFundations`, and `ZImages`, have their own Git state. Check status from the relevant submodule before assuming a file is clean or dirty.
- Do not revert user edits or unrelated working-tree changes.

## Entrypoints

- Use `python3 mynote.py sync ...` for sync and security-scan workflows.
- Use `python3 mynote.py index gen <dir>` or `python3 mynote.py index clean <dir>` for index maintenance.
- Implementation lives under `scripts/`; the root should stay clean and expose only `mynote.py` as the script entrypoint.

## Index Policy

- Follow `INDEX_POLICY.md`.
- Index files are navigation, not learning roadmaps.
- Use unique `*INDEX.md` names instead of generic `INDEX.md`.
- Preserve hand-written index content. Do not run broad index generation over curated indexes without checking the diff.
- When adding or moving notes, update the nearest relevant `*INDEX.md` in the same pass.

## Note Style

- Prefer source-backed, concise technical writing.
- For study notes, keep the main body organized by topic. If a book or course drives the sequence, put the reading order in a roadmap file and keep durable knowledge in topic notes.
- Use diagrams, tables, and compact code snippets where they improve understanding.
- Keep examples self-authored and generic. Do not copy private or internal code snippets into notes.
- For fast-moving technical facts, prefer official docs, release notes, or stable upstream references.

## Security

- Run the MyNote security scan before sync or publication-sensitive changes:

```bash
python3 mynote.py sync --scan-only --subfolder <submodule>
```

- For broader checks, run:

```bash
python3 mynote.py sync --full-scan --subfolder <submodule>
```

- The versioned baseline scanner config is `scripts/note_security_scan_config.json`.
- The local private override is `.git/info/note_security_scan_config.json`; it may include machine- or user-specific deny rules and should not be committed.
- When the scanner flags local absolute paths or private/internal terms, prefer replacing them with verified public upstream URLs. If no public URL is available, use repository-relative paths or generic placeholders.
- Standard Linux example paths such as `/mnt/...` and `/tmp/...` are legitimate examples and should not be treated as leaks by default.
- `.gitmodules` SSH remotes using the `git at host` form are valid repository configuration; prefer allowlisting over rewriting them.

## Common Commands

```bash
python3 -m unittest scripts.test_git_operations_security scripts.test_mynote_entrypoint -v
python3 -m py_compile mynote.py scripts/git_operations.py scripts/markdown_index.py
python3 mynote.py sync --scan-only --subfolder CppLearn
python3 mynote.py index gen CppLearn/Topics/Performance_Efficiency
```

## Commit Hygiene

- For index-only syncs, stage only `*INDEX.md` changes.
- Push submodules before pushing the root repository so root submodule pointers reference commits already available on remotes.
