# AGENTS.md

- Guidance for future agent sessions working on this codebase. 
  - Terse on purpose.
  - Exclude any information that easier to get by reading the code.

## Project context

Phase 1.a is the `org-members` Rust library: an immutable binary Sparse Merkle
Tree (SMT) for organisation membership. The local-first collaboration layer
consumes this lib's types (using the `p2p_key` as the member-as-a-group key
when granting access) but is out of scope here.

For crate-specific guidance, see the AGENTS.md inside each crate directory:
- `org-members/AGENTS.md` -- Phase 1.a SMT library

## User preferences (sticky)

- **No `Co-Authored-By:` lines in commit messages.** Hard rule.
- **`/superpowers:brainstorming` before any non-trivial design work.** Don't
  start coding alternatives until brainstorming has run and the user has
  confirmed direction.
- **Always work in a git worktree for feature work.** Use the worktree skill.
- **Don't ask "should I commit?" repeatedly.** Just commit at natural points.
- **Disable gpg signing for git commits in worktrees**, UNLESS when git merging the worktree into main branch (e.g. `master`) in which case squash the worktree commits and require the user signature for the merge.
  How: `git config extensions.worktreeConfig true && git config --worktree commit.gpgsign false`
  inside the worktree. Never write `commit.gpgsign` to the shared repo config
  from a worktree. If the merge commit ends up unsigned (agent session),
  re-sign with `git commit --amend -S` from a regular terminal.
- **Always include fuzz testing.**

## Lessons learned (don't repeat these)

- **Don't use `sed` on Rust test files.** It wiped a 600-line file once.
  Use the `Edit` tool instead.
