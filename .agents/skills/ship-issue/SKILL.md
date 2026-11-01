---
name: ship-issue
description: Design, build and review a GitHub issue in one session, ending with a branch ready to push.
disable-model-invocation: true
---

# Ship issue

Takes one issue from design to a reviewed branch. The user steps in twice: once to settle the design, and once to approve the push.

## 1. Design

1. Read the issue: `gh issue view <number> --json number,title,body,labels,comments`.
2. Read `GLOSSARY.md` and the ADRs in `docs/adr/` that touch the area, as `docs/agents/domain.md` describes.
3. Invoke the `codebase-design` skill and use its vocabulary to design the change against the code it touches: which modules change, where the seams are, which tests prove the behaviour.
4. **Checkpoint.** Present the design in a few lines, followed by a numbered list of the decisions that need the user: choices between real alternatives, scope questions, and conflicts with an ADR. Give a recommendation for each. Then stop and wait.

The step is done when the user has answered every numbered decision. If they change the design, update it before you build.

## 2. Build

1. Create a branch off an up-to-date `main`.
2. Implement in atomic commits, one per clear advancement, each leaving `go test ./...` and `go tool -modfile=tools.mod golangci-lint run ./...` green. After a schema or query edit, run `go tool -modfile=tools.mod sqlc generate` in the same commit.

The step is done when every behaviour in the issue has a test that would fail on `main`.

## 3. Review

1. Dispatch the `reviewer` agent on the branch. It returns findings and does not edit.
2. Apply every finding as its own commit. A finding you reject goes in the final report with the reason.
3. If a fix restructured code (not just a rename or a deleted line), dispatch the `reviewer` again on the new diff. Stop after two rounds and report whatever is still open.

The step is done when the reviewer approves, or the two rounds are spent, and tests and lint are green.

## 4. Hand off

Report the commits, the review findings and how each was resolved, and any rejected findings. Push and open the PR only when the user approves; a request in the invocation itself counts as approval. Write the PR body with the `pr` skill and put `Closes #<number>` in it.
