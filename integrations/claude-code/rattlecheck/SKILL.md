---
name: rattlecheck
description: Review local Supabase SQL migrations before merge or deploy. Use RattleCheck to check row-level security policies, column grants, SQL functions and triggers, and explain findings to the reviewer.
---

# rattlecheck: rattle every door before you ship

RattleCheck replays the project's local SQL migration history. Findings may originate on an older migration. Use the reported file and line to explain what the current PR changes.

## When to run it

- Before deploying a Supabase app.
- After you write or change a migration that touches tables, policies, functions, triggers, or grants.
- When the user asks "is my app secure?", "is my data safe?", or similar.

## How

1. From the project root, run:
   ```bash
   npx rattlecheck@latest --json
   ```
   Or call the `scan` tool if the rattlecheck MCP server is connected.
2. Read `coverage.tables` and `doors.checked` before interpreting the result. Zero tables gives no evidence about column permissions. For each finding, read `plain` (what's wrong, in plain words), `todo`, and `fix` (SQL).
3. For a review request, report the results and suggested changes. If the user requests a fix, put it in a **new** migration file, for example `supabase/migrations/<timestamp>_rattlecheck_fixes.sql`.
   - Never edit a migration that has already run.
   - Never run SQL against a production database yourself.
   - Read each fix before using it. Fixes that turn on row-level security may need a policy so the app keeps working; write one scoped to the row's owner.
4. After an authorized change, rerun the check and say which finding cleared and which warnings remain. An intentional public read can leave a warning on a passing check.
5. If a finding is intentional (a public menu, store hours), **ask the user** before adding an allow entry to `rattlecheck.config.json`:
   ```json
   { "allow": [{ "rule": "RC005", "object": "public.menu_items", "reason": "The menu is public on the website." }] }
   ```
   Never add an allow entry just to make a finding go away.
6. Tell the user what you found and fixed, in plain words, using each finding's `plain` text.

## Live check

`npx rattlecheck@latest --live` also asks the running project, read-only, how many rows each table hands to the public key. It only runs after proving the user owns the project (a `SUPABASE_ACCESS_TOKEN` or the service key in the local `.env`). Ask the user before running it.

## Exit codes

`0` no high or critical findings (warnings can remain), `1` high or critical findings, `2` usage or config error, `3` incomplete coverage, `4` live check refused.
