---
name: rattlecheck
description: Check a Supabase project for open doors (tables anyone can read, functions anyone can call with full database powers, policies that let anyone change every row) before deploying, and fix them with a new migration. Use before any deploy of a Supabase app, after writing or changing migrations, or when the user asks whether their app or data is secure.
---

# rattlecheck: rattle every door before you ship

rattlecheck replays `supabase/migrations` and grades the project A to F. It never changes the database.

## When to run it

- Before deploying a Supabase app.
- After you write or change a migration that touches tables, policies, functions, triggers, or grants.
- When the user asks "is my app secure?", "is my data safe?", or similar.

## How

1. From the project root, run:
   ```bash
   npx rattlecheck --json
   ```
   Or call the `scan` tool if the rattlecheck MCP server is connected.
2. For each finding, read `plain` (what's wrong, in plain words), `todo`, and `fix` (SQL).
3. Put the fixes in a **new** migration file, for example `supabase/migrations/<timestamp>_rattlecheck_fixes.sql`.
   - Never edit a migration that has already run.
   - Never run SQL against a production database yourself.
   - Read each fix before using it. Fixes that turn on row-level security may need a policy so the app keeps working; write one scoped to the row's owner.
4. Run rattlecheck again. Repeat until the grade is **A**.
5. If a finding is intentional (a public menu, store hours), **ask the user** before adding an allow entry to `rattlecheck.config.json`:
   ```json
   { "allow": [{ "rule": "RC005", "object": "public.menu_items", "reason": "The menu is public on the website." }] }
   ```
   Never add an allow entry just to make a finding go away.
6. Tell the user what you found and fixed, in plain words, using each finding's `plain` text.

## Live check

`npx rattlecheck --live` also asks the running project, read-only, how many rows each table hands to the public key. It only runs after proving the user owns the project (a `SUPABASE_ACCESS_TOKEN` or the service key in the local `.env`). Ask the user before running it.

## Exit codes

`0` nothing open, `1` open door found, `2` usage or config error, `3` migrations could not be parsed (don't trust the result), `4` live check refused.
