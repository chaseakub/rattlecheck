# rattlecheck

**Rattle every door you own.**

At closing time, a good manager walks the building and rattles every door to make sure it's locked. rattlecheck does that for your app. It checks every table, function, and rule in your Supabase project the way someone on the outside would, tells you in plain English which doors are open, and gives you the exact fix.

```bash
npx rattlecheck
```

> Status: 0.1, pre-release. Not yet published to npm.

```
  rattlecheck 0.1.0  rattle every door you own

  ┌──────────────────────────────────────────────┐
  │ GRADE  F  Wide open                          │
  │ 3 doors checked, 3 open                      │
  └──────────────────────────────────────────────┘

  CRITICAL Anyone on the internet, using only the key that ships in your website's code,
           can read and change every row in the "_snapshot_orders" table. It was created
           as a copy of another table (CREATE TABLE AS), and copies inherit none of the
           original's security.
           What to do: Lock the copy, or drop it if you no longer need it.

  CRITICAL Anyone on the internet can run the "get_orders" function. It runs with full
           database powers and skips your security rules, so whatever it can read or
           change, anyone can.
           What to do: Stop the public from calling it. If signed-in users need it,
           allow only them.
```

Add `--technical` for file and line, the standards each finding maps to, and the SQL fix.

## Why this exists

Supabase serves your database straight to the browser. That's what makes it fast to build on, and it's why one missed line of SQL can put every customer's data on the open internet. The key that unlocks it ships inside your website's code, so anyone can find it. Apps built in a weekend, by people or by coding agents, ship these holes all the time, and nothing in the normal build process notices.

Every rule in rattlecheck comes from a real incident in a production app:

- **A snapshot table, readable by anyone.** Someone made a quick backup copy of a customer table before a risky change (`create table ... as select`). Copies inherit none of the original's security. For a day, every guest name and message in it was readable with nothing but the public key, while the real table was locked tight. (RC001)
- **A helper function that skipped every lock.** A `SECURITY DEFINER` function was written to fetch one customer's data. Postgres lets everyone run new functions by default, and nobody revoked that, so anyone could call it with someone else's id. (RC002)
- **A week of silent failures.** A trigger wrote audit rows to a table locked to the server. Every save by a real user failed and rolled back. Server jobs bypass the lock, so every dashboard stayed green for seven days. (RC004)

## What it checks

| Rule | What it catches | Severity |
|---|---|---|
| [RC001](docs/rules/RC001.md) | A table reachable through the API with row-level security off, including `CREATE TABLE AS` copies | critical |
| [RC002](docs/rules/RC002.md) | A `SECURITY DEFINER` function anyone can call | critical |
| [RC003](docs/rules/RC003.md) | A `SECURITY DEFINER` function without a pinned `search_path` | high |
| [RC004](docs/rules/RC004.md) | A trigger that runs with the user's rights and writes to a server-only table, so user saves fail | high |
| [RC005](docs/rules/RC005.md) | A policy whose condition is just `true`, letting anyone change every row | high |
| [RC101](docs/rules/RC101.md) | **Live:** a table on your running project that hands rows to the public key | critical |

rattlecheck doesn't grep your files. It replays every migration in order, statement by statement, the way Postgres would, so it knows the current state: a revoke from March doesn't count if the function was dropped and re-created in June, and a policy that was later dropped protects nothing.

Grades: **A** nothing open, **B** only things worth a look, **C** one high finding, **D** two or more, **F** anything critical.

## For coding agents

rattlecheck has an MCP server built in. Connect it and your agent can check its own work before it ships, then write the fixes as a new migration.

**Claude Code**
```bash
claude mcp add rattlecheck -- npx -y rattlecheck mcp
```

**Cursor, Windsurf, and other MCP clients** (`.cursor/mcp.json` or your client's equivalent):
```json
{ "mcpServers": { "rattlecheck": { "command": "npx", "args": ["-y", "rattlecheck", "mcp"] } } }
```

Tools: `scan` (grade, plain-English findings, fix SQL), `explain_rule`, `list_rules`. The server tells the agent to put fixes in a new migration, never to run SQL against production, and never to silence a finding without asking you.

Prefer instructions over a server? Drop in one of these:
- Claude Code skill: [`integrations/claude-code/rattlecheck/SKILL.md`](integrations/claude-code/rattlecheck/SKILL.md) (copy the folder into `.claude/skills/`)
- `AGENTS.md` / `CLAUDE.md` section: [`integrations/AGENTS.md`](integrations/AGENTS.md)
- Cursor rule: [`integrations/cursor/rattlecheck.mdc`](integrations/cursor/rattlecheck.mdc) (copy into `.cursor/rules/`)

## Share your grade

```bash
npx rattlecheck --card     # 1200x630 share image: rattlecheck-card.svg
npx rattlecheck --badge    # README badge: rattlecheck-badge.svg
```

The card shows the grade and counts only. It never names a table, a function, or your project, so a failing card doesn't tell anyone where the hole is.

## Live check

```bash
npx rattlecheck --live
```

Static checks read your migration files. The live check asks your running project, with only the public key, how many rows each table will hand over. It catches what migrations can't: a policy someone added in the dashboard, or a table that was changed by hand.

- **Your project only.** Before anything else, rattlecheck proves you control the project: either a `SUPABASE_ACCESS_TOKEN` (from `supabase login`) that can see it, or the project's service key in your local `.env`. Without proof, it refuses. There is no flag to skip this.
- **Read-only.** Every table request is a `HEAD` asking for a row count; the one `GET` asks for the list of table names. No rows are downloaded, nothing is written, nothing is stored. Counting is exact, so very large tables can take a moment.
- **Keys go nowhere else.** Your keys are only ever sent to `https://<project-ref>.supabase.co` or a local Supabase on `localhost`, never through a redirect. The URL and keys must come from the same place (all from your environment, or all from your `.env` files), so a repo's `.env` can't point your shell's keys somewhere else.
- **Every table, not just the ones in your migrations.** Tables made in the dashboard or by hand (a quick backup copy, say) never show up in migrations, and they're the likeliest to be left open. With `SUPABASE_ACCESS_TOKEN`, rattlecheck reads the full list of table and view names through Supabase's read-only query endpoint (names only, no rows). Without it, the report says exactly which part it couldn't cover instead of calling it an all-clear.
- **Honest zeros.** A table that returns zero rows is reported as "locked or empty", because from outside those look the same.

The project URL and public key are read from the environment, or from `.env`, `.env.local`, `.env.development` (`SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_URL`, `VITE_SUPABASE_URL`, and the matching `..._ANON_KEY` or `..._PUBLISHABLE_KEY`). Keys are never printed or included in any report.

## In CI

```yaml
# .github/workflows/rattlecheck.yml
name: rattlecheck
on: [pull_request]
permissions: { contents: read, security-events: write }
jobs:
  rattlecheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - run: npx -y rattlecheck --sarif --out rattlecheck.sarif
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: rattlecheck.sarif }
```

Exit codes: `0` nothing open, `1` open door found, `2` usage or config error, `3` migrations could not be parsed (don't trust the result), `4` live check refused.

`--json` prints a stable, versioned report (`rattlecheck.report/v1`). `--sarif` prints SARIF 2.1.0 for GitHub code scanning and other security tools. `--fix-sql` writes every suggested fix to one file for review.

## Config

`rattlecheck.config.json` in your project folder:

```json
{
  "defaults": "supabase-stock",
  "allow": [
    { "rule": "RC005", "object": "public.menu_items", "reason": "The menu is public on the website." }
  ]
}
```

- **`allow`**: some doors are meant to be open, like a public menu. Every entry needs a written reason. Entries that no longer match anything are reported, so an old exception can't quietly cover something new.
- **`defaults`**: rattlecheck assumes Supabase's stock privileges, where new tables and functions in `public` are open to `anon` and `authenticated` until you revoke them. If your baseline migration revokes those defaults through dynamic SQL that a static reader can't see, set `"clean"`, or `{ "functions": "clean", "tables": "supabase-stock" }`.
- **`exposedSchemas`**: read from `supabase/config.toml` (`[api] schemas`) by default.
- **`migrationRoles`**: the roles your migrations run as (default `["postgres"]`). `ALTER DEFAULT PRIVILEGES FOR ROLE` only counts when it names one of them.

## Standards

Every finding is labeled with the controls auditors and agencies already use, so a rattlecheck report can go straight into a security review.

| Rule | CWE | NIST SP 800-53 | CIS Controls v8 |
|---|---|---|---|
| RC001 | CWE-284, CWE-862 | AC-3, AC-6 | 3.3 |
| RC002 | CWE-269, CWE-862 | AC-3, AC-6 | 3.3, 6.8 |
| RC003 | CWE-426 | CM-6, AC-6 | 4.1 |
| RC004 | CWE-279 | AC-6, AU-9 | 8.2 |
| RC005 | CWE-732 | AC-3, AC-6 | 3.3 |
| RC101 | CWE-200, CWE-284 | AC-3, AC-6 | 3.3 |

## Built to be trusted

- **Zero runtime dependencies.** Including the MCP server. Every line that runs is in this repository.
- **No telemetry.** rattlecheck never phones home. Static checks work fully offline.
- **Never changes your database.** Fixes are printed for you to review and commit.
- **Checks only what you own.** Live checks require proof of ownership, every time.
- **Shows its coverage.** Every run says how many files, statements, tables, and functions it parsed, and fails loudly if it found migrations but couldn't read them. A clean report from a checker that saw nothing is worse than no report.

## What it doesn't check yet

rattlecheck 0.1 reads Supabase migrations and, with `--live`, your running project's tables. It does not yet look at views, storage buckets, edge functions, auth settings, or secrets leaked into your website's code. It can't see inside dynamic SQL (`EXECUTE format(...)`), which is one more reason to run `--live`.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
