<!-- Paste this section into your project's AGENTS.md (or CLAUDE.md) so coding agents check security before they ship. -->

## Security check before deploy (rattlecheck)

This project uses Supabase. Before deploying, and after any migration that touches tables, policies, functions, triggers, or grants:

1. Run `npx rattlecheck@latest --json` from the project root (or call the `scan` tool from the rattlecheck MCP server).
2. Put each finding's `fix` SQL into a **new** migration file. Never edit migrations that already ran. Never run SQL against production yourself.
3. Run it again until the grade is A.
4. If a finding is intentional, ask before adding an allow entry with a written reason to `rattlecheck.config.json`. Never allow a finding just to silence it.
5. Explain what you found and fixed using each finding's `plain` text.
