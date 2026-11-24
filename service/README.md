# rattlecheck publish service

The public grade and badge behind `rattlecheck --publish`. A Cloudflare Worker with one key-value store.

| Route | What it does |
|---|---|
| `POST /api/publish` | Body `{"repo": "owner/name", "dir": "optional/folder"}`. Fetches the repository's default branch from GitHub, requires the `rattlecheck.config.json` at its top to opt in (`"publish": true`, or the folder in `"publishDirs"`), runs the check, stores the grade. |
| `GET /r/:owner/:repo` | The public page. `?dir=` for a project in a subfolder. |
| `GET /badge/:owner/:repo.svg` | The badge. |
| `GET /api/r/:owner/:repo` | The stored record as JSON. |

## Rules

1. The service does the check itself. Nothing a caller sends can change a grade.
2. A repository is only graded when the committed config at its top opts in. Removing the opt-in deletes the published grade at the next check, and so does anything else that leaves the check without a grade (the repository went private, lost its migrations, grew past the limits).
3. The stored record holds the grade and counts. Never which table or function is open.
4. Only the `allow` list is read from the project's config. `defaults`, `exposedSchemas` and `migrationRoles` are ignored, so every project is graded with the same stock settings.
5. A repository that uses `export-ignore` or `export-subst` in a `.gitattributes` on the path to its migrations is refused: GitHub leaves such files out of the archive the service reads.

## Limits

Four checks per repository per minute, ten publish requests per address per minute (per /64 for IPv6), 1 MB and 15,000 statements of migrations, 60 MB download, one check at a time per isolate. Public GitHub repositories only. The migration cap is a memory limit: a megabyte of SQL can cost the scanner about 70 MB.

## Deploy

```bash
cd service
npx wrangler deploy
```

Tests run with the rest of the suite: `npm test` from the repository root.
