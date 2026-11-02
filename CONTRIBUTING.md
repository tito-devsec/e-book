# Contributing

## Setup

Follow the development quick start in [README.md](README.md). You need PostgreSQL and
`pdftoppm` locally. Create a separate test database:

```bash
createdb bookapp_test
```

## Workflow

1. Branch from `main`.
2. Make the change with tests. Security-relevant behaviour (authorization, tokens, OTP,
   devices, content delivery) must have an acceptance test in `test/`.
3. Run `npm test` and `npm run audit`.
4. Open a pull request describing what changed and how it was verified.

## Conventions

- ES modules, Node 22.9+. No build step; the browser code in `public/` is plain modern JavaScript.
- SQL is always parameterized (`$1, $2`). Never interpolate request data into SQL.
- Validate every request body with `validate()` from `src/lib/http.js`.
- State changes in the dashboard run in a transaction with an `audit_logs` entry.
- Browser code builds DOM with `textContent`. The only `innerHTML` is the server-sanitized
  chapter HTML in the reader.
- No inline scripts or `style=""` attributes: the Content Security Policy blocks them.
- Schema changes are new files in `migrations/` (`NNN_description.sql`). Never edit an applied
  migration.
- Never log raw tokens, OTP codes, cookies or passwords. The logger redacts common names, but
  don't rely on that.

## Commit messages

Use a short imperative subject line ("Add device replacement history"), and a body when the
reason is not obvious.
