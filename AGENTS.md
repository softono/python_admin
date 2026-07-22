# Python Admin API (port 4301)

Idiomatic FastAPI port of `express/express_admin`. Same shared Postgres DB as `python` — **runs no migrations**. Serves `react_admin` via `VITE_API_ORIGIN`. Mounts the shared `/api/auth` router alongside `/api/admin/*`.

## Stack

Same as `python`'s AGENTS.md.

## Structure

Same as `python`'s `app/` tree (core libs/models copied, not imported, from `python`), plus:

```
app/services/admin_service.py   dashboard, admin+user CRUD, blogs/pages/seos/email-templates CRUD,
                                 sessions/activities, settings
app/api/routes/admin.py          admin route module
get_current_admin_principal       role-gate dependency: SUPER_ADMIN/ADMIN only
```

## Wire contract — identical to `python`'s AGENTS.md, plus:

- **Auth router**: `/api/auth/*` mounted here too, same session/cookie/TFA machinery as the user API.
- **Admin routes**: `/api/admin/*` — full CRUD parity with `express_admin/src/modules/admin/admin.routes.ts` (58 routes). Do not drop any.
- **Permission gate**: `get_current_admin_principal` dependency enforces `SUPER_ADMIN`/`ADMIN` role; port the finer-grained METHOD+path → permission-key matcher from `express_admin/src/modules/account/{permission.ts,permission.constants.ts}` for any route needing more than the coarse role check.
- Settings save must AES-GCM-encrypt `google_client_secret`/`smtp_password`/`google_recaptcha_secret_key` on write and invalidate `setting:all` (3600s TTL) on mutation.
- **`update_setting`'s insert path** (`setting_service.py`) previously hit the same ORM-insert-NULL pitfall as `user_activities` in `python` — already fixed by explicitly setting `created_at`/`updated_at`. Apply the same audit to any new insert path added here.
- Dashboard/chart endpoints: raw SQLAlchemy Core-style aggregate queries, no unnecessary ORM overhead.

## Conventions

Same as `python`/AGENTS.md, including the SQLAlchemy naive-datetime and insert-NULL pitfalls. Verify via curl: admin login → dashboard → users list (base64 `filter`) → permission-denied case → blog CRUD → settings save → sessions/activities → compare with `:4001`.
- **Test**: `.venv/Scripts/python.exe -m pytest tests/ -v` — black-box HTTP integration tests in `tests/test_integration.py` (fixtures in `tests/conftest.py`). Boots the real app via `uvicorn` on port 4397 against the live shared Postgres DB, drives it purely over HTTP, and cleans up every row it creates (`%@integration.local` emails, cascades via FK). Add new endpoint coverage here as modules grow; keep the `@integration.local` marker convention so cleanup stays exhaustive.
- **Query**: `.venv/Scripts/python.exe -m app.db_query --file <name>` (reads `db/sql/<name>`) or `.venv/Scripts/python.exe -m app.db_query --sql "<query>"` — ad-hoc SQL against the live shared DB, mirroring express's `npm run db:query`. Inspection/manual-fix only, never migrations (express still owns schema changes).
