"""Ad-hoc SQL query runner against the live shared Postgres DB, mirroring
express's `npm run db:query`. Read-only or write — used for schema
inspection and manual fixes, never for migrations (express owns those).

Usage:
    python -m app.db_query --file <name>   (reads db/sql/<name>)
    python -m app.db_query --sql "<query>"
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

import asyncpg

from app.core.config import settings


def _print_table(headers: list[str], records: list[list[str]]) -> None:
    if not records:
        print("(0 rows)")
        return
    widths = [len(h) for h in headers]
    for rec in records:
        for i, v in enumerate(rec):
            widths[i] = max(widths[i], len(v))

    def print_row(cols: list[str]) -> None:
        print(" | ".join(c.ljust(widths[i]) for i, c in enumerate(cols)))

    print_row(headers)
    print_row(["-" * w for w in widths])
    for rec in records:
        print_row(rec)


async def run_query(query_text: str) -> None:
    conn = await asyncpg.connect(settings.database_url)
    try:
        rows = await conn.fetch(query_text)
    except Exception as exc:
        print("Error executing query:", exc)
        sys.exit(1)
    finally:
        await conn.close()

    if not rows:
        print("Result: query executed (no rows returned).")
        return

    headers = list(rows[0].keys())
    records = [[str(v) for v in row.values()] for row in rows]
    print("Result:")
    _print_table(headers, records)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run an ad-hoc SQL query against the live DB.")
    parser.add_argument("--file", dest="file_name", default=None)
    parser.add_argument("--sql", dest="sql_query", default=None)
    args = parser.parse_args()

    if not args.file_name and not args.sql_query:
        print("Usage: python -m app.db_query --file <filename> OR python -m app.db_query --sql <query>")
        sys.exit(1)

    if args.sql_query:
        print(f"Executing query: {args.sql_query}\n")
        query_text = args.sql_query
    else:
        file_path = Path("db") / "sql" / args.file_name
        print(f"Executing query from: {file_path}\n")
        try:
            query_text = file_path.read_text()
        except OSError as exc:
            print("Error executing query:", exc)
            sys.exit(1)

    asyncio.run(run_query(query_text))


if __name__ == "__main__":
    main()
