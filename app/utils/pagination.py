"""Generic list executor — mirrors express src/lib/pagination/index.ts:
limit clamp [1,100], offset-wins-over-page, whitelist sort, count subquery,
{list, pagination:{page,limit,total,pages,count}} envelope. Filter parsing
mirrors express src/lib/pagination/buildFilter.ts."""
from __future__ import annotations

import base64
import json
import math
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import parse_qs

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


@dataclass
class PageInput:
    page: int = 0
    offset: int | None = None
    limit: int = 0
    sort_field: str = ""
    sort_dir: str = ""
    search: str = ""
    filter: dict[str, list[str]] = field(default_factory=dict)


def _parse_filter(raw: str) -> dict[str, list[str]]:
    try:
        data = json.loads(base64.b64decode(raw).decode("utf-8"))
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    result: dict[str, list[str]] = {}
    for key, value in data.items():
        if isinstance(value, list):
            result[key] = [str(v) for v in value]
        elif value is not None:
            result[key] = [str(value)]
    return result


def parse_query(query_string: str) -> PageInput:
    q = parse_qs(query_string)

    def first(key: str, default: str = "") -> str:
        return q.get(key, [default])[0]

    offset_raw = first("offset")
    filter_raw = first("filter")
    return PageInput(
        page=int(first("page") or 0),
        offset=int(offset_raw) if offset_raw else None,
        limit=int(first("limit") or 0),
        sort_field=first("sortField"),
        sort_dir=first("sortDir"),
        search=first("search"),
        filter=_parse_filter(filter_raw) if filter_raw else {},
    )


# column SQL expression, filter variant ("select"/"multiSelect"/"boolean"/"text"/"number"/"range"/"date"/"dateRange")
FilterMap = dict[str, tuple[str, str]]


def build_filter(filter_map: FilterMap, filter_values: dict[str, list[str]] | None) -> tuple[str, dict[str, Any]]:
    """Turns a parsed `filter` map into a SQL AND-fragment + bind params,
    validated against a per-query column whitelist. Unknown keys are skipped."""
    if not filter_values:
        return "", {}

    clauses: list[str] = []
    params: dict[str, Any] = {}
    for i, (key, values) in enumerate(filter_values.items()):
        entry = filter_map.get(key)
        if not entry or not isinstance(values, list):
            continue
        col, ftype = entry
        clean = [v for v in values if v not in ("", None)]
        if not clean:
            continue
        prefix = f"filt{i}"

        if ftype in ("select", "multiSelect"):
            names = []
            for j, v in enumerate(clean):
                pname = f"{prefix}_{j}"
                params[pname] = v
                names.append(f":{pname}")
            clauses.append(f"({col})::text IN ({', '.join(names)})")
        elif ftype == "boolean":
            pname = f"{prefix}_0"
            params[pname] = clean[0] == "true"
            clauses.append(f"{col} = :{pname}")
        elif ftype == "text":
            pname = f"{prefix}_0"
            params[pname] = f"%{clean[0]}%"
            clauses.append(f"{col} ILIKE :{pname}")
        elif ftype in ("number", "range"):
            min_v = clean[0] if len(clean) > 0 else ""
            max_v = clean[1] if len(clean) > 1 else ""
            if min_v:
                pname = f"{prefix}_min"
                params[pname] = float(min_v)
                clauses.append(f"{col} >= :{pname}::numeric")
            if max_v:
                pname = f"{prefix}_max"
                params[pname] = float(max_v)
                clauses.append(f"{col} <= :{pname}::numeric")
        elif ftype in ("date", "dateRange"):
            from_v = clean[0] if len(clean) > 0 else ""
            to_v = clean[1] if len(clean) > 1 else ""
            if from_v:
                pname = f"{prefix}_from"
                params[pname] = from_v
                clauses.append(f"{col} >= :{pname}::date")
            if to_v:
                pname = f"{prefix}_to"
                params[pname] = to_v
                clauses.append(f"{col} <= :{pname}::date")

    if not clauses:
        return "", {}
    return " AND ".join(clauses), params


@dataclass
class PageOptions:
    default_sort_field: str = ""
    default_sort_dir: str = "desc"
    sort_map: dict[str, str] = field(default_factory=dict)
    map_row: Callable[[dict[str, Any]], dict[str, Any]] | None = None


async def paginate(
    db: AsyncSession, base_query: str, params: dict[str, Any], page_in: PageInput, opts: PageOptions
) -> dict[str, Any]:
    limit = page_in.limit or 20
    limit = max(1, min(limit, 100))

    if page_in.offset is not None:
        offset = max(page_in.offset, 0)
        page = offset // limit + 1
    else:
        page = max(page_in.page or 1, 1)
        offset = (page - 1) * limit

    total = (await db.execute(text(f"SELECT count(*)::int FROM ({base_query}) sub"), params)).scalar_one()

    field_name = opts.default_sort_field
    direction = opts.default_sort_dir or "desc"
    if page_in.sort_field and page_in.sort_field in opts.sort_map:
        field_name = opts.sort_map[page_in.sort_field]
    elif opts.default_sort_field:
        field_name = opts.sort_map.get(opts.default_sort_field, opts.default_sort_field)
    if page_in.sort_dir in ("asc", "desc"):
        direction = page_in.sort_dir

    query = base_query
    if field_name:
        safe_dir = "ASC" if direction.lower() == "asc" else "DESC"
        query += f" ORDER BY {field_name} {safe_dir}"
    query += f" LIMIT {limit} OFFSET {offset}"

    rows = (await db.execute(text(query), params)).mappings().all()
    list_ = [dict(r) for r in rows]
    if opts.map_row:
        list_ = [opts.map_row(r) for r in list_]

    pages = max(1, math.ceil(total / limit)) if total > 0 else 1
    if total == 0:
        count = "No items"
    else:
        start, end = offset + 1, min(offset + limit, total)
        count = f"Showing {start}-{end} of {total} items"

    return {
        "list": list_,
        "pagination": {"page": page, "limit": limit, "total": total, "pages": pages, "count": count},
    }
