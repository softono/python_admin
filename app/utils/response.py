"""Standard {status, message, data, ...extras} envelope (ApiResult parity)."""
from __future__ import annotations

from typing import Any

from fastapi.responses import JSONResponse


class ApiResult:
    def __init__(self, http_status: int = 200, status: int = 1, message: str = "", data: Any = None, **extras: Any):
        self.http_status = http_status
        self.status = status
        self.message = message
        self.data = data if data is not None else []
        self.extras = extras


def ok(message: str, data: Any = None, **extras: Any) -> ApiResult:
    return ApiResult(200, 1, message, data, **extras)


def err(http_status: int, message: str) -> ApiResult:
    return ApiResult(http_status, 0, message, [])


def send_result(result: ApiResult, response: Any = None) -> JSONResponse:
    body = {"status": result.status, "message": result.message, "data": result.data, **result.extras}
    out = JSONResponse(status_code=result.http_status, content=jsonable(body))
    if response is not None:
        out.raw_headers.extend(
            h for h in response.raw_headers if h[0].decode("latin-1").lower() == "set-cookie"
        )
    return out


def send_error(http_status: int, message: str) -> JSONResponse:
    return send_result(err(http_status, message))


def jsonable(obj: Any) -> Any:
    """Recursively convert datetimes and other non-JSON-native values."""
    import datetime

    if isinstance(obj, dict):
        return {k: jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [jsonable(v) for v in obj]
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    return obj
