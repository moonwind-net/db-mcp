"""
DB MCP Server (Streamable HTTP transport)

Connects to a PostgreSQL container and exposes SQL / CRUD tools
via the Model Context Protocol.

Auth model
----------
Three role tokens are supported: read, write, admin. The Authorization header
carries the caller's bearer token; the middleware maps it to a role, and each
tool checks the minimum role it needs. Roles form a hierarchy: admin > write > read.

Run locally:
    python server.py

Run in Docker:
    docker compose up -d --build
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import re
import time
import uuid
from contextvars import ContextVar
from typing import Any

import uvicorn
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
from pydantic import Field
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("db-mcp")

MCP_HOST = os.getenv("MCP_HOST", "0.0.0.0")
MCP_PORT = int(os.getenv("MCP_PORT", "8765"))

DB_HOST = os.getenv("DB_HOST", "db")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_NAME = os.getenv("DB_NAME", "postgres")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "postgres")

# Row cap for any single query response to protect the LLM context.
MAX_ROWS = int(os.getenv("MAX_ROWS", "500"))

# DB pool sizing
POOL_MIN_SIZE = int(os.getenv("DB_POOL_MIN_SIZE", "1"))
POOL_MAX_SIZE = int(os.getenv("DB_POOL_MAX_SIZE", "10"))

# --- Role-based bearer tokens ---
TOKENS: dict[str, str] = {
    "read": os.getenv("MCP_TOKEN_READ", "").strip(),
    "write": os.getenv("MCP_TOKEN_WRITE", "").strip(),
    "admin": os.getenv("MCP_TOKEN_ADMIN", "").strip(),
}
ROLE_LEVEL: dict[str, int] = {"read": 1, "write": 2, "admin": 3}
AUTH_ENABLED = any(TOKENS.values())

# Paths that skip auth (e.g. health checks). Everything else requires a token.
AUTH_EXEMPT_PATHS: tuple[str, ...] = tuple(
    p.strip() for p in os.getenv("MCP_AUTH_EXEMPT_PATHS", "/healthz").split(",") if p.strip()
)

# Middleware -> tool boundary: same async task, so a ContextVar propagates.
current_role: ContextVar[str | None] = ContextVar("current_role", default=None)

mcp = FastMCP("db-mcp", host=MCP_HOST, port=MCP_PORT)


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Reject requests without a valid `Authorization: Bearer <token>` header
    and stash the matched role in a ContextVar for downstream tools to check."""

    def __init__(self, app, tokens: dict[str, str], exempt: tuple[str, ...] = ()) -> None:
        super().__init__(app)
        # Drop empty entries so we never compare against "".
        self._tokens = {r: t for r, t in tokens.items() if t}
        self._exempt = exempt

    async def dispatch(self, request, call_next):
        if request.url.path in self._exempt:
            return await call_next(request)

        header = request.headers.get("authorization", "")
        prefix = "Bearer "
        if not header.startswith(prefix):
            return JSONResponse(
                {"error": "unauthorized", "detail": "Missing Bearer token"},
                status_code=401,
                headers={"WWW-Authenticate": 'Bearer realm="db-mcp"'},
            )

        offered = header[len(prefix):]
        matched: str | None = None
        # Walk all configured tokens so timing does not leak which role matched.
        for role, expected in self._tokens.items():
            if hmac.compare_digest(offered, expected):
                matched = role
        if matched is None:
            return JSONResponse(
                {"error": "unauthorized", "detail": "Invalid token"},
                status_code=401,
            )

        token = current_role.set(matched)
        try:
            return await call_next(request)
        finally:
            current_role.reset(token)


def _conninfo() -> str:
    return (
        f"host={DB_HOST} port={DB_PORT} dbname={DB_NAME} "
        f"user={DB_USER} password={DB_PASSWORD} "
        f"application_name=db-mcp"
    )


pool = ConnectionPool(
    conninfo=_conninfo(),
    min_size=POOL_MIN_SIZE,
    max_size=POOL_MAX_SIZE,
    kwargs={"autocommit": False, "row_factory": dict_row},
    open=False,
)


def _connect():
    return pool.connection()


_DML_KEYWORDS = {"insert", "update", "delete"}
_DDL_KEYWORDS = {
    "drop", "alter", "truncate", "create", "grant", "revoke",
    "vacuum", "reindex", "cluster",
}
_TXN_KEYWORDS = {"begin", "start", "commit", "rollback", "savepoint", "release"}
_READ_KEYWORDS = {"select", "show", "explain", "values"}
_ADMIN_KEYWORDS = _DDL_KEYWORDS | {
    "copy", "set", "reset", "discard", "listen", "unlisten", "notify",
}
# Statements that can be safely wrapped in `SELECT * FROM (...) AS sub`.
_PAGEABLE_HEADS = {"select", "values", "with"}

_LEADING_COMMENT_RE = re.compile(
    r"""
    \A\s*(
        --[^\n]*\n\s*         |   # line comment
        /\*.*?\*/\s*              # block comment
    )*
    """,
    re.DOTALL | re.VERBOSE,
)


def _strip_leading_comments(sql: str) -> str:
    return _LEADING_COMMENT_RE.sub("", sql, count=1).lstrip()


def _has_multiple_statements(sql: str) -> bool:
    s = sql.strip()
    if not s:
        return False
    # Simple conservative check. If you need exact SQL parsing later,
    # consider sqlparse/pglast.
    return ";" in s.rstrip(";")


def _leading_keyword(sql: str) -> str:
    s = _strip_leading_comments(sql)
    if not s:
        return ""
    return s.split(None, 1)[0].lower()


def _classify_sql(sql: str) -> str:
    """Classify SQL into read/write/admin/unknown.

    Fail closed: unknown statements are rejected by execute_sql.
    """
    head = _leading_keyword(sql)
    if not head:
        return "unknown"

    if head in _TXN_KEYWORDS:
        return "admin"
    if head in _ADMIN_KEYWORDS:
        return "admin"
    if head in _DML_KEYWORDS:
        return "write"
    if head in _READ_KEYWORDS:
        return "read"

    if head == "with":
        lowered = _strip_leading_comments(sql).lower()
        if re.search(r"\)\s*insert\b", lowered):
            return "write"
        if re.search(r"\)\s*update\b", lowered):
            return "write"
        if re.search(r"\)\s*delete\b", lowered):
            return "write"
        if re.search(r"\)\s*select\b", lowered):
            return "read"
        return "unknown"

    return "unknown"


def _sanitize_paging(limit: int, offset: int) -> tuple[int, int]:
    safe_limit = min(max(1, int(limit)), MAX_ROWS)
    safe_offset = max(0, int(offset))
    return safe_limit, safe_offset


def _apply_pagination(sql: str, limit: int, offset: int) -> str:
    s = sql.strip().rstrip(";")
    return f"SELECT * FROM ({s}) AS sub LIMIT {limit} OFFSET {offset}"


def _quote_ident(name: str) -> str:
    """Safely quote a PostgreSQL identifier (table / column)."""
    if not name or not all(c.isalnum() or c == "_" or c == "." for c in name):
        raise ValueError(f"Invalid identifier: {name!r}")
    if "." in name:
        return ".".join(f'"{p}"' for p in name.split("."))
    return f'"{name}"'


def _err(msg: str, **extra: Any) -> dict[str, Any]:
    return {"ok": False, "error": msg, **extra}


def _current_actor() -> str:
    role = current_role.get()
    return role or "anonymous"


def _truncate_sql(sql: str, max_len: int = 2000) -> str:
    s = " ".join(sql.split())
    return s if len(s) <= max_len else s[:max_len] + "...[truncated]"


def _audit(event: str, **fields: Any) -> None:
    log.info("AUDIT %s", json.dumps({"event": event, **fields}, default=str))


def _require(min_role: str) -> dict[str, Any] | None:
    """Return an error dict when the caller lacks `min_role`, else None."""
    if not AUTH_ENABLED:
        return None  # dev mode: all callers act as admin
    role = current_role.get()
    if role is None:
        return _err("no role in context (auth misconfigured)")
    if min_role not in ROLE_LEVEL:
        return _err(f"invalid required role: {min_role}")
    if ROLE_LEVEL[role] < ROLE_LEVEL[min_role]:
        return _err(f"forbidden: role '{min_role}' required, have '{role}'")
    return None


@mcp.tool()
def ping() -> dict[str, Any]:
    """Health check. Confirms MCP server can reach the database."""
    if err := _require("read"):
        return err
    try:
        with _connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT version() AS version, current_database() AS db, current_user AS user;")
            row = cur.fetchone()
        return {
            "ok": True,
            "mcp": {
                "host": MCP_HOST,
                "port": MCP_PORT,
                "max_rows": MAX_ROWS,
                "role": current_role.get(),
                "roles_available": [r for r, t in TOKENS.items() if t] or ["(auth-disabled)"],
            },
            "db": {"host": DB_HOST, "port": DB_PORT, "name": DB_NAME, "user": DB_USER, **row},
        }
    except Exception as e:
        return _err(f"connect failed: {e}")


@mcp.tool()
def execute_sql(
    sql: str = Field(description="Any SQL statement. Multiple statements are NOT allowed."),
    params: list[Any] | None = Field(
        default=None,
        description="Positional parameters bound with %s placeholders. Prefer this over string interpolation.",
    ),
    limit: int = Field(default=100, description="Rows to return for read queries (<= MAX_ROWS)"),
    offset: int = Field(default=0, description="Rows to skip for read queries (>= 0)"),
) -> dict[str, Any]:
    """Execute an arbitrary SQL statement.

    - Read queries return rows (paged, capped by MAX_ROWS).
    - INSERT/UPDATE/DELETE returns affected row count.
    - Required role is derived from SQL classification.
    """
    request_id = str(uuid.uuid4())
    started = time.monotonic()
    actor = _current_actor()

    if not sql or not sql.strip():
        _audit("sql_rejected", request_id=request_id, actor=actor, reason="empty_sql")
        return _err("empty sql", request_id=request_id)

    if _has_multiple_statements(sql):
        _audit("sql_rejected", request_id=request_id, actor=actor, reason="multiple_statements")
        return _err("multiple statements are not allowed; send them one at a time", request_id=request_id)

    required = _classify_sql(sql)
    if required == "unknown":
        _audit(
            "sql_rejected",
            request_id=request_id,
            actor=actor,
            reason="unknown_sql_classification",
            sql=_truncate_sql(sql),
        )
        return _err("unsupported or unclassifiable SQL; statement rejected", request_id=request_id)

    if err := _require(required):
        _audit(
            "sql_forbidden",
            request_id=request_id,
            actor=actor,
            required_role=required,
            sql_class=required,
            sql=_truncate_sql(sql),
        )
        return {**err, "request_id": request_id}

    safe_limit, safe_offset = _sanitize_paging(limit, offset)

    _audit(
        "sql_execute_start",
        request_id=request_id,
        actor=actor,
        sql_class=required,
        sql=_truncate_sql(sql),
        has_params=bool(params),
        param_count=len(params or []),
        limit=safe_limit,
        offset=safe_offset,
    )

    try:
        exec_sql = sql
        fetch_limit: int | None = None
        pageable = False
        if required == "read":
            head = _leading_keyword(sql)
            # EXPLAIN / SHOW cannot be wrapped in a subquery in PostgreSQL,
            # so we only paginate statements that survive `SELECT * FROM (...)`.
            if head in _PAGEABLE_HEADS:
                exec_sql = _apply_pagination(sql, safe_limit + 1, safe_offset)
                fetch_limit = safe_limit
                pageable = True

        with _connect() as conn, conn.cursor() as cur:
            cur.execute(exec_sql, params or None)

            if cur.description is None:
                affected = cur.rowcount
                conn.commit()
                duration_ms = int((time.monotonic() - started) * 1000)
                _audit(
                    "sql_execute_success",
                    request_id=request_id,
                    actor=actor,
                    sql_class=required,
                    affected=affected,
                    duration_ms=duration_ms,
                )
                return {
                    "ok": True,
                    "affected": affected,
                    "rows": None,
                    "role_used": required,
                    "request_id": request_id,
                }

            rows = cur.fetchall()
            truncated = False
            has_more = False

            if pageable and fetch_limit is not None and len(rows) > fetch_limit:
                rows = rows[:fetch_limit]
                truncated = True
                has_more = True

            duration_ms = int((time.monotonic() - started) * 1000)
            _audit(
                "sql_execute_success",
                request_id=request_id,
                actor=actor,
                sql_class=required,
                row_count=len(rows),
                truncated=truncated,
                has_more=has_more,
                duration_ms=duration_ms,
            )

            return {
                "ok": True,
                "columns": [d.name for d in cur.description],
                "rows": rows,
                "row_count": len(rows),
                "truncated": truncated,
                "has_more": has_more,
                "limit": safe_limit if pageable else None,
                "offset": safe_offset if pageable else None,
                "role_used": required,
                "request_id": request_id,
            }
    except Exception as e:
        duration_ms = int((time.monotonic() - started) * 1000)
        _audit(
            "sql_execute_error",
            request_id=request_id,
            actor=actor,
            sql_class=required,
            duration_ms=duration_ms,
            error=str(e),
        )
        return _err(str(e), request_id=request_id)


@mcp.tool()
def list_schemas() -> dict[str, Any]:
    """List non-system schemas."""
    if err := _require("read"):
        return err
    try:
        with _connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT schema_name FROM information_schema.schemata "
                "WHERE schema_name NOT IN ('pg_catalog','information_schema') "
                "AND schema_name NOT LIKE 'pg_%' ORDER BY schema_name;"
            )
            return {"ok": True, "schemas": [r["schema_name"] for r in cur.fetchall()]}
    except Exception as e:
        return _err(str(e))


@mcp.tool()
def list_tables(
    schema: str = Field(default="public", description="Schema name"),
) -> dict[str, Any]:
    """List tables in the given schema."""
    if err := _require("read"):
        return err
    try:
        with _connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT table_name, table_type FROM information_schema.tables "
                "WHERE table_schema = %s ORDER BY table_name;",
                [schema],
            )
            return {"ok": True, "schema": schema, "tables": cur.fetchall()}
    except Exception as e:
        return _err(str(e))


@mcp.tool()
def describe_table(
    table: str = Field(description="Table name, optionally schema-qualified e.g. 'public.users'"),
) -> dict[str, Any]:
    """Return column definitions for a table."""
    if err := _require("read"):
        return err
    try:
        if "." in table:
            schema, tname = table.split(".", 1)
        else:
            schema, tname = "public", table
        with _connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT column_name, data_type, is_nullable, column_default "
                "FROM information_schema.columns "
                "WHERE table_schema=%s AND table_name=%s ORDER BY ordinal_position;",
                [schema, tname],
            )
            cols = cur.fetchall()
            if not cols:
                return _err(f"table not found: {schema}.{tname}")
            cur.execute(
                "SELECT kcu.column_name FROM information_schema.table_constraints tc "
                "JOIN information_schema.key_column_usage kcu "
                "ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema "
                "WHERE tc.table_schema=%s AND tc.table_name=%s AND tc.constraint_type='PRIMARY KEY';",
                [schema, tname],
            )
            pk = [r["column_name"] for r in cur.fetchall()]
            return {"ok": True, "schema": schema, "table": tname, "columns": cols, "primary_key": pk}
    except Exception as e:
        return _err(str(e))


@mcp.tool()
def select(
    table: str = Field(description="Table name, optionally schema-qualified"),
    columns: list[str] | None = Field(default=None, description="Column list (default all)"),
    where: dict[str, Any] | None = Field(default=None, description="Equality filters, {col: value}"),
    order_by: str | None = Field(default=None, description="Column to order by (asc)"),
    limit: int = Field(default=100, description="Max rows to return (<= MAX_ROWS)"),
    offset: int = Field(default=0, description="Rows to skip (>= 0)"),
) -> dict[str, Any]:
    """Safe SELECT with equality filters."""
    if err := _require("read"):
        return err
    try:
        cols_sql = "*" if not columns else ", ".join(_quote_ident(c) for c in columns)
        sql = f"SELECT {cols_sql} FROM {_quote_ident(table)}"
        params: list[Any] = []
        if where:
            clauses = []
            for k, v in where.items():
                clauses.append(f"{_quote_ident(k)} = %s")
                params.append(v)
            sql += " WHERE " + " AND ".join(clauses)
        if order_by:
            sql += f" ORDER BY {_quote_ident(order_by)}"
        safe_limit, safe_offset = _sanitize_paging(limit, offset)
        sql += f" LIMIT {safe_limit} OFFSET {safe_offset}"
        with _connect() as conn, conn.cursor() as cur:
            cur.execute(sql, params or None)
            rows = cur.fetchall()
            return {
                "ok": True,
                "sql": sql,
                "row_count": len(rows),
                "rows": rows,
                "limit": safe_limit,
                "offset": safe_offset,
            }
    except Exception as e:
        return _err(str(e))


@mcp.tool()
def insert(
    table: str = Field(description="Target table"),
    values: dict[str, Any] = Field(description="Column -> value map"),
    returning: list[str] | None = Field(default=None, description="Columns to return"),
) -> dict[str, Any]:
    """Insert a single row."""
    if err := _require("write"):
        return err
    if not values:
        return _err("values is empty")

    request_id = str(uuid.uuid4())
    started = time.monotonic()
    actor = _current_actor()

    try:
        cols = list(values.keys())
        placeholders = ", ".join(["%s"] * len(cols))
        col_sql = ", ".join(_quote_ident(c) for c in cols)
        sql = f"INSERT INTO {_quote_ident(table)} ({col_sql}) VALUES ({placeholders})"
        if returning:
            sql += " RETURNING " + ", ".join(_quote_ident(c) for c in returning)

        _audit(
            "insert_start",
            request_id=request_id,
            actor=actor,
            table=table,
            returning=returning or [],
            column_count=len(cols),
        )

        with _connect() as conn, conn.cursor() as cur:
            cur.execute(sql, list(values.values()))
            ret = cur.fetchone() if returning else None
            affected = cur.rowcount
            conn.commit()

        duration_ms = int((time.monotonic() - started) * 1000)
        _audit(
            "insert_success",
            request_id=request_id,
            actor=actor,
            table=table,
            affected=affected,
            duration_ms=duration_ms,
        )
        return {"ok": True, "affected": affected, "returning": ret, "sql": sql, "request_id": request_id}
    except Exception as e:
        duration_ms = int((time.monotonic() - started) * 1000)
        _audit(
            "insert_error",
            request_id=request_id,
            actor=actor,
            table=table,
            duration_ms=duration_ms,
            error=str(e),
        )
        return _err(str(e), request_id=request_id)


@mcp.tool()
def update(
    table: str = Field(description="Target table"),
    values: dict[str, Any] = Field(description="Columns to set"),
    where: dict[str, Any] = Field(description="Equality filters. Empty dict is REJECTED to prevent full-table updates."),
) -> dict[str, Any]:
    """Update rows matching equality filters. Refuses to run without WHERE."""
    if err := _require("write"):
        return err
    if not values:
        return _err("values is empty")
    if not where:
        return _err("where is empty; refusing full-table update")

    request_id = str(uuid.uuid4())
    started = time.monotonic()
    actor = _current_actor()

    try:
        set_sql = ", ".join(f"{_quote_ident(k)} = %s" for k in values.keys())
        where_sql = " AND ".join(f"{_quote_ident(k)} = %s" for k in where.keys())
        sql = f"UPDATE {_quote_ident(table)} SET {set_sql} WHERE {where_sql}"
        params = list(values.values()) + list(where.values())

        _audit(
            "update_start",
            request_id=request_id,
            actor=actor,
            table=table,
            set_columns=list(values.keys()),
            where_columns=list(where.keys()),
        )

        with _connect() as conn, conn.cursor() as cur:
            cur.execute(sql, params)
            affected = cur.rowcount
            conn.commit()

        duration_ms = int((time.monotonic() - started) * 1000)
        _audit(
            "update_success",
            request_id=request_id,
            actor=actor,
            table=table,
            affected=affected,
            duration_ms=duration_ms,
        )
        return {"ok": True, "affected": affected, "sql": sql, "request_id": request_id}
    except Exception as e:
        duration_ms = int((time.monotonic() - started) * 1000)
        _audit(
            "update_error",
            request_id=request_id,
            actor=actor,
            table=table,
            duration_ms=duration_ms,
            error=str(e),
        )
        return _err(str(e), request_id=request_id)


@mcp.tool()
def delete(
    table: str = Field(description="Target table"),
    where: dict[str, Any] = Field(description="Equality filters. Empty dict is REJECTED to prevent full-table deletes."),
) -> dict[str, Any]:
    """Delete rows matching equality filters. Refuses to run without WHERE."""
    if err := _require("write"):
        return err
    if not where:
        return _err("where is empty; refusing full-table delete")

    request_id = str(uuid.uuid4())
    started = time.monotonic()
    actor = _current_actor()

    try:
        where_sql = " AND ".join(f"{_quote_ident(k)} = %s" for k in where.keys())
        sql = f"DELETE FROM {_quote_ident(table)} WHERE {where_sql}"

        _audit(
            "delete_start",
            request_id=request_id,
            actor=actor,
            table=table,
            where_columns=list(where.keys()),
        )

        with _connect() as conn, conn.cursor() as cur:
            cur.execute(sql, list(where.values()))
            affected = cur.rowcount
            conn.commit()

        duration_ms = int((time.monotonic() - started) * 1000)
        _audit(
            "delete_success",
            request_id=request_id,
            actor=actor,
            table=table,
            affected=affected,
            duration_ms=duration_ms,
        )
        return {"ok": True, "affected": affected, "sql": sql, "request_id": request_id}
    except Exception as e:
        duration_ms = int((time.monotonic() - started) * 1000)
        _audit(
            "delete_error",
            request_id=request_id,
            actor=actor,
            table=table,
            duration_ms=duration_ms,
            error=str(e),
        )
        return _err(str(e), request_id=request_id)


if __name__ == "__main__":
    if not AUTH_ENABLED:
        log.warning("All MCP_TOKEN_* are EMPTY — authentication is DISABLED. Do not expose beyond localhost.")
    else:
        roles = [r for r, t in TOKENS.items() if t]
        log.info("Bearer auth ENABLED. Roles: %s. Exempt paths: %s",
                 ", ".join(roles), ", ".join(AUTH_EXEMPT_PATHS) or "(none)")

    pool.open()
    log.info("DB connection pool opened (min=%d, max=%d)", POOL_MIN_SIZE, POOL_MAX_SIZE)

    log.info(
        "Starting DB MCP on http://%s:%d/mcp  (DB=%s@%s:%d/%s)",
        MCP_HOST, MCP_PORT, DB_USER, DB_HOST, DB_PORT, DB_NAME,
    )

    app = mcp.streamable_http_app()
    if AUTH_ENABLED:
        app.add_middleware(BearerAuthMiddleware, tokens=TOKENS, exempt=AUTH_EXEMPT_PATHS)
    uvicorn.run(app, host=MCP_HOST, port=MCP_PORT)
