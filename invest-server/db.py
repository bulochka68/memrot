"""Доступ к Postgres: пул соединений + запросы по клиентским данным."""

import os

import psycopg2
import psycopg2.extras
import psycopg2.pool

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://invest:invest@postgres:5432/invest")

_pool: psycopg2.pool.SimpleConnectionPool | None = None


def _get_pool() -> psycopg2.pool.SimpleConnectionPool:
    global _pool
    if _pool is None:
        _pool = psycopg2.pool.SimpleConnectionPool(1, 10, DATABASE_URL)
    return _pool


def _query(sql: str, params: tuple) -> list[dict]:
    pool = _get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, params)
            return [dict(row) for row in cur.fetchall()]
    finally:
        pool.putconn(conn)


def get_client_with_accounts(cus: str) -> dict | None:
    clients = _query("SELECT cus, name FROM clients WHERE cus = %s", (cus,))
    if not clients:
        return None
    client = clients[0]
    accounts = _query(
        "SELECT account_id, cash_rub FROM accounts WHERE cus = %s ORDER BY account_id", (cus,)
    )
    for acc in accounts:
        positions = _query(
            "SELECT isin, amount FROM positions WHERE account_id = %s ORDER BY isin",
            (acc["account_id"],),
        )
        acc["positions"] = positions
        acc["cash_rub"] = float(acc["cash_rub"])
        for p in positions:
            p["amount"] = float(p["amount"])
    client["accounts"] = accounts
    return client


def get_account_owner(account_id: str) -> str | None:
    rows = _query("SELECT cus FROM accounts WHERE account_id = %s", (account_id,))
    return rows[0]["cus"] if rows else None


def get_tax_record(account_id: str, year: int) -> dict | None:
    rows = _query(
        "SELECT income, tax_accrued, tax_paid, tax_to_pay, tax_to_return "
        "FROM tax_records WHERE account_id = %s AND year = %s",
        (account_id, year),
    )
    if not rows:
        return None
    record = rows[0]
    return {k: float(v) for k, v in record.items()}


def get_operations(account_id: str, date_from: str | None, date_to: str | None) -> list[dict]:
    sql = "SELECT date, type, isin, amount, sum FROM operations WHERE account_id = %s"
    params: list = [account_id]
    if date_from:
        sql += " AND date >= %s"
        params.append(date_from)
    if date_to:
        sql += " AND date <= %s"
        params.append(date_to)
    sql += " ORDER BY date"
    rows = _query(sql, tuple(params))
    for r in rows:
        r["date"] = r["date"].isoformat()
        r["amount"] = float(r["amount"])
        r["sum"] = float(r["sum"])
    return rows


def get_training(cus: str) -> list[dict]:
    rows = _query(
        "SELECT test_id, test_name, completed FROM client_training WHERE cus = %s ORDER BY test_id",
        (cus,),
    )
    return rows
