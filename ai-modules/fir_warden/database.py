"""
database.py — Local SQLite backend replacing Supabase.
Provides a compatibility layer for the Supabase-style chainable API.
"""

import os
import sqlite3
import json
import threading
from pathlib import Path
from dotenv import load_dotenv

# Load environment
load_dotenv(dotenv_path=Path(__file__).parents[2] / ".env")

DB_PATH = Path(__file__).parent / "kavach_local.db"
db_lock = threading.Lock()

class SQLiteQueryBuilder:
    def __init__(self, table_name):
        self.table_name = table_name
        self.filters = []
        self.limit_val = None
        self.order_by = None
        self.op_type = None # select, insert, update, delete
        self.data_payload = None

    def select(self, columns="*"):
        self.op_type = "select"
        self.columns = columns
        return self

    def insert(self, data):
        self.op_type = "insert"
        self.data_payload = data
        return self

    def update(self, data):
        self.op_type = "update"
        self.data_payload = data
        return self

    def upsert(self, data, on_conflict=None):
        self.op_type = "upsert"
        self.data_payload = data
        self.on_conflict = on_conflict
        return self

    def eq(self, column, value):
        self.filters.append((column, "=", value))
        return self

    def in_(self, column, values):
        self.filters.append((column, "IN", values))
        return self

    def gte(self, column, value):
        self.filters.append((column, ">=", value))
        return self

    def lte(self, column, value):
        self.filters.append((column, "<=", value))
        return self

    def order(self, column, desc=False):
        self.order_by = f"{column} {'DESC' if desc else 'ASC'}"
        return self

    def limit(self, val):
        self.limit_val = val
        return self

    def execute(self):
        with db_lock:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            result_data = []
            try:
                if self.op_type == "select":
                    query = f"SELECT {self.columns} FROM {self.table_name}"
                    params = []
                    if self.filters:
                        where_clauses = []
                        params = []
                        for col, op, val in self.filters:
                            if op == "IN":
                                placeholders = ", ".join(["?" for _ in val])
                                where_clauses.append(f"{col} IN ({placeholders})")
                                params.extend(val)
                            else:
                                where_clauses.append(f"{col} {op} ?")
                                params.append(val)
                        query += " WHERE " + " AND ".join(where_clauses)
                    if self.order_by:
                        query += f" ORDER BY {self.order_by}"
                    if self.limit_val:
                        query += f" LIMIT {self.limit_val}"
                    
                    cursor.execute(query, params)
                    result_data = [dict(row) for row in cursor.fetchall()]

                elif self.op_type == "insert":
                    # Handle JSON fields (if any)
                    prepared_data = {}
                    for k, v in self.data_payload.items():
                        if isinstance(v, (dict, list)):
                            prepared_data[k] = json.dumps(v)
                        else:
                            prepared_data[k] = v
                    
                    cols = ", ".join(prepared_data.keys())
                    placeholders = ", ".join(["?" for _ in prepared_data])
                    query = f"INSERT INTO {self.table_name} ({cols}) VALUES ({placeholders})"
                    cursor.execute(query, list(prepared_data.values()))
                    conn.commit()

                elif self.op_type == "update":
                    prepared_data = {}
                    for k, v in self.data_payload.items():
                        if isinstance(v, (dict, list)):
                            prepared_data[k] = json.dumps(v)
                        else:
                            prepared_data[k] = v
                    
                    set_clause = ", ".join([f"{k} = ?" for k in prepared_data.keys()])
                    params = list(prepared_data.values())
                    query = f"UPDATE {self.table_name} SET {set_clause}"
                    if self.filters:
                        query += " WHERE " + " AND ".join([f"{f[0]} {f[1]} ?" for f in self.filters])
                        params += [f[2] for f in self.filters]
                    
                    cursor.execute(query, params)
                    conn.commit()

                elif self.op_type == "upsert":
                    prepared_data = {}
                    for k, v in self.data_payload.items():
                        if isinstance(v, (dict, list)):
                            prepared_data[k] = json.dumps(v)
                        else:
                            prepared_data[k] = v
                    
                    cols = ", ".join(prepared_data.keys())
                    placeholders = ", ".join(["?" for _ in prepared_data])
                    query = f"INSERT INTO {self.table_name} ({cols}) VALUES ({placeholders})"
                    if self.on_conflict:
                        conflict_col = self.on_conflict
                        update_clause = ", ".join([f"{k} = EXCLUDED.{k}" for k in prepared_data.keys() if k != conflict_col])
                        query += f" ON CONFLICT({conflict_col}) DO UPDATE SET {update_clause}"
                    
                    cursor.execute(query, list(prepared_data.values()))
                    conn.commit()

            except Exception as e:
                print(f"[SQLite] Error in {self.op_type} on {self.table_name}: {e}")
            finally:
                conn.close()

            class Result:
                def __init__(self, data):
                    self.data = data
            return Result(result_data)

class SQLiteClient:
    def table(self, name):
        return SQLiteQueryBuilder(name)

_client = SQLiteClient()

def get_supabase():
    return _client

def init_db():
    from .init_local_db import init_local_db
    init_local_db()

def log_audit(action: str, detail: dict):
    from .utils import now_iso
    _client.table("audit_log").insert({
        "action": action,
        "detail": detail,
        "ts": now_iso()
    }).execute()

def emit_event(event_type: str, location: str, confidence: float, payload: dict = {}):
    from .utils import now_iso, new_id
    from net_watch.fusion import check_fusion
    ev_id = new_id()
    _client.table("events").insert({
        "event_type": event_type,
        "summary": f"Event triggered in {location}",
        "occurred_at": now_iso(),
        "detail": payload,
        "severity": "high" if confidence > 0.8 else "info"
    }).execute()
    try:
        check_fusion(event_type)
    except: pass
    return ev_id

def get_db():
    raise RuntimeError("get_db() is deprecated. Use get_supabase().")
