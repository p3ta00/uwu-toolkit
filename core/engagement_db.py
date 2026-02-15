"""
Engagement Database for UwU Toolkit
SQLite-backed relational database replacing scattered JSON files.

Tracks targets, credentials, sessions, findings, loot, timeline,
attack graph edges, and engagement configuration in a single DB.

Usage:
    from core.engagement_db import EngagementDB
    db = EngagementDB.get_instance()
    db.add_target("10.10.10.1", hostname="dc01.corp.local", is_dc=True)
    db.add_credential("admin", domain="CORP", password="P@ss1234", source="kerberoast")
"""

import json
import os
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Schema DDL
# ---------------------------------------------------------------------------

_SCHEMA = """
-- Target machines discovered during engagement
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    hostname TEXT DEFAULT '',
    domain TEXT DEFAULT '',
    os_info TEXT DEFAULT '',
    arch TEXT DEFAULT '',
    is_dc BOOLEAN DEFAULT 0,
    ports TEXT DEFAULT '[]',
    vhosts TEXT DEFAULT '[]',
    notes TEXT DEFAULT '',
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(ip)
);

-- Credentials found during engagement
CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    domain TEXT DEFAULT '',
    password TEXT DEFAULT '',
    ntlm_hash TEXT DEFAULT '',
    aes_key TEXT DEFAULT '',
    ticket_path TEXT DEFAULT '',
    cred_type TEXT DEFAULT 'password',
    source TEXT DEFAULT '',
    cracked BOOLEAN DEFAULT 0,
    admin_on TEXT DEFAULT '[]',
    notes TEXT DEFAULT '',
    added TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(username, domain, cred_type)
);

-- Active sessions
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY,
    session_type TEXT NOT NULL,
    target_id INTEGER REFERENCES targets(id) ON DELETE SET NULL,
    credential_id INTEGER REFERENCES credentials(id) ON DELETE SET NULL,
    target_ip TEXT NOT NULL,
    port INTEGER DEFAULT 0,
    username TEXT DEFAULT '',
    domain TEXT DEFAULT '',
    status TEXT DEFAULT 'active',
    pid INTEGER DEFAULT 0,
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Security findings
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    severity TEXT DEFAULT 'info',
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    evidence TEXT DEFAULT '',
    target_id INTEGER REFERENCES targets(id) ON DELETE SET NULL,
    module_used TEXT DEFAULT '',
    remediation TEXT DEFAULT '',
    found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Loot files
CREATE TABLE IF NOT EXISTS loot (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filepath TEXT NOT NULL,
    loot_type TEXT DEFAULT 'file',
    description TEXT DEFAULT '',
    source_session INTEGER REFERENCES sessions(id) ON DELETE SET NULL,
    target_id INTEGER REFERENCES targets(id) ON DELETE SET NULL,
    collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Timeline of all actions
CREATE TABLE IF NOT EXISTS timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    action TEXT NOT NULL,
    tool TEXT DEFAULT '',
    target TEXT DEFAULT '',
    target_id INTEGER REFERENCES targets(id) ON DELETE SET NULL,
    credential_id INTEGER REFERENCES credentials(id) ON DELETE SET NULL,
    session_id INTEGER REFERENCES sessions(id) ON DELETE SET NULL,
    result TEXT DEFAULT '',
    output_summary TEXT DEFAULT '',
    opsec_rating TEXT DEFAULT '',
    duration_ms INTEGER DEFAULT 0
);

-- Attack graph edges
CREATE TABLE IF NOT EXISTS attack_graph (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_node TEXT NOT NULL,
    source_type TEXT DEFAULT 'user',
    edge_type TEXT NOT NULL,
    target_node TEXT NOT NULL,
    target_type TEXT DEFAULT 'user',
    module_used TEXT DEFAULT '',
    exploited BOOLEAN DEFAULT 0,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Engagement configuration
CREATE TABLE IF NOT EXISTS engagement_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""


# ---------------------------------------------------------------------------
# EngagementDB
# ---------------------------------------------------------------------------

class EngagementDB:
    """
    SQLite-backed engagement database.

    Singleton instance accessible via ``get_instance()``.  All write
    operations are serialized through a ``threading.Lock`` while reads can
    proceed concurrently thanks to WAL journal mode.

    JSON columns (``ports``, ``vhosts``, ``admin_on``) are transparently
    serialized / deserialized so callers always work with native Python
    lists.
    """

    _instance: Optional["EngagementDB"] = None
    _instance_lock = threading.Lock()

    # JSON-encoded columns that should be auto-deserialized
    _JSON_COLUMNS = frozenset({"ports", "vhosts", "admin_on"})

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            config_dir = Path(os.path.expanduser("~/.uwu-toolkit"))
            config_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            db_path = str(config_dir / "engagement.db")

        self._db_path = db_path
        self._write_lock = threading.Lock()

        # Open connection (thread-safe, dict rows)
        # NOTE: We intentionally omit PARSE_DECLTYPES/PARSE_COLNAMES so that
        # TIMESTAMP columns are returned as plain ISO-8601 strings rather than
        # being fed through sqlite3's naive datetime converter (which chokes
        # on the 'T' separator we use).
        self._conn = sqlite3.connect(
            self._db_path,
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")

        # Create schema
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Singleton
    # ------------------------------------------------------------------

    @classmethod
    def get_instance(cls, db_path: Optional[str] = None) -> "EngagementDB":
        """Return the global singleton, creating it if necessary."""
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls(db_path)
        return cls._instance

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _now(self) -> str:
        """ISO-8601 timestamp for the current moment."""
        return datetime.utcnow().isoformat(timespec="seconds") + "Z"

    def _execute(self, query: str, params: tuple = ()) -> sqlite3.Cursor:
        """Execute a write query under the write lock."""
        with self._write_lock:
            try:
                cur = self._conn.execute(query, params)
                self._conn.commit()
                return cur
            except sqlite3.Error as exc:
                self._conn.rollback()
                raise exc

    def _fetchone(self, query: str, params: tuple = ()) -> Optional[Dict[str, Any]]:
        """Execute a read query and return a single row as a dict (or None)."""
        try:
            cur = self._conn.execute(query, params)
            row = cur.fetchone()
            return self._row_to_dict(row) if row is not None else None
        except sqlite3.Error:
            return None

    def _fetchall(self, query: str, params: tuple = ()) -> List[Dict[str, Any]]:
        """Execute a read query and return all rows as a list of dicts."""
        try:
            cur = self._conn.execute(query, params)
            return [self._row_to_dict(r) for r in cur.fetchall()]
        except sqlite3.Error:
            return []

    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        """Convert a ``sqlite3.Row`` to a plain dict, deserializing JSON columns."""
        d = dict(row)
        for col in self._JSON_COLUMNS:
            if col in d and isinstance(d[col], str):
                try:
                    d[col] = json.loads(d[col])
                except (json.JSONDecodeError, TypeError):
                    d[col] = []
        return d

    @staticmethod
    def _json_dumps(obj: Any) -> str:
        """Compact JSON serialization for storage."""
        return json.dumps(obj, separators=(",", ":"), default=str)

    def _resolve_target_id(self, target_id_or_ip) -> Optional[int]:
        """Resolve a target_id (int) or IP (str) to a target row id."""
        if isinstance(target_id_or_ip, int):
            return target_id_or_ip
        row = self._fetchone("SELECT id FROM targets WHERE ip = ?", (str(target_id_or_ip),))
        return row["id"] if row else None

    # ==================================================================
    # Targets
    # ==================================================================

    def add_target(
        self,
        ip: str,
        hostname: str = "",
        domain: str = "",
        os_info: str = "",
        is_dc: bool = False,
        ports: Optional[List[Dict[str, Any]]] = None,
        notes: str = "",
    ) -> int:
        """
        Add or update a target (upsert on *ip*).

        Returns:
            The ``id`` of the inserted or existing row.
        """
        now = self._now()
        ports_json = self._json_dumps(ports or [])

        try:
            cur = self._execute(
                """
                INSERT INTO targets (ip, hostname, domain, os_info, is_dc, ports, notes, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    hostname  = CASE WHEN excluded.hostname  != '' THEN excluded.hostname  ELSE targets.hostname  END,
                    domain    = CASE WHEN excluded.domain    != '' THEN excluded.domain    ELSE targets.domain    END,
                    os_info   = CASE WHEN excluded.os_info   != '' THEN excluded.os_info   ELSE targets.os_info   END,
                    is_dc     = CASE WHEN excluded.is_dc     THEN 1 ELSE targets.is_dc END,
                    ports     = CASE WHEN excluded.ports     != '[]' THEN excluded.ports   ELSE targets.ports     END,
                    notes     = CASE WHEN excluded.notes     != '' THEN excluded.notes     ELSE targets.notes     END,
                    last_seen = excluded.last_seen
                """,
                (ip, hostname, domain, os_info, int(is_dc), ports_json, notes, now, now),
            )
            if cur.lastrowid:
                return cur.lastrowid
        except sqlite3.Error:
            pass

        # Fallback: row already existed, fetch its id
        row = self._fetchone("SELECT id FROM targets WHERE ip = ?", (ip,))
        return row["id"] if row else -1

    def get_target(self, target_id: int) -> Optional[Dict[str, Any]]:
        """Get a target by its primary key."""
        return self._fetchone("SELECT * FROM targets WHERE id = ?", (target_id,))

    def get_target_by_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get a target by IP address."""
        return self._fetchone("SELECT * FROM targets WHERE ip = ?", (ip,))

    def list_targets(self, domain: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List all targets, optionally filtered by *domain*.

        Returns:
            List of target dicts sorted by ``id``.
        """
        if domain:
            return self._fetchall(
                "SELECT * FROM targets WHERE LOWER(domain) = LOWER(?) ORDER BY id",
                (domain,),
            )
        return self._fetchall("SELECT * FROM targets ORDER BY id")

    def update_target(self, target_id: int, **kwargs) -> bool:
        """
        Update arbitrary columns on a target row.

        Accepts keyword arguments whose names match column names.
        JSON-list columns (``ports``, ``vhosts``) are serialized automatically.

        Returns:
            ``True`` if the row was found and updated.
        """
        if not kwargs:
            return False
        sets = []
        vals: list = []
        for col, val in kwargs.items():
            if col in self._JSON_COLUMNS and not isinstance(val, str):
                val = self._json_dumps(val)
            sets.append(f"{col} = ?")
            vals.append(val)
        sets.append("last_seen = ?")
        vals.append(self._now())
        vals.append(target_id)
        try:
            cur = self._execute(
                f"UPDATE targets SET {', '.join(sets)} WHERE id = ?",
                tuple(vals),
            )
            return cur.rowcount > 0
        except sqlite3.Error:
            return False

    def add_target_port(
        self,
        target_id_or_ip,
        port: int,
        service: str = "",
        version: str = "",
    ) -> bool:
        """
        Append a port entry to a target's ``ports`` JSON array.

        Deduplicates by port number.

        Returns:
            ``True`` on success.
        """
        tid = self._resolve_target_id(target_id_or_ip)
        if tid is None:
            return False
        target = self.get_target(tid)
        if target is None:
            return False
        ports: list = target.get("ports", [])
        # Deduplicate by port number
        if any(p.get("port") == port for p in ports):
            # Update existing entry
            ports = [
                ({"port": port, "service": service, "version": version} if p.get("port") == port else p)
                for p in ports
            ]
        else:
            ports.append({"port": port, "service": service, "version": version})
        return self.update_target(tid, ports=ports)

    def add_target_vhost(self, target_id_or_ip, vhost: str) -> bool:
        """
        Append a virtual hostname to a target's ``vhosts`` JSON array.

        Returns:
            ``True`` on success, ``False`` if already present or target not found.
        """
        tid = self._resolve_target_id(target_id_or_ip)
        if tid is None:
            return False
        target = self.get_target(tid)
        if target is None:
            return False
        vhosts: list = target.get("vhosts", [])
        if vhost in vhosts:
            return True  # already present
        vhosts.append(vhost)
        return self.update_target(tid, vhosts=vhosts)

    def delete_target(self, target_id: int) -> bool:
        """
        Delete a target by id.

        Returns:
            ``True`` if a row was deleted.
        """
        try:
            cur = self._execute("DELETE FROM targets WHERE id = ?", (target_id,))
            return cur.rowcount > 0
        except sqlite3.Error:
            return False

    # ==================================================================
    # Credentials
    # ==================================================================

    def add_credential(
        self,
        username: str,
        domain: str = "",
        password: str = "",
        ntlm_hash: str = "",
        aes_key: str = "",
        cred_type: str = "password",
        source: str = "",
        notes: str = "",
    ) -> int:
        """
        Add or update a credential (upsert on *username*, *domain*, *cred_type*).

        Returns:
            The ``id`` of the credential row.
        """
        now = self._now()

        try:
            cur = self._execute(
                """
                INSERT INTO credentials
                    (username, domain, password, ntlm_hash, aes_key, cred_type, source, notes, added, updated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(username, domain, cred_type) DO UPDATE SET
                    password  = CASE WHEN excluded.password  != '' THEN excluded.password  ELSE credentials.password  END,
                    ntlm_hash = CASE WHEN excluded.ntlm_hash != '' THEN excluded.ntlm_hash ELSE credentials.ntlm_hash END,
                    aes_key   = CASE WHEN excluded.aes_key   != '' THEN excluded.aes_key   ELSE credentials.aes_key   END,
                    source    = CASE WHEN excluded.source    != '' THEN excluded.source    ELSE credentials.source    END,
                    notes     = CASE WHEN excluded.notes     != '' THEN excluded.notes     ELSE credentials.notes     END,
                    updated   = excluded.updated
                """,
                (username, domain, password, ntlm_hash, aes_key, cred_type, source, notes, now, now),
            )
            if cur.lastrowid:
                return cur.lastrowid
        except sqlite3.Error:
            pass

        row = self._fetchone(
            "SELECT id FROM credentials WHERE username = ? AND domain = ? AND cred_type = ?",
            (username, domain, cred_type),
        )
        return row["id"] if row else -1

    def get_credential(self, cred_id: int) -> Optional[Dict[str, Any]]:
        """Get a credential by primary key."""
        return self._fetchone("SELECT * FROM credentials WHERE id = ?", (cred_id,))

    def list_credentials(
        self,
        domain: Optional[str] = None,
        cracked_only: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        List credentials, optionally filtered by *domain* and/or cracked status.

        Returns:
            List of credential dicts sorted by ``id``.
        """
        clauses: List[str] = []
        params: List[Any] = []
        if domain:
            clauses.append("LOWER(domain) = LOWER(?)")
            params.append(domain)
        if cracked_only:
            clauses.append("cracked = 1")
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        return self._fetchall(f"SELECT * FROM credentials {where} ORDER BY id", tuple(params))

    def search_credentials(self, query: str) -> List[Dict[str, Any]]:
        """
        Free-text search across username, domain, source, and notes.

        Returns:
            Matching credential rows.
        """
        like = f"%{query}%"
        return self._fetchall(
            """
            SELECT * FROM credentials
            WHERE username LIKE ? OR domain LIKE ? OR source LIKE ? OR notes LIKE ?
            ORDER BY id
            """,
            (like, like, like, like),
        )

    def mark_admin_on(self, cred_id: int, target_ip: str) -> bool:
        """
        Record that a credential has admin access on *target_ip*.

        Returns:
            ``True`` on success.
        """
        cred = self.get_credential(cred_id)
        if cred is None:
            return False
        admin_list: list = cred.get("admin_on", [])
        if target_ip not in admin_list:
            admin_list.append(target_ip)
        try:
            self._execute(
                "UPDATE credentials SET admin_on = ?, updated = ? WHERE id = ?",
                (self._json_dumps(admin_list), self._now(), cred_id),
            )
            return True
        except sqlite3.Error:
            return False

    def mark_cracked(self, cred_id: int, password: str) -> bool:
        """
        Mark a credential as cracked and store the plaintext *password*.

        Returns:
            ``True`` on success.
        """
        try:
            cur = self._execute(
                "UPDATE credentials SET cracked = 1, password = ?, updated = ? WHERE id = ?",
                (password, self._now(), cred_id),
            )
            return cur.rowcount > 0
        except sqlite3.Error:
            return False

    def delete_credential(self, cred_id: int) -> bool:
        """
        Delete a credential by id.

        Returns:
            ``True`` if a row was deleted.
        """
        try:
            cur = self._execute("DELETE FROM credentials WHERE id = ?", (cred_id,))
            return cur.rowcount > 0
        except sqlite3.Error:
            return False

    def import_secretsdump(self, filepath: str) -> int:
        """
        Import credentials from an Impacket secretsdump output file.

        Expected line format::

            [DOMAIN\\]user:rid:lmhash:nthash:::

        Lines with empty NT hashes (``31d6cfe0d16ae931b73c59d7e0c089c0``)
        are skipped automatically.

        Returns:
            Number of credentials imported.
        """
        count = 0
        try:
            with open(filepath, "r") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("["):
                        continue

                    parts = line.split(":")
                    if len(parts) < 4:
                        continue

                    user_part = parts[0]
                    nt_hash = parts[3]

                    # Skip disabled / empty hashes
                    if nt_hash.lower() == "31d6cfe0d16ae931b73c59d7e0c089c0":
                        continue

                    domain = ""
                    username = user_part
                    if "\\" in user_part:
                        domain, username = user_part.split("\\", 1)

                    # Skip computer accounts
                    if username.endswith("$"):
                        continue

                    self.add_credential(
                        username=username,
                        domain=domain,
                        ntlm_hash=nt_hash,
                        cred_type="hash",
                        source=f"secretsdump:{os.path.basename(filepath)}",
                    )
                    count += 1
        except (OSError, IOError):
            pass
        return count

    def export_hashcat(self, filepath: Optional[str] = None) -> str:
        """
        Export all NT hashes in ``[DOMAIN\\\\]user:hash`` format suitable
        for hashcat mode 1000.

        If *filepath* is provided the output is also written to that file.

        Returns:
            The exported text.
        """
        creds = self._fetchall(
            "SELECT username, domain, ntlm_hash FROM credentials WHERE ntlm_hash != '' ORDER BY id"
        )
        lines: List[str] = []
        for c in creds:
            prefix = f"{c['domain']}\\{c['username']}" if c.get("domain") else c["username"]
            lines.append(f"{prefix}:{c['ntlm_hash']}")
        content = "\n".join(lines)
        if filepath:
            try:
                with open(filepath, "w") as fh:
                    fh.write(content + "\n")
            except OSError:
                pass
        return content

    # ==================================================================
    # Sessions
    # ==================================================================

    def register_session(
        self,
        session_id: int,
        session_type: str,
        target_ip: str,
        port: int,
        username: str = "",
        domain: str = "",
        credential_id: Optional[int] = None,
        pid: int = 0,
    ) -> None:
        """
        Register a new active session.

        The *session_id* is caller-assigned (e.g. from Sliver or a local
        counter) and used as the primary key.
        """
        target = self.get_target_by_ip(target_ip)
        target_id = target["id"] if target else None
        now = self._now()
        try:
            self._execute(
                """
                INSERT OR REPLACE INTO sessions
                    (id, session_type, target_id, credential_id, target_ip, port,
                     username, domain, status, pid, created, last_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
                """,
                (session_id, session_type, target_id, credential_id, target_ip,
                 port, username, domain, pid, now, now),
            )
        except sqlite3.Error:
            pass

    def update_session_status(self, session_id: int, status: str) -> None:
        """Update the status of a session (e.g. ``active``, ``closed``, ``dead``)."""
        try:
            self._execute(
                "UPDATE sessions SET status = ?, last_active = ? WHERE id = ?",
                (status, self._now(), session_id),
            )
        except sqlite3.Error:
            pass

    def remove_session(self, session_id: int) -> None:
        """Delete a session record."""
        try:
            self._execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        except sqlite3.Error:
            pass

    def list_sessions(self, active_only: bool = True) -> List[Dict[str, Any]]:
        """
        List sessions.

        Args:
            active_only: If ``True`` (default), only return sessions with
                ``status = 'active'``.

        Returns:
            List of session dicts.
        """
        if active_only:
            return self._fetchall(
                "SELECT * FROM sessions WHERE status = 'active' ORDER BY created DESC"
            )
        return self._fetchall("SELECT * FROM sessions ORDER BY created DESC")

    # ==================================================================
    # Findings
    # ==================================================================

    def add_finding(
        self,
        title: str,
        severity: str = "info",
        description: str = "",
        evidence: str = "",
        target_id: Optional[int] = None,
        module_used: str = "",
        remediation: str = "",
    ) -> int:
        """
        Record a security finding.

        Args:
            severity: One of ``critical``, ``high``, ``medium``, ``low``, ``info``.

        Returns:
            The ``id`` of the new finding.
        """
        severity = severity.lower()
        if severity not in ("critical", "high", "medium", "low", "info"):
            severity = "info"
        try:
            cur = self._execute(
                """
                INSERT INTO findings
                    (severity, title, description, evidence, target_id, module_used, remediation, found_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (severity, title, description, evidence, target_id, module_used, remediation, self._now()),
            )
            return cur.lastrowid or -1
        except sqlite3.Error:
            return -1

    def list_findings(self, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List findings, optionally filtered by *severity*.

        Returns:
            List of finding dicts, most recent first.
        """
        if severity:
            return self._fetchall(
                "SELECT * FROM findings WHERE LOWER(severity) = LOWER(?) ORDER BY found_at DESC",
                (severity,),
            )
        return self._fetchall("SELECT * FROM findings ORDER BY found_at DESC")

    # ==================================================================
    # Loot
    # ==================================================================

    def add_loot(
        self,
        filepath: str,
        loot_type: str = "file",
        description: str = "",
        source_session: Optional[int] = None,
        target_id: Optional[int] = None,
    ) -> int:
        """
        Record a piece of loot (file, screenshot, config, etc.).

        Returns:
            The ``id`` of the new loot entry.
        """
        try:
            cur = self._execute(
                """
                INSERT INTO loot (filepath, loot_type, description, source_session, target_id, collected_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (filepath, loot_type, description, source_session, target_id, self._now()),
            )
            return cur.lastrowid or -1
        except sqlite3.Error:
            return -1

    def list_loot(self, loot_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List loot entries, optionally filtered by *loot_type*.

        Returns:
            List of loot dicts, most recent first.
        """
        if loot_type:
            return self._fetchall(
                "SELECT * FROM loot WHERE LOWER(loot_type) = LOWER(?) ORDER BY collected_at DESC",
                (loot_type,),
            )
        return self._fetchall("SELECT * FROM loot ORDER BY collected_at DESC")

    # ==================================================================
    # Timeline
    # ==================================================================

    def log_action(
        self,
        action: str,
        tool: str = "",
        target: str = "",
        target_id: Optional[int] = None,
        credential_id: Optional[int] = None,
        session_id: Optional[int] = None,
        result: str = "",
        output_summary: str = "",
        opsec_rating: str = "",
        duration_ms: int = 0,
    ) -> int:
        """
        Append an entry to the engagement timeline.

        Returns:
            The ``id`` of the new timeline entry.
        """
        try:
            cur = self._execute(
                """
                INSERT INTO timeline
                    (timestamp, action, tool, target, target_id, credential_id,
                     session_id, result, output_summary, opsec_rating, duration_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (self._now(), action, tool, target, target_id, credential_id,
                 session_id, result, output_summary, opsec_rating, duration_ms),
            )
            return cur.lastrowid or -1
        except sqlite3.Error:
            return -1

    def get_timeline(
        self,
        limit: int = 50,
        target: Optional[str] = None,
        tool: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve timeline entries, most recent first.

        Args:
            limit: Maximum number of entries to return.
            target: Filter by target string (partial match).
            tool: Filter by tool name (partial match).

        Returns:
            List of timeline dicts.
        """
        clauses: List[str] = []
        params: List[Any] = []
        if target:
            clauses.append("target LIKE ?")
            params.append(f"%{target}%")
        if tool:
            clauses.append("tool LIKE ?")
            params.append(f"%{tool}%")
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        return self._fetchall(
            f"SELECT * FROM timeline {where} ORDER BY timestamp DESC LIMIT ?",
            tuple(params),
        )

    # ==================================================================
    # Attack Graph
    # ==================================================================

    def add_edge(
        self,
        source_node: str,
        edge_type: str,
        target_node: str,
        source_type: str = "user",
        target_type: str = "user",
        module_used: str = "",
    ) -> int:
        """
        Add an edge to the attack graph.

        Edge types follow BloodHound conventions (e.g. ``GenericAll``,
        ``WriteDACL``, ``AdminTo``, ``HasSession``, ``CanPSRemote``,
        ``MemberOf``, ``DCSync``, etc.).

        Returns:
            The ``id`` of the new edge.
        """
        try:
            cur = self._execute(
                """
                INSERT INTO attack_graph
                    (source_node, source_type, edge_type, target_node, target_type, module_used, discovered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (source_node, source_type, edge_type, target_node, target_type, module_used, self._now()),
            )
            return cur.lastrowid or -1
        except sqlite3.Error:
            return -1

    def mark_edge_exploited(self, edge_id: int) -> bool:
        """
        Mark an attack graph edge as exploited.

        Returns:
            ``True`` if the row was updated.
        """
        try:
            cur = self._execute(
                "UPDATE attack_graph SET exploited = 1 WHERE id = ?",
                (edge_id,),
            )
            return cur.rowcount > 0
        except sqlite3.Error:
            return False

    def get_attack_paths(
        self,
        from_node: Optional[str] = None,
        to_node: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Query edges of the attack graph.

        Args:
            from_node: Filter edges originating from this node (case-insensitive).
            to_node: Filter edges targeting this node (case-insensitive).

        Returns:
            Matching edge dicts.
        """
        clauses: List[str] = []
        params: List[Any] = []
        if from_node:
            clauses.append("LOWER(source_node) = LOWER(?)")
            params.append(from_node)
        if to_node:
            clauses.append("LOWER(target_node) = LOWER(?)")
            params.append(to_node)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        return self._fetchall(
            f"SELECT * FROM attack_graph {where} ORDER BY discovered_at",
            tuple(params),
        )

    def list_edges(self) -> List[Dict[str, Any]]:
        """Return all attack graph edges."""
        return self._fetchall("SELECT * FROM attack_graph ORDER BY id")

    # ==================================================================
    # Config
    # ==================================================================

    def set_config(self, key: str, value: str) -> None:
        """Set an engagement configuration value (upsert)."""
        try:
            self._execute(
                """
                INSERT INTO engagement_config (key, value, updated) VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated = excluded.updated
                """,
                (key, value, self._now()),
            )
        except sqlite3.Error:
            pass

    def get_config(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """
        Get an engagement configuration value.

        Returns:
            The stored value or *default* if the key does not exist.
        """
        row = self._fetchone("SELECT value FROM engagement_config WHERE key = ?", (key,))
        return row["value"] if row else default

    # ==================================================================
    # Migration / Legacy Import
    # ==================================================================

    def import_legacy_creds(self, creds_json_path: str) -> int:
        """
        Import credentials from the legacy ``creds.json`` format used by
        ``CredentialManager``.

        The file is a JSON object whose keys are ``domain\\\\user`` or
        ``user`` strings, each mapping to a dict with ``username``,
        ``domain``, ``password``, ``ntlm_hash``, ``source``, ``notes``,
        ``added``, ``updated``, ``pwned`` fields.

        Returns:
            Number of credentials imported.
        """
        count = 0
        try:
            with open(creds_json_path, "r") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return 0

        for _key, cred in data.items():
            if not isinstance(cred, dict):
                continue
            username = cred.get("username", "")
            if not username:
                continue
            domain = cred.get("domain", "") or ""
            password = cred.get("password", "") or ""
            ntlm_hash = cred.get("ntlm_hash", "") or ""
            source = cred.get("source", "") or ""
            notes = cred.get("notes", "") or ""

            # Determine cred_type
            if ntlm_hash and not password:
                cred_type = "hash"
            else:
                cred_type = "password"

            self.add_credential(
                username=username,
                domain=domain,
                password=password,
                ntlm_hash=ntlm_hash,
                cred_type=cred_type,
                source=source,
                notes=notes,
            )
            count += 1

        return count

    def import_legacy_targets(self, targets_json_path: str) -> int:
        """
        Import targets from the legacy ``targets.json`` format used by
        ``TargetManager``.

        The file has the structure::

            {"next_id": N, "targets": {"1": {...}, "2": {...}}}

        Each target dict contains ``ip``, ``hostname``, ``is_dc``,
        ``domain``, ``vhosts``, ``notes``.

        Returns:
            Number of targets imported.
        """
        count = 0
        try:
            with open(targets_json_path, "r") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return 0

        targets_dict = data.get("targets", {})
        for _tid, t in targets_dict.items():
            if not isinstance(t, dict):
                continue
            ip = t.get("ip", "")
            if not ip:
                continue

            tid = self.add_target(
                ip=ip,
                hostname=t.get("hostname", ""),
                domain=t.get("domain", ""),
                is_dc=bool(t.get("is_dc", False)),
                notes=t.get("notes", ""),
            )

            # Import vhosts
            for vhost in t.get("vhosts", []):
                self.add_target_vhost(tid, vhost)

            count += 1

        return count

    # ==================================================================
    # Reporting
    # ==================================================================

    def get_engagement_summary(self) -> Dict[str, Any]:
        """
        Build a summary of the current engagement state.

        Returns:
            Dict with counts and breakdowns::

                {
                    "target_count": int,
                    "cred_count": int,
                    "session_count": int,
                    "finding_count": int,
                    "findings_by_severity": {"critical": N, ...},
                    "timeline_count": int,
                    "attack_paths": int,
                    "loot_count": int,
                }
        """

        def _count(table: str) -> int:
            row = self._fetchone(f"SELECT COUNT(*) AS cnt FROM {table}")
            return row["cnt"] if row else 0

        findings_by_severity: Dict[str, int] = {}
        for sev in ("critical", "high", "medium", "low", "info"):
            row = self._fetchone(
                "SELECT COUNT(*) AS cnt FROM findings WHERE LOWER(severity) = ?",
                (sev,),
            )
            findings_by_severity[sev] = row["cnt"] if row else 0

        return {
            "target_count": _count("targets"),
            "cred_count": _count("credentials"),
            "session_count": _count("sessions"),
            "finding_count": _count("findings"),
            "findings_by_severity": findings_by_severity,
            "timeline_count": _count("timeline"),
            "attack_paths": _count("attack_graph"),
            "loot_count": _count("loot"),
        }

    # ==================================================================
    # Utility
    # ==================================================================

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        try:
            self._conn.close()
        except sqlite3.Error:
            pass
        # Clear singleton so a new instance can be created if needed
        with self._instance_lock:
            if EngagementDB._instance is self:
                EngagementDB._instance = None

    def __del__(self):
        try:
            self._conn.close()
        except Exception:
            pass

    def __repr__(self) -> str:
        return f"<EngagementDB path={self._db_path!r}>"
