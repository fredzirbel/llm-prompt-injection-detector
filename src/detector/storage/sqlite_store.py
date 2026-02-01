"""SQLite storage for analysis results."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone


class AnalysisStore:
    def __init__(self, db_path: str = "detector_results.db"):
        self.db_path = db_path
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS analyses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    prompt_hash TEXT NOT NULL,
                    prompt_length INTEGER,
                    verdict TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    primary_category TEXT,
                    triggered_detectors TEXT,
                    explanation TEXT,
                    latency_ms REAL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_analyses_verdict ON analyses(verdict)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_analyses_timestamp ON analyses(timestamp)
            """)

    def save(
        self,
        prompt_hash: str,
        prompt_length: int,
        verdict: str,
        confidence: float,
        primary_category: str,
        triggered_detectors: str,
        explanation: str,
        latency_ms: float,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO analyses (timestamp, prompt_hash, prompt_length, verdict, confidence, primary_category, triggered_detectors, explanation, latency_ms) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    datetime.now(timezone.utc).isoformat(),
                    prompt_hash,
                    prompt_length,
                    verdict,
                    confidence,
                    primary_category,
                    triggered_detectors,
                    explanation,
                    latency_ms,
                ),
            )

    def get_stats(self) -> dict:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
            clean = conn.execute("SELECT COUNT(*) FROM analyses WHERE verdict='CLEAN'").fetchone()[0]
            suspicious = conn.execute("SELECT COUNT(*) FROM analyses WHERE verdict='SUSPICIOUS'").fetchone()[0]
            malicious = conn.execute("SELECT COUNT(*) FROM analyses WHERE verdict='MALICIOUS'").fetchone()[0]

            cat_rows = conn.execute(
                "SELECT primary_category, COUNT(*) as cnt FROM analyses "
                "WHERE verdict != 'CLEAN' GROUP BY primary_category ORDER BY cnt DESC"
            ).fetchall()
            top_categories = {row["primary_category"]: row["cnt"] for row in cat_rows}

        return {
            "total_analyzed": total,
            "total_clean": clean,
            "total_suspicious": suspicious,
            "total_malicious": malicious,
            "top_categories": top_categories,
        }

    def get_recent(self, limit: int = 50) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM analyses ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    def get_verdict_timeseries(self, days: int = 30) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT DATE(timestamp) as date, verdict, COUNT(*) as count "
                "FROM analyses GROUP BY DATE(timestamp), verdict "
                "ORDER BY date DESC LIMIT ?",
                (days * 3,),
            ).fetchall()
            return [dict(r) for r in rows]
