import json
import os
import sqlite3
from typing import Dict, Any, List
from datetime import datetime
from skills.base import BaseSkill, SkillResult


class MemorySkill(BaseSkill):
    """Persistent memory with SQLite — pattern learning, session storage, knowledge base, strategy memory."""

    def __init__(self):
        super().__init__()
        db_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
        os.makedirs(db_dir, exist_ok=True)
        self.db_path = os.path.join(db_dir, "pentest.db")
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                target TEXT,
                mode TEXT,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                finding_count INTEGER,
                summary TEXT
            );
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                target TEXT,
                vuln_type TEXT,
                url TEXT,
                param TEXT,
                severity TEXT,
                cvss_score REAL,
                description TEXT,
                evidence TEXT,
                payload TEXT,
                confidence REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            );
            CREATE TABLE IF NOT EXISTS patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_type TEXT,
                vuln_type TEXT,
                url_pattern TEXT,
                param_pattern TEXT,
                success_count INTEGER DEFAULT 1,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS chains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                target TEXT,
                chain_name TEXT,
                chain_path TEXT,
                severity TEXT,
                impact TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS knowledge_base (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT,
                vuln_class TEXT,
                title TEXT,
                technique TEXT,
                lesson TEXT
            );
            CREATE TABLE IF NOT EXISTS strategy_memory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tech_stack TEXT,
                vuln_class TEXT,
                attack_strategy TEXT,
                success_count INTEGER DEFAULT 0,
                failure_count INTEGER DEFAULT 0,
                avg_confidence REAL DEFAULT 0.0,
                last_used TIMESTAMP,
                notes TEXT
            );
            CREATE TABLE IF NOT EXISTS signal_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tech_stack TEXT,
                signal_type TEXT,
                signal_value TEXT,
                correlated_vuln TEXT,
                correlation_strength REAL DEFAULT 0.0,
                sample_count INTEGER DEFAULT 1
            );
        """)
        conn.commit()
        conn.close()

    def can_handle(self, task_type: str) -> bool:
        return task_type in ["memory", "pattern_learning", "session_memory", "knowledge"]

    async def execute(self, context: Dict[str, Any]) -> SkillResult:
        action = context.get("action", "save")
        if action == "save":
            return await self._save_session(context)
        elif action == "load":
            return await self._load_session(context)
        elif action == "pattern":
            return await self._learn_patterns(context)
        return SkillResult(success=False, findings=[], data={}, next_skills=[], confidence=0.0)

    async def _save_session(self, context: dict) -> SkillResult:
        session_data = context.get("session_data", {})
        target = session_data.get("target", "unknown")
        mode = session_data.get("mode", "full")
        findings = session_data.get("findings", [])
        chains = session_data.get("stages", {}).get("chain", {}).get("chains", [])

        session_id = datetime.now().strftime("%Y%m%d_%H%M%S")

        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        c.execute(
            "INSERT OR REPLACE INTO sessions (id, target, mode, started_at, completed_at, finding_count) VALUES (?, ?, ?, ?, ?, ?)",
            (session_id, target, mode, datetime.now().isoformat(), datetime.now().isoformat(), len(findings)),
        )

        for f in findings:
            c.execute(
                "INSERT INTO findings (session_id, target, vuln_type, url, param, severity, cvss_score, description, evidence, payload, confidence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    session_id,
                    target,
                    f.get("type", f.get("vuln_class", "Unknown")),
                    f.get("url", ""),
                    f.get("param", ""),
                    f.get("severity", "medium"),
                    f.get("cvss_score", 0.0),
                    f.get("description", "")[:500],
                    f.get("evidence", "")[:500],
                    f.get("payload", ""),
                    f.get("confidence", 0.5),
                ),
            )

        for chain in chains:
            c.execute(
                "INSERT INTO chains (session_id, target, chain_name, chain_path, severity, impact) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    session_id,
                    target,
                    chain.get("chain_name", ""),
                    json.dumps(chain.get("chain_path", [])),
                    chain.get("computed_severity", "medium"),
                    chain.get("chain_impact", ""),
                ),
            )

        conn.commit()
        conn.close()

        return SkillResult(
            success=True,
            findings=findings,
            data={"session_id": session_id, "stored": len(findings), "chains": len(chains)},
            next_skills=[],
            confidence=1.0,
        )

    async def _load_session(self, context: dict) -> SkillResult:
        session_id = context.get("session_id", "")
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        c.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
        session = dict(c.fetchone()) if c.fetchone() else None

        if not session:
            conn.close()
            return SkillResult(success=False, findings=[], data={"error": "Session not found"}, next_skills=[], confidence=0.0)

        c.execute("SELECT * FROM findings WHERE session_id = ?", (session_id,))
        findings = [dict(r) for r in c.fetchall()]

        c.execute("SELECT * FROM chains WHERE session_id = ?", (session_id,))
        chains = [dict(r) for r in c.fetchall()]

        conn.close()

        return SkillResult(
            success=True,
            findings=findings,
            data={"session": session, "findings": findings, "chains": chains},
            next_skills=[],
            confidence=1.0,
        )

    async def _learn_patterns(self, context: dict) -> SkillResult:
        findings = context.get("findings", [])
        if not findings:
            return self._load_relevant_patterns(context.get("target", ""))

        prompt = f"""Extract attack patterns from these findings:

{json.dumps(findings, indent=2)[:4000]}

Return JSON:
{{
    "patterns": [
        {{"vuln_type": "...", "url_pattern": "...", "param_pattern": "...", "technique": "..."}}
    ]
}}"""

        response = await self.llm_analyze(prompt)

        try:
            parsed = json.loads(response)
            patterns = parsed.get("patterns", [])
        except (json.JSONDecodeError, ValueError):
            patterns = []

        if patterns:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            for p in patterns:
                c.execute(
                    "INSERT INTO patterns (target_type, vuln_type, url_pattern, param_pattern) VALUES (?, ?, ?, ?)",
                    (context.get("target", "generic"), p.get("vuln_type", ""), p.get("url_pattern", ""), p.get("param_pattern", "")),
                )
            conn.commit()
            conn.close()

        return SkillResult(
            success=True,
            findings=findings,
            data={"patterns_learned": len(patterns), "total_patterns": self._count_patterns()},
            next_skills=[],
            confidence=0.9 if patterns else 0.0,
        )

    async def _load_relevant_patterns(self, target: str) -> SkillResult:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        c.execute("""
            SELECT vuln_type, url_pattern, param_pattern, success_count
            FROM patterns
            WHERE target_type = ? OR target_type = 'generic'
            ORDER BY success_count DESC
            LIMIT 20
        """, (target,))

        patterns = [dict(r) for r in c.fetchall()]
        conn.close()

        return SkillResult(
            success=True,
            findings=[],
            data={"patterns": patterns, "count": len(patterns)},
            next_skills=[],
            confidence=1.0 if patterns else 0.0,
        )

    def _count_patterns(self) -> int:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM patterns")
        count = c.fetchone()[0]
        conn.close()
        return count

    # ─── Strategy Memory ─────────────────────────────────────────

    async def record_strategy(self, tech_stack: str, vuln_class: str,
                               strategy: str, success: bool, confidence: float = 0.5):
        """Record whether a strategy worked on a given tech stack."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        # Check if strategy exists
        c.execute("""
            SELECT id, success_count, failure_count, avg_confidence
            FROM strategy_memory
            WHERE tech_stack = ? AND vuln_class = ? AND attack_strategy = ?
        """, (tech_stack, vuln_class, strategy))
        row = c.fetchone()

        if row:
            # Update existing
            sid, success_count, failure_count, avg_conf = row
            if success:
                success_count += 1
            else:
                failure_count += 1
            total = success_count + failure_count
            new_avg = ((avg_conf * (total - 1)) + confidence) / total

            c.execute("""
                UPDATE strategy_memory
                SET success_count = ?, failure_count = ?, avg_confidence = ?, last_used = ?
                WHERE id = ?
            """, (success_count, failure_count, new_avg, datetime.now().isoformat(), sid))
        else:
            # Insert new
            c.execute("""
                INSERT INTO strategy_memory (tech_stack, vuln_class, attack_strategy,
                    success_count, failure_count, avg_confidence, last_used)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                tech_stack, vuln_class, strategy,
                1 if success else 0,
                0 if success else 1,
                confidence,
                datetime.now().isoformat(),
            ))

        conn.commit()
        conn.close()

    async def get_strategy_rankings(self, tech_stack: str) -> list:
        """
        Get ranked attack strategies for a tech stack.
        Returns strategies sorted by success rate.
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        c.execute("""
            SELECT vuln_class, attack_strategy, success_count, failure_count,
                   avg_confidence,
                   CAST(success_count AS REAL) / (success_count + failure_count + 1) as success_rate
            FROM strategy_memory
            WHERE tech_stack = ? OR tech_stack = 'generic'
            ORDER BY success_rate DESC, avg_confidence DESC
            LIMIT 20
        """, (tech_stack,))

        strategies = [dict(r) for r in c.fetchall()]
        conn.close()

        return strategies

    async def get_adaptive_vuln_order(self, tech_stack: str) -> list:
        """
        Get the optimal order to test vuln classes for a given tech stack.
        Based on historical success rates.
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        c.execute("""
            SELECT vuln_class,
                   SUM(success_count) as total_successes,
                   SUM(success_count + failure_count) as total_attempts,
                   AVG(avg_confidence) as avg_conf
            FROM strategy_memory
            WHERE tech_stack = ? OR tech_stack = 'generic'
            GROUP BY vuln_class
            ORDER BY total_successes DESC
        """, (tech_stack,))

        rankings = [dict(r) for r in c.fetchall()]
        conn.close()

        # Return ordered list of vuln classes
        return [r["vuln_class"] for r in rankings]

    async def record_signal_correlation(self, tech_stack: str, signal_type: str,
                                         signal_value: str, correlated_vuln: str,
                                         strength: float = 0.5):
        """Record that a signal correlated with a vulnerability."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        c.execute("""
            SELECT id, sample_count, correlation_strength
            FROM signal_patterns
            WHERE tech_stack = ? AND signal_type = ? AND signal_value = ?
                  AND correlated_vuln = ?
        """, (tech_stack, signal_type, signal_value, correlated_vuln))
        row = c.fetchone()

        if row:
            sid, count, old_strength = row
            new_count = count + 1
            new_strength = ((old_strength * count) + strength) / new_count
            c.execute("""
                UPDATE signal_patterns
                SET sample_count = ?, correlation_strength = ?
                WHERE id = ?
            """, (new_count, new_strength, sid))
        else:
            c.execute("""
                INSERT INTO signal_patterns (tech_stack, signal_type, signal_value,
                    correlated_vuln, correlation_strength, sample_count)
                VALUES (?, ?, ?, ?, ?, 1)
            """, (tech_stack, signal_type, signal_value, correlated_vuln, strength))

        conn.commit()
        conn.close()

    async def get_signal_predictions(self, tech_stack: str, signal_type: str,
                                      signal_value: str) -> list:
        """Given a signal, predict which vulns are likely."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        c.execute("""
            SELECT correlated_vuln, correlation_strength, sample_count
            FROM signal_patterns
            WHERE tech_stack IN (?, 'generic')
              AND signal_type = ? AND signal_value = ?
            ORDER BY correlation_strength DESC
            LIMIT 5
        """, (tech_stack, signal_type, signal_value))

        predictions = [dict(r) for r in c.fetchall()]
        conn.close()

        return predictions

    async def get_strategy_stats(self) -> dict:
        """Get overall strategy memory statistics."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        c.execute("SELECT COUNT(*) FROM strategy_memory")
        total_strategies = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM signal_patterns")
        total_signals = c.fetchone()[0]

        c.execute("""
            SELECT tech_stack, COUNT(*) as cnt
            FROM strategy_memory
            GROUP BY tech_stack
            ORDER BY cnt DESC
            LIMIT 10
        """)
        by_tech = {r[0]: r[1] for r in c.fetchall()}

        c.execute("""
            SELECT vuln_class,
                   SUM(success_count) as successes,
                   SUM(success_count + failure_count) as attempts
            FROM strategy_memory
            GROUP BY vuln_class
            ORDER BY successes DESC
        """)
        by_vuln = {r[0]: {"successes": r[1], "attempts": r[2]} for r in c.fetchall()}

        conn.close()

        return {
            "total_strategies": total_strategies,
            "total_signal_patterns": total_signals,
            "by_tech_stack": by_tech,
            "by_vuln_class": by_vuln,
        }
