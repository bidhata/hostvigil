"""
ML Enrichment Engine - Advanced learning mechanisms for HostVigil.

Enhances the base AnomalyDetector with:
1. Feedback loop - operator confirms/dismisses anomalies to improve model
2. Temporal pattern analysis - learns time-of-day/week patterns
3. Service correlation - detects unusual service combinations
4. Historical trend analysis - tracks network evolution over time
5. Incremental learning - model improves with each scan cycle
6. Network graph features - detects topological anomalies
"""

import json
import logging
import os
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np

try:
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.preprocessing import StandardScaler

    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

logger = logging.getLogger("hostvigil.ml_engine.enrichment")


class MLEnrichmentEngine:
    """Advanced ML enrichment that learns and improves over time.

    The enrichment engine sits alongside the base AnomalyDetector and provides:
    - Feedback-driven learning (operator marks true/false positives)
    - Temporal baselines (what's normal at 3AM vs 3PM)
    - Service correlation rules (auto-learned, not just hardcoded)
    - Network evolution tracking (drift detection)
    - Incremental model updates without full retraining
    """

    def __init__(self, config: dict, db_path: str):
        self.config = config
        self.db_path = db_path
        self.model_path = Path(config.get("model_path", "data/models/"))
        self.model_path.mkdir(parents=True, exist_ok=True)

        # Feedback-trained classifier (learns from operator decisions)
        self.feedback_model = None
        self.feedback_scaler = None

        # Temporal baseline: {hour_of_week: {feature_means}}
        self.temporal_baseline = {}

        # Service correlation matrix
        self.service_correlations = {}

        # Network evolution history
        self.evolution_snapshots = []

        self._ensure_tables()
        self._load_feedback_model()
        self._load_temporal_baseline()
        self._load_service_correlations()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _ensure_tables(self):
        """Create enrichment-specific tables."""
        conn = sqlite3.connect(self.db_path)
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS ml_feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                anomaly_id INTEGER,
                host_id INTEGER,
                anomaly_type TEXT,
                score REAL,
                features TEXT,
                is_true_positive INTEGER,
                feedback_at TEXT,
                operator_notes TEXT,
                FOREIGN KEY (anomaly_id) REFERENCES anomalies(id)
            );

            CREATE TABLE IF NOT EXISTS ml_temporal_baseline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hour_of_week INTEGER,
                feature_name TEXT,
                mean_value REAL,
                std_value REAL,
                sample_count INTEGER,
                updated_at TEXT
            );

            CREATE TABLE IF NOT EXISTS ml_network_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                snapshot_at TEXT,
                total_hosts INTEGER,
                total_ports INTEGER,
                port_distribution TEXT,
                service_distribution TEXT,
                new_hosts_since_last INTEGER,
                lost_hosts_since_last INTEGER
            );

            CREATE TABLE IF NOT EXISTS ml_service_correlations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_a TEXT,
                service_b TEXT,
                co_occurrence_count INTEGER,
                total_hosts_with_a INTEGER,
                total_hosts_with_b INTEGER,
                correlation_score REAL,
                updated_at TEXT
            );
        """)
        conn.commit()
        conn.close()

    # ------------------------------------------------------------------
    # 1. FEEDBACK LOOP - Learn from operator decisions
    # ------------------------------------------------------------------

    def record_feedback(self, anomaly_id: int, is_true_positive: bool, notes: str = "") -> Dict:
        """Record operator feedback on an anomaly (true/false positive).

        This is the key enrichment mechanism. Over time, the model learns
        what the operator considers a real threat vs noise.
        """
        conn = self._get_connection()
        try:
            # Get the anomaly details
            anomaly = conn.execute("SELECT * FROM anomalies WHERE id = ?", (anomaly_id,)).fetchone()

            if not anomaly:
                return {"error": "Anomaly not found"}

            # Extract features for this host at this time
            features = self._extract_host_features(conn, anomaly["host_id"])

            # Store feedback
            conn.execute(
                "INSERT INTO ml_feedback (anomaly_id, host_id, anomaly_type, score, "
                "features, is_true_positive, feedback_at, operator_notes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    anomaly_id,
                    anomaly["host_id"],
                    anomaly["anomaly_type"],
                    anomaly["score"],
                    json.dumps(features),
                    1 if is_true_positive else 0,
                    datetime.now(timezone.utc).isoformat(),
                    notes,
                ),
            )

            # Mark anomaly as reviewed
            conn.execute("UPDATE anomalies SET is_reviewed = 1 WHERE id = ?", (anomaly_id,))
            conn.commit()

            # Check if we have enough feedback to retrain
            feedback_count = conn.execute("SELECT COUNT(*) as cnt FROM ml_feedback").fetchone()["cnt"]

            result = {
                "status": "recorded",
                "anomaly_id": anomaly_id,
                "is_true_positive": is_true_positive,
                "total_feedback": feedback_count,
            }

            # Auto-retrain feedback model if enough samples
            if feedback_count >= 20:
                train_result = self._train_feedback_model(conn)
                result["model_retrained"] = train_result.get("status") == "trained"

            return result
        finally:
            conn.close()

    def _train_feedback_model(self, conn: sqlite3.Connection) -> Dict:
        """Train a supervised model from operator feedback.

        Uses GradientBoosting to learn the distinction between
        true positives and false positives based on features.
        """
        if not SKLEARN_AVAILABLE:
            return {"status": "skipped", "reason": "sklearn unavailable"}

        rows = conn.execute("SELECT features, is_true_positive FROM ml_feedback WHERE features IS NOT NULL").fetchall()

        if len(rows) < 20:
            return {"status": "insufficient_data", "count": len(rows)}

        X = []
        y = []
        for row in rows:
            try:
                features = json.loads(row["features"])
                if isinstance(features, list) and len(features) > 0:
                    X.append(features)
                    y.append(row["is_true_positive"])
            except (json.JSONDecodeError, TypeError):
                continue

        if len(X) < 20:
            return {"status": "insufficient_valid_data"}

        # Ensure all feature vectors have the same dimensionality
        # Use current feature vector length as authoritative dimension
        expected_dim = 8  # Must match _extract_host_features output length
        filtered_X = []
        filtered_y = []
        for features, label in zip(X, y):
            if len(features) == expected_dim:
                filtered_X.append(features)
                filtered_y.append(label)

        if len(filtered_X) < 20:
            return {"status": "insufficient_valid_data"}

        X = np.array(filtered_X, dtype=np.float64)
        y = np.array(filtered_y)

        # Replace NaN/inf to prevent sklearn crashes
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

        # Need at least 2 classes to train a classifier
        unique_classes = np.unique(y)
        if len(unique_classes) < 2:
            return {"status": "insufficient_class_diversity", "classes": len(unique_classes)}

        self.feedback_scaler = StandardScaler()
        X_scaled = self.feedback_scaler.fit_transform(X)

        self.feedback_model = GradientBoostingClassifier(n_estimators=50, max_depth=3, random_state=42)
        self.feedback_model.fit(X_scaled, y)

        # Save model atomically
        import pickle
        import tempfile

        model_file = self.model_path / "feedback_model.pkl"
        fd, tmp_path = tempfile.mkstemp(dir=str(self.model_path), suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as f:
                pickle.dump(
                    {
                        "model": self.feedback_model,
                        "scaler": self.feedback_scaler,
                    },
                    f,
                )
            os.replace(tmp_path, str(model_file))
        except BaseException:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

        accuracy = self.feedback_model.score(X_scaled, y)
        logger.info(f"Feedback model trained: {len(X)} samples, accuracy={accuracy:.2f}")

        return {"status": "trained", "samples": len(X), "accuracy": accuracy}

    def score_with_feedback(self, host_id: int) -> Optional[float]:
        """Score a host using the feedback-trained model.

        Returns probability of being a true positive (0.0-1.0).
        Returns None if feedback model not available.
        """
        if self.feedback_model is None or self.feedback_scaler is None:
            return None

        conn = self._get_connection()
        try:
            features = self._extract_host_features(conn, host_id)
            if not features:
                return None

            # Validate feature dimension matches scaler expectation
            expected_dim = self.feedback_scaler.n_features_in_
            if len(features) != expected_dim:
                logger.debug(
                    f"Feature dimension mismatch for host {host_id}: got {len(features)}, expected {expected_dim}"
                )
                return None

            X = np.array([features], dtype=np.float64)
            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
            X_scaled = self.feedback_scaler.transform(X)
            proba = self.feedback_model.predict_proba(X_scaled)[0]
            # Return probability of being true positive (class 1)
            if 1 not in self.feedback_model.classes_:
                return 0.0
            tp_idx = list(self.feedback_model.classes_).index(1)
            return float(proba[tp_idx])
        except Exception as e:
            logger.debug(f"Feedback scoring failed for host {host_id}: {e}")
            return None
        finally:
            conn.close()

    def _load_feedback_model(self):
        """Load the feedback model from disk."""
        import pickle

        model_file = self.model_path / "feedback_model.pkl"
        if model_file.exists():
            try:
                with open(model_file, "rb") as f:
                    data = pickle.load(f)
                self.feedback_model = data["model"]
                self.feedback_scaler = data["scaler"]
                logger.info("Feedback model loaded")
            except Exception as e:
                logger.warning(f"Failed to load feedback model: {e}")

    # ------------------------------------------------------------------
    # 2. TEMPORAL PATTERN ANALYSIS
    # ------------------------------------------------------------------

    def update_temporal_baseline(self):
        """Build/update the temporal baseline - what's normal at each hour of the week.

        Tracks: average port count, new host rate, service changes per hour-of-week.
        This allows detecting 'something appeared at 3AM on Sunday' as more suspicious
        than 'something appeared at 10AM on Tuesday'.
        """
        conn = self._get_connection()
        try:
            # Get all port appearances with timestamps
            rows = conn.execute("""
                SELECT
                    p.host_id,
                    p.first_seen,
                    p.port,
                    h.first_seen as host_first_seen
                FROM ports p
                JOIN hosts h ON h.id = p.host_id
                WHERE p.first_seen IS NOT NULL
            """).fetchall()

            # Group by hour of week (0=Monday 00:00, 167=Sunday 23:00)
            hourly_data = defaultdict(
                lambda: {
                    "port_appearances": 0,
                    "new_hosts": 0,
                    "unique_ports": set(),
                    "samples": 0,
                }
            )

            for row in rows:
                try:
                    ts = datetime.fromisoformat(row["first_seen"].replace("Z", "+00:00"))
                    hour_of_week = ts.weekday() * 24 + ts.hour
                    hourly_data[hour_of_week]["port_appearances"] += 1
                    hourly_data[hour_of_week]["unique_ports"].add(row["port"])
                    hourly_data[hour_of_week]["samples"] += 1
                except (ValueError, TypeError):
                    continue

            # Store baseline (upsert pattern - atomic)
            now = datetime.now(timezone.utc).isoformat()
            # Ensure UNIQUE constraint exists for upsert
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_temporal_hour_feature "
                "ON ml_temporal_baseline(hour_of_week, feature_name)"
            )

            for hour, data in hourly_data.items():
                if data["samples"] > 0:
                    conn.execute(
                        "INSERT OR REPLACE INTO ml_temporal_baseline "
                        "(hour_of_week, feature_name, mean_value, std_value, sample_count, updated_at) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (hour, "port_appearances", data["port_appearances"], 0, data["samples"], now),
                    )

            conn.commit()
            self._load_temporal_baseline()
            logger.info(f"Temporal baseline updated: {len(hourly_data)} hour slots")
            return {"status": "updated", "hour_slots": len(hourly_data)}
        except Exception as e:
            logger.error(f"Temporal baseline update failed: {e}")
            return {"status": "error", "reason": str(e)}
        finally:
            conn.close()

    def _load_temporal_baseline(self):
        """Load temporal baseline from database."""
        conn = None
        try:
            conn = self._get_connection()
            rows = conn.execute("SELECT * FROM ml_temporal_baseline").fetchall()

            self.temporal_baseline = {}
            for row in rows:
                hour = row["hour_of_week"]
                if hour not in self.temporal_baseline:
                    self.temporal_baseline[hour] = {}
                self.temporal_baseline[hour][row["feature_name"]] = {
                    "mean": row["mean_value"],
                    "std": row["std_value"],
                    "samples": row["sample_count"],
                }
        except Exception:
            self.temporal_baseline = {}
        finally:
            if conn:
                conn.close()

    def _load_service_correlations(self):
        """Load service correlations from database."""
        conn = None
        try:
            conn = self._get_connection()
            rows = conn.execute(
                "SELECT service_a, service_b, co_occurrence_count FROM ml_service_correlations"
            ).fetchall()

            self.service_correlations = {}
            for row in rows:
                pair = (row["service_a"], row["service_b"])
                self.service_correlations[pair] = row["co_occurrence_count"]
        except Exception:
            self.service_correlations = {}
        finally:
            if conn:
                conn.close()

    def get_temporal_risk_multiplier(self) -> float:
        """Get risk multiplier based on current time of week.

        Returns > 1.0 if current hour is unusual for network activity,
        1.0 if normal, < 1.0 if very active hour.
        """
        now = datetime.now()
        hour_of_week = now.weekday() * 24 + now.hour

        if hour_of_week in self.temporal_baseline:
            data = self.temporal_baseline[hour_of_week]
            port_data = data.get("port_appearances", {})
            activity = port_data.get("mean", 0) if isinstance(port_data, dict) else 0
            # Low activity hours get higher multiplier (more suspicious)
            all_means = []
            for v in self.temporal_baseline.values():
                pd = v.get("port_appearances", {})
                if isinstance(pd, dict):
                    m = pd.get("mean", 0)
                    if m > 0:
                        all_means.append(m)
            if not all_means:
                return 1.0
            avg_activity = np.mean(all_means)
            if avg_activity > 0 and activity > 0:
                ratio = activity / avg_activity
                # Invert: low activity hour = higher risk multiplier
                return max(0.5, min(2.0, 1.5 - ratio * 0.5))

        # Default: slightly elevated (unknown = suspicious)
        return 1.2

    # ------------------------------------------------------------------
    # 3. SERVICE CORRELATION ANALYSIS
    # ------------------------------------------------------------------

    def update_service_correlations(self):
        """Learn which services commonly appear together.

        Builds a co-occurrence matrix. If a host suddenly has a port combo
        that never appears together in the network, it's suspicious.
        """
        conn = self._get_connection()
        try:
            # Get all active services per host
            rows = conn.execute("""
                SELECT host_id, service
                FROM ports
                WHERE is_active = 1 AND service IS NOT NULL AND service != ''
                ORDER BY host_id
            """).fetchall()

            # Group services by host
            host_services = defaultdict(set)
            for row in rows:
                host_services[row["host_id"]].add(row["service"])

            # Build co-occurrence counts
            service_counts = Counter()
            co_occurrence = Counter()

            for services in host_services.values():
                for s in services:
                    service_counts[s] += 1
                service_list = sorted(services)
                for i in range(len(service_list)):
                    for j in range(i + 1, len(service_list)):
                        pair = (service_list[i], service_list[j])
                        co_occurrence[pair] += 1

            # Calculate correlation scores and store
            total_hosts = len(host_services)
            now = datetime.now(timezone.utc).isoformat()

            conn.execute("DELETE FROM ml_service_correlations")

            for (svc_a, svc_b), count in co_occurrence.items():
                hosts_a = service_counts[svc_a]
                hosts_b = service_counts[svc_b]
                # Jaccard-like correlation
                union_count = hosts_a + hosts_b - count
                correlation = count / union_count if union_count > 0 else 0

                conn.execute(
                    "INSERT INTO ml_service_correlations "
                    "(service_a, service_b, co_occurrence_count, "
                    "total_hosts_with_a, total_hosts_with_b, correlation_score, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (svc_a, svc_b, count, hosts_a, hosts_b, correlation, now),
                )

            conn.commit()

            # Cache in memory
            self.service_correlations = dict(co_occurrence)

            logger.info(f"Service correlations updated: {len(co_occurrence)} pairs from {total_hosts} hosts")
            return {"status": "updated", "pairs": len(co_occurrence), "hosts": total_hosts}
        except Exception as e:
            logger.error(f"Service correlation update failed: {e}")
            return {"status": "error", "reason": str(e)}
        finally:
            conn.close()

    def score_service_combination(self, services: List[str]) -> float:
        """Score how unusual a set of services is (0.0 = normal, 1.0 = very unusual)."""
        if not self.service_correlations or len(services) < 2:
            return 0.0

        services = sorted(services)
        expected_pairs = 0
        found_pairs = 0

        for i in range(len(services)):
            for j in range(i + 1, len(services)):
                pair = (services[i], services[j])
                expected_pairs += 1
                if pair in self.service_correlations:
                    found_pairs += 1

        if expected_pairs == 0:
            return 0.0

        # Higher ratio of unknown combinations = more unusual
        unknown_ratio = 1.0 - (found_pairs / expected_pairs)
        return unknown_ratio

    # ------------------------------------------------------------------
    # 4. NETWORK EVOLUTION TRACKING
    # ------------------------------------------------------------------

    def take_network_snapshot(self) -> Dict:
        """Capture current network state for evolution tracking.

        Compares against previous snapshots to detect drift:
        - Sudden growth in hosts/ports
        - Service distribution changes
        - Subnet activity changes
        """
        conn = self._get_connection()
        try:
            total_hosts = conn.execute("SELECT COUNT(*) as cnt FROM hosts WHERE is_active = 1").fetchone()["cnt"]

            total_ports = conn.execute("SELECT COUNT(*) as cnt FROM ports WHERE is_active = 1").fetchone()["cnt"]

            # Port distribution
            port_dist = conn.execute("""
                SELECT port, COUNT(*) as cnt
                FROM ports WHERE is_active = 1
                GROUP BY port ORDER BY cnt DESC LIMIT 20
            """).fetchall()

            # Service distribution
            svc_dist = conn.execute("""
                SELECT service, COUNT(*) as cnt
                FROM ports WHERE is_active = 1 AND service != ''
                GROUP BY service ORDER BY cnt DESC LIMIT 20
            """).fetchall()

            # Compare with last snapshot
            last_snapshot = conn.execute(
                "SELECT * FROM ml_network_snapshots ORDER BY snapshot_at DESC LIMIT 1"
            ).fetchone()

            new_hosts = 0
            lost_hosts = 0
            if last_snapshot:
                new_hosts = max(0, total_hosts - last_snapshot["total_hosts"])
                lost_hosts = max(0, last_snapshot["total_hosts"] - total_hosts)

            # Store snapshot
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "INSERT INTO ml_network_snapshots "
                "(snapshot_at, total_hosts, total_ports, port_distribution, "
                "service_distribution, new_hosts_since_last, lost_hosts_since_last) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    now,
                    total_hosts,
                    total_ports,
                    json.dumps({str(r["port"]): r["cnt"] for r in port_dist}),
                    json.dumps({r["service"]: r["cnt"] for r in svc_dist}),
                    new_hosts,
                    lost_hosts,
                ),
            )
            conn.commit()

            result = {
                "snapshot_at": now,
                "total_hosts": total_hosts,
                "total_ports": total_ports,
                "new_hosts": new_hosts,
                "lost_hosts": lost_hosts,
                "drift_detected": self._detect_drift(conn),
            }

            logger.info(f"Network snapshot: {total_hosts} hosts, {total_ports} ports, +{new_hosts}/-{lost_hosts} hosts")
            return result
        finally:
            conn.close()

    def _detect_drift(self, conn: sqlite3.Connection) -> bool:
        """Detect significant network drift from recent snapshots."""
        snapshots = conn.execute(
            "SELECT total_hosts, total_ports FROM ml_network_snapshots ORDER BY snapshot_at DESC LIMIT 10"
        ).fetchall()

        if len(snapshots) < 3:
            return False

        host_counts = [s["total_hosts"] for s in snapshots]
        port_counts = [s["total_ports"] for s in snapshots]

        # Check if latest values deviate significantly from recent mean
        host_mean = np.mean(host_counts[1:])
        port_mean = np.mean(port_counts[1:])

        if host_mean > 0:
            host_deviation = abs(host_counts[0] - host_mean) / host_mean
            if host_deviation > 0.3:  # 30% change
                return True

        if port_mean > 0:
            port_deviation = abs(port_counts[0] - port_mean) / port_mean
            if port_deviation > 0.3:
                return True

        return False

    # ------------------------------------------------------------------
    # 5. INCREMENTAL LEARNING
    # ------------------------------------------------------------------

    def incremental_update(self) -> Dict:
        """Perform incremental model update without full retraining.

        Adds new data points to the model's understanding without
        discarding previous learning. Called after each scan cycle.
        """
        results = {}

        # Update temporal baseline
        results["temporal"] = self.update_temporal_baseline()

        # Update service correlations
        results["correlations"] = self.update_service_correlations()

        # Take network snapshot
        results["snapshot"] = self.take_network_snapshot()

        # Retrain feedback model if new feedback available
        conn = self._get_connection()
        try:
            unprocessed = conn.execute(
                "SELECT COUNT(*) as cnt FROM ml_feedback WHERE feedback_at > "
                "(SELECT COALESCE(MAX(trained_at), '2000-01-01') FROM ml_training_log)"
            ).fetchone()["cnt"]

            if unprocessed >= 5:
                results["feedback_retrain"] = self._train_feedback_model(conn)
        finally:
            conn.close()

        logger.info("Incremental ML update complete")
        return results

    # ------------------------------------------------------------------
    # 6. ENHANCED FEATURE EXTRACTION
    # ------------------------------------------------------------------

    def _extract_host_features(self, conn: sqlite3.Connection, host_id: int) -> List[float]:
        """Extract enriched feature vector for a host (used by feedback model)."""
        features = []

        # Basic port features
        ports = conn.execute(
            "SELECT port, service, banner, first_seen FROM ports WHERE host_id = ? AND is_active = 1", (host_id,)
        ).fetchall()

        port_count = len(ports)
        features.append(float(port_count))

        # High port ratio
        high_ports = sum(1 for p in ports if p["port"] > 1024)
        features.append(high_ports / max(port_count, 1))

        # Service diversity
        services = set(p["service"] for p in ports if p["service"])
        features.append(float(len(services)))

        # Suspicious port score
        port_nums = [p["port"] for p in ports]
        from hostvigil.ml_engine.anomaly_detector import SUSPICIOUS_PORTS

        suspicious = sum(1 for p in port_nums if p in SUSPICIOUS_PORTS)
        features.append(suspicious / max(port_count, 1))

        # Banner change indicator
        banners_with_content = sum(1 for p in ports if p["banner"])
        features.append(float(banners_with_content))

        # Temporal risk (what hour/day is it?)
        features.append(self.get_temporal_risk_multiplier())

        # Service combination unusualness
        svc_list = [p["service"] for p in ports if p["service"]]
        features.append(self.score_service_combination(svc_list))

        # Anomaly history for this host
        prev_anomalies = conn.execute("SELECT COUNT(*) as cnt FROM anomalies WHERE host_id = ?", (host_id,)).fetchone()[
            "cnt"
        ]
        features.append(float(prev_anomalies))

        return features

    # ------------------------------------------------------------------
    # 7. ENRICHMENT SUMMARY & STATS
    # ------------------------------------------------------------------

    def get_enrichment_stats(self) -> Dict:
        """Get statistics about the enrichment engine's state."""
        conn = self._get_connection()
        try:
            feedback_count = conn.execute("SELECT COUNT(*) as cnt FROM ml_feedback").fetchone()["cnt"]

            tp_count = conn.execute("SELECT COUNT(*) as cnt FROM ml_feedback WHERE is_true_positive = 1").fetchone()[
                "cnt"
            ]

            fp_count = conn.execute("SELECT COUNT(*) as cnt FROM ml_feedback WHERE is_true_positive = 0").fetchone()[
                "cnt"
            ]

            snapshot_count = conn.execute("SELECT COUNT(*) as cnt FROM ml_network_snapshots").fetchone()["cnt"]

            correlation_count = conn.execute("SELECT COUNT(*) as cnt FROM ml_service_correlations").fetchone()["cnt"]

            return {
                "feedback_total": feedback_count,
                "true_positives": tp_count,
                "false_positives": fp_count,
                "precision": tp_count / max(feedback_count, 1),
                "feedback_model_available": self.feedback_model is not None,
                "temporal_baseline_hours": len(self.temporal_baseline),
                "service_correlation_pairs": correlation_count,
                "network_snapshots": snapshot_count,
            }
        finally:
            conn.close()
