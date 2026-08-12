"""
Anomaly Detector - ML-based network behavior anomaly detection.

Trains on historical scan data to identify unusual port configurations,
new services, behavioral pattern deviations, and banner changes.

Supports cold-start with rule-based detection until enough samples
accumulate for ML model training.
"""

import logging
import os
import pickle
import sqlite3
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

logger = logging.getLogger("hostvigil.ml_engine")

# Ports commonly associated with suspicious activity
SUSPICIOUS_PORTS = {
    4444,
    5555,
    6666,
    7777,
    8888,
    9999,  # Common reverse shells
    1337,
    31337,  # Leet ports
    4443,
    8443,  # Alt HTTPS (sometimes C2)
    2222,  # Alt SSH
    6667,
    6668,
    6669,  # IRC (botnet C2)
    3128,
    8080,
    8081,  # Proxy ports
    5900,
    5901,  # VNC
    4899,  # Radmin
    1234,
    12345,  # Generic backdoor
}

# Well-known service ports (expected on most networks)
COMMON_PORTS = {
    22,
    25,
    53,
    80,
    110,
    143,
    443,
    445,
    993,
    995,
    3306,
    5432,
    8080,
    8443,
    3389,
    5900,
}

# Feature vector indices
FEAT_PORT_COUNT = 0
FEAT_HIGH_PORT_RATIO = 1
FEAT_SERVICE_DIVERSITY = 2
FEAT_TIME_SINCE_FIRST = 3
FEAT_PORT_VELOCITY = 4
FEAT_BANNER_CHANGES = 5
FEAT_UNUSUAL_PORT_SCORE = 6
NUM_FEATURES = 7


class AnomalyDetector:
    """ML-based anomaly detection engine for network monitoring.

    Uses IsolationForest and rule-based heuristics to identify
    anomalous network behavior from scan data.
    """

    def __init__(self, config: dict, db_path: str):
        self.config = config
        self.db_path = db_path
        self.model_path = Path(config.get("model_path", "data/models/"))
        self.model_path.mkdir(parents=True, exist_ok=True)
        self._model_lock = threading.Lock()
        self.model = None
        self.scaler = None
        self.threshold = config.get("anomaly_threshold", 0.7)
        self.min_samples = config.get("min_training_samples", 50)
        self.baseline_window_days = config.get("baseline_window_days", 7)
        self.disappeared_threshold_hours = config.get("disappeared_threshold_hours", 48)
        self._load_model()

    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection with row factory."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _now_iso(self) -> str:
        """Return current UTC time as ISO string."""
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train(self) -> Dict:
        """Train/retrain the model on current network data.

        Returns a dict with training stats (samples, model version, status).
        Falls back to rule-based mode if insufficient data or sklearn missing.
        """
        if not SKLEARN_AVAILABLE:
            logger.warning("sklearn not available - using rule-based detection only")
            return {
                "status": "skipped",
                "reason": "sklearn not installed",
                "mode": "rule_based",
            }

        try:
            features, host_ids = self._extract_all_features()
        except Exception as e:
            logger.error(f"Feature extraction failed during training: {e}")
            return {"status": "error", "reason": str(e)}

        sample_count = len(host_ids)
        if sample_count < self.min_samples:
            logger.info(
                f"Insufficient samples for training ({sample_count}/{self.min_samples}). Using rule-based detection."
            )
            return {
                "status": "insufficient_data",
                "samples": sample_count,
                "min_required": self.min_samples,
                "mode": "rule_based",
            }

        try:
            # Fit scaler
            scaler = StandardScaler()
            scaled_features = scaler.fit_transform(features)

            # Train Isolation Forest
            contamination = self.config.get("contamination", 0.05)
            model = IsolationForest(
                n_estimators=100,
                contamination=contamination,
                random_state=42,
                n_jobs=-1,
            )
            model.fit(scaled_features)

            # Atomically update model and scaler
            with self._model_lock:
                self.scaler = scaler
                self.model = model

            # Save model
            self._save_model()

            # Log training event
            model_version = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            self._log_training(sample_count, model_version)

            logger.info(f"Model trained successfully on {sample_count} samples")
            return {
                "status": "trained",
                "samples": sample_count,
                "model_version": model_version,
                "mode": "ml",
            }

        except Exception as e:
            logger.error(f"Model training failed: {e}")
            return {"status": "error", "reason": str(e)}

    def _log_training(self, samples: int, version: str):
        """Record training event in ml_training_log table."""
        conn = None
        try:
            conn = self._get_connection()
            conn.execute(
                "INSERT INTO ml_training_log (trained_at, samples_count, model_version) VALUES (?, ?, ?)",
                (self._now_iso(), samples, version),
            )
            conn.commit()
        except Exception as e:
            logger.error(f"Failed to log training event: {e}")
        finally:
            if conn:
                conn.close()

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    def detect_anomalies(self) -> List[Dict]:
        """Run anomaly detection on latest scan data.

        Combines rule-based detections with ML-based scoring when model
        is available. Returns list of anomaly dicts.
        """
        anomalies = []

        # Rule-based detections (always active)
        try:
            anomalies.extend(self._detect_new_hosts())
        except Exception as e:
            logger.error(f"Error detecting new hosts: {e}")

        try:
            anomalies.extend(self._detect_new_ports())
        except Exception as e:
            logger.error(f"Error detecting new ports: {e}")

        try:
            anomalies.extend(self._detect_banner_changes())
        except Exception as e:
            logger.error(f"Error detecting banner changes: {e}")

        try:
            anomalies.extend(self._detect_disappeared_hosts())
        except Exception as e:
            logger.error(f"Error detecting disappeared hosts: {e}")

        # ML-based detection (when model is trained)
        if self.model is not None and self.scaler is not None:
            try:
                ml_anomalies = self._detect_ml_anomalies()
                anomalies.extend(ml_anomalies)
            except Exception as e:
                logger.error(f"ML anomaly detection failed: {e}")

        # Store all anomalies
        for anomaly in anomalies:
            try:
                self._store_anomaly(
                    host_id=anomaly["host_id"],
                    anomaly_type=anomaly["type"],
                    score=anomaly["score"],
                    description=anomaly["description"],
                )
            except Exception as e:
                logger.error(f"Failed to store anomaly: {e}")

        logger.info(f"Detection complete: {len(anomalies)} anomalies found")
        return anomalies

    def _detect_ml_anomalies(self) -> List[Dict]:
        """Use trained ML model to detect statistical anomalies.

        Uses batch scoring: transforms and scores ALL hosts in a single
        numpy operation instead of per-host loops. This is 100-1000x faster
        on large networks (200k+ hosts).
        """
        anomalies = []

        try:
            features, host_ids = self._extract_all_features()
        except Exception:
            return anomalies

        if len(host_ids) == 0:
            return anomalies

        # Batch scoring — single call for all hosts
        with self._model_lock:
            if self.model is None or self.scaler is None:
                return anomalies
            model = self.model
            scaler = self.scaler

        try:
            # Transform all features at once (single matrix operation)
            scaled_features = scaler.transform(features)
            # Score all hosts at once (single model call)
            raw_scores = model.decision_function(scaled_features)
            # Normalize: more negative = more anomalous, map to [0, 1]
            scores = np.clip(0.5 - raw_scores, 0.0, 1.0)
        except Exception as e:
            logger.error(f"Batch scoring failed: {e}")
            return anomalies

        # Filter only hosts above threshold
        anomaly_mask = scores >= self.threshold
        anomaly_indices = np.where(anomaly_mask)[0]

        for idx in anomaly_indices:
            score = round(float(scores[idx]), 4)
            description = self._describe_ml_anomaly(features[idx], score)
            anomalies.append(
                {
                    "host_id": host_ids[idx],
                    "type": "statistical_anomaly",
                    "score": score,
                    "description": description,
                }
            )

        logger.info(
            f"ML batch scoring: {len(host_ids)} hosts scored, {len(anomalies)} anomalies (threshold={self.threshold})"
        )
        return anomalies

    def _describe_ml_anomaly(self, features: np.ndarray, score: float) -> str:
        """Generate human-readable description of ML-detected anomaly."""
        parts = [f"Statistical anomaly (score: {score:.2f})."]

        if features[FEAT_PORT_COUNT] > 20:
            parts.append(f"Unusually high port count ({int(features[FEAT_PORT_COUNT])}).")
        if features[FEAT_HIGH_PORT_RATIO] > 0.8:
            parts.append("Most ports are high-numbered (possible evasion).")
        if features[FEAT_PORT_VELOCITY] > 5:
            parts.append(f"Rapid port changes ({features[FEAT_PORT_VELOCITY]:.1f} new ports/day).")
        if features[FEAT_UNUSUAL_PORT_SCORE] > 0.5:
            parts.append("Host has unusual port combinations.")
        if features[FEAT_BANNER_CHANGES] > 3:
            parts.append(f"Frequent banner changes ({int(features[FEAT_BANNER_CHANGES])}).")

        return " ".join(parts)

    # ------------------------------------------------------------------
    # Feature Engineering
    # ------------------------------------------------------------------

    def _extract_features(self, host_id: int, conn: Optional[sqlite3.Connection] = None) -> Optional[np.ndarray]:
        """Extract feature vector for a single host.

        Features:
            0 - Total open port count
            1 - High-port ratio (ports > 1024 / total)
            2 - Service diversity score (unique services / total ports)
            3 - Time since first seen (days)
            4 - Port change velocity (new ports per day)
            5 - Banner change count
            6 - Unusual port score (suspicious ports / total)
        """
        try:
            own_conn = conn is None
            if own_conn:
                conn = self._get_connection()

            # Get host info
            host = conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
            if host is None:
                if own_conn:
                    conn.close()
                return None

            # Get active ports for this host
            ports = conn.execute("SELECT * FROM ports WHERE host_id = ? AND is_active = 1", (host_id,)).fetchall()

            # Get all ports ever seen (for velocity calculation)
            all_ports = conn.execute("SELECT * FROM ports WHERE host_id = ?", (host_id,)).fetchall()

            # FEAT_BANNER_CHANGES: query banner_changes table
            try:
                banner_changes_row = conn.execute(
                    "SELECT COUNT(*) as cnt FROM banner_changes "
                    "WHERE host_id = ? AND detected_at > datetime('now', '-24 hours')",
                    (host_id,),
                ).fetchone()
                banner_change_count = banner_changes_row["cnt"] if banner_changes_row else 0
            except sqlite3.OperationalError:
                # Table doesn't exist yet — fall back to 0
                banner_change_count = 0

            if own_conn:
                conn.close()

            features = np.zeros(NUM_FEATURES, dtype=np.float64)

            total_ports = len(ports)
            features[FEAT_PORT_COUNT] = total_ports

            if total_ports == 0:
                return features

            # High-port ratio
            high_ports = sum(1 for p in ports if p["port"] > 1024)
            features[FEAT_HIGH_PORT_RATIO] = high_ports / total_ports

            # Service diversity (unique services / total ports)
            services = set()
            for p in ports:
                if p["service"]:
                    services.add(p["service"])
            features[FEAT_SERVICE_DIVERSITY] = len(services) / total_ports if total_ports > 0 else 0

            # Time since first seen (days)
            try:
                first_seen = datetime.fromisoformat(host["first_seen"])
                now = datetime.now(timezone.utc)
                # Handle naive timestamps
                if first_seen.tzinfo is None:
                    first_seen = first_seen.replace(tzinfo=timezone.utc)
                days_active = (now - first_seen).total_seconds() / 86400.0
                features[FEAT_TIME_SINCE_FIRST] = max(days_active, 0.01)
            except (ValueError, TypeError):
                features[FEAT_TIME_SINCE_FIRST] = 0.01

            # Port change velocity (total unique ports ever / days active)
            total_ever = len(all_ports)
            days = features[FEAT_TIME_SINCE_FIRST]
            features[FEAT_PORT_VELOCITY] = total_ever / days if days > 0 else total_ever

            # Banner change count from banner_changes table
            features[FEAT_BANNER_CHANGES] = banner_change_count

            # Unusual port score (suspicious ports / total)
            suspicious_count = sum(1 for p in ports if p["port"] in SUSPICIOUS_PORTS)
            features[FEAT_UNUSUAL_PORT_SCORE] = suspicious_count / total_ports

            return features

        except Exception as e:
            logger.error(f"Feature extraction failed for host {host_id}: {e}")
            return None

    def _extract_all_features(self) -> Tuple[np.ndarray, List[int]]:
        """Extract features for all active hosts using batch SQL queries.

        Instead of N+1 queries (1 per host), uses 3 aggregate queries:
        - Port stats per host (GROUP BY host_id)
        - Host metadata (first_seen for time calculation)
        - Banner changes per host

        This reduces 200k individual queries to 3 queries total.

        Returns:
            Tuple of (feature_matrix, host_id_list)
        """
        conn = self._get_connection()
        try:
            # Query 1: Aggregate port features per host in a single query
            port_stats = conn.execute("""
                SELECT
                    host_id,
                    COUNT(*) as port_count,
                    SUM(CASE WHEN port > 1024 THEN 1 ELSE 0 END) as high_ports,
                    COUNT(DISTINCT CASE WHEN service IS NOT NULL AND service != '' THEN service END) as unique_services,
                    SUM(CASE WHEN port IN (4444,5555,6666,7777,8888,9999,1337,31337,4443,2222,6667,6668,6669,3128,8080,8081,5900,5901,4899,1234,12345) THEN 1 ELSE 0 END) as suspicious_ports
                FROM ports
                WHERE is_active = 1
                GROUP BY host_id
            """).fetchall()

            # Build lookup: host_id -> port stats
            port_data = {}
            for row in port_stats:
                port_data[row["host_id"]] = {
                    "port_count": row["port_count"],
                    "high_ports": row["high_ports"],
                    "unique_services": row["unique_services"],
                    "suspicious_ports": row["suspicious_ports"],
                }

            # Query 2: All ports ever seen per host (for velocity calc)
            all_port_counts = conn.execute("""
                SELECT host_id, COUNT(*) as total_ever
                FROM ports
                GROUP BY host_id
            """).fetchall()
            velocity_data = {row["host_id"]: row["total_ever"] for row in all_port_counts}

            # Query 3: Host metadata (first_seen, id)
            hosts = conn.execute("SELECT id, first_seen FROM hosts WHERE is_active = 1").fetchall()

            # Query 4: Banner changes per host (last 24h) - may not exist
            banner_data = {}
            try:
                banner_rows = conn.execute("""
                    SELECT host_id, COUNT(*) as cnt
                    FROM banner_changes
                    WHERE detected_at > datetime('now', '-24 hours')
                    GROUP BY host_id
                """).fetchall()
                for row in banner_rows:
                    banner_data[row["host_id"]] = row["cnt"]
            except sqlite3.OperationalError:
                pass  # Table doesn't exist yet

        finally:
            conn.close()

        # Build feature matrix in numpy (no more per-host queries)
        now = datetime.now(timezone.utc)
        features_list = []
        host_ids = []

        for host in hosts:
            host_id = host["id"]
            pdata = port_data.get(host_id)

            # Skip hosts with no ports at all
            if pdata is None:
                continue

            features = np.zeros(NUM_FEATURES, dtype=np.float64)
            total_ports = pdata["port_count"]
            features[FEAT_PORT_COUNT] = total_ports

            if total_ports > 0:
                features[FEAT_HIGH_PORT_RATIO] = pdata["high_ports"] / total_ports
                features[FEAT_SERVICE_DIVERSITY] = pdata["unique_services"] / total_ports
                features[FEAT_UNUSUAL_PORT_SCORE] = pdata["suspicious_ports"] / total_ports

            # Time since first seen
            try:
                first_seen = datetime.fromisoformat(host["first_seen"])
                if first_seen.tzinfo is None:
                    first_seen = first_seen.replace(tzinfo=timezone.utc)
                days_active = max((now - first_seen).total_seconds() / 86400.0, 0.01)
            except (ValueError, TypeError):
                days_active = 0.01
            features[FEAT_TIME_SINCE_FIRST] = days_active

            # Port velocity
            total_ever = velocity_data.get(host_id, total_ports)
            features[FEAT_PORT_VELOCITY] = total_ever / days_active if days_active > 0 else total_ever

            # Banner changes
            features[FEAT_BANNER_CHANGES] = banner_data.get(host_id, 0)

            features_list.append(features)
            host_ids.append(host_id)

        if len(features_list) == 0:
            return np.empty((0, NUM_FEATURES)), []

        feature_matrix = np.array(features_list)
        # Replace NaN/inf with 0 to prevent sklearn crashes during transform/fit
        feature_matrix = np.nan_to_num(feature_matrix, nan=0.0, posinf=0.0, neginf=0.0)
        return feature_matrix, host_ids

    # ------------------------------------------------------------------
    # Rule-Based Detection
    # ------------------------------------------------------------------

    def _detect_new_hosts(self) -> List[Dict]:
        """Check for hosts not in baseline (seen within baseline window).

        A host is 'new' if its first_seen is within the last scan cycle
        but wasn't in the baseline window before that.
        """
        anomalies = []
        conn = self._get_connection()

        # Hosts first seen in last 24 hours
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        new_hosts = conn.execute(
            "SELECT id, ip, hostname, first_seen FROM hosts WHERE first_seen > ? AND is_active = 1", (cutoff,)
        ).fetchall()

        conn.close()

        for host in new_hosts:
            hostname_str = f" ({host['hostname']})" if host["hostname"] else ""
            anomalies.append(
                {
                    "host_id": host["id"],
                    "type": "new_host",
                    "score": 0.8,
                    "description": (
                        f"New host discovered: {host['ip']}{hostname_str}. First seen: {host['first_seen']}"
                    ),
                }
            )

        return anomalies

    def _detect_new_ports(self) -> List[Dict]:
        """Check for new ports on known hosts.

        A port is 'new' if first_seen is recent but the host has been
        known for longer than the baseline window.
        """
        anomalies = []
        conn = self._get_connection()

        baseline_cutoff = (datetime.now(timezone.utc) - timedelta(days=self.baseline_window_days)).isoformat()
        recent_cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

        # Find ports first seen recently on hosts that existed before baseline
        new_ports = conn.execute(
            """
            SELECT p.id, p.host_id, p.port, p.protocol, p.service, p.first_seen,
                   h.ip, h.hostname
            FROM ports p
            JOIN hosts h ON p.host_id = h.id
            WHERE p.first_seen > ?
              AND h.first_seen < ?
              AND p.is_active = 1
              AND h.is_active = 1
            """,
            (recent_cutoff, baseline_cutoff),
        ).fetchall()

        conn.close()

        for port in new_ports:
            is_suspicious = port["port"] in SUSPICIOUS_PORTS
            score = 0.9 if is_suspicious else 0.6
            service_str = f" ({port['service']})" if port["service"] else ""

            anomalies.append(
                {
                    "host_id": port["host_id"],
                    "type": "new_port",
                    "score": score,
                    "description": (
                        f"New port {port['port']}/{port['protocol']}{service_str} "
                        f"opened on {port['ip']}. "
                        f"{'SUSPICIOUS PORT!' if is_suspicious else ''}"
                    ).strip(),
                }
            )

        return anomalies

    def _detect_banner_changes(self) -> List[Dict]:
        """Detect service banner modifications.

        The ports table only stores the *current* banner, so a true
        old-vs-new comparison is not possible from that table. The
        ``banner_changes`` table records real old->new transitions when
        the scanner observes them; we flag those. The previous heuristic
        flagged every host with any banner on a suspicious port on every
        scan cycle, spamming the anomaly store.
        """
        anomalies = []
        conn = self._get_connection()

        # Prefer real recorded transitions.
        recent_cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        try:
            changes = conn.execute(
                """
                SELECT bc.host_id, bc.port, bc.old_banner, bc.new_banner,
                       bc.detected_at, h.ip
                FROM banner_changes bc
                JOIN hosts h ON h.id = bc.host_id
                WHERE bc.detected_at > ?
                """,
                (recent_cutoff,),
            ).fetchall()
        except sqlite3.OperationalError:
            changes = []

        for change in changes:
            anomalies.append(
                {
                    "host_id": change["host_id"],
                    "type": "banner_change",
                    "score": 0.8,
                    "description": (
                        f"Banner changed on {change['ip']}:{change['port']} - "
                        f"'{str(change['old_banner'] or '')[:60]}' -> "
                        f"'{str(change['new_banner'] or '')[:60]}' at {change['detected_at']}"
                    ),
                }
            )

        conn.close()
        return anomalies

    def _detect_disappeared_hosts(self) -> List[Dict]:
        """Detect hosts that went offline.

        A host is considered disappeared if it was active but hasn't
        been seen within the disappeared threshold.
        """
        anomalies = []
        conn = self._get_connection()

        threshold = (datetime.now(timezone.utc) - timedelta(hours=self.disappeared_threshold_hours)).isoformat()

        # Hosts marked active but not seen recently
        disappeared = conn.execute(
            """
            SELECT id, ip, hostname, first_seen, last_seen
            FROM hosts
            WHERE is_active = 1
              AND last_seen < ?
            """,
            (threshold,),
        ).fetchall()

        conn.close()

        for host in disappeared:
            hostname_str = f" ({host['hostname']})" if host["hostname"] else ""
            anomalies.append(
                {
                    "host_id": host["id"],
                    "type": "host_disappeared",
                    "score": 0.65,
                    "description": (
                        f"Host {host['ip']}{hostname_str} has not been seen since "
                        f"{host['last_seen']}. Possible takedown or network change."
                    ),
                }
            )

        return anomalies

    # ------------------------------------------------------------------
    # Scoring & Storage
    # ------------------------------------------------------------------

    def _calculate_anomaly_score(self, features: np.ndarray) -> float:
        """Get anomaly score from model.

        Returns a score between 0.0 (normal) and 1.0 (highly anomalous).
        Uses sklearn's decision_function which returns negative values for
        anomalies, normalized to [0, 1] range.
        """
        with self._model_lock:
            if self.model is None or self.scaler is None:
                return 0.0
            model = self.model
            scaler = self.scaler

        try:
            # Ensure features is 2D for sklearn (reshape if 1D)
            if features.ndim == 1:
                features = features.reshape(1, -1)
            scaled = scaler.transform(features)
            # decision_function returns negative for anomalies
            raw_score = model.decision_function(scaled)[0]
            # Normalize: more negative = more anomalous
            # Typical range is [-0.5, 0.5], map to [0, 1] where 1 = anomalous
            normalized = max(0.0, min(1.0, 0.5 - raw_score))
            return round(normalized, 4)
        except Exception as e:
            logger.error(f"Score calculation failed: {e}")
            return 0.0

    def _store_anomaly(self, host_id: int, anomaly_type: str, score: float, description: str):
        """Store detected anomaly in database (deduplicates within 24h)."""
        conn = None
        try:
            conn = self._get_connection()

            # Dedup: skip if same anomaly_type for same host within last 24 hours
            existing = conn.execute(
                "SELECT id FROM anomalies WHERE host_id=? AND anomaly_type=? "
                "AND detected_at > datetime('now', '-24 hours')",
                (host_id, anomaly_type),
            ).fetchone()
            if existing:
                return

            conn.execute(
                """
                INSERT INTO anomalies (host_id, anomaly_type, score, description, detected_at, is_reviewed)
                VALUES (?, ?, ?, ?, ?, 0)
                """,
                (host_id, anomaly_type, score, description, self._now_iso()),
            )
            conn.commit()
        except Exception as e:
            logger.error(f"Failed to store anomaly for host {host_id}: {e}")
        finally:
            if conn:
                conn.close()

    # ------------------------------------------------------------------
    # Model Persistence
    # ------------------------------------------------------------------

    def _save_model(self):
        """Persist model and scaler to disk atomically."""
        try:
            model_file = self.model_path / "isolation_forest.pkl"
            scaler_file = self.model_path / "scaler.pkl"

            # Write model atomically via temp file
            fd, tmp_path = tempfile.mkstemp(dir=str(self.model_path), suffix=".pkl")
            try:
                with os.fdopen(fd, "wb") as f:
                    pickle.dump(self.model, f)
                os.replace(tmp_path, str(model_file))
            except BaseException:
                os.unlink(tmp_path)
                raise

            # Write scaler atomically via temp file
            fd, tmp_path = tempfile.mkstemp(dir=str(self.model_path), suffix=".pkl")
            try:
                with os.fdopen(fd, "wb") as f:
                    pickle.dump(self.scaler, f)
                os.replace(tmp_path, str(scaler_file))
            except BaseException:
                os.unlink(tmp_path)
                raise

            logger.info(f"Model saved to {self.model_path}")
        except Exception as e:
            logger.error(f"Failed to save model: {e}")

    def _load_model(self):
        """Load model from disk if exists."""
        model_file = self.model_path / "isolation_forest.pkl"
        scaler_file = self.model_path / "scaler.pkl"

        if not model_file.exists() or not scaler_file.exists():
            logger.info("No saved model found - starting in rule-based mode")
            return

        try:
            with open(model_file, "rb") as f:
                self.model = pickle.load(f)

            with open(scaler_file, "rb") as f:
                self.scaler = pickle.load(f)

            logger.info("Model loaded from disk successfully")
        except Exception as e:
            logger.warning(f"Failed to load model (will retrain): {e}")
            self.model = None
            self.scaler = None

    # ------------------------------------------------------------------
    # Network Summary
    # ------------------------------------------------------------------

    def get_network_summary(self) -> Dict:
        """Return current network baseline summary.

        Provides overview statistics about the monitored network including
        host count, port distribution, and model status.
        """
        try:
            conn = self._get_connection()

            # Host counts
            total_hosts = conn.execute("SELECT COUNT(*) as cnt FROM hosts WHERE is_active = 1").fetchone()["cnt"]

            inactive_hosts = conn.execute("SELECT COUNT(*) as cnt FROM hosts WHERE is_active = 0").fetchone()["cnt"]

            # Port statistics
            total_ports = conn.execute("SELECT COUNT(*) as cnt FROM ports WHERE is_active = 1").fetchone()["cnt"]

            # Service distribution
            services = conn.execute(
                """
                SELECT service, COUNT(*) as cnt
                FROM ports
                WHERE is_active = 1 AND service IS NOT NULL
                GROUP BY service
                ORDER BY cnt DESC
                LIMIT 10
                """
            ).fetchall()

            # Recent anomalies
            anomaly_count = conn.execute("SELECT COUNT(*) as cnt FROM anomalies WHERE is_reviewed = 0").fetchone()[
                "cnt"
            ]

            # Last training info
            last_training = conn.execute("SELECT * FROM ml_training_log ORDER BY trained_at DESC LIMIT 1").fetchone()

            conn.close()

            # Model status
            if self.model is not None:
                model_status = "trained"
            elif total_hosts < self.min_samples:
                model_status = f"cold_start (need {self.min_samples - total_hosts} more hosts)"
            else:
                model_status = "untrained"

            return {
                "active_hosts": total_hosts,
                "inactive_hosts": inactive_hosts,
                "total_open_ports": total_ports,
                "top_services": [{"service": s["service"], "count": s["cnt"]} for s in services],
                "unreviewed_anomalies": anomaly_count,
                "model_status": model_status,
                "last_training": dict(last_training) if last_training else None,
                "detection_mode": "ml" if self.model else "rule_based",
                "threshold": self.threshold,
            }

        except Exception as e:
            logger.error(f"Failed to generate network summary: {e}")
            return {
                "error": str(e),
                "model_status": "unknown",
            }
