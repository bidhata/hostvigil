"""HostVigil ML Engine - Machine learning anomaly detection.

Provides network behavior baseline learning and anomaly detection
using a combination of rule-based heuristics and sklearn models.
"""

from .anomaly_detector import SKLEARN_AVAILABLE, AnomalyDetector

__all__ = ["AnomalyDetector", "SKLEARN_AVAILABLE"]
