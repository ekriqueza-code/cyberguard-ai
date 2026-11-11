import json
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, List

import numpy as np
import pandas as pd
from scipy.spatial.distance import jensenshannon
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


@dataclass
class ModelMetadata:
    model_id: str
    version: str
    algorithm: str
    dataset_summary: str
    features: List[str]
    metrics: Dict[str, float]
    trained_at: str
    retrain_threshold_jsd: float = 0.15


class SyntheticAuthGenerator:
    """Gera telemetria sintética de autenticação normal e cenários de intrusão (ATO)."""

    def __init__(self, seed: int = 42):
        self.rng = np.random.default_rng(seed)
        self.users = [
            "ana.silva@nexuscorp-demo.local",
            "carlos.mendes@nexuscorp-demo.local",
            "beatriz.costa@nexuscorp-demo.local",
            "rafael.oliveira@nexuscorp-demo.local",
            "juliana.santos@nexuscorp-demo.local",
        ]

    def generate(self, n_normal: int = 2500, n_anomalies: int = 120) -> pd.DataFrame:
        records = []
        base_time = datetime(2026, 11, 1, 8, 0, tzinfo=timezone.utc)

        # 1. Tráfego Legítimo (Baseline Corporativo)
        for _ in range(n_normal):
            user = self.rng.choice(self.users)
            day_offset = int(self.rng.integers(0, 10))
            hour = int(np.clip(self.rng.normal(13, 2.5), 7, 20))
            minute = int(self.rng.integers(0, 60))
            ts = base_time + timedelta(days=day_offset, hours=hour - 8, minutes=minute)

            records.append({
                "event_id": str(uuid.uuid4()),
                "timestamp": ts.isoformat(),
                "user": user,
                "source_ip": f"177.32.{self.rng.integers(1, 254)}.{self.rng.integers(1, 254)}",
                "asn_type": self.rng.choice(["RESIDENTIAL_ISP", "CORPORATE_VPN"], p=[0.7, 0.3]),
                "is_known_device": int(self.rng.choice([1, 0], p=[0.95, 0.05])),
                "geo_velocity_kmh": float(np.abs(self.rng.normal(15, 20))),
                "failed_attempts_10m": int(self.rng.choice([0, 1, 2], p=[0.85, 0.12, 0.03])),
                "is_headless_ua": 0,
                "post_auth_sensitive_action": int(self.rng.choice([0, 1], p=[0.98, 0.02])),
                "is_intrusion": 0,
            })

        # 2. Tráfego Malicioso Simulado
        for _ in range(n_anomalies):
            attack_type = self.rng.choice(
                ["PASSWORD_SPRAY", "ATO_IMPOSSIBLE_TRAVEL", "POST_AUTH_PERSISTENCE"]
            )
            user = self.rng.choice(self.users)
            day_offset = int(self.rng.integers(0, 10))
            hour = int(self.rng.integers(1, 5))
            minute = int(self.rng.integers(0, 60))
            ts = base_time + timedelta(days=day_offset, hours=hour - 8, minutes=minute)

            if attack_type == "PASSWORD_SPRAY":
                rec = {
                    "asn_type": "HOSTING_VPS",
                    "is_known_device": 0,
                    "geo_velocity_kmh": float(self.rng.uniform(500, 1500)),
                    "failed_attempts_10m": int(self.rng.integers(6, 25)),
                    "is_headless_ua": 1,
                    "post_auth_sensitive_action": 0,
                }
            elif attack_type == "ATO_IMPOSSIBLE_TRAVEL":
                rec = {
                    "asn_type": "HOSTING_VPS",
                    "is_known_device": 0,
                    "geo_velocity_kmh": float(self.rng.uniform(2500, 7500)),
                    "failed_attempts_10m": int(self.rng.integers(1, 4)),
                    "is_headless_ua": int(self.rng.choice([0, 1], p=[0.4, 0.6])),
                    "post_auth_sensitive_action": 0,
                }
            else:
                rec = {
                    "asn_type": "HOSTING_VPS",
                    "is_known_device": 0,
                    "geo_velocity_kmh": float(self.rng.uniform(1800, 5000)),
                    "failed_attempts_10m": 0,
                    "is_headless_ua": 1,
                    "post_auth_sensitive_action": 1,
                }

            records.append({
                "event_id": str(uuid.uuid4()),
                "timestamp": ts.isoformat(),
                "user": user,
                "source_ip": f"198.51.100.{self.rng.integers(10, 200)}",
                "is_intrusion": 1,
                **rec,
            })

        return pd.DataFrame(records).sample(frac=1, random_state=42).reset_index(drop=True)


class SecurityFeatureEngineer:
    """Transforma eventos brutos em vetores numéricos comportamentais."""

    FEATURE_COLUMNS = [
        "hour_sin",
        "hour_cos",
        "is_off_hours",
        "is_vps_asn",
        "is_known_device",
        "log_geo_velocity",
        "failed_attempts_10m",
        "is_headless_ua",
        "post_auth_sensitive_action",
    ]

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        data = df.copy()
        dt = pd.to_datetime(data["timestamp"])

        hour = dt.dt.hour + dt.dt.minute / 60.0
        data["hour_sin"] = np.sin(2 * np.pi * hour / 24.0)
        data["hour_cos"] = np.cos(2 * np.pi * hour / 24.0)

        data["is_off_hours"] = ((dt.dt.hour < 7) | (dt.dt.hour > 20)).astype(int)
        data["is_vps_asn"] = (data["asn_type"] == "HOSTING_VPS").astype(int)
        data["log_geo_velocity"] = np.log1p(data["geo_velocity_kmh"])

        return data[self.FEATURE_COLUMNS]


class AnomalyDetectionPipeline:
    """Pipeline híbrido calibrado para inferência unitária e em lote."""

    def __init__(self, contamination: float = 0.045):
        self.scaler = StandardScaler()
        self.iso_forest = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=42,
            n_jobs=-1,
        )
        self.rf_classifier = RandomForestClassifier(
            n_estimators=150,
            max_depth=8,
            class_weight="balanced",
            random_state=42,
        )
        self.iso_min: float = 0.0
        self.iso_max: float = 1.0
        self.baseline_dist: np.ndarray | None = None
        self.metadata: ModelMetadata | None = None

    def train_and_evaluate(self, X: pd.DataFrame, y: pd.Series) -> ModelMetadata:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.25, stratify=y, random_state=42
        )

        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        # 1. Treinamento e calibração de escala do Isolation Forest
        self.iso_forest.fit(X_train_scaled)
        train_raw_iso = -self.iso_forest.decision_function(X_train_scaled)
        self.iso_min = float(np.percentile(train_raw_iso, 1))
        self.iso_max = float(np.percentile(train_raw_iso, 99))

        iso_preds_raw = self.iso_forest.predict(X_test_scaled)
        iso_preds = np.where(iso_preds_raw == -1, 1, 0)

        # 2. Treinamento do Random Forest
        self.rf_classifier.fit(X_train_scaled, y_train)
        rf_preds = self.rf_classifier.predict(X_test_scaled)

        # 3. Referência de Data Drift
        hist_counts, _ = np.histogram(X_train["log_geo_velocity"], bins=10, density=True)
        self.baseline_dist = hist_counts + 1e-8

        cm = confusion_matrix(y_test, iso_preds)
        false_positives = cm[0, 1]

        metrics = {
            "iso_precision": round(float(precision_score(y_test, iso_preds)), 4),
            "iso_recall": round(float(recall_score(y_test, iso_preds)), 4),
            "iso_f1": round(float(f1_score(y_test, iso_preds)), 4),
            "rf_precision": round(float(precision_score(y_test, rf_preds)), 4),
            "rf_recall": round(float(recall_score(y_test, rf_preds)), 4),
            "rf_f1": round(float(f1_score(y_test, rf_preds)), 4),
            "false_positive_rate_iso": round(float(false_positives / (y_test == 0).sum()), 4),
        }

        self.metadata = ModelMetadata(
            model_id=f"cg-anomaly-{uuid.uuid4().hex[:8]}",
            version="1.1.0",
            algorithm="Hybrid Calibrated (IsolationForest + RandomForest)",
            dataset_summary=f"Total={len(X)} | Normal={(y == 0).sum()} | Intrusion={(y == 1).sum()}",
            features=list(X.columns),
            metrics=metrics,
            trained_at=datetime.now(timezone.utc).isoformat(),
        )
        return self.metadata

    def score_events(self, X_new: pd.DataFrame) -> pd.DataFrame:
        """Calcula score calibrado (0-100) e nível de risco para eventos individuais ou em lote."""
        X_scaled = self.scaler.transform(X_new)

        raw_iso_score = -self.iso_forest.decision_function(X_scaled)
        iso_norm = np.clip(
            (raw_iso_score - self.iso_min) / (self.iso_max - self.iso_min + 1e-8), 0.0, 1.0
        )

        rf_prob = self.rf_classifier.predict_proba(X_scaled)[:, 1]
        combined_score = np.round((0.40 * iso_norm + 0.60 * rf_prob) * 100, 2)

        def map_risk_level(score: float) -> str:
            if score >= 85:
                return "CRITICAL"
            if score >= 65:
                return "HIGH"
            if score >= 40:
                return "MODERATE"
            return "LOW"

        return pd.DataFrame({
            "anomaly_score_0_100": combined_score,
            "iso_anomaly_flag": (self.iso_forest.predict(X_scaled) == -1),
            "rf_intrusion_prob": np.round(rf_prob, 4),
            "risk_level": [map_risk_level(s) for s in combined_score],
        })

    def check_data_drift(self, X_production: pd.DataFrame) -> Dict[str, float | bool]:
        """Detecta Data Drift usando Divergência de Jensen-Shannon."""
        prod_counts, _ = np.histogram(X_production["log_geo_velocity"], bins=10, density=True)
        prod_dist = prod_counts + 1e-8
        js_distance = float(jensenshannon(self.baseline_dist, prod_dist))
        return {
            "jensen_shannon_distance": round(js_distance, 4),
            "drift_detected": bool(js_distance > self.metadata.retrain_threshold_jsd),
        }


if __name__ == "__main__":
    generator = SyntheticAuthGenerator(seed=42)
    raw_df = generator.generate(n_normal=2500, n_anomalies=120)

    fe = SecurityFeatureEngineer()
    X_features = fe.transform(raw_df)
    y_target = raw_df["is_intrusion"]

    pipeline = AnomalyDetectionPipeline(contamination=0.045)
    meta = pipeline.train_and_evaluate(X_features, y_target)

    print("=== METADADOS E MÉTRICAS DO MODELO CALIBRADO (MÓDULO 05) ===")
    print(json.dumps(asdict(meta), indent=2))

    test_events = pd.DataFrame([
        {
            "timestamp": "2026-11-10T03:14:22Z",
            "user": "ana.silva@nexuscorp-demo.local",
            "asn_type": "HOSTING_VPS",
            "is_known_device": 0,
            "geo_velocity_kmh": 4200.0,
            "failed_attempts_10m": 2,
            "is_headless_ua": 1,
            "post_auth_sensitive_action": 1,
        },
        {
            "timestamp": "2026-11-10T10:30:00Z",
            "user": "carlos.mendes@nexuscorp-demo.local",
            "asn_type": "CORPORATE_VPN",
            "is_known_device": 1,
            "geo_velocity_kmh": 12.0,
            "failed_attempts_10m": 0,
            "is_headless_ua": 0,
            "post_auth_sensitive_action": 0,
        },
    ])

    X_sim = fe.transform(test_events)
    predictions = pipeline.score_events(X_sim)
    predictions["user"] = test_events["user"]

    print("\n=== RESULTADO DA INFERÊNCIA CALIBRADA ===")
    print(predictions[["user", "anomaly_score_0_100", "iso_anomaly_flag", "rf_intrusion_prob", "risk_level"]].to_dict(orient="records"))