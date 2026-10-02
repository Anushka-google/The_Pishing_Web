"""
Phishing Detection & Risk Intelligence Platform
Phase 22: MLflow Experiment Tracking & Model Registry

Tracks ML experiments, hyperparameters, dataset versions, metrics, and model artifacts:
- Experiment: Phishing_Detection_Intelligence
- Models tracked: XGBoost Tuned (300 est, depth 6, lr 0.05), XGBoost Baseline, Random Forest, Decision Tree, Logistic Regression
- Dataset metadata: version hash, sample count, feature count, split strategy
- Metrics: Precision, Recall, F1, ROC-AUC, PR-AUC, Accuracy, Latency, Confusion Matrix
- Model artifacts: Signatures, input examples, metrics JSON, confusion matrix, feature importance
- Model Registry: Champion model registration, versioning, and staging
"""

import os
import sys
import json
import time
import hashlib
from typing import Dict, Any, List, Tuple, Optional
import pandas as pd
import numpy as np
import joblib

# Silence MLflow tips in automated environments
os.environ["MLFLOW_DISABLE_AGENT_HINT"] = "1"

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

import mlflow
import mlflow.sklearn
import mlflow.xgboost
from mlflow.models.signature import infer_signature
from mlflow.tracking import MlflowClient

from sklearn.model_selection import train_test_split, GroupShuffleSplit
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
import xgboost as xgb
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix
)
import tldextract

from src.features.extractor import FeatureExtractor


class MLflowExperimentTracker:
    """
    Production-grade MLflow experiment tracking, artifact logging, and model registry manager.
    """
    DEFAULT_EXPERIMENT_NAME = "Phishing_Detection_Intelligence"
    REGISTERED_MODEL_NAME = "Phishing_Detection_Intelligence"

    def __init__(
        self,
        tracking_uri: Optional[str] = None,
        experiment_name: str = DEFAULT_EXPERIMENT_NAME,
        features_csv: str = "data/processed/features.csv",
        dataset_version: str = "v1.2.0-curated",
        models_dir: str = "models",
        random_state: int = 42
    ):
        self.experiment_name = experiment_name
        self.features_csv = features_csv
        self.dataset_version = dataset_version
        self.models_dir = models_dir
        self.random_state = random_state

        os.makedirs(self.models_dir, exist_ok=True)
        os.makedirs("data/processed", exist_ok=True)

        if not os.path.exists(features_csv):
            raise FileNotFoundError(f"Feature dataset not found at {features_csv}")

        # Set tracking URI
        if tracking_uri is None:
            tracking_uri = os.environ.get("MLFLOW_TRACKING_URI", "sqlite:///data/mlflow.db")
        self.tracking_uri = tracking_uri
        mlflow.set_tracking_uri(self.tracking_uri)

        # Set or create experiment
        self.experiment = mlflow.set_experiment(self.experiment_name)
        self.client = MlflowClient(tracking_uri=self.tracking_uri)

        # Precompute dataset hash and metadata
        self.dataset_metadata = self._compute_dataset_metadata()

    def _compute_dataset_metadata(self) -> Dict[str, Any]:
        """Calculates cryptographic SHA-256 hash and statistical metadata of the features dataset."""
        hasher = hashlib.sha256()
        with open(self.features_csv, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        sha256_hash = hasher.hexdigest()

        df = pd.read_csv(self.features_csv)
        total_samples = len(df)
        phishing_samples = int((df["label"] == 1).sum())
        legitimate_samples = int((df["label"] == 0).sum())
        phishing_ratio = round(phishing_samples / total_samples, 4) if total_samples > 0 else 0.0

        return {
            "version": self.dataset_version,
            "sha256": sha256_hash,
            "file_path": self.features_csv,
            "total_samples": total_samples,
            "num_features": len(FeatureExtractor.FEATURE_NAMES),
            "phishing_samples": phishing_samples,
            "legitimate_samples": legitimate_samples,
            "phishing_ratio": phishing_ratio
        }

    def load_and_split_data(
        self,
        test_size: float = 0.20,
        split_strategy: str = "stratified_holdout"
    ) -> Tuple[pd.DataFrame, pd.DataFrame, np.ndarray, np.ndarray, StandardScaler]:
        """
        Loads dataset and partitions into train and test splits according to chosen strategy.
        """
        df = pd.read_csv(self.features_csv)
        feature_cols = FeatureExtractor.FEATURE_NAMES
        X = df[feature_cols].copy().fillna(0)
        y = df["label"].astype(int).values

        if split_strategy == "domain_grouped" and "url" in df.columns:
            # Extract domain group
            ext = tldextract.TLDExtract()
            def get_dom(u: str) -> str:
                e = ext(str(u))
                d = getattr(e, "top_domain_under_public_suffix", None) or e.registered_domain
                return d.lower() if d else "unknown"

            groups = df["url"].apply(get_dom)
            gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=self.random_state)
            train_idx, test_idx = next(gss.split(X, y, groups=groups))
            X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
            y_train, y_test = y[train_idx], y[test_idx]
        else:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y,
                test_size=test_size,
                random_state=self.random_state,
                stratify=y
            )

        scaler = StandardScaler()
        scaler.fit(X_train)

        return X_train, X_test, y_train, y_test, scaler

    def get_candidate_models(self) -> List[Dict[str, Any]]:
        """
        Returns list of candidate model configurations to benchmark and track in MLflow.
        Includes tuned XGBoost (max_depth=6, lr=0.05, n_estimators=300), baseline XGBoost,
        Random Forest, Decision Tree, and Logistic Regression.
        """
        return [
            {
                "run_name": "XGBoost_Tuned",
                "model_name": "XGBoost",
                "framework": "xgboost",
                "requires_scaling": False,
                "model": xgb.XGBClassifier(
                    n_estimators=300,
                    max_depth=6,
                    learning_rate=0.05,
                    subsample=0.8,
                    colsample_bytree=0.8,
                    eval_metric="logloss",
                    random_state=self.random_state,
                    n_jobs=-1
                ),
                "params": {
                    "model_type": "XGBoost",
                    "n_estimators": 300,
                    "max_depth": 6,
                    "learning_rate": 0.05,
                    "subsample": 0.8,
                    "colsample_bytree": 0.8,
                    "eval_metric": "logloss",
                    "random_state": self.random_state
                },
                "tags": {
                    "model_family": "gradient_boosting",
                    "tuning_status": "tuned_hyperparameters",
                    "candidate_role": "high_capacity_champion_contender"
                }
            },
            {
                "run_name": "XGBoost_Baseline",
                "model_name": "XGBoost",
                "framework": "xgboost",
                "requires_scaling": False,
                "model": xgb.XGBClassifier(
                    n_estimators=100,
                    max_depth=6,
                    learning_rate=0.1,
                    eval_metric="logloss",
                    random_state=self.random_state,
                    n_jobs=-1
                ),
                "params": {
                    "model_type": "XGBoost",
                    "n_estimators": 100,
                    "max_depth": 6,
                    "learning_rate": 0.1,
                    "eval_metric": "logloss",
                    "random_state": self.random_state
                },
                "tags": {
                    "model_family": "gradient_boosting",
                    "tuning_status": "default_baseline"
                }
            },
            {
                "run_name": "Random_Forest",
                "model_name": "Random Forest",
                "framework": "sklearn",
                "requires_scaling": False,
                "model": RandomForestClassifier(
                    n_estimators=100,
                    max_depth=12,
                    criterion="gini",
                    random_state=self.random_state,
                    n_jobs=-1
                ),
                "params": {
                    "model_type": "Random Forest",
                    "n_estimators": 100,
                    "max_depth": 12,
                    "criterion": "gini",
                    "random_state": self.random_state
                },
                "tags": {
                    "model_family": "bagging_ensemble",
                    "tuning_status": "production_baseline"
                }
            },
            {
                "run_name": "Decision_Tree",
                "model_name": "Decision Tree",
                "framework": "sklearn",
                "requires_scaling": False,
                "model": DecisionTreeClassifier(
                    max_depth=10,
                    min_samples_split=5,
                    criterion="gini",
                    random_state=self.random_state
                ),
                "params": {
                    "model_type": "Decision Tree",
                    "max_depth": 10,
                    "min_samples_split": 5,
                    "criterion": "gini",
                    "random_state": self.random_state
                },
                "tags": {
                    "model_family": "decision_tree",
                    "tuning_status": "non_linear_single_tree"
                }
            },
            {
                "run_name": "Logistic_Regression",
                "model_name": "Logistic Regression",
                "framework": "sklearn",
                "requires_scaling": True,
                "model": LogisticRegression(
                    C=1.0,
                    solver="lbfgs",
                    max_iter=1000,
                    random_state=self.random_state
                ),
                "params": {
                    "model_type": "Logistic Regression",
                    "C": 1.0,
                    "solver": "lbfgs",
                    "max_iter": 1000,
                    "scaler": "StandardScaler",
                    "random_state": self.random_state
                },
                "tags": {
                    "model_family": "linear_model",
                    "tuning_status": "calibrated_linear_reference"
                }
            }
        ]

    def train_and_log_run(
        self,
        candidate: Dict[str, Any],
        X_train: pd.DataFrame,
        X_test: pd.DataFrame,
        y_train: np.ndarray,
        y_test: np.ndarray,
        scaler: StandardScaler,
        split_strategy: str = "stratified_holdout"
    ) -> Dict[str, Any]:
        """
        Fits candidate model, computes metrics, and logs run parameters, metrics, tags,
        and model artifacts to MLflow.
        """
        model = candidate["model"]
        requires_scaling = candidate["requires_scaling"]
        framework = candidate["framework"]
        run_name = candidate["run_name"]

        # Prepare feature matrices preserving feature names
        if requires_scaling:
            X_tr = pd.DataFrame(scaler.transform(X_train), columns=X_train.columns)
            X_te = pd.DataFrame(scaler.transform(X_test), columns=X_test.columns)
        else:
            X_tr = X_train
            X_te = X_test

        with mlflow.start_run(run_name=run_name) as run:
            run_id = run.info.run_id

            # 1. Log Dataset & Experiment Tags
            tags = {
                "dataset_version": self.dataset_version,
                "dataset_sha256": self.dataset_metadata["sha256"][:12],
                "dataset_total_samples": str(self.dataset_metadata["total_samples"]),
                "split_strategy": split_strategy,
                "feature_count": str(len(FeatureExtractor.FEATURE_NAMES)),
                "framework": framework,
                **candidate.get("tags", {})
            }
            mlflow.set_tags(tags)

            # 2. Log Hyperparameters
            mlflow.log_params(candidate["params"])

            # 3. Train Model and measure training time
            t0 = time.perf_counter()
            model.fit(X_tr, y_train)
            train_time_sec = round(time.perf_counter() - t0, 4)

            # 4. Measure Inference Latency & Predictions
            t_inf0 = time.perf_counter()
            y_pred = model.predict(X_te)
            y_proba = model.predict_proba(X_te)[:, 1]
            inf_duration = time.perf_counter() - t_inf0
            latency_ms_per_url = round((inf_duration / len(X_te)) * 1000.0, 4)

            # 5. Calculate Metrics
            acc = round(float(accuracy_score(y_test, y_pred)), 4)
            prec = round(float(precision_score(y_test, y_pred, zero_division=0)), 4)
            rec = round(float(recall_score(y_test, y_pred, zero_division=0)), 4)
            f1 = round(float(f1_score(y_test, y_pred, zero_division=0)), 4)
            roc = round(float(roc_auc_score(y_test, y_proba)), 4)
            pr_auc = round(float(average_precision_score(y_test, y_proba)), 4)

            cm = confusion_matrix(y_test, y_pred)
            tn, fp, fn, tp = [int(v) for v in cm.ravel()]
            fpr = round(float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0, 4)
            fnr = round(float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0, 4)

            metrics = {
                "precision": prec,
                "recall": rec,
                "f1_score": f1,
                "roc_auc": roc,
                "pr_auc": pr_auc,
                "accuracy": acc,
                "training_time_seconds": train_time_sec,
                "latency_ms_per_url": latency_ms_per_url,
                "true_positives": tp,
                "false_positives": fp,
                "true_negatives": tn,
                "false_negatives": fn,
                "false_positive_rate": fpr,
                "false_negative_rate": fnr
            }
            mlflow.log_metrics(metrics)

            # 6. Log Structured Artifacts (JSON)
            metrics_artifact = {
                "model_name": candidate["model_name"],
                "run_name": run_name,
                "run_id": run_id,
                "parameters": candidate["params"],
                "metrics": metrics,
                "dataset_version": self.dataset_version,
                "split_strategy": split_strategy
            }
            mlflow.log_dict(metrics_artifact, "metrics.json")

            cm_artifact = {
                "tp": tp, "fp": fp, "tn": tn, "fn": fn,
                "fpr": fpr, "fnr": fnr,
                "sample_size": len(y_test)
            }
            mlflow.log_dict(cm_artifact, "confusion_matrix.json")

            # Feature importances if available
            feature_names = FeatureExtractor.FEATURE_NAMES
            feature_imp = {}
            if hasattr(model, "feature_importances_"):
                importances = model.feature_importances_
                feature_imp = {fn: round(float(val), 5) for fn, val in zip(feature_names, importances)}
                feature_imp = dict(sorted(feature_imp.items(), key=lambda kv: kv[1], reverse=True))
                mlflow.log_dict(feature_imp, "feature_importance.json")
            elif hasattr(model, "coef_"):
                importances = model.coef_[0]
                feature_imp = {fn: round(float(val), 5) for fn, val in zip(feature_names, importances)}
                feature_imp = dict(sorted(feature_imp.items(), key=lambda kv: abs(kv[1]), reverse=True))
                mlflow.log_dict(feature_imp, "feature_importance.json")

            # 7. Log Model Artifact with Signature
            input_sample = X_test.iloc[:5]
            if requires_scaling:
                input_sample_eval = scaler.transform(input_sample)
            else:
                input_sample_eval = input_sample.values

            sample_pred = model.predict(input_sample_eval)
            signature = infer_signature(input_sample, sample_pred)

            if framework == "xgboost":
                mlflow.xgboost.log_model(
                    xgb_model=model,
                    name="model",
                    signature=signature,
                    input_example=input_sample
                )
            else:
                mlflow.sklearn.log_model(
                    sk_model=model,
                    name="model",
                    signature=signature,
                    input_example=input_sample
                )

            # Return run record
            record = {
                "run_id": run_id,
                "run_name": run_name,
                "model_name": candidate["model_name"],
                "framework": framework,
                "requires_scaling": requires_scaling,
                "model_object": model,
                "scaler": scaler if requires_scaling else None,
                "metrics": metrics,
                "params": candidate["params"],
                "feature_importance": feature_imp
            }
            return record

    def run_all_experiments(
        self,
        split_strategy: str = "stratified_holdout",
        register_champion: bool = True
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any], str]:
        """
        Runs complete experiment suite for all candidate models, logs to MLflow,
        determines champion, registers champion in the MLflow Model Registry,
        and saves production bundle.
        """
        X_train, X_test, y_train, y_test, scaler = self.load_and_split_data(
            test_size=0.20,
            split_strategy=split_strategy
        )

        candidates = self.get_candidate_models()
        records: List[Dict[str, Any]] = []

        for candidate in candidates:
            print(f"[MLflow] Running experiment for: {candidate['run_name']}...")
            rec = self.train_and_log_run(
                candidate=candidate,
                X_train=X_train,
                X_test=X_test,
                y_train=y_train,
                y_test=y_test,
                scaler=scaler,
                split_strategy=split_strategy
            )
            records.append(rec)
            print(
                f"  -> Precision: {rec['metrics']['precision']*100:.2f}% | "
                f"Recall: {rec['metrics']['recall']*100:.2f}% | "
                f"F1: {rec['metrics']['f1_score']*100:.2f}% | "
                f"ROC-AUC: {rec['metrics']['roc_auc']:.4f}"
            )

        # Determine Champion Model by F1-Score (and ROC-AUC as tie breaker)
        champion_record = max(
            records,
            key=lambda r: (r["metrics"]["f1_score"], r["metrics"]["roc_auc"])
        )
        champion_run_id = champion_record["run_id"]
        champion_name = champion_record["model_name"]
        print(f"\n[MLflow] [CHAMPION] Champion Model Selected: {champion_record['run_name']} (Run ID: {champion_run_id})")

        # Load calibrated thresholds if existing
        thresholds = {"t1_low": 0.40, "t2_high": 0.65, "t_optimal": 0.2872}
        calib_file = "data/processed/threshold_calibration.json"
        if os.path.exists(calib_file):
            try:
                with open(calib_file, "r") as f:
                    calib_data = json.load(f)
                    cal_thresh = calib_data.get("calibrated_thresholds", {})
                    thresholds["t1_low"] = float(cal_thresh.get("t1_low_risk_threshold", 0.40))
                    thresholds["t2_high"] = float(cal_thresh.get("t2_high_risk_threshold", 0.65))
                    thresholds["t_optimal"] = float(calib_data.get("optimal_f1_threshold", 0.2872))
            except Exception:
                pass

        # Save Champion bundle to models/champion_phishing_model.joblib for production runtime
        champion_joblib_path = os.path.join(self.models_dir, "champion_phishing_model.joblib")
        benchmark_results = [
            {
                "model": r["model_name"],
                "run_name": r["run_name"],
                "precision": r["metrics"]["precision"],
                "recall": r["metrics"]["recall"],
                "f1": r["metrics"]["f1_score"],
                "roc_auc": r["metrics"]["roc_auc"],
                "pr_auc": r["metrics"]["pr_auc"],
                "accuracy": r["metrics"]["accuracy"],
                "train_time_sec": r["metrics"]["training_time_seconds"],
                "latency_ms_per_url": r["metrics"]["latency_ms_per_url"]
            }
            for r in records
        ]

        bundle = {
            "model_name": champion_record["model_name"],
            "model": champion_record["model_object"],
            "scaler": champion_record["scaler"],
            "requires_scaling": champion_record["requires_scaling"],
            "feature_names": FeatureExtractor.FEATURE_NAMES,
            "training_samples": len(X_train),
            "test_samples": len(X_test),
            "benchmark_results": benchmark_results,
            "thresholds": thresholds,
            "mlflow_run_id": champion_run_id,
            "dataset_version": self.dataset_version,
            "model_version": "v1.0.0"
        }
        joblib.dump(bundle, champion_joblib_path)
        print(f"[MLflow] Champion bundle successfully exported to: {champion_joblib_path}")

        # Register Champion in MLflow Model Registry
        model_version_str = "1"
        if register_champion:
            model_uri = f"runs:/{champion_run_id}/model"
            try:
                reg_model = mlflow.register_model(
                    model_uri=model_uri,
                    name=self.REGISTERED_MODEL_NAME
                )
                model_version_str = str(reg_model.version)
                self.client.set_model_version_tag(
                    name=self.REGISTERED_MODEL_NAME,
                    version=model_version_str,
                    key="is_champion",
                    value="true"
                )
                self.client.set_model_version_tag(
                    name=self.REGISTERED_MODEL_NAME,
                    version=model_version_str,
                    key="dataset_version",
                    value=self.dataset_version
                )
                self.client.set_model_version_tag(
                    name=self.REGISTERED_MODEL_NAME,
                    version=model_version_str,
                    key="f1_score",
                    value=str(champion_record["metrics"]["f1_score"])
                )
                print(f"[MLflow] Model successfully registered as '{self.REGISTERED_MODEL_NAME}' version {model_version_str}")
            except Exception as e:
                print(f"[MLflow] Model registry registration warning: {e}")

        # Export summaries
        summary_json_path = "data/processed/mlflow_experiment_summary.json"
        doc_md_path = "docs/phase_22_mlflow_tracking.md"
        self._export_summaries(records, champion_record, summary_json_path, doc_md_path)

        return records, champion_record, champion_joblib_path

    def _export_summaries(
        self,
        records: List[Dict[str, Any]],
        champion: Dict[str, Any],
        json_path: str,
        md_path: str
    ):
        """Generates structured JSON summary and comprehensive markdown documentation."""
        serializable_records = [
            {
                "run_id": r["run_id"],
                "run_name": r["run_name"],
                "model_name": r["model_name"],
                "framework": r["framework"],
                "params": r["params"],
                "metrics": r["metrics"],
                "is_champion": (r["run_id"] == champion["run_id"])
            }
            for r in records
        ]

        summary = {
            "experiment_name": self.experiment_name,
            "tracking_uri": self.tracking_uri,
            "dataset_metadata": self.dataset_metadata,
            "champion_model": {
                "run_id": champion["run_id"],
                "run_name": champion["run_name"],
                "model_name": champion["model_name"],
                "metrics": champion["metrics"],
                "params": champion["params"]
            },
            "runs": serializable_records
        }

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        # Markdown Document
        os.makedirs(os.path.dirname(md_path), exist_ok=True)
        md = f"""# Phase 22: MLflow Experiment Tracking & Model Registry

## 🎯 Objective
Establish rigorous MLOps experiment tracking and model governance using **MLflow 3.x**. Every candidate model is systematically trained, evaluated, and tracked with its complete lineage:
- **Architecture & Frameworks**: Scikit-Learn and XGBoost
- **Hyperparameter Configurations**: Depth, estimators, learning rate, subsampling, regularization
- **Dataset Provenance**: Version `{self.dataset_version}`, SHA-256 fingerprint, feature schema
- **Standardized Metrics**: Precision, Recall, F1, ROC-AUC, PR-AUC, Accuracy, Latency, Confusion Matrix
- **Model Artifacts & Signatures**: Input examples, model artifacts, feature importances, and Model Registry registration

---

## 📊 Experiment Results Summary

- **Experiment Name**: `{self.experiment_name}`
- **Tracking Database**: `{self.tracking_uri}`
- **Dataset Fingerprint**: `{self.dataset_metadata['sha256'][:16]}...` ({self.dataset_metadata['total_samples']} samples, {self.dataset_metadata['num_features']} signals)

| Run Name | Model | Precision | Recall | F1-Score | ROC-AUC | PR-AUC | Accuracy | Train Time | Latency / URL |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
"""
        for r in records:
            is_champ = "**" if r["run_id"] == champion["run_id"] else ""
            m = r["metrics"]
            md += (
                f"| {is_champ}{r['run_name']}{is_champ} | {r['model_name']} | "
                f"{m['precision']*100:.2f}% | {m['recall']*100:.2f}% | "
                f"{is_champ}{m['f1_score']*100:.2f}%{is_champ} | {m['roc_auc']:.4f} | "
                f"{m['pr_auc']:.4f} | {m['accuracy']*100:.2f}% | "
                f"{m['training_time_seconds']:.3f}s | {m['latency_ms_per_url']:.4f} ms |\n"
            )

        md += f"""
---

## 🏆 Champion Model Selection

- **Champion Run**: `{champion['run_name']}`
- **Model Architecture**: `{champion['model_name']}`
- **MLflow Run ID**: `{champion['run_id']}`
- **Registered Model Name**: `{self.REGISTERED_MODEL_NAME}`

### Hyperparameter Metadata:
```json
{json.dumps(champion['params'], indent=2)}
```

### Measured Performance:
- **Precision**: `{champion['metrics']['precision']*100:.2f}%`
- **Recall**: `{champion['metrics']['recall']*100:.2f}%`
- **F1-Score**: `{champion['metrics']['f1_score']*100:.2f}%`
- **ROC-AUC**: `{champion['metrics']['roc_auc']:.4f}`
- **PR-AUC**: `{champion['metrics']['pr_auc']:.4f}`
- **Inference Latency**: `{champion['metrics']['latency_ms_per_url']:.4f} ms / URL`

---

## 🔍 Model Artifacts & Governance

Each tracked run in MLflow includes:
1. **Model Signature**: Strictly typed input schema (22 URL feature signals) and binary output tensor.
2. **Input Example**: 5 sample URL feature rows demonstrating expected production payload.
3. **Artifacts**:
   - `metrics.json`: Full metric breakdown including False Positive Rate and False Negative Rate.
   - `confusion_matrix.json`: Raw confusion counts (`tp`, `fp`, `tn`, `fn`).
   - `feature_importance.json`: Ranked feature weight attributions.
4. **Model Registry**: Automated promotion of champion model with tags `is_champion=true` and `dataset_version={self.dataset_version}`.

---

## 💻 How to View Experiments in MLflow UI

To launch the local MLflow dashboard:
```bash
mlflow ui --backend-store-uri sqlite:///data/mlflow.db --port 5000
```
Then navigate to `http://localhost:5000` to inspect runs, compare parameters, plot metric curves, and audit registered models.
"""
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md)

    def get_runs_dataframe(self) -> pd.DataFrame:
        """Queries MLflow for all runs in the current experiment as a DataFrame."""
        return mlflow.search_runs(experiment_names=[self.experiment_name])


if __name__ == "__main__":
    tracker = MLflowExperimentTracker()
    records, champ, artifact_path = tracker.run_all_experiments()
    print("\n" + "=" * 80)
    print("  PHASE 22: MLFLOW EXPERIMENT TRACKING COMPLETE")
    print("=" * 80)
    print(f"Logged {len(records)} runs to MLflow experiment '{tracker.experiment_name}'.")
    print(f"Champion Model: {champ['run_name']} ({champ['model_name']})")
    print(f"Tracking Database: {tracker.tracking_uri}")
    print(f"Saved Production Artifact: {artifact_path}")
    print("=" * 80)
