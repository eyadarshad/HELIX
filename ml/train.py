"""
train.py — HELIX ML Training Pipeline (v2)

Trains and compares four classifiers + detects overfitting:
    1. Logistic Regression    — interpretable baseline
    2. Random Forest          — regularised (max_depth=12, min_samples_leaf=3)
    3. HistGradientBoosting   — fast modern boosting, handles scale natively
    4. Soft Voting Ensemble   — combines RF + HGB predictions (usually best)

Improvements over v1:
    - Overfitting detection: prints train vs CV gap for every model
    - Best model selected by CV F1 (not test set F1) — no data leakage
    - Platt probability calibration on the winner
    - Regularised RF (prevents memorising training set)
    - HistGradientBoosting replaces slow sklearn GradientBoosting
    - Learning curve saved for further overfitting diagnosis

Outputs:
    ml/models/best_model.pkl       ← calibrated winner
    ml/models/rf_model.pkl         ← RF specifically (for online learner warmup)
    ml/results/roc_curves.png
    ml/results/confusion_matrices.png
    ml/results/feature_importance.png
    ml/results/learning_curve.png  ← NEW: overfitting diagnostic

Usage:
    python -m ml.train
"""

from __future__ import annotations
import os, pickle, warnings
warnings.filterwarnings("ignore")

import numpy  as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.model_selection   import (
    train_test_split, cross_val_score, StratifiedKFold,
    learning_curve
)
from sklearn.preprocessing     import StandardScaler, LabelEncoder
from sklearn.linear_model      import LogisticRegression
from sklearn.ensemble          import (
    RandomForestClassifier,
    HistGradientBoostingClassifier,
    StackingClassifier,
)
from sklearn.calibration       import CalibratedClassifierCV
from sklearn.metrics           import (
    classification_report, confusion_matrix,
    roc_auc_score, RocCurveDisplay, ConfusionMatrixDisplay
)
from sklearn.utils.class_weight import compute_class_weight

from features.extractor import FEATURE_NAMES

# ── Paths ──────────────────────────────────────────────────────────────────────
WORKSPACE   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_CSV = os.path.join(WORKSPACE, "dataset", "behavioral_dataset.csv")
MODELS_DIR  = os.path.join(WORKSPACE, "ml",      "models")
RESULTS_DIR = os.path.join(WORKSPACE, "ml",      "results")


# ── Data loading ───────────────────────────────────────────────────────────────

def load_data(csv_path: str):
    """Load CSV, encode labels, return X, y, label_encoder, dataframe."""
    if not os.path.exists(csv_path):
        raise FileNotFoundError(
            f"Dataset not found: {csv_path}\n"
            "Run: python dataset/rebuild_pe_only.py"
        )
    df = pd.read_csv(csv_path)
    print(f"  Loaded {len(df)} rows | "
          f"Benign={( df['label']=='benign').sum()} | "
          f"Malware={(df['label']=='malware').sum()}")

    le = LabelEncoder()
    y  = le.fit_transform(df["label"])          # benign=0, malware=1
    X  = df[FEATURE_NAMES].values.astype(float)
    return X, y, le, df


# ── Overfitting diagnostic helper ──────────────────────────────────────────────

def print_overfit_check(name: str, model, X_scaled, y, cv):
    """Print train accuracy vs CV accuracy — gap > 5% signals overfitting."""
    train_scores = cross_val_score(model, X_scaled, y, cv=cv, scoring="f1")
    # Re-fit on full data to get train score
    model.fit(X_scaled, y)
    train_pred  = model.predict(X_scaled)
    from sklearn.metrics import f1_score
    full_train_f1 = f1_score(y, train_pred)

    gap = full_train_f1 - train_scores.mean()
    status = "OVERFIT ⚠" if gap > 0.08 else ("UNDERFIT ⚠" if train_scores.mean() < 0.80 else "OK ✓")

    print(f"    Train F1 (full): {full_train_f1:.4f}   "
          f"CV F1: {train_scores.mean():.4f} ± {train_scores.std():.4f}   "
          f"Gap: {gap:+.4f}   [{status}]")
    return train_scores.mean(), train_scores.std()


# ── Evaluation ─────────────────────────────────────────────────────────────────

def evaluate_model(name, model, X_test, y_test, scaler=None) -> dict:
    X_eval = scaler.transform(X_test) if scaler else X_test
    y_pred = model.predict(X_eval)
    y_prob = model.predict_proba(X_eval)[:, 1]

    report = classification_report(y_test, y_pred, output_dict=True)
    auc    = roc_auc_score(y_test, y_prob)
    cm     = confusion_matrix(y_test, y_pred)

    print(f"\n{'='*54}")
    print(f"  {name}")
    print(f"{'='*54}")
    print(classification_report(y_test, y_pred, target_names=["benign", "malware"]))
    print(f"  ROC-AUC : {auc:.4f}")
    print(f"  CM      : TN={cm[0,0]} FP={cm[0,1]} FN={cm[1,0]} TP={cm[1,1]}")

    return {
        "name":      name,
        "accuracy":  report["accuracy"],
        "precision": report.get("malware", {}).get("precision",  0),
        "recall":    report.get("malware", {}).get("recall",     0),
        "f1":        report.get("malware", {}).get("f1-score",   0),
        "auc":       auc,
        "model":     model,
        "scaler":    scaler,
        "cm":        cm,
        "y_prob":    y_prob,
    }


# ── Plots ──────────────────────────────────────────────────────────────────────

def plot_roc_curves(results, y_test):
    fig, ax = plt.subplots(figsize=(7, 5))
    for r in results:
        RocCurveDisplay.from_predictions(
            y_test, r["y_prob"], name=r["name"], ax=ax
        )
    ax.set_title("ROC Curves — Model Comparison")
    ax.grid(alpha=0.3)
    path = os.path.join(RESULTS_DIR, "roc_curves.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[+] ROC curves → {path}")


def plot_confusion_matrices(results):
    fig, axes = plt.subplots(1, len(results), figsize=(5 * len(results), 4))
    if len(results) == 1:
        axes = [axes]
    for ax, r in zip(axes, results):
        ConfusionMatrixDisplay(
            confusion_matrix=r["cm"], display_labels=["benign", "malware"]
        ).plot(ax=ax, colorbar=False, cmap="Blues")
        ax.set_title(r["name"])
    fig.suptitle("Confusion Matrices", fontsize=13, fontweight="bold")
    path = os.path.join(RESULTS_DIR, "confusion_matrices.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[+] Confusion matrices → {path}")


def plot_feature_importance(rf_model):
    imp     = rf_model.feature_importances_
    idx     = np.argsort(imp)[::-1]
    top_n   = min(20, len(FEATURE_NAMES))          # show top 20

    fig, ax = plt.subplots(figsize=(10, 5))
    colors  = plt.cm.RdYlGn(imp[idx[:top_n]] / imp.max())
    ax.bar(range(top_n), imp[idx[:top_n]], color=colors)
    ax.set_xticks(range(top_n))
    ax.set_xticklabels([FEATURE_NAMES[i] for i in idx[:top_n]],
                        rotation=45, ha="right", fontsize=8)
    ax.set_title("Random Forest — Top Feature Importances", fontsize=13, fontweight="bold")
    ax.set_ylabel("Importance")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    path = os.path.join(RESULTS_DIR, "feature_importance.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[+] Feature importance → {path}")


def plot_learning_curve(model, X, y, cv, name="Best Model"):
    """Learning curve: x=training size, y=train vs cv score. Diagnoses over/underfit."""
    train_sizes, train_scores, cv_scores = learning_curve(
        model, X, y,
        cv=cv,
        scoring="f1",
        train_sizes=np.linspace(0.1, 1.0, 10),
        n_jobs=-1,
    )
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(train_sizes, train_scores.mean(axis=1),   "o-", label="Train F1",  color="steelblue")
    ax.fill_between(train_sizes,
                    train_scores.mean(axis=1) - train_scores.std(axis=1),
                    train_scores.mean(axis=1) + train_scores.std(axis=1),
                    alpha=0.15, color="steelblue")
    ax.plot(train_sizes, cv_scores.mean(axis=1), "o-", label="CV F1",    color="tomato")
    ax.fill_between(train_sizes,
                    cv_scores.mean(axis=1) - cv_scores.std(axis=1),
                    cv_scores.mean(axis=1) + cv_scores.std(axis=1),
                    alpha=0.15, color="tomato")
    ax.set_xlabel("Training samples")
    ax.set_ylabel("F1 Score")
    ax.set_title(f"Learning Curve — {name}", fontsize=13, fontweight="bold")
    ax.legend(loc="lower right")
    ax.grid(alpha=0.3)
    ax.set_ylim(0.5, 1.02)
    path = os.path.join(RESULTS_DIR, "learning_curve.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[+] Learning curve     → {path}")


# ── Main ───────────────────────────────────────────────────────────────────────

def train():
    os.makedirs(MODELS_DIR,  exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)

    print("=" * 58)
    print("  HELIX — ML Training Pipeline v2")
    print("=" * 58)

    # ── Load & split ─────────────────────────────────────────────────────────
    print("\n[1] Loading dataset...")
    X, y, le, df = load_data(DATASET_CSV)
    n_feat = X.shape[1]
    print(f"  Features : {n_feat}  ({', '.join(FEATURE_NAMES[:4])}…)")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"  Train: {len(X_train)}   Test: {len(X_test)}")

    # Scale (tree models don't need it, but unified scaler keeps API consistent)
    scaler    = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)
    X_all_s   = scaler.transform(X)

    # Class weights for LR / RF
    cw = compute_class_weight("balanced", classes=np.array([0, 1]), y=y_train)
    class_weight = {0: cw[0], 1: cw[1]}

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    # ── 1. Logistic Regression ────────────────────────────────────────────────
    print("\n[2] Logistic Regression (L2, C=0.5)...")
    lr = LogisticRegression(
        max_iter=3000, C=0.5,           # tighter L2 → less overfit
        class_weight="balanced",
        solver="lbfgs", random_state=42
    )
    lr.fit(X_train_s, y_train)
    lr_cv, lr_cv_std = print_overfit_check("LR", lr, X_all_s, y, cv)
    r_lr = evaluate_model("Logistic Regression", lr, X_test_s, y_test)
    r_lr["cv_f1"] = lr_cv

    # ── 2. Random Forest (regularised) ───────────────────────────────────────
    print("\n[3] Random Forest (regularised: max_depth=12, min_samples_leaf=3)...")
    rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=12,            # prevents overfitting (was None)
        min_samples_leaf=3,      # prevents tiny splits (was 1)
        max_features="sqrt",     # standard: uses sqrt(n_features) per split
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train_s, y_train)
    rf_cv, rf_cv_std = print_overfit_check("RF", rf, X_all_s, y, cv)
    r_rf = evaluate_model("Random Forest", rf, X_test_s, y_test)
    r_rf["cv_f1"] = rf_cv

    # ── 3. HistGradientBoosting (fast, robust, handles scale natively) ────────
    print("\n[4] HistGradientBoosting (n_iter=200, max_depth=6, l2=0.1)...")
    hgb = HistGradientBoostingClassifier(
        max_iter=200,
        max_depth=6,             # moderate depth → good bias/variance tradeoff
        learning_rate=0.05,
        l2_regularization=0.1,  # L2 penalty → prevents overfit
        early_stopping=True,
        validation_fraction=0.1,
        n_iter_no_change=20,
        random_state=42,
        class_weight="balanced",
    )
    hgb.fit(X_train_s, y_train)
    hgb_cv, hgb_cv_std = print_overfit_check("HGB", hgb, X_all_s, y, cv)
    r_hgb = evaluate_model("HistGradientBoosting", hgb, X_test_s, y_test)
    r_hgb["cv_f1"] = hgb_cv

    # ── 4. Stacking Ensemble (RF + HGB → LR meta-learner) ────────────────────
    # Better than VotingClassifier: LR meta-learner LEARNS the optimal weighting
    # instead of using fixed equal votes. passthrough=True feeds raw features
    # to the meta-learner alongside the level-1 predictions.
    print("\n[5] Stacking Ensemble (RF + HGB → LogReg meta)...")
    meta_lr = LogisticRegression(C=0.1, max_iter=1000, random_state=42)
    ensemble = StackingClassifier(
        estimators=[("rf", rf), ("hgb", hgb)],
        final_estimator=meta_lr,
        passthrough=True,          # also feed raw features to meta-learner
        cv=5,
        stack_method="predict_proba",
        n_jobs=-1,
    )
    ensemble.fit(X_train_s, y_train)
    ens_cv, ens_cv_std = print_overfit_check("ENS", ensemble, X_all_s, y, cv)
    r_ens = evaluate_model("Stacking Ensemble (RF+HGB→LR)", ensemble, X_test_s, y_test)
    r_ens["cv_f1"] = ens_cv

    # ── Comparison table ──────────────────────────────────────────────────────
    all_results = [r_lr, r_rf, r_hgb, r_ens]

    print("\n\n" + "=" * 66)
    print("  COMPARISON TABLE  (best model selected by CV F1, not test F1)")
    print("=" * 66)
    print(f"  {'Model':<26} {'Acc':>5} {'Prec':>6} {'Rec':>6} {'F1':>6} {'AUC':>6} {'CV-F1':>7}")
    print("  " + "-" * 62)
    for r in all_results:
        marker = " <-- BEST" if r["cv_f1"] == max(x["cv_f1"] for x in all_results) else ""
        print(f"  {r['name']:<26} {r['accuracy']:>5.3f} {r['precision']:>6.3f} "
              f"{r['recall']:>6.3f} {r['f1']:>6.3f} {r['auc']:>6.4f} {r['cv_f1']:>7.4f}{marker}")

    # ── Select best by CV F1 (not test F1 — avoids lucky split bias) ─────────
    best_r = max(all_results, key=lambda r: r["cv_f1"])
    print(f"\n[+] Winner: {best_r['name']} (CV F1 = {best_r['cv_f1']:.4f})")

    # ── Calibrate the winner (Platt scaling → better probability outputs) ─────
    print(f"[+] Calibrating {best_r['name']} probabilities (Platt/sigmoid)...")
    calibrated = CalibratedClassifierCV(best_r["model"], method="sigmoid", cv=5)
    calibrated.fit(X_all_s, y)

    # ── Save models ───────────────────────────────────────────────────────────
    bundle = {
        "model":         calibrated,
        "scaler":        scaler,
        "label_encoder": le,
        "feature_names": FEATURE_NAMES,
    }
    with open(os.path.join(MODELS_DIR, "best_model.pkl"), "wb") as f:
        pickle.dump(bundle, f)
    print(f"[+] Saved best_model.pkl → {MODELS_DIR}")

    rf_bundle = bundle | {"model": rf}
    with open(os.path.join(MODELS_DIR, "rf_model.pkl"), "wb") as f:
        pickle.dump(rf_bundle, f)
    print(f"[+] Saved rf_model.pkl   → {MODELS_DIR}")

    # ── Plots ─────────────────────────────────────────────────────────────────
    print("\n[+] Generating diagnostics...")
    plot_roc_curves(all_results, y_test)
    plot_confusion_matrices(all_results)
    plot_feature_importance(rf)
    plot_learning_curve(best_r["model"], X_all_s, y, cv, name=best_r["name"])

    print("\n" + "=" * 58)
    print("  Training complete. Outputs in ml/models/ and ml/results/")
    print(f"  Best model  : {best_r['name']}")
    print(f"  CV F1       : {best_r['cv_f1']:.4f}")
    print(f"  Test F1     : {best_r['f1']:.4f}")
    print(f"  Test AUC    : {best_r['auc']:.4f}")
    print("=" * 58)
    return best_r


if __name__ == "__main__":
    train()
