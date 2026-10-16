"""
CICIDS2017 PortScan Intrusion Detection System - Optimized Pipeline
===================================================================
This script executes the complete machine learning workflow planned in Untitled.ipynb:
1. Memory-efficient data loading & preprocessing
2. Balanced class sampling (50,000 Benign vs 50,000 PortScan)
3. Exploratory Data Analysis (EDA) visualizations saved to outputs/
4. Standardization (StandardScaler) & Feature Selection (SelectKBest ANOVA F-test, k=20)
5. Model Training: Random Forest, Support Vector Machine (SVC), and Multi-Layer Perceptron (MLP)
6. Evaluation: Accuracy, Precision, Recall, F1-score, Confusion Matrix heatmaps, ROC-AUC curves
7. 5-Fold Stratified Cross-Validation on Random Forest
"""

import os
import sys
import gc
import time
import warnings
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_curve, auc
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import SelectKBest, f_classif

# Ensure UTF-8 output on Windows terminal
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

warnings.filterwarnings("ignore")

# Create outputs directory
OUTPUT_DIR = "outputs"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def main():
    print("=" * 70)
    print("[*] CICIDS2017 PortScan Intrusion Detection Pipeline Starting...")
    print("=" * 70)

    # -------------------------------------------------------------
    # Step 1: Memory-Efficient Data Loading
    # -------------------------------------------------------------
    target_file = 'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv'
    if not os.path.exists(target_file):
        raise FileNotFoundError(f"Target dataset file '{target_file}' not found in current directory.")

    print(f"\n[1/7] Ingesting dataset from '{target_file}'...")
    start_load = time.time()
    df_raw = pd.read_csv(target_file)
    print(f"      Loaded raw shape: {df_raw.shape} in {time.time() - start_load:.2f} seconds.")

    # Clean header whitespace
    df_raw.columns = df_raw.columns.str.strip()

    # -------------------------------------------------------------
    # Step 2: Filtering & Sanitization
    # -------------------------------------------------------------
    print("\n[2/7] Preprocessing and sanitizing network flows...")
    # Filter only BENIGN and PortScan
    filtered_df = df_raw[df_raw['Label'].isin(['BENIGN', 'PortScan'])].copy()
    del df_raw
    gc.collect()

    # Drop constant (single-value) columns
    constant_cols = [col for col in filtered_df.columns if filtered_df[col].nunique() <= 1]
    filtered_df.drop(columns=constant_cols, inplace=True)
    print(f"      Dropped {len(constant_cols)} constant columns.")

    # Replace infinite values and drop NaNs
    filtered_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    filtered_df.dropna(inplace=True)
    print(f"      Cleaned shape after null/inf removal: {filtered_df.shape}")

    # Map labels: BENIGN -> 0, PortScan -> 1
    filtered_df['Label'] = filtered_df['Label'].replace({'BENIGN': 0, 'PortScan': 1})

    # Balanced Sampling (50,000 from each class)
    print("      Balancing classes (50,000 BENIGN + 50,000 PortScan)...")
    df_benign = filtered_df[filtered_df['Label'] == 0].sample(n=50000, random_state=42)
    df_portscan = filtered_df[filtered_df['Label'] == 1].sample(n=50000, random_state=42)
    df = pd.concat([df_benign, df_portscan], ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)

    del filtered_df, df_benign, df_portscan
    gc.collect()

    print(f"      Final balanced dataset shape: {df.shape}")
    print(f"      Class distribution:\n{df['Label'].value_counts().to_string()}")

    # -------------------------------------------------------------
    # Step 3: Exploratory Data Analysis (EDA) Visualizations
    # -------------------------------------------------------------
    print("\n[3/7] Generating Exploratory Data Analysis (EDA) charts...")

    # Plot 1: Top 20 Targeted Ports by PortScan
    if 'Destination Port' in df.columns:
        portscan_df = df[df['Label'] == 1]
        top_ports = portscan_df['Destination Port'].value_counts().head(20)
        plt.figure(figsize=(12, 6))
        sns.barplot(x=top_ports.index.astype(str), y=top_ports.values, palette="mako")
        plt.xticks(rotation=45, ha='right')
        plt.title('Top 20 Destination Ports Targeted by PortScan', fontsize=14, fontweight='bold')
        plt.xlabel('Destination Port', fontsize=12)
        plt.ylabel('Flow Count', fontsize=12)
        plt.tight_layout()
        plt.savefig(os.path.join(OUTPUT_DIR, 'top_targeted_ports.png'), dpi=300)
        plt.close()
        print(f"      Saved: {OUTPUT_DIR}/top_targeted_ports.png")

    # Plot 2: Flow Duration Distribution (KDE)
    if 'Flow Duration' in df.columns:
        plt.figure(figsize=(10, 5))
        sns.kdeplot(data=df[df['Label'] == 0]['Flow Duration'], label='BENIGN', fill=True, color='teal')
        sns.kdeplot(data=df[df['Label'] == 1]['Flow Duration'], label='PortScan', fill=True, color='crimson')
        plt.title('Flow Duration Distribution (BENIGN vs PortScan)', fontsize=14, fontweight='bold')
        plt.xlabel('Flow Duration (microseconds)', fontsize=12)
        plt.ylabel('Density', fontsize=12)
        plt.legend()
        plt.tight_layout()
        plt.savefig(os.path.join(OUTPUT_DIR, 'flow_duration_kde.png'), dpi=300)
        plt.close()
        print(f"      Saved: {OUTPUT_DIR}/flow_duration_kde.png")

    # Plot 3: Boxplot of Average Packet Size
    if 'Average Packet Size' in df.columns:
        plot_df = df[['Label', 'Average Packet Size']].copy()
        plot_df['Traffic Type'] = plot_df['Label'].replace({0: 'BENIGN', 1: 'PortScan'})
        plt.figure(figsize=(8, 5))
        sns.boxplot(x='Traffic Type', y='Average Packet Size', data=plot_df, palette=['#3b82f6', '#ef4444'])
        plt.title('Average Packet Size: BENIGN vs PortScan', fontsize=14, fontweight='bold')
        plt.tight_layout()
        plt.savefig(os.path.join(OUTPUT_DIR, 'avg_packet_size_boxplot.png'), dpi=300)
        plt.close()
        del plot_df
        print(f"      Saved: {OUTPUT_DIR}/avg_packet_size_boxplot.png")

    # Plot 4: Scatter Plot of Total Forward vs Backward Packets
    if 'Total Fwd Packets' in df.columns and 'Total Backward Packets' in df.columns:
        fig, axes = plt.subplots(1, 2, figsize=(14, 5))
        sns.scatterplot(
            x='Total Fwd Packets', y='Total Backward Packets',
            data=df[df['Label'] == 0], color='royalblue', alpha=0.4, ax=axes[0]
        )
        axes[0].set_title('BENIGN Traffic Packets Distribution', fontweight='bold')
        axes[0].set_xlim(-5, 150)
        axes[0].set_ylim(-5, 150)

        sns.scatterplot(
            x='Total Fwd Packets', y='Total Backward Packets',
            data=df[df['Label'] == 1], color='crimson', alpha=0.4, ax=axes[1]
        )
        axes[1].set_title('PortScan Traffic Packets Distribution', fontweight='bold')
        axes[1].set_xlim(-5, 150)
        axes[1].set_ylim(-5, 150)

        plt.tight_layout()
        plt.savefig(os.path.join(OUTPUT_DIR, 'fwd_bwd_packets_scatter.png'), dpi=300)
        plt.close()
        print(f"      Saved: {OUTPUT_DIR}/fwd_bwd_packets_scatter.png")

    # -------------------------------------------------------------
    # Step 4: Feature Scaling & Selection
    # -------------------------------------------------------------
    print("\n[4/7] Normalizing features & selecting top 20 attributes (SelectKBest)...")
    X = df.drop(columns=['Label'])
    y = df['Label']

    # Standardize numeric features
    scaler = StandardScaler()
    X_scaled = pd.DataFrame(scaler.fit_transform(X), columns=X.columns)

    # Select top 20 features via ANOVA F-test
    selector = SelectKBest(score_func=f_classif, k=20)
    X_new = selector.fit_transform(X_scaled, y)
    selected_features = X.columns[selector.get_support()]

    print("      Top 20 Selected Features:")
    for idx, feat in enumerate(selected_features, 1):
        print(f"        {idx:2d}. {feat}")

    X_selected = pd.DataFrame(X_new, columns=selected_features)

    # 80/20 Stratified Train-Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X_selected, y, stratify=y, test_size=0.2, random_state=42
    )
    print(f"      Train Set: {X_train.shape[0]} samples | Test Set: {X_test.shape[0]} samples")

    # -------------------------------------------------------------
    # Step 5: Feature Importance via Random Forest
    # -------------------------------------------------------------
    print("\n[5/7] Calculating Random Forest Feature Importance...")
    rf_feat_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf_feat_model.fit(X_train, y_train)

    feat_importance = pd.Series(rf_feat_model.feature_importances_, index=selected_features).sort_values()
    plt.figure(figsize=(10, 8))
    feat_importance.plot(kind='barh', color='darkcyan')
    plt.title("Top 20 Features Importance (Random Forest)", fontsize=14, fontweight='bold')
    plt.xlabel("Gini Importance", fontsize=12)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'rf_feature_importance.png'), dpi=300)
    plt.close()
    print(f"      Saved: {OUTPUT_DIR}/rf_feature_importance.png")

    # -------------------------------------------------------------
    # Step 6: Multi-Model Training & Evaluation
    # -------------------------------------------------------------
    print("\n[6/7] Training & Benchmarking Models (RF, SVM, FNN/MLP)...")

    models = {
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
        "Neural Network (MLP)": MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=300, random_state=42),
        "Support Vector Machine": SVC(kernel='rbf', probability=True, random_state=42)
    }

    results = {}
    y_probs = {}

    for name, model in models.items():
        print(f"\n      --> Training {name}...")
        t_start = time.time()
        
        # For SVM, subsample 10,000 training points for swift convergence
        if name == "Support Vector Machine" and len(X_train) > 10000:
            sub_idx = np.random.RandomState(42).choice(len(X_train), size=10000, replace=False)
            model.fit(X_train.iloc[sub_idx], y_train.iloc[sub_idx])
        else:
            model.fit(X_train, y_train)

        elapsed = time.time() - t_start
        print(f"        Completed training in {elapsed:.2f}s")

        y_pred = model.predict(X_test)
        if hasattr(model, "predict_proba"):
            y_probs[name] = model.predict_proba(X_test)[:, 1]
        else:
            y_probs[name] = model.decision_function(X_test)

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred)
        rec = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        cm = confusion_matrix(y_test, y_pred)

        results[name] = {
            "Accuracy": acc,
            "Precision": prec,
            "Recall": rec,
            "F1-score": f1,
            "Confusion Matrix": cm,
            "Train Time (s)": elapsed
        }

        print(f"        Accuracy  : {acc * 100:.2f}%")
        print(f"        Precision : {prec:.4f}")
        print(f"        Recall    : {rec:.4f}")
        print(f"        F1-Score  : {f1:.4f}")

    # Plot Confusion Matrices
    fig, axes = plt.subplots(1, len(models), figsize=(18, 5))
    for ax, (name, metrics) in zip(axes, results.items()):
        sns.heatmap(metrics["Confusion Matrix"], annot=True, fmt='d', cmap='Blues', ax=ax, cbar=False)
        ax.set_title(f"{name}\nConfusion Matrix", fontweight='bold')
        ax.set_xlabel('Predicted Label (0=Benign, 1=PortScan)')
        ax.set_ylabel('Actual Label')
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'confusion_matrices.png'), dpi=300)
    plt.close()
    print(f"\n      Saved: {OUTPUT_DIR}/confusion_matrices.png")

    # Plot Model Performance Comparison
    metrics_list = []
    for model_name, metric_dict in results.items():
        metrics_list.append({
            'Model': model_name,
            'Accuracy': f"{metric_dict['Accuracy'] * 100:.2f}%",
            'Precision': f"{metric_dict['Precision']:.4f}",
            'Recall': f"{metric_dict['Recall']:.4f}",
            'F1-Score': f"{metric_dict['F1-score']:.4f}",
            'Train Time': f"{metric_dict['Train Time (s)']:.2f}s"
        })
    metrics_df = pd.DataFrame(metrics_list).set_index('Model')
    
    # Numerical version for plotting
    plot_metrics_list = []
    for model_name, metric_dict in results.items():
        plot_metrics_list.append({
            'Model': model_name,
            'Accuracy': metric_dict['Accuracy'],
            'Precision': metric_dict['Precision'],
            'Recall': metric_dict['Recall'],
            'F1-Score': metric_dict['F1-score']
        })
    plot_metrics_df = pd.DataFrame(plot_metrics_list).set_index('Model')

    plt.figure(figsize=(10, 6))
    plot_metrics_df.plot(kind='bar', figsize=(11, 6), colormap='viridis')
    plt.title("Model Performance Comparison (BENIGN vs PortScan)", fontsize=14, fontweight='bold')
    plt.ylabel("Score", fontsize=12)
    plt.ylim(0.95, 1.005)
    plt.legend(bbox_to_anchor=(1.02, 1), loc='upper left')
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'model_performance_comparison.png'), dpi=300)
    plt.close()
    print(f"      Saved: {OUTPUT_DIR}/model_performance_comparison.png")

    # Plot ROC Curves
    plt.figure(figsize=(9, 7))
    for name, prob in y_probs.items():
        fpr, tpr, _ = roc_curve(y_test, prob)
        roc_auc = auc(fpr, tpr)
        plt.plot(fpr, tpr, lw=2, label=f'{name} (AUC = {roc_auc:.4f})')
    plt.plot([0, 1], [0, 1], 'k--', lw=1.5, label='Random Guess')
    plt.xlim([-0.01, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate', fontsize=12)
    plt.ylabel('True Positive Rate', fontsize=12)
    plt.title('Receiver Operating Characteristic (ROC) - PortScan Detection', fontsize=14, fontweight='bold')
    plt.legend(loc='lower right', fontsize=11)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'roc_curves.png'), dpi=300)
    plt.close()
    print(f"      Saved: {OUTPUT_DIR}/roc_curves.png")

    # -------------------------------------------------------------
    # Step 7: 5-Fold Stratified Cross-Validation on Random Forest
    # -------------------------------------------------------------
    print("\n[7/7] Running 5-Fold Stratified Cross-Validation on Random Forest...")
    cv_scores = cross_val_score(
        RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
        X_selected, y, cv=5, scoring='accuracy'
    )
    print(f"      RF 5-Fold CV Accuracy: {cv_scores.mean() * 100:.2f}% (+/- {cv_scores.std() * 100:.2f}%)")

    # -------------------------------------------------------------
    # Final Summary Table
    # -------------------------------------------------------------
    print("\n" + "=" * 70)
    print("[+] FINAL BENCHMARK SUMMARY")
    print("=" * 70)
    summary_df = pd.DataFrame(metrics_list)
    print(summary_df.to_string(index=False))
    print(f"\nAll generated plots have been saved into: '{os.path.abspath(OUTPUT_DIR)}'")
    print("=" * 70)

if __name__ == "__main__":
    main()
