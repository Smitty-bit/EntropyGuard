"""Train malware detector with focus on packed sample performance."""

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from pathlib import Path
import time

print("Malware Detector - Packed vs Unpacked Analysis")
print("=" * 60)

data_dir = Path('data/raw/ember2018')

# Load packing features
print("\nLoading data...")
X_train = np.load(data_dir / 'X_train_packing.npy')
y_train = np.load(data_dir / 'y_train_packing.npy')
X_test = np.load(data_dir / 'X_test_packing.npy')
y_test = np.load(data_dir / 'y_test_packing.npy')

# Load packing labels
train_packed = np.load(data_dir / 'train_packed_labels.npy')
test_packed = np.load(data_dir / 'test_packed_labels.npy')

print(f"  X_train: {X_train.shape}")
print(f"  X_test: {X_test.shape}")

# Filter to labeled samples only
print("\nFiltering to labeled samples...")
labeled_mask = y_train != -1
X_train = X_train[labeled_mask]
y_train = y_train[labeled_mask]
train_packed = train_packed[labeled_mask]

print(f"  Training samples: {len(X_train):,}")
print(f"  Test samples: {len(X_test):,}")

# Show dataset breakdown
print("\n" + "=" * 60)
print("Dataset Breakdown")
print("=" * 60)

print("\nTraining set:")
train_benign = y_train == 0
train_malware = y_train == 1
print(f"  Benign (unpacked): {(train_benign & ~train_packed).sum():,}")
print(f"  Benign (packed):   {(train_benign & train_packed).sum():,}")
print(f"  Malware (unpacked): {(train_malware & ~train_packed).sum():,}")
print(f"  Malware (packed):   {(train_malware & train_packed).sum():,}")

print("\nTest set:")
test_benign = y_test == 0
test_malware = y_test == 1
print(f"  Benign (unpacked): {(test_benign & ~test_packed).sum():,}")
print(f"  Benign (packed):   {(test_benign & test_packed).sum():,}")
print(f"  Malware (unpacked): {(test_malware & ~test_packed).sum():,}")
print(f"  Malware (packed):   {(test_malware & test_packed).sum():,}")

# Train classifier
print("\n" + "=" * 60)
print("Training Random Forest Classifier")
print("=" * 60)
print("(This should be faster with only 44 features!)\n")

model = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    min_samples_split=10,
    n_jobs=-1,
    random_state=42,
    verbose=1
)

start_time = time.time()
model.fit(X_train, y_train)
train_time = time.time() - start_time

print(f"\n✓ Training complete! ({train_time:.1f} seconds)")

# Overall predictions
print("\nMaking predictions...")
y_pred = model.predict(X_test)

# Overall results
print("\n" + "=" * 60)
print("OVERALL RESULTS")
print("=" * 60)

accuracy = accuracy_score(y_test, y_pred)
print(f"\nOverall Accuracy: {accuracy * 100:.2f}%")

print("\nClassification Report:")
print(classification_report(y_test, y_pred,
                          target_names=['Benign', 'Malware'],
                          digits=3))

print("Confusion Matrix:")
cm = confusion_matrix(y_test, y_pred)
print(f"                Predicted")
print(f"                Benign  Malware")
print(f"Actual Benign   {cm[0,0]:>6}  {cm[0,1]:>7}")
print(f"       Malware  {cm[1,0]:>6}  {cm[1,1]:>7}")

# Performance breakdown by packing status
print("\n" + "=" * 60)
print("PERFORMANCE BY PACKING STATUS")
print("=" * 60)

# Unpacked samples
unpacked_mask = ~test_packed
y_test_unpacked = y_test[unpacked_mask]
y_pred_unpacked = y_pred[unpacked_mask]
acc_unpacked = accuracy_score(y_test_unpacked, y_pred_unpacked)

print(f"\nUNPACKED Samples ({unpacked_mask.sum():,} samples):")
print(f"  Accuracy: {acc_unpacked * 100:.2f}%")
print("\n  Classification Report:")
print(classification_report(y_test_unpacked, y_pred_unpacked,
                          target_names=['Benign', 'Malware'],
                          digits=3))

cm_unpacked = confusion_matrix(y_test_unpacked, y_pred_unpacked)
print("  Confusion Matrix:")
print(f"                  Predicted")
print(f"                  Benign  Malware")
print(f"  Actual Benign   {cm_unpacked[0,0]:>6}  {cm_unpacked[0,1]:>7}")
print(f"         Malware  {cm_unpacked[1,0]:>6}  {cm_unpacked[1,1]:>7}")

# Packed samples
packed_mask = test_packed
y_test_packed = y_test[packed_mask]
y_pred_packed = y_pred[packed_mask]
acc_packed = accuracy_score(y_test_packed, y_pred_packed)

print(f"\n" + "-" * 60)
print(f"\nPACKED Samples ({packed_mask.sum():,} samples):")
print(f"  Accuracy: {acc_packed * 100:.2f}%")
print(f"  Performance gap: {(acc_unpacked - acc_packed) * 100:.2f}% worse on packed")
print("\n  Classification Report:")
print(classification_report(y_test_packed, y_pred_packed,
                          target_names=['Benign', 'Malware'],
                          digits=3))

cm_packed = confusion_matrix(y_test_packed, y_pred_packed)
print("  Confusion Matrix:")
print(f"                  Predicted")
print(f"                  Benign  Malware")
print(f"  Actual Benign   {cm_packed[0,0]:>6}  {cm_packed[0,1]:>7}")
print(f"         Malware  {cm_packed[1,0]:>6}  {cm_packed[1,1]:>7}")

# Feature importance
print("\n" + "=" * 60)
print("TOP 15 MOST IMPORTANT FEATURES")
print("=" * 60)

feature_names = []
# Section features (0-19)
for i in range(5):
    feature_names.extend([
        f"section[{i}].entropy",
        f"section[{i}].size",
        f"section[{i}].vsize",
        f"section[{i}].size_diff"
    ])
# General (20-28)
feature_names.extend(['file_size', 'file_vsize', 'vsize_ratio', 'has_debug', 
                     'has_signature', 'has_relocations', 'has_resources', 
                     'num_imports', 'num_exports'])
# Strings (29-32)
feature_names.extend(['num_strings', 'avg_string_len', 'string_entropy', 'printable_chars'])
# Header (33-36)
feature_names.extend(['subsystem', 'dll_characteristics', 'sizeof_code', 'sizeof_headers'])
# Imports/Exports (37-38)
feature_names.extend(['import_count', 'export_count'])
# Data dirs (39-43)
feature_names.extend([f'datadir[{i}].size' for i in range(5)])

feature_importance = model.feature_importances_
top_indices = np.argsort(feature_importance)[-15:][::-1]

print("\n")
for i, idx in enumerate(top_indices, 1):
    print(f"  {i:2d}. {feature_names[idx]:30s} importance: {feature_importance[idx]:.4f}")

print("\n" + "=" * 60)
print("✓ Analysis complete!")
print(f"\nKey insight: {'Model struggles more with packed samples!' if acc_packed < acc_unpacked - 0.05 else 'Model handles packed samples well!'}")
print("=" * 60)
