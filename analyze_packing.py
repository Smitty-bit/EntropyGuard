"""Analyze packing features and identify packed samples."""

import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path

print("Packing Detection Analysis")
print("=" * 60)

data_dir = Path('data/raw/ember2018')

# Load packing-focused features
print("\nLoading packing features...")
X_train = np.load(data_dir / 'X_train_packing.npy')
y_train = np.load(data_dir / 'y_train_packing.npy')
X_test = np.load(data_dir / 'X_test_packing.npy')
y_test = np.load(data_dir / 'y_test_packing.npy')

print(f"  Training: {X_train.shape}")
print(f"  Test: {X_test.shape}")

# Feature indices:
# 0-19: Section features (5 sections × 4: entropy, size, vsize, size_diff)
# 20-28: General file info
# 29-32: String info
# 33-36: Header info
# 37-38: Import/export counts
# 39-43: Data directories

# Extract section entropy values (every 4th feature starting at 0)
section_entropies_train = X_train[:, [0, 4, 8, 12, 16]]  # 5 sections
section_entropies_test = X_test[:, [0, 4, 8, 12, 16]]

# Calculate max section entropy per sample (packed files have at least one high-entropy section)
max_section_entropy_train = np.max(section_entropies_train, axis=1)
max_section_entropy_test = np.max(section_entropies_test, axis=1)

print("\n" + "=" * 60)
print("Section Entropy Statistics")
print("=" * 60)

print(f"\nTraining set:")
print(f"  Max section entropy - Min: {max_section_entropy_train.min():.2f}")
print(f"  Max section entropy - Max: {max_section_entropy_train.max():.2f}")
print(f"  Max section entropy - Mean: {max_section_entropy_train.mean():.2f}")
print(f"  Max section entropy - Median: {np.median(max_section_entropy_train):.2f}")

print(f"\nTest set:")
print(f"  Max section entropy - Min: {max_section_entropy_test.min():.2f}")
print(f"  Max section entropy - Max: {max_section_entropy_test.max():.2f}")
print(f"  Max section entropy - Mean: {max_section_entropy_test.mean():.2f}")
print(f"  Max section entropy - Median: {np.median(max_section_entropy_test):.2f}")

# Try different thresholds
print("\n" + "=" * 60)
print("Packing Detection at Different Thresholds")
print("=" * 60)

for threshold in [6.5, 7.0, 7.2, 7.5]:
    train_packed = max_section_entropy_train > threshold
    test_packed = max_section_entropy_test > threshold
    
    print(f"\nThreshold: {threshold}")
    print(f"  Training: {train_packed.sum():,} packed ({train_packed.sum()/len(train_packed)*100:.1f}%)")
    print(f"  Test: {test_packed.sum():,} packed ({test_packed.sum()/len(test_packed)*100:.1f}%)")

# Look at distribution by malware type
print("\n" + "=" * 60)
print("Packing by Sample Type (threshold = 7.0)")
print("=" * 60)

THRESHOLD = 7.0
train_packed = max_section_entropy_train > THRESHOLD

# Filter to labeled samples
labeled_mask = y_train != -1
y_train_labeled = y_train[labeled_mask]
train_packed_labeled = train_packed[labeled_mask]
max_entropy_labeled = max_section_entropy_train[labeled_mask]

benign_mask = y_train_labeled == 0
malware_mask = y_train_labeled == 1

print(f"\nBenign samples:")
print(f"  Total: {benign_mask.sum():,}")
print(f"  Packed: {train_packed_labeled[benign_mask].sum():,} ({train_packed_labeled[benign_mask].sum()/benign_mask.sum()*100:.1f}%)")
print(f"  Avg max entropy: {max_entropy_labeled[benign_mask].mean():.2f}")

print(f"\nMalware samples:")
print(f"  Total: {malware_mask.sum():,}")
print(f"  Packed: {train_packed_labeled[malware_mask].sum():,} ({train_packed_labeled[malware_mask].sum()/malware_mask.sum()*100:.1f}%)")
print(f"  Avg max entropy: {max_entropy_labeled[malware_mask].mean():.2f}")

# Visualize
print("\nGenerating section entropy distribution...")

fig, axes = plt.subplots(2, 2, figsize=(14, 10))

# Training set - by sample type
ax = axes[0, 0]
ax.hist(max_entropy_labeled[benign_mask], bins=50, alpha=0.6, label='Benign', color='blue', density=True)
ax.hist(max_entropy_labeled[malware_mask], bins=50, alpha=0.6, label='Malware', color='red', density=True)
ax.axvline(THRESHOLD, color='black', linestyle='--', linewidth=2, label=f'Threshold ({THRESHOLD})')
ax.set_xlabel('Max Section Entropy')
ax.set_ylabel('Density')
ax.set_title('Training Set - Max Section Entropy by Type')
ax.legend()
ax.set_xlim(0, 8)

# Test set
ax = axes[0, 1]
test_benign = y_test == 0
test_malware = y_test == 1
ax.hist(max_section_entropy_test[test_benign], bins=50, alpha=0.6, label='Benign', color='blue', density=True)
ax.hist(max_section_entropy_test[test_malware], bins=50, alpha=0.6, label='Malware', color='red', density=True)
ax.axvline(THRESHOLD, color='black', linestyle='--', linewidth=2, label=f'Threshold ({THRESHOLD})')
ax.set_xlabel('Max Section Entropy')
ax.set_ylabel('Density')
ax.set_title('Test Set - Max Section Entropy by Type')
ax.legend()
ax.set_xlim(0, 8)

# Individual section entropies - Training
ax = axes[1, 0]
for i in range(5):
    section_ent = section_entropies_train[labeled_mask, i]
    # Only plot sections that have data
    valid = section_ent > 0
    if valid.sum() > 100:
        ax.hist(section_ent[valid], bins=50, alpha=0.3, label=f'Section {i}', density=True)
ax.axvline(THRESHOLD, color='black', linestyle='--', linewidth=2)
ax.set_xlabel('Section Entropy')
ax.set_ylabel('Density')
ax.set_title('Training Set - Individual Section Entropies')
ax.legend()
ax.set_xlim(0, 8)

# CDF
ax = axes[1, 1]
sorted_entropy = np.sort(max_entropy_labeled[malware_mask])
cdf = np.arange(1, len(sorted_entropy) + 1) / len(sorted_entropy)
ax.plot(sorted_entropy, cdf, label='Malware', color='red', linewidth=2)

sorted_entropy_benign = np.sort(max_entropy_labeled[benign_mask])
cdf_benign = np.arange(1, len(sorted_entropy_benign) + 1) / len(sorted_entropy_benign)
ax.plot(sorted_entropy_benign, cdf_benign, label='Benign', color='blue', linewidth=2)

ax.axvline(THRESHOLD, color='black', linestyle='--', linewidth=2, label=f'Threshold ({THRESHOLD})')
ax.set_xlabel('Max Section Entropy')
ax.set_ylabel('Cumulative Probability')
ax.set_title('CDF - Max Section Entropy')
ax.legend()
ax.grid(alpha=0.3)
ax.set_xlim(0, 8)

plt.tight_layout()
plt.savefig(data_dir / 'section_entropy_analysis.png', dpi=150, bbox_inches='tight')
print(f"  ✓ Saved plot to {data_dir / 'section_entropy_analysis.png'}")

# Save packing labels
print("\nSaving packing labels (threshold = 7.0)...")
np.save(data_dir / 'train_packed_labels.npy', train_packed)
test_packed = max_section_entropy_test > THRESHOLD
np.save(data_dir / 'test_packed_labels.npy', test_packed)

print("\n" + "=" * 60)
print("✓ Analysis complete!")
print("\nNext: Train a packing detector on these labels")
print("=" * 60)
