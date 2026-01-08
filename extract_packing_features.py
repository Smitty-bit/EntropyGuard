"""Extract ONLY packing-relevant features from EMBER - DEFENSIVE."""

import numpy as np
import json
from pathlib import Path
from tqdm import tqdm

print("EMBER Packing-Focused Feature Extraction (Defensive)")
print("=" * 60)

data_dir = Path('data/raw/ember2018')

def safe_float(value, default=0.0):
    """Convert to float, handling lists/dicts/None."""
    if value is None:
        return default
    if isinstance(value, (list, dict)):
        return default
    try:
        return float(value)
    except (ValueError, TypeError):
        return default

def extract_packing_features(sample):
    """Extract ~44 features specifically for packing detection."""
    features = []
    
    # 1. Section entropy (THE KEY FEATURE - 5 sections × 4 features)
    section_data = sample.get('section', {})
    if isinstance(section_data, dict):
        sections = section_data.get('sections', [])
    elif isinstance(section_data, list):
        sections = section_data
    else:
        sections = []
    
    if not isinstance(sections, list):
        sections = []
    
    # Get entropy for up to 5 sections
    for i in range(5):
        if i < len(sections) and isinstance(sections[i], dict):
            sec = sections[i]
            entropy = safe_float(sec.get('entropy'))
            size = safe_float(sec.get('size'))
            vsize = safe_float(sec.get('vsize'))
            size_diff = safe_float(vsize - size if (vsize and size) else 0)
            
            features.extend([entropy, size, vsize, size_diff])
        else:
            features.extend([0.0, 0.0, 0.0, 0.0])
    # = 20 features
    
    # 2. General file characteristics (9 features)
    general = sample.get('general', {})
    if not isinstance(general, dict):
        general = {}
    
    size = safe_float(general.get('size'))
    vsize = safe_float(general.get('vsize'))
    ratio = safe_float(vsize / size if (size and size > 0) else 0)
    
    features.extend([
        size,
        vsize,
        ratio,
        safe_float(general.get('has_debug')),
        safe_float(general.get('has_signature')),
        safe_float(general.get('has_relocations')),
        safe_float(general.get('has_resources')),
        safe_float(general.get('imports')),
        safe_float(general.get('exports')),
    ])
    
    # 3. String characteristics (4 features)
    strings = sample.get('strings', {})
    if not isinstance(strings, dict):
        strings = {}
    
    features.extend([
        safe_float(strings.get('numstrings')),
        safe_float(strings.get('avlength')),
        safe_float(strings.get('entropy')),
        safe_float(strings.get('printables')),
    ])
    
    # 4. Header info (4 features)
    header = sample.get('header', {})
    if not isinstance(header, dict):
        header = {}
    
    optional = header.get('optional', {})
    if not isinstance(optional, dict):
        optional = {}
    
    features.extend([
        safe_float(optional.get('subsystem')),
        safe_float(optional.get('dll_characteristics')),
        safe_float(optional.get('sizeof_code')),
        safe_float(optional.get('sizeof_headers')),
    ])
    
    # 5. Import/Export counts (2 features)
    imports = sample.get('imports', [])
    exports = sample.get('exports', [])
    
    import_count = len(imports) if isinstance(imports, list) else 0
    export_count = len(exports) if isinstance(exports, list) else 0
    
    features.extend([safe_float(import_count), safe_float(export_count)])
    
    # 6. Data directories (5 features)
    datadirs = sample.get('datadirectories', [])
    if not isinstance(datadirs, list):
        datadirs = []
    
    for i in range(5):
        if i < len(datadirs) and isinstance(datadirs[i], dict):
            features.append(safe_float(datadirs[i].get('size')))
        else:
            features.append(0.0)
    
    # Verify all are scalars
    assert len(features) == 44, f"Expected 44 features, got {len(features)}"
    for idx, f in enumerate(features):
        if not isinstance(f, (int, float)):
            raise ValueError(f"Feature {idx} is not scalar: {type(f)} = {f}")
    
    return features

def process_jsonl(jsonl_file):
    """Load packing features from JSONL."""
    X, y = [], []
    errors = 0
    
    with open(jsonl_file, 'r') as f:
        for line_num, line in enumerate(tqdm(f, desc=f"Loading {jsonl_file.name}"), 1):
            try:
                sample = json.loads(line.strip())
                features = extract_packing_features(sample)
                label = sample.get('label', -1)
                
                X.append(features)
                y.append(label)
            except Exception as e:
                errors += 1
                if errors <= 3:
                    print(f"\n  Error on line {line_num}: {e}")
                continue
    
    if errors > 0:
        print(f"\n  ⚠ Skipped {errors} samples")
    
    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int32)

# Process training data
print("\nProcessing training files...")
X_train_list, y_train_list = [], []

for i in range(6):
    jsonl_file = data_dir / f'train_features_{i}.jsonl'
    print(f"\n  File {i+1}/6: {jsonl_file.name}")
    
    X_chunk, y_chunk = process_jsonl(jsonl_file)
    X_train_list.append(X_chunk)
    y_train_list.append(y_chunk)
    
    print(f"  ✓ Loaded {len(X_chunk):,} samples")

# Combine
X_train = np.vstack(X_train_list)
y_train = np.hstack(y_train_list)

print(f"\n  Total training: {len(X_train):,} samples")

# Process test
print("\nProcessing test file...")
X_test, y_test = process_jsonl(data_dir / 'test_features.jsonl')
print(f"  Total test: {len(X_test):,} samples")

# Save
print("\nSaving packing-focused features...")
np.save(data_dir / 'X_train_packing.npy', X_train)
np.save(data_dir / 'y_train_packing.npy', y_train)
np.save(data_dir / 'X_test_packing.npy', X_test)
np.save(data_dir / 'y_test_packing.npy', y_test)

print("\n" + "=" * 60)
print("✓ Done!")
print(f"Training: {X_train.shape} (44 packing-focused features)")
print(f"Test: {X_test.shape}")
print("=" * 60)
