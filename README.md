# EntropyGuard

Detecting malware by analyzing file entropy patterns to identify obfuscation techniques like packing and compression.

## Overview

EntropyGuard is a machine learning-based malware detection system that analyzes Windows PE files using entropy-based features. The project reveals a surprising finding: **packed malware is actually easier to detect than unpacked malware** due to the distinctive entropy signatures created by packing.

### Key Results

- **Overall Accuracy:** 94.36% on EMBER 2018 dataset
- **Packed Malware Detection:** 95.79% accuracy (better than unpacked!)
- **Unpacked Malware Detection:** 93.46% accuracy
- **Dataset:** 600k training samples, 200k test samples

## The Packing Paradox

Malware authors use packers to obfuscate their code and evade detection. However, this project demonstrates that packing itself creates detectable patterns:

- **45.1%** of malware samples are packed
- **15.2%** of benign samples are packed
- High section entropy (>7.0) is a strong malware indicator
- The obfuscation technique becomes a detection feature

## Dataset

This project uses the [EMBER 2018 dataset](https://github.com/elastic/ember), which contains:
- 1 million Windows PE files (800k training, 200k test)
- Pre-extracted features from static analysis
- Balanced benign/malware split

### Download EMBER Dataset
```bash
mkdir -p data/raw/ember2018
cd data/raw/ember2018
wget https://ember.elastic.co/ember_dataset_2018_2.tar.bz2
tar -xvjf ember_dataset_2018_2.tar.bz2
```

## Features

EntropyGuard uses 44 carefully selected features focused on detecting packing:

### Section Features (20 features)
- **Section entropy** - The primary indicator of packing
- Section sizes and virtual sizes
- Size mismatches between raw and virtual sections

### File Characteristics (9 features)
- File size and virtual size
- Virtual/raw size ratios
- Debug info, signatures, relocations, resources
- Import/export counts

### String Analysis (4 features)
- Number of strings
- Average string length
- String entropy
- Printable character ratio

### PE Header Info (4 features)
- Subsystem type
- DLL characteristics
- Code section size
- Header size

### Additional Indicators (7 features)
- Import/export counts
- Data directory sizes

## Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/EntropyGuard.git
cd EntropyGuard

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Requirements
```
numpy>=1.21.0
scikit-learn>=1.0.0
matplotlib>=3.5.0
tqdm>=4.62.0
```

## Usage

### 1. Extract Features from EMBER Dataset
```python
# Extract packing-focused features (44 features per sample)
python extract_packing_features.py
```

This creates:
- `X_train_packing.npy` - Training features (600k samples × 44 features)
- `y_train_packing.npy` - Training labels
- `X_test_packing.npy` - Test features (200k samples × 44 features)
- `y_test_packing.npy` - Test labels

### 2. Analyze Packing Patterns
```python
# Generate packing statistics and visualizations
python analyze_packing.py
```

This creates:
- `train_packed_labels.npy` - Binary labels for packed samples
- `test_packed_labels.npy` - Binary labels for packed samples
- `section_entropy_analysis.png` - Entropy distribution plots

### 3. Train Malware Detector
```python
# Train Random Forest classifier and evaluate on packed vs unpacked
python train_packing_detector.py
```

## Results

### Overall Performance
```
              precision    recall  f1-score   support
      Benign      0.937     0.951     0.944    100000
     Malware      0.950     0.937     0.943    100000
    accuracy                          0.944    200000
```

### Performance by Packing Status

| Sample Type | Accuracy | Precision | Recall | F1-Score | Samples |
|-------------|----------|-----------|--------|----------|---------|
| **Packed** | **95.79%** | 0.962 | 0.983 | 0.972 | 77,030 |
| **Unpacked** | 93.46% | 0.932 | 0.873 | 0.901 | 122,970 |

### Most Important Features

1. **Data directory size** (0.084) - Resource directory size
2. **String entropy** (0.079) - Entropy of embedded strings
3. **Average string length** (0.059)
4. **Section[0] entropy** (0.050) - First code section entropy
5. **Number of imports** (0.048)
6. **Has debug info** (0.041)
7. **Section[1] entropy** (0.040) - Second section entropy

## Key Findings

### 1. Packing Aids Detection
Contrary to the intended purpose of obfuscation, packed samples are **2.3% easier to detect** than unpacked samples. This is because:
- High section entropy is a strong malware indicator
- Benign software rarely uses aggressive packing
- The obfuscation technique itself becomes suspicious

### 2. Malware Packs More
- **45.1%** of malware samples show high entropy (>7.0)
- **15.2%** of benign samples show high entropy
- Malware is **3x more likely** to be packed

### 3. Section Entropy is Key
Section entropy features rank #4 and #7 in feature importance, confirming their role in detecting packed samples. However, other features (string characteristics, data directories) are also critical.

## Visualizations

<img width="2247" height="1583" alt="image" src="https://github.com/user-attachments/assets/ab8a10c8-b394-4f8d-8556-0d0d50ae7452" />


*Section entropy distributions showing clear separation between packed and unpacked samples, with malware trending toward higher entropy values.*

## Project Structure
```
EntropyGuard/
├── README.md
├── requirements.txt
├── extract_packing_features.py    # Feature extraction from EMBER
├── analyze_packing.py              # Packing pattern analysis
├── train_packing_detector.py      # Model training & evaluation
└── data/
    └── raw/
        └── ember2018/
            ├── train_features_*.jsonl
            ├── test_features.jsonl
            ├── X_train_packing.npy
            ├── y_train_packing.npy
            ├── X_test_packing.npy
            ├── y_test_packing.npy
            ├── train_packed_labels.npy
            ├── test_packed_labels.npy
            └── section_entropy_analysis.png
```

## Future Work

- [ ] Analyze the 5,343 false negatives (unpacked malware that evaded detection)
- [ ] Test on specific packer types (UPX, Themida, ASPack, custom packers)
- [ ] Implement gradient boosting models (XGBoost, LightGBM) for comparison
- [ ] Add dynamic analysis features to complement static entropy analysis
- [ ] Build real-time PE file analyzer for new samples

## Technical Details

**Model:** Random Forest Classifier
- 100 trees
- Max depth: 20
- Training time: ~27 seconds on 600k samples

**Packing Detection Threshold:** Section entropy > 7.0

**Hardware:** Trained on consumer laptop (16 threads)

## References

1. Anderson, H. S., & Roth, P. (2018). EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models. *ArXiv preprint arXiv:1804.04637*
2. [EMBER Dataset Repository](https://github.com/elastic/ember)
3. Shafiq, M. Z., et al. (2009). "PE-Miner: Mining Structural Information to Detect Malicious Executables in Realtime"

## License

MIT License

## Author

**Smitty** - Cybersecurity student and researcher  
[GitHub](https://github.com/Smitty-bit) |

---

*Built during Winter Break as part of ongoing malware analysis research.*
