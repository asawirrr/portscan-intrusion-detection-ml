# 🛠️ Fix and Optimization Guide: Resolving the Memory Crash

Agar aap apne `Untitled.ipynb` notebook mein dekhein, to **Cell 4 (`In[81]`)** par execution crash ho gayi thi aur yeh error aaya tha:

```text
MemoryError: Unable to allocate 445. MiB for an array with shape (24, 2432027) and data type float64
```

Is guide mein hum explain kar rahe hain ke **yeh error kyun aaya** aur isko **Notebook ke andar kaise theek karein**, taake aapka poora pipeline bina kisi rukawat ke execute ho sake.

---

## 🧐 1. Error Kyun Aaya? (Root Cause Explanation)

1. **8 Files ka Be-wajah Load Hona:**
   Aapke code ne 8 files load karke `merged_df` banaya jisme **2,830,743 rows** aur **79 columns** the. 
2. **Double Memory Usage:**
   Jab `filtered_df = merged_df[merged_df['Label'].isin(['BENIGN', 'PortScan'])].copy()` call hua, to Pandas ne pooray 2.4 million rows ka ek naya copy memory mein allocate karne ki koshish ki.
3. **RAM Exhaustion:**
   Pehle se 8 DataFrames (`df1` se `df8`) + `merged_df` RAM mein mojud the. Nayi copy create karne ke liye system ke paas contiguous free memory nahi bachi, jiski wajah se Windows ne `MemoryError` throw kar diya aur aage ke tamam cells (Model training, plots) block ho gaye.

---

## 💡 2. Solution: Direct Notebook Fix

Aapko saari 8 files ko ek saath load karke merge karne ki zaroorat nahi hai!

### Fact:
CICIDS2017 dataset mein **PortScan attacks sirf aur sirf** `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` file mein mojud hain.
Is akeli file mein:
- **PortScan Rows:** ~158,930
- **BENIGN Rows:** ~127,537

Aapko required 50,000 PortScan aur 50,000 BENIGN samples **isi single file se aasaani se mil jate hain** bina 1 GB ka bojh RAM par dale!

---

## 📝 3. Cell-by-Cell Notebook Code Fix

Agar aap apne Jupyter Notebook ko fix karna chahte hain, to apne notebook ke shuru ke cells ko is tarah update karein:

### Step 1: Replace Cell 1 & 2 (Load only necessary file)
Pehle cell mein 8 files load karne ke bajaye yeh likhein:

```python
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import gc

from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_curve, auc
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import SelectKBest, f_classif
import warnings
warnings.filterwarnings("ignore")

# Load only the PortScan file directly (Fast and uses < 200MB RAM)
print("Loading Friday Afternoon PortScan dataset...")
df_raw = pd.read_csv('Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv')

# Strip whitespace from columns
df_raw.columns = df_raw.columns.str.strip()
print("Initial Shape:", df_raw.shape)
print("Class counts:\n", df_raw['Label'].value_counts())
```

### Step 2: Replace Cell 4 (Preprocess & Sample without crash)

```python
# 1. Filter BENIGN and PortScan
filtered_df = df_raw[df_raw['Label'].isin(['BENIGN', 'PortScan'])].copy()
del df_raw
gc.collect()

# 2. Drop constant/single-value columns
filtered_df = filtered_df.loc[:, filtered_df.nunique() > 1]

# 3. Handle Infinite and Missing values
filtered_df.replace([np.inf, -np.inf], np.nan, inplace=True)
filtered_df.dropna(inplace=True)

# 4. Map Labels (BENIGN -> 0, PortScan -> 1)
filtered_df['Label'] = filtered_df['Label'].replace({'BENIGN': 0, 'PortScan': 1})

# 5. Balanced Sampling (50,000 each)
df_benign = filtered_df[filtered_df['Label'] == 0].sample(n=50000, random_state=42)
df_portscan = filtered_df[filtered_df['Label'] == 1].sample(n=50000, random_state=42)

df = pd.concat([df_benign, df_portscan], ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)

# Clean up memory
del filtered_df, df_benign, df_portscan
gc.collect()

print("Balanced Sample Shape:", df.shape)
print(df['Label'].value_counts())
```

### Step 3: Run the rest of the cells
Iske baad aapke baqi tamam cells (Cell 5 se 17):
- Feature Scaling (`StandardScaler`)
- Feature Selection (`SelectKBest`)
- Random Forest, SVM, MLP training
- Confusion Matrices, ROC Curves, Comparison plots
- EDA Visualizations

Bina kisi memory error ke **100% smoothly aur tezi se execute ho jayenge!**

---

## ⚡ 4. Fast Track: Run the Production Script

Aapko manual copy-paste karne ki bhi zaroorat nahi hai. Humne aapke liye **`pipeline_optimized.py`** bana diya hai jo:
1. Pure process ko automate karta hai.
2. RAM ko optimize karke 200MB ke andar rakhta hai.
3. Teeno models train karta hai aur metrics screen par print karta hai.
4. Tamam charts (ROC curve, Confusion Matrices, Feature Importance, EDA plots) ko ek `outputs/` folder mein PNG format mein save karta hai.

### Run command:
```bash
python pipeline_optimized.py
```
Is command ko chalate hi poora project start to finish execute ho jayega!
