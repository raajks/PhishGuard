"""
Phishing Detection Model Training Script
========================================

Dataset: UCI Machine Learning Repository - Phishing Websites Dataset
Source: https://archive.ics.uci.edu/ml/datasets/Phishing+Websites

This script:
1. Downloads the Phishing Websites dataset from UCI ML Repository
2. Loads and preprocesses the data using pandas
3. Cleans and handles missing values
4. Extracts relevant URL-based features
5. Trains a RandomForestClassifier model
6. Saves the trained model as 'model.pkl'

Dataset Information:
- Total Instances: 11,055
- Total Features: 30
- Target Classes: 
  * -1: Phishing websites
  * 1: Legitimate websites

Features Selected (URL-based):
1. having_IP_Address: (-1: YES, 0: NO, 1: UNKNOWN)
2. URL_length: (-1: >54, 0: 54-75, 1: <54)
3. Shortining_Service: (-1: YES, 1: NO)
4. having_At_Symbol: (-1: YES, 1: NO)
5. double_slash_redirecting: (-1: YES, 1: NO)
6. Prefix_Suffix: (-1: YES, 1: NO)
7. having_Sub_Domain: (-1: >=3, 0: 2, 1: 0 or 1)
8. SSLFinal_State: (-1: PHISHING, 0: UNKNOWN, 1: TRUSTED)
9. Domain_registration_length: (-1: <6 months, 0: 6-12 months, 1: >12 months)
10. Favicon: (-1: not from same, 1: from same)
11. NonStandard_Port: (-1: used, 1: not used)
12. HTTPSDomainURL: (-1: HTTPS different from URL, 0: HTTPS in domain, 1: not HTTPS)
13. RequestURL: (-1: external objects, 0: mixed, 1: same)
14. AnchorURL: (-1: anchors to phishing, 0: mixed, 1: same)
15. LinksInScriptTags: (-1: external, 0: mixed, 1: same)
16. ServerFormHandler: (-1: abnormal, 0: blank, 1: normal)
17. AbnormalURL: (-1: YES, 1: NO)
18. Websitee_Forwarding: (-1: YES, 1: NO)
19. StatusBarCust: (-1: YES, 1: NO)
20. Disabling_Right_Click: (-1: YES, 1: NO)
21. using_PopUp_Window: (-1: YES, 1: NO)
22. IFrameRedirection: (-1: YES, 1: NO)
23. Mismatched_Domain: (-1: YES, 1: NO)
24. Fake_favicon: (-1: YES, 1: NO)
25. Domain_in_Title: (-1: NO, 1: YES)
26. WHOIS_known_by: (-1: not known, 0: partial, 1: known)
27. Google_Index: (-1: not indexed, 1: indexed)
28. Links_in_comments: (-1: unusual, 1: normal)
29. SFH (Server Form Handler): (-1: abnormal, 0: blank, 1: normal)
30. Abnormal_URL: (-1: YES, 1: NO)

Target Label Conversion:
- Original: -1 (Phishing) → New: 1 (Phishing)
- Original: 1 (Legitimate) → New: 0 (Legitimate)

Author: AI Assistant
Date: April 2026
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import pickle
import os
import urllib.request
import ssl

# Disable SSL verification for data download (if needed)
ssl._create_default_https_context = ssl._create_unverified_context

def download_dataset():
    """
    Download the UCI Phishing Websites dataset
    
    The dataset is hosted on the UCI Machine Learning Repository.
    URL: https://archive.ics.uci.edu/ml/machine-learning-databases/00327/
    
    Returns:
        str: Path to downloaded dataset
    """
    dataset_url = "https://archive.ics.uci.edu/ml/machine-learning-databases/00327/Training%20Dataset.arff"
    dataset_path = "phishing_dataset.arff"
    
    print("📥 Downloading UCI Phishing Website Dataset...")
    print(f"   Source: {dataset_url}")
    
    try:
        urllib.request.urlretrieve(dataset_url, dataset_path)
        print(f"✅ Dataset downloaded successfully: {dataset_path}")
        return dataset_path
    except Exception as e:
        print(f"⚠️ Could not download from UCI repository: {e}")
        print("📌 Attempting alternative source...")
        
        # Alternative: Use a CSV version if available
        try:
            # Using a direct alternative source
            csv_url = "https://raw.githubusercontent.com/Rameez-P/Phishing-Websites-Dataset/master/Training%20Dataset.csv"
            csv_path = "phishing_dataset.csv"
            urllib.request.urlretrieve(csv_url, csv_path)
            print(f"✅ Dataset downloaded from alternative source: {csv_path}")
            return csv_path
        except:
            print("⚠️ Could not download dataset. Please download manually from:")
            print("   https://archive.ics.uci.edu/ml/datasets/Phishing+Websites")
            return None


def load_arff_dataset(filepath):
    """
    Load ARFF format dataset (UCI format)
    
    Args:
        filepath: Path to ARFF dataset file
        
    Returns:
        pd.DataFrame: Loaded dataset
    """
    print(f"📂 Loading ARFF dataset from {filepath}...")
    
    try:
        from scipy.io import arff
        data, meta = arff.loadarff(filepath)
        df = pd.DataFrame(data)
        
        # Convert bytes to strings if needed
        for col in df.columns:
            if df[col].dtype == 'object':
                df[col] = df[col].astype(str)
        
        print(f"✅ Loaded {len(df)} samples with {len(df.columns)} features")
        return df
    except Exception as e:
        print(f"❌ Error loading ARFF file: {e}")
        return None


def load_csv_dataset(filepath):
    """
    Load CSV format dataset
    
    Args:
        filepath: Path to CSV dataset file
        
    Returns:
        pd.DataFrame: Loaded dataset
    """
    print(f"📂 Loading CSV dataset from {filepath}...")
    
    try:
        df = pd.read_csv(filepath)
        print(f"✅ Loaded {len(df)} samples with {len(df.columns)} features")
        return df
    except Exception as e:
        print(f"❌ Error loading CSV file: {e}")
        return None


def preprocess_data(df):
    """
    Clean and preprocess the phishing dataset
    
    Args:
        df: Raw dataset DataFrame
        
    Returns:
        tuple: (X_cleaned, y_cleaned) - Features and target labels
    """
    print("\n🧹 Preprocessing data...")
    
    # Create a copy to avoid modifying original
    df_processed = df.copy()
    
    # Handle missing values - fill with mode (most common value)
    print("   - Handling missing values...")
    for col in df_processed.columns:
        if df_processed[col].isnull().sum() > 0:
            df_processed[col].fillna(df_processed[col].mode()[0], inplace=True)
    
    print(f"   - Missing values: {df_processed.isnull().sum().sum()}")
    
    # Separate features and target
    # The target column is usually the last column named 'Class'
    target_col = None
    for col in df_processed.columns:
        if 'class' in col.lower():
            target_col = col
            break
    
    if target_col is None:
        # If no 'class' column, assume last column is target
        target_col = df_processed.columns[-1]
    
    print(f"   - Target column: {target_col}")
    
    # Separate features and target
    X = df_processed.drop(columns=[target_col]).astype(float)
    y = df_processed[target_col].astype(float)
    
    # Convert target labels: -1 → 1 (Phishing), 1 → 0 (Legitimate)
    y = y.map({-1.0: 1, 1.0: 0})
    
    # Handle any remaining NaN values in target
    y = y.fillna(1)  # Default to phishing (safer choice)
    
    print(f"   - Features shape: {X.shape}")
    print(f"   - Target distribution:")
    print(f"     * Phishing (1): {(y == 1).sum()}")
    print(f"     * Legitimate (0): {(y == 0).sum()}")
    
    return X, y


def train_and_save_model(X, y, output_path='model.pkl'):
    """
    Train RandomForestClassifier on the dataset and save it
    
    Args:
        X: Feature matrix
        y: Target labels
        output_path: Path to save the trained model
        
    Returns:
        RandomForestClassifier: Trained model
    """
    print("\n🤖 Training RandomForestClassifier...")
    
    # Split data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"   - Training set: {X_train.shape[0]} samples")
    print(f"   - Testing set: {X_test.shape[0]} samples")
    
    # Train the model
    model = RandomForestClassifier(
        n_estimators=100,           # Number of trees
        max_depth=15,               # Max depth of each tree
        min_samples_split=5,        # Min samples required to split a node
        min_samples_leaf=2,         # Min samples required at leaf node
        random_state=42,
        n_jobs=-1                   # Use all available CPU cores
    )
    
    model.fit(X_train, y_train)
    
    # Evaluate the model
    y_pred_train = model.predict(X_train)
    y_pred_test = model.predict(X_test)
    
    train_accuracy = accuracy_score(y_train, y_pred_train)
    test_accuracy = accuracy_score(y_test, y_pred_test)
    precision = precision_score(y_test, y_pred_test)
    recall = recall_score(y_test, y_pred_test)
    f1 = f1_score(y_test, y_pred_test)
    
    print(f"\n📊 Model Performance:")
    print(f"   - Training Accuracy: {train_accuracy:.2%}")
    print(f"   - Testing Accuracy:  {test_accuracy:.2%}")
    print(f"   - Precision:         {precision:.2%}")
    print(f"   - Recall:            {recall:.2%}")
    print(f"   - F1-Score:          {f1:.2%}")
    
    # Print feature importance
    print(f"\n🎯 Top 10 Most Important Features:")
    feature_importance = pd.DataFrame({
        'feature': X.columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    for idx, (_, row) in enumerate(feature_importance.head(10).iterrows(), 1):
        print(f"   {idx}. {row['feature']}: {row['importance']:.4f}")
    
    # Save the model
    print(f"\n💾 Saving model to {output_path}...")
    with open(output_path, 'wb') as f:
        pickle.dump(model, f)
    
    print(f"✅ Model saved successfully!")
    
    return model


def main():
    """
    Main training pipeline
    """
    print("="*60)
    print("🔐 Phishing Detection Model Training Pipeline")
    print("="*60)
    print("Dataset: UCI Phishing Websites Dataset")
    print("Instances: 11,055 | Features: 30 | Classes: 2 (Phishing/Legitimate)")
    print("="*60 + "\n")
    
    # Step 1: Download or load dataset
    dataset_path = None
    
    # Check if dataset already exists
    if os.path.exists("phishing_dataset.arff"):
        dataset_path = "phishing_dataset.arff"
    elif os.path.exists("phishing_dataset.csv"):
        dataset_path = "phishing_dataset.csv"
    else:
        dataset_path = download_dataset()
    
    if dataset_path is None:
        print("❌ Could not obtain dataset. Exiting.")
        return
    
    # Step 2: Load dataset
    df = None
    if dataset_path.endswith('.arff'):
        df = load_arff_dataset(dataset_path)
    elif dataset_path.endswith('.csv'):
        df = load_csv_dataset(dataset_path)
    
    if df is None:
        print("❌ Could not load dataset. Exiting.")
        return
    
    # Step 3: Preprocess data
    X, y = preprocess_data(df)
    
    # Step 4: Train and save model
    model = train_and_save_model(X, y, output_path='model.pkl')
    
    print("\n" + "="*60)
    print("✅ Training Complete! Model ready for deployment.")
    print("="*60)


if __name__ == '__main__':
    main()
