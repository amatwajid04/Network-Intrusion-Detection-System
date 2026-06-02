
# ---- Import Libraries ----
import os
import pickle
import json
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report
)



def generate_nslkdd_data(n_samples=5000):
    """
    Generate synthetic network traffic data similar to NSL-KDD.

    Features generated:
      - duration         : Length of connection (seconds)
      - protocol_type    : Protocol used (tcp, udp, icmp)
      - service          : Network service (http, ftp, ssh, etc.)
      - flag             : Connection status (SF, S0, REJ, etc.)
      - src_bytes        : Bytes from source to destination
      - dst_bytes        : Bytes from destination to source
      - count            : Connections to same host in 2 sec window
      - srv_count        : Connections to same service in 2 sec window
      - serror_rate      : % connections with SYN errors
      - same_srv_rate    : % connections to same service
      - dst_host_count   : Connections to same destination host
      - dst_host_srv_count       : Same destination & service count
      - dst_host_same_srv_rate   : % same-service connections at dest
      - dst_host_serror_rate     : % SYN error connections at dest

    Labels: normal, dos, probe, r2l, u2r
    """
    print("=" * 55)
    print("  NETWORK INTRUSION DETECTION - MODEL TRAINER")
    print("=" * 55)
    print("\n[>>] Step 1: Generating synthetic NSL-KDD dataset...")

    # Set random seed so results are the same every time
    np.random.seed(42)

    # Possible values for categorical features
    protocols = ['tcp', 'udp', 'icmp']
    services = ['http', 'ftp', 'smtp', 'ssh', 'dns', 'telnet', 'pop3', 'imap']
    flags = ['SF', 'S0', 'REJ', 'RSTO', 'SH', 'RSTR', 'S1', 'S2', 'OTH']


    class_counts = {
        'normal': int(n_samples * 0.40),
        'dos':    int(n_samples * 0.30),
        'probe':  int(n_samples * 0.15),
        'r2l':    int(n_samples * 0.10),
        'u2r':    n_samples - int(n_samples * 0.95)  # remainder (~5%)
    }

    records = []  # Will hold all generated records

    for label, count in class_counts.items():
        for _ in range(count):
            # Each attack type has distinct traffic patterns
            if label == 'normal':
            
                record = {
                    'duration':               round(np.random.exponential(10), 2),
                    'protocol_type':          np.random.choice(protocols, p=[0.70, 0.20, 0.10]),
                    'service':                np.random.choice(services, p=[0.35, 0.10, 0.10, 0.15, 0.10, 0.05, 0.10, 0.05]),
                    'flag':                   np.random.choice(flags, p=[0.70, 0.05, 0.05, 0.05, 0.02, 0.03, 0.03, 0.04, 0.03]),
                    'src_bytes':              round(np.random.exponential(500), 0),
                    'dst_bytes':              round(np.random.exponential(1000), 0),
                    'count':                  np.random.randint(1, 20),
                    'srv_count':              np.random.randint(1, 20),
                    'serror_rate':            round(np.random.uniform(0.0, 0.10), 4),
                    'same_srv_rate':          round(np.random.uniform(0.80, 1.0), 4),
                    'dst_host_count':         np.random.randint(1, 255),
                    'dst_host_srv_count':     np.random.randint(1, 255),
                    'dst_host_same_srv_rate': round(np.random.uniform(0.50, 1.0), 4),
                    'dst_host_serror_rate':   round(np.random.uniform(0.0, 0.10), 4),
                }

            elif label == 'dos':
              
                record = {
                    'duration':               round(np.random.exponential(1), 2),
                    'protocol_type':          np.random.choice(protocols, p=[0.50, 0.10, 0.40]),
                    'service':                np.random.choice(services, p=[0.40, 0.05, 0.05, 0.10, 0.15, 0.05, 0.10, 0.10]),
                    'flag':                   np.random.choice(flags, p=[0.15, 0.30, 0.15, 0.10, 0.05, 0.10, 0.05, 0.05, 0.05]),
                    'src_bytes':              round(np.random.exponential(50), 0),
                    'dst_bytes':              round(np.random.exponential(10), 0),
                    'count':                  np.random.randint(100, 511),
                    'srv_count':              np.random.randint(50, 511),
                    'serror_rate':            round(np.random.uniform(0.70, 1.0), 4),
                    'same_srv_rate':          round(np.random.uniform(0.0, 0.30), 4),
                    'dst_host_count':         np.random.randint(200, 255),
                    'dst_host_srv_count':     np.random.randint(1, 50),
                    'dst_host_same_srv_rate': round(np.random.uniform(0.0, 0.30), 4),
                    'dst_host_serror_rate':   round(np.random.uniform(0.70, 1.0), 4),
                }

            elif label == 'probe':
           
                record = {
                    'duration':               round(np.random.exponential(2), 2),
                    'protocol_type':          np.random.choice(protocols, p=[0.40, 0.20, 0.40]),
                    'service':                np.random.choice(services, p=[0.12, 0.13, 0.12, 0.13, 0.13, 0.12, 0.13, 0.12]),
                    'flag':                   np.random.choice(flags, p=[0.25, 0.15, 0.20, 0.10, 0.05, 0.10, 0.05, 0.05, 0.05]),
                    'src_bytes':              round(np.random.exponential(100), 0),
                    'dst_bytes':              round(np.random.exponential(50), 0),
                    'count':                  np.random.randint(20, 200),
                    'srv_count':              np.random.randint(1, 10),
                    'serror_rate':            round(np.random.uniform(0.30, 0.70), 4),
                    'same_srv_rate':          round(np.random.uniform(0.0, 0.20), 4),
                    'dst_host_count':         np.random.randint(100, 255),
                    'dst_host_srv_count':     np.random.randint(1, 30),
                    'dst_host_same_srv_rate': round(np.random.uniform(0.0, 0.20), 4),
                    'dst_host_serror_rate':   round(np.random.uniform(0.30, 0.70), 4),
                }

            elif label == 'r2l':
       
                record = {
                    'duration':               round(np.random.exponential(50), 2),
                    'protocol_type':          np.random.choice(protocols, p=[0.80, 0.10, 0.10]),
                    'service':                np.random.choice(services, p=[0.15, 0.20, 0.10, 0.10, 0.05, 0.20, 0.10, 0.10]),
                    'flag':                   np.random.choice(flags, p=[0.45, 0.10, 0.15, 0.10, 0.05, 0.05, 0.03, 0.04, 0.03]),
                    'src_bytes':              round(np.random.exponential(2000), 0),
                    'dst_bytes':              round(np.random.exponential(200), 0),
                    'count':                  np.random.randint(1, 10),
                    'srv_count':              np.random.randint(1, 10),
                    'serror_rate':            round(np.random.uniform(0.0, 0.30), 4),
                    'same_srv_rate':          round(np.random.uniform(0.50, 1.0), 4),
                    'dst_host_count':         np.random.randint(1, 100),
                    'dst_host_srv_count':     np.random.randint(1, 100),
                    'dst_host_same_srv_rate': round(np.random.uniform(0.30, 0.80), 4),
                    'dst_host_serror_rate':   round(np.random.uniform(0.0, 0.30), 4),
                }

            else:  # u2r
           
                record = {
                    'duration':               round(np.random.exponential(100), 2),
                    'protocol_type':          np.random.choice(protocols, p=[0.80, 0.10, 0.10]),
                    'service':                np.random.choice(services, p=[0.10, 0.15, 0.05, 0.25, 0.05, 0.25, 0.10, 0.05]),
                    'flag':                   np.random.choice(flags, p=[0.55, 0.05, 0.10, 0.05, 0.05, 0.05, 0.05, 0.05, 0.05]),
                    'src_bytes':              round(np.random.exponential(300), 0),
                    'dst_bytes':              round(np.random.exponential(500), 0),
                    'count':                  np.random.randint(1, 5),
                    'srv_count':              np.random.randint(1, 5),
                    'serror_rate':            round(np.random.uniform(0.0, 0.20), 4),
                    'same_srv_rate':          round(np.random.uniform(0.80, 1.0), 4),
                    'dst_host_count':         np.random.randint(1, 50),
                    'dst_host_srv_count':     np.random.randint(1, 50),
                    'dst_host_same_srv_rate': round(np.random.uniform(0.50, 1.0), 4),
                    'dst_host_serror_rate':   round(np.random.uniform(0.0, 0.20), 4),
                }

            # Add the label to the record
            record['label'] = label
            records.append(record)


    df = pd.DataFrame(records)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"   [OK] Generated {len(df)} records")
    print(f"\n   Label distribution:")
    for label, count in df['label'].value_counts().items():
        print(f"     {label:>8s}: {count} records ({count/len(df)*100:.1f}%)")

    return df




def preprocess_data(df):
    """
    Preprocess the dataset for machine learning.

    Args:
        df: pandas DataFrame with features and 'label' column

    Returns:
        X_scaled       : Scaled feature matrix
        y_encoded      : Numerically encoded target labels
        label_encoders : Dict of encoders for categorical columns
        target_encoder : Encoder for the target (label) column
        scaler         : StandardScaler fitted on the features
        feature_names  : List of feature column names
    """
    print("\n[>>] Step 2: Preprocessing data...")

    # Separate features (X) and target labels (y)
    X = df.drop('label', axis=1).copy()
    y = df['label'].copy()

    # --- Encode Categorical Columns ---
    # Convert text values like 'tcp', 'http', 'SF' to numbers
    label_encoders = {}
    categorical_columns = ['protocol_type', 'service', 'flag']

    for col in categorical_columns:
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col])
        label_encoders[col] = le
        print(f"   Encoded '{col}': {list(le.classes_)} -> {list(range(len(le.classes_)))}")

    # --- Encode Target Labels ---
    # Convert 'normal', 'dos', 'probe', etc. to 0, 1, 2, etc.
    target_encoder = LabelEncoder()
    y_encoded = target_encoder.fit_transform(y)
    print(f"   Encoded labels: {list(target_encoder.classes_)} -> {list(range(len(target_encoder.classes_)))}")

  
    feature_names = X.columns.tolist()
    scaler = StandardScaler()
    X_scaled = pd.DataFrame(
        scaler.fit_transform(X),
        columns=feature_names
    )

    print("   [OK] Preprocessing complete!")
    return X_scaled, y_encoded, label_encoders, target_encoder, scaler, feature_names




def train_and_compare_models(X_train, X_test, y_train, y_test, target_encoder):
    """
    Train three ML models and compare their accuracy.

    Models:
        1. Random Forest  - Ensemble of decision trees (best for this task)
        2. Decision Tree   - Single tree (simpler, less accurate)
        3. Logistic Regression - Linear model (good baseline)

    Returns:
        trained_models : Dict of trained model objects
        results        : Dict of performance metrics per model
    """
    print("\n[>>] Step 3: Training and comparing models...\n")

    # Define the three models with their hyperparameters
    models = {
        'Random Forest': RandomForestClassifier(
            n_estimators=100,   # Use 100 decision trees
            max_depth=15,       # Max depth of each tree
            random_state=42,    # Reproducible results
            n_jobs=-1           # Use all CPU cores for speed
        ),
        'Decision Tree': DecisionTreeClassifier(
            max_depth=15,       # Limit depth to prevent overfitting
            random_state=42
        ),
        'Logistic Regression': LogisticRegression(
            max_iter=1000,      # Allow enough iterations to converge
            random_state=42,
            multi_class='multinomial'  # Handle multiple classes
        )
    }

    # Train each model and measure performance
    trained_models = {}
    results = {}

    for name, model in models.items():
        print(f"   Training {name}...")

        # Train (fit) the model on training data
        model.fit(X_train, y_train)

        # Make predictions on test data
        y_pred = model.predict(X_test)

        # Calculate performance metrics
        accuracy  = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
        recall    = recall_score(y_test, y_pred, average='weighted', zero_division=0)
        f1        = f1_score(y_test, y_pred, average='weighted', zero_division=0)

        # Store the results
        results[name] = {
            'accuracy':  round(accuracy, 4),
            'precision': round(precision, 4),
            'recall':    round(recall, 4),
            'f1':        round(f1, 4)
        }
        trained_models[name] = model

        print(f"   [OK] {name}: Accuracy = {accuracy:.2%}")

    # ---- Print Comparison Table ----
    print("\n" + "=" * 70)
    print("  MODEL COMPARISON RESULTS")
    print("=" * 70)
    print(f"  {'Model':<25} {'Accuracy':<12} {'Precision':<12} {'Recall':<12} {'F1 Score':<12}")
    print("  " + "-" * 65)
    for name, metrics in results.items():
        marker = " [*]" if name == "Random Forest" else ""
        print(f"  {name:<25} {metrics['accuracy']:<12.4f} {metrics['precision']:<12.4f} "
              f"{metrics['recall']:<12.4f} {metrics['f1']:<12.4f}{marker}")
    print("=" * 70)
    print("  [*] = Selected as the deployed model\n")

    # ---- Print Detailed Report for Random Forest ----
    print("Detailed Classification Report (Random Forest):")
    print("-" * 55)
    rf_predictions = trained_models['Random Forest'].predict(X_test)
    target_names = list(target_encoder.classes_)
    print(classification_report(y_test, rf_predictions,
                                target_names=target_names,
                                zero_division=0))

    return trained_models, results




def save_model_artifacts(model, label_encoders, target_encoder, scaler, feature_names, results):
    """
    Save the trained model and comparison results.

    Saves:
        model/intrusion_model.pkl    - Pickled model package
        model/model_comparison.json  - Accuracy comparison data
    """
    print("[>>] Step 4: Saving model and artifacts...")

    # Create the model directory
    os.makedirs('model', exist_ok=True)

    # Package everything needed for predictions
    model_package = {
        'model':           model,             # The Random Forest model
        'label_encoders':  label_encoders,    # Text -> number encoders
        'target_encoder':  target_encoder,    # Label encoder (dos->0, etc.)
        'scaler':          scaler,            # Feature scaler
        'feature_names':   feature_names      # Expected column names
    }

    # Save model package as a pickle file
    model_path = os.path.join('model', 'intrusion_model.pkl')
    with open(model_path, 'wb') as f:
        pickle.dump(model_package, f)
    print(f"   [OK] Model saved to {model_path}")

    # Save comparison results as JSON (for the web dashboard)
    comparison_path = os.path.join('model', 'model_comparison.json')
    with open(comparison_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"   [OK] Comparison data saved to {comparison_path}")




def generate_sample_csv():
    """
    Create a 20-row sample CSV for testing the web application.
    This file does NOT include labels (those are what we predict).
    """
    print("\n[>>] Step 5: Generating sample test CSV...")

    os.makedirs('dataset', exist_ok=True)

    np.random.seed(123)

    protocols = ['tcp', 'udp', 'icmp']
    services = ['http', 'ftp', 'smtp', 'ssh', 'dns', 'telnet', 'pop3', 'imap']
    flags = ['SF', 'S0', 'REJ', 'RSTO', 'SH']

    records = []
    # Mix of different traffic patterns for a realistic sample
    patterns = [
        # Normal-like patterns (8 records)
        *[{'dur': (5, 30), 'sb': (100, 2000), 'db': (200, 3000), 'cnt': (1, 20), 'ser': (0, 0.1)}] * 8,
        # DoS-like patterns (5 records)
        *[{'dur': (0, 2), 'sb': (0, 100), 'db': (0, 50), 'cnt': (100, 500), 'ser': (0.7, 1.0)}] * 5,
        # Probe-like patterns (3 records)
        *[{'dur': (0, 5), 'sb': (10, 200), 'db': (0, 100), 'cnt': (20, 200), 'ser': (0.3, 0.7)}] * 3,
        # R2L-like patterns (2 records)
        *[{'dur': (20, 100), 'sb': (500, 5000), 'db': (50, 500), 'cnt': (1, 10), 'ser': (0, 0.3)}] * 2,
        # U2R-like patterns (2 records)
        *[{'dur': (50, 200), 'sb': (100, 800), 'db': (100, 1000), 'cnt': (1, 5), 'ser': (0, 0.2)}] * 2,
    ]

    for p in patterns:
        records.append({
            'duration':               round(np.random.uniform(p['dur'][0], p['dur'][1]), 2),
            'protocol_type':          np.random.choice(protocols),
            'service':                np.random.choice(services),
            'flag':                   np.random.choice(flags),
            'src_bytes':              int(np.random.uniform(p['sb'][0], p['sb'][1])),
            'dst_bytes':              int(np.random.uniform(p['db'][0], p['db'][1])),
            'count':                  int(np.random.uniform(p['cnt'][0], p['cnt'][1])),
            'srv_count':              np.random.randint(1, max(2, int(np.random.uniform(p['cnt'][0], p['cnt'][1]) * 0.5))),
            'serror_rate':            round(np.random.uniform(p['ser'][0], p['ser'][1]), 4),
            'same_srv_rate':          round(np.random.uniform(0, 1), 4),
            'dst_host_count':         np.random.randint(1, 255),
            'dst_host_srv_count':     np.random.randint(1, 255),
            'dst_host_same_srv_rate': round(np.random.uniform(0, 1), 4),
            'dst_host_serror_rate':   round(np.random.uniform(p['ser'][0], p['ser'][1]), 4),
        })

    # Save to CSV (no 'label' column - that's what the model predicts)
    sample_path = os.path.join('dataset', 'sample_data.csv')
    pd.DataFrame(records).to_csv(sample_path, index=False)
    print(f"   [OK] Sample data saved to {sample_path} ({len(records)} records)")




if __name__ == '__main__':
    # --- Step 1: Generate synthetic data ---
    df = generate_nslkdd_data(n_samples=5000)

    # --- Step 2: Preprocess ---
    X, y, label_encoders, target_encoder, scaler, feature_names = preprocess_data(df)

    # --- Step 3: Split into training (80%) and testing (20%) sets ---
    print("\n[>>] Splitting data: 80% training, 20% testing...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,        # 20% for testing
        random_state=42,      # Reproducible split
        stratify=y            # Keep class balance in both sets
    )
    print(f"   Training set: {len(X_train)} records")
    print(f"   Testing set:  {len(X_test)} records")

    # --- Step 4: Train and compare models ---
    trained_models, results = train_and_compare_models(
        X_train, X_test, y_train, y_test, target_encoder
    )

    # --- Step 5: Save the best model (Random Forest) ---
    save_model_artifacts(
        model=trained_models['Random Forest'],
        label_encoders=label_encoders,
        target_encoder=target_encoder,
        scaler=scaler,
        feature_names=feature_names,
        results=results
    )

    # --- Step 6: Generate sample CSV for web app testing ---
    generate_sample_csv()

    # --- Done! ---
    print("\n" + "=" * 55)
    print("  TRAINING COMPLETE!")
    print("=" * 55)
    print("  Next steps:")
    print("    1. Run the web app:  python app.py")
    print("    2. Open browser:     http://127.0.0.1:5000")
    print("    3. Upload:           dataset/sample_data.csv")
    print("=" * 55)
