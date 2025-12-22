import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import os

# --- Path Configuration ---
# Use dynamic path detection instead of hardcoded Desktop path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(BASE_DIR, "dataset.csv")
MODEL_DIR = os.path.join(BASE_DIR, "backend") 
MODEL_PATH = os.path.join(MODEL_DIR, "malware_model.pkl")

def train():
    print("--- Starting Model Training ---")
    
    # 1. Load the Data
    if not os.path.exists(CSV_PATH):
        print(f"❌ Error: {CSV_PATH} not found!")
        return

    df = pd.read_csv(CSV_PATH)
    print(f"Loaded dataset with {len(df)} samples.")
    
    # Print the count of each type to ensure balance
    print("Distribution:")
    print(df['label'].value_counts())

    # Fill missing values with 0
    df = df.fillna(0)

    # 2. Data Preparation
    # We must drop the 'filename' column because the model only learns from numeric data
    X = df.drop(["label", "filename"], axis=1, errors='ignore')
    y = df["label"]

    # Split: 80% for training, 20% for testing
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 3. Training
    print("Training Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # 4. Results Evaluation
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    
    print(f"\n✅ Model Accuracy: {acc:.4f} ({acc*100:.2f}%)")
    print("\nConfusion Matrix (shows where the model made errors):")
    print(confusion_matrix(y_test, y_pred))
    
    print("\nDetailed Report:")
    print(classification_report(y_test, y_pred))

    # 5. Save the Model for Server Usage
    if not os.path.exists(MODEL_DIR):
        os.makedirs(MODEL_DIR)
        
    joblib.dump(model, MODEL_PATH)
    print(f"\n🚀 Model saved successfully to: {MODEL_PATH}")

if __name__ == "__main__":
    train()