import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import os

# --- Path Configuration ---
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
CSV_PATH = os.path.join(BASE_DIR, "data", "dataset.csv")
MODEL_DIR = os.path.join(BASE_DIR, "app", "models") 
MODEL_PATH = os.path.join(MODEL_DIR, "malware_model.pkl")

def train():
    """Load dataset, train a RandomForest classifier, evaluate it, and save the model.

    The function prints progress and evaluation metrics to stdout and performs
    a simple error analysis listing misclassified samples (if any).
    """
    print("--- Starting Model Training (Optimized) ---")
    
    # 1. Load the Data
    if not os.path.exists(CSV_PATH):
        print(f"Error: {CSV_PATH} not found!")
        return

    # Read CSV into a DataFrame
    df = pd.read_csv(CSV_PATH)
    print(f"Loaded dataset with {len(df)} samples.")
    
    # Print the count of each class label to inspect balance
    print("Distribution:")
    print(df['label'].value_counts())

    # Fill missing values with 0 to avoid errors during training
    df = df.fillna(0)

    # 2. Data Preparation
    # Drop non-numeric columns that shouldn't be features (e.g., filename)
    X = df.drop(["label", "filename"], axis=1, errors='ignore')
    y = df["label"]

    # Split the dataset into training and testing subsets (80/20 split)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 3. Training with OPTIMIZED Parameters
    print("Training Random Forest Classifier with optimized parameters...")
    model = RandomForestClassifier(
        n_estimators=100,       # number of trees in the forest
        bootstrap=True,        # use bootstrap samples when building trees
        min_samples_split=2,   # minimum samples required to split an internal node
        max_depth=None,        # allow nodes to expand until all leaves are pure
        random_state=42        # reproducible results
    )
    
    # Fit the model to the training data
    model.fit(X_train, y_train)

    # 4. Results Evaluation
    # Predict on the held-out test set and compute common metrics
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    
    print(f"\nModel Accuracy: {acc:.4f} ({acc*100:.2f}%)")
    print("\nConfusion Matrix (shows where the model made errors):")
    print(confusion_matrix(y_test, y_pred))
    
    print("\nDetailed Report:")
    print(classification_report(y_test, y_pred))

    # --- New Feature: Error Analysis ---
    # Identify specific test samples that were misclassified for manual review
    print("\nError Analysis: Which files confused the model?")
    test_indices = X_test.index
    errors = df.loc[test_indices][y_test != y_pred]
    
    if not errors.empty:
        # Print a concise table identifying filenames and their true labels
        print(errors[['filename', 'label', 'file_size', 'num_imported_functions']])
    else:
        print("Amazing! No errors found in the test set.")

    # 5. Save the Model for Server Usage
    if not os.path.exists(MODEL_DIR):
        os.makedirs(MODEL_DIR)
        
    # Persist the trained model with joblib for later loading by the server
    joblib.dump(model, MODEL_PATH)
    print(f"\nModel saved successfully to: {MODEL_PATH}")

if __name__ == "__main__":
    # Execute training routine when run as a script
    train()