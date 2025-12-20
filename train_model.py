import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import os

# הגדרות נתיבים
BASE_DIR = os.path.expanduser("~/Desktop/CyberProject")
CSV_PATH = os.path.join(BASE_DIR, "dataset.csv")
MODEL_DIR = os.path.join(BASE_DIR, "backend") 
MODEL_PATH = os.path.join(MODEL_DIR, "malware_model.pkl")

def train():
    print("--- Starting Model Training ---")
    
    # 1. טעינת הדאטה
    if not os.path.exists(CSV_PATH):
        print("❌ Error: dataset.csv not found!")
        return

    df = pd.read_csv(CSV_PATH)
    print(f"Loaded dataset with {len(df)} samples.")
    
    # הדפסת כמות מכל סוג כדי לוודא איזון
    print("Distribution:")
    print(df['label'].value_counts())

    # מילוי ערכים חסרים
    df = df.fillna(0)

    # 2. הכנת הנתונים
    # אנחנו חייבים להעיף את עמודת השם (filename) כי המודל לומד רק מספרים
    X = df.drop(["label", "filename"], axis=1, errors='ignore')
    y = df["label"]

    # חלוקה: 80% לאימון, 20% למבחן
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 3. אימון
    print("Training Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # 4. בדיקת תוצאות
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    
    print(f"\n✅ Model Accuracy: {acc:.4f} ({acc*100:.2f}%)")
    print("\nConfusion Matrix (מה הוא פיספס):")
    print(confusion_matrix(y_test, y_pred))
    
    print("\nDetailed Report:")
    print(classification_report(y_test, y_pred))

    # 5. שמירת המודל לשימוש בשרת
    if not os.path.exists(MODEL_DIR):
        os.makedirs(MODEL_DIR)
        
    joblib.dump(model, MODEL_PATH)
    print(f"\n🚀 Model saved successfully to: {MODEL_PATH}")

if __name__ == "__main__":
    train()