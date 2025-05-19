import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

def train_models():
    # Load dataset
    df = pd.read_csv('custom_fraud_dataset_1L.csv')
    print("Dataset Columns:", df.columns)

    # ✅ Check if target exists
    if 'isFraud' not in df.columns:
        raise Exception("⚠️ Column 'isFraud' not found in dataset")
    
    y = df['isFraud']

    # ✅ Create features to match app input
    df['hour'] = 12  # Or use: pd.to_datetime(df['time_column']).dt.hour if real timestamp
    df['location_mismatch'] = 0
    df['device_mismatch'] = 0
    df['multiple_transfers'] = 0
    df['otp_failures'] = 0

    features = ['amount', 'hour', 'location_mismatch', 'device_mismatch', 'multiple_transfers', 'otp_failures']
    X = df[features]

    # ✅ Split dataset
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42)

    # ✅ Train Random Forest
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
    rf_model.fit(X_train, y_train)
    rf_preds = rf_model.predict(X_test)
    print("\n📊 Random Forest Report:")
    print(classification_report(y_test, rf_preds))

    # ✅ Train XGBoost
    xgb_model = XGBClassifier(use_label_encoder=False, eval_metric='logloss', scale_pos_weight=47)  # 24483/517 ≈ 47
    xgb_model.fit(X_train, y_train)
    xgb_preds = xgb_model.predict(X_test)
    print("\n📊 XGBoost Report:")
    print(classification_report(y_test, xgb_preds))

    # ✅ Save models
    joblib.dump(rf_model, 'models/random_forest_model.pkl')
    joblib.dump(xgb_model, 'models/xgboost_model.pkl')
    print("\n✅ Models saved successfully to /models/")

# Entry point
if __name__ == '__main__':
    train_models()
