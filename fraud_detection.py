import joblib
import numpy as np

# Load trained models
rf_model = joblib.load('models/random_forest_model.pkl')
xgb_model = joblib.load('models/xgboost_model.pkl')

def predict_fraud(input_features):
    """
    Predict whether a transaction is fraudulent.

    input_features: list or numpy array
    Example: [amount, time_hour, location_mismatch, device_mismatch, multiple_transfers, otp_failures]

    Returns:
        (prediction: 0/1, fraud_score: float 0–100%)
    """
    print("⚠️ Feature count during prediction:", len(input_features))  # Debug

    # Convert to numpy array
    input_array = np.array(input_features).reshape(1, -1)

    # Predict probability using both models
    rf_prob = rf_model.predict_proba(input_array)[0][1]
    xgb_prob = xgb_model.predict_proba(input_array)[0][1]

    # Average score
    avg_score = (rf_prob + xgb_prob) / 2

    # Classification threshold
    prediction = 1 if avg_score >= 0.5 else 0

    return prediction, avg_score * 100


# Test block (optional, remove in production)
if __name__ == "__main__":
    sample_input = [25000, 2, 1, 1, 0, 2]  # test example
    result, score = predict_fraud(sample_input)
    if result:
        print(f"⚠️ FRAUD predicted! (Fraud Score: {score:.2f}%)")
    else:
        print(f"✅ SAFE transaction. (Fraud Score: {score:.2f}%)")
