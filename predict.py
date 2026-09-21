import pandas as pd
import joblib

# Load trained model
model = joblib.load("model/ransomware_model.pkl")

# Load test data
X_test = pd.read_csv("data/MLRan_X_test_RFE.csv")

# Take one test sample
sample = X_test.iloc[[0]]

# Predict
prediction = model.predict(sample)

print("Prediction:", prediction[0])
print("Prediction completed successfully!")