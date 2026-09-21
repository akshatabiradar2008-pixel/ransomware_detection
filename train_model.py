import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

# Load datasets
X_train = pd.read_csv("data/MLRan_X_train_RFE.csv")
X_test = pd.read_csv("data/MLRan_X_test_RFE.csv")
labels = pd.read_csv("data/MLRan_labels.csv")

# Use the last column of labels as the target
y = labels.iloc[:, -1]

# Split labels according to train/test
y_train = y.iloc[:len(X_train)]
y_test = y.iloc[len(X_train):]

print("Training data:", X_train.shape)
print("Testing data:", X_test.shape)
print("Training labels:", y_train.shape)
print("Testing labels:", y_test.shape)

# Train Random Forest model
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X_train, y_train)

# Create model folder if it doesn't exist
os.makedirs("model", exist_ok=True)

# Save model
joblib.dump(model, "model/ransomware_model.pkl")

print("Model training completed!")
print("Model saved as model/ransomware_model.pkl")