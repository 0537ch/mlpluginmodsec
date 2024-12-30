import joblib
import pickle

# Load the joblib model
model = joblib.load('model_testing/20241206_031147/best_model.joblib')

# Save as pickle
with open('converted_model.pkl', 'wb') as f:
    pickle.dump(model, f)

print("Model successfully converted from .joblib to .pkl")
