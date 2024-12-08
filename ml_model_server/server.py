from flask import Flask, request, jsonify
from sqli import SQLInjectionDetector
import pickle
import os

app = Flask(__name__)
model = None

def load_model():
    global model
    model_path = os.path.join(os.path.dirname(__file__), 'sql_injection_detector.pkl')
    if os.path.exists(model_path):
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
    else:
        # Use best parameters from testing
        model_params = {
            'n_estimators': 50,
            'max_depth': 15,
            'min_samples_split': 10,
            'class_weight': 'balanced',
            'random_state': 42
        }
        model = SQLInjectionDetector(model_params)
        # Train with some default data if needed
        # model.train(...)

@app.before_first_request
def initialize():
    load_model()

@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Get data from request
        method = request.form.get('method', '')
        uri = request.form.get('uri', '')
        body = request.form.get('body', '')
        
        # Get all arguments that start with arg_
        args = {k[4:]: v for k, v in request.form.items() if k.startswith('arg_')}
        
        # Combine all data into a single query string for analysis
        query = f"{method} {uri}"
        if args:
            query += " " + " ".join(f"{k}={v}" for k, v in args.items())
        if body:
            query += " " + body
            
        # Extract features and make prediction
        features = model.extract_sql_features(query)
        X = model.prepare_data([query])  # Prepare single query for prediction
        probs = model.predict(X)
        
        # Get probability of malicious class (1)
        score = float(probs[0][1])
        
        return jsonify({
            'score': score,
            'features': features
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'score': 0.0
        })

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
