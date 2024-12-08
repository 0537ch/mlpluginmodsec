# Importing all the required libraries
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pickle
import sklearn
import psutil
import os
import json
from sqli import SQLInjectionDetector
import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from functools import partial
import signal
import gc
import numpy as np
import joblib

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ml_server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize Flask
app = Flask(__name__)

# Add rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per minute"]
)

# Global variables
MODEL_TIMEOUT = 1.0  # seconds
MAX_WORKERS = 4
executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
pid = os.getpid()

class MLServer:
    def __init__(self):
        self.model = None
        self.load_model()
        
    def load_model(self):
        try:
            # Update path to ml_model_server directory
            current_dir = os.path.dirname(os.path.abspath(__file__))
            pkl_filename = os.path.join(current_dir, 'sql_injection_detector.pkl')
            with open(pkl_filename, 'rb') as file:
                self.model = pickle.load(file)
            logger.info(f"Model loaded successfully from {pkl_filename}")
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            raise

    def predict(self, queries):
        try:
            if not queries:
                return 1
                
            # Use the loaded model for prediction
            detector = SQLInjectionDetector()
            X = detector.prepare_data(queries)
            
            # Use our loaded model for prediction
            probabilities = self.model.predict_proba(X)
            
            # Get probability of malicious class (class 1)
            malicious_probs = probabilities[:, 1]
            
            # If any query has high probability of being malicious (>0.5)
            threshold = 0.5
            is_malicious = any(prob > threshold for prob in malicious_probs)
            
            # Log the prediction details
            for query, prob in zip(queries, malicious_probs):
                logger.info(f"Query: {query}")
                logger.info(f"Malicious probability: {prob}")
                
            if is_malicious:
                logger.warning("SQL Injection attempt detected!")
                return -1
            return 1
            
        except Exception as e:
            logger.error(f"Prediction error: {str(e)}")
            return 1  # Fail open

# Initialize ML Server
ml_server = MLServer()

def process_request(form_data):
    try:
        method = form_data['method']
        path = form_data['path']
        args = json.loads(form_data['args']) if isinstance(form_data['args'], str) else form_data['args']
        hour = int(form_data['hour'])
        day = int(form_data['day'])

        # Log incoming request details
        logger.info("Received request:")
        logger.info(f"Method: {method}")
        logger.info(f"Path: {path}")
        logger.info(f"Args: {json.dumps(args, indent=2)}")
        logger.info(f"Hour: {hour}, Day: {day}")

        # Clean and prepare args
        queries = []
        for k, v in args.items():
            cleaned_value = v.replace("$#$", '"')
            queries.append(cleaned_value)
            args[k] = cleaned_value
            logger.debug(f"Processing argument - Key: {k}, Value: {cleaned_value}")

        # Log request details
        logger.info(f"Processing request - Method: {method}, Path: {path}, Args Count: {len(args)}")
        logger.info(f"Queries to check: {queries}")
        
        # Make prediction
        score = ml_server.predict(queries)
        
        # Force garbage collection after prediction
        gc.collect()
        
        logger.info(f"Prediction result: {score}")
        if score < 0:
            logger.warning(f"SQL Injection detected in queries: {queries}")
            logger.info("Returning score=-1, status=403")
            return "-1", 403  # Return score and 403 for SQL injection
        logger.info("Returning score=1, status=200")
        return "1", 200  # Return score and 200 for safe queries
        
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}", exc_info=True)
        return "1", 200  # Fail open on error

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Basic model validation
        test_prediction = ml_server.predict(["SELECT * FROM users"])
        memory_usage = psutil.Process(pid).memory_info().rss / 1024 / 1024  # MB
        return jsonify({
            "status": "healthy",
            "model_loaded": ml_server.model is not None,
            "memory_usage_mb": f"{memory_usage:.2f}"
        })
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

@app.route('/', methods=['POST', 'GET'])
@limiter.limit("200/minute")
def query_ml():
    if request.method == 'POST':
        try:
            # Log raw request data
            logger.debug("Raw request data:")
            logger.debug(f"Headers: {dict(request.headers)}")
            logger.debug(f"Form: {request.form}")
            logger.debug(f"JSON: {request.get_json(silent=True)}")
            
            # Handle both form data and JSON
            if request.is_json:
                data = request.get_json()
                logger.info("Received JSON request")
            else:
                data = request.form
                logger.info("Received form data request")
                
            # Convert data to expected format
            form_data = {
                'method': data.get('method', ''),
                'path': data.get('path', ''),
                'args': data.get('args', '{}') if isinstance(data.get('args'), str) else json.dumps(data.get('args', {})),
                'hour': data.get('hour', 0),
                'day': data.get('day', 0)
            }
            
            logger.info(f"Processed request data: {json.dumps(form_data, indent=2)}")
            
            future = executor.submit(process_request, form_data)
            score, status_code = future.result(timeout=MODEL_TIMEOUT)
            logger.info(f"Returning response - Score: {score}, Status: {status_code}")
            
            # Ensure score is string and status is int
            return str(score), int(status_code)
            
        except TimeoutError:
            logger.warning("Request timed out")
            return "1", 200  # Fail open on timeout
        except Exception as e:
            logger.error(f"Error in query_ml: {str(e)}", exc_info=True)
            return "1", 200  # Fail open on error
    elif request.method == 'GET':
        return "Service is up", 200
    return "Bad Request", 400

def cleanup(signum, frame):
    """Cleanup handler for graceful shutdown"""
    logger.info("Shutting down ML server...")
    executor.shutdown(wait=False)
    os._exit(0)

if __name__ == '__main__':
    # Register signal handlers
    signal.signal(signal.SIGTERM, cleanup)
    signal.signal(signal.SIGINT, cleanup)
    
    # Log initial memory usage
    memory_use = psutil.Process(pid).memory_info().rss
    logger.info(f'Initial RAM usage: {memory_use / 1024 / 1024:.2f} MB')
    
    # Run the Flask app
    app.run(host='0.0.0.0', port=5000, threaded=True)
