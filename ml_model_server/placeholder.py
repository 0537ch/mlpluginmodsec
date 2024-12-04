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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
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
            logger.info("Model loaded successfully")
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            raise

    def predict(self, queries):
        try:
            if not queries:
                return 1
            predictions = self.model.predict(queries)
            return -1 if any(pred == 1 for pred in predictions) else 1
        except Exception as e:
            logger.error(f"Prediction error: {str(e)}")
            return 1  # Fail open

# Initialize ML Server
ml_server = MLServer()

def process_request(form_data):
    try:
        method = form_data['method']
        path = form_data['path']
        args = json.loads(form_data['args'])
        hour = int(form_data['hour'])
        day = int(form_data['day'])

        # Clean and prepare args
        queries = []
        for k, v in args.items():
            cleaned_value = v.replace("$#$", '"')
            queries.append(cleaned_value)
            args[k] = cleaned_value

        # Log request details
        logger.info(f"Processing request - Method: {method}, Path: {path}, Args Count: {len(args)}")
        
        # Make prediction
        score = ml_server.predict(queries)
        
        # Force garbage collection after prediction
        gc.collect()
        
        return str(score), 200 if score > 0 else 401
        
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}")
        return "1", 200  # Fail open on error

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Basic model validation
        test_prediction = ml_server.predict(["SELECT * FROM users"])
        return jsonify({
            "status": "healthy",
            "model_loaded": ml_server.model is not None,
            "memory_usage_mb": psutil.Process(pid).memory_info().rss / 1024 / 1024
        })
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

@app.route('/', methods=['POST', 'GET'])
@limiter.limit("200/minute")
def query_ml():
    if request.method == 'POST':
        try:
            future = executor.submit(process_request, request.form)
            result = future.result(timeout=MODEL_TIMEOUT)
            return result
        except TimeoutError:
            logger.warning("Request timed out")
            return "1", 200  # Fail open on timeout
        except Exception as e:
            logger.error(f"Error in query_ml: {str(e)}")
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
