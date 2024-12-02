# Importing all the required libraries
from flask import Flask
from flask import request
import pickle
import sklearn
import psutil
import os
import json
from sqli import SQLInjectionDetector

pid = os.getpid()
py = psutil.Process(pid)
memoryUse = py.memory_info().rss
print('RAM INIT: ', memoryUse)

# Model path
pkl_filename = 'sql_injection_detector.pkl'

# Initialize Flask
app = Flask(__name__)

# Load ML model
with open(pkl_filename, 'rb') as file:
    ml_model = pickle.load(file)

@app.route('/', methods=['POST', 'GET'])
def query_ml():
    if request.method == 'POST':
        # Retrieve arguments from the request
        method = request.form['method']
        path = request.form['path']
        args = json.loads(request.form['args'])
        files = request.form['files']
        for k, v in args.items():
            args[k] = v.replace("$#$", '"')
        hour = int(request.form['hour'])
        day = int(request.form['day'])
        print(request.form)

        # Predict a score (1 for normal, -1 for attack)
        score = predict(method, path, args, hour, day)

        # Return the score to the Lua script
        if score > 0:
            return str(score), 200
        return str(score), 401
    elif request.method == 'GET':
        # Simply return 200 on GET / for health checking
        return "Service is up", 200
    return "Bad Request", 400

def predict(method, path, args, hour, day):
    queries = []
    for k, v in args.items():
        queries.append(v)
    
    if not queries:
        return 1
        
    predictions = ml_model.predict(queries)
    return -1 if any(pred == 1 for pred in predictions) else 1

if __name__ == '__main__':
    app.run()
