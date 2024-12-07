import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.feature_extraction.text import TfidfVectorizer
from datetime import datetime
import os
import joblib
import gc
import csv
from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler
from imblearn.pipeline import Pipeline as ImbPipeline
import itertools
import json
import time
from tqdm.auto import tqdm
import matplotlib.pyplot as plt
import seaborn as sns
import random
import re
import pickle
from sklearn.metrics import classification_report, confusion_matrix

class SQLInjectionDetector:
    def __init__(self, model_params=None):
        """
        Initialize detector with custom model parameters and versioning
        """
        self.model_params = model_params if model_params else {
            'n_estimators': 200,
            'max_depth': 15,
            'min_samples_split': 10,
            'class_weight': 'balanced',
            'random_state': 42
        }
        self.model = None
        self.vectorizer = None
        self.model_version = None
        self.last_reload_time = None
        self.reload_interval = 3600  # Reload model every hour
        self._load_or_create_model()
        
    def _load_or_create_model(self):
        """
        Load existing model or create new one with versioning
        """
        model_path = 'sql_injection_detector.pkl'
        vectorizer_path = 'vectorizer.pkl'
        version_path = 'model_version.txt'
        
        try:
            # Check if model exists and is recent
            if (os.path.exists(model_path) and 
                os.path.exists(vectorizer_path) and 
                os.path.exists(version_path)):
                
                # Load version info
                with open(version_path, 'r') as f:
                    saved_version = f.read().strip()
                
                # Load model and vectorizer
                with open(model_path, 'rb') as f:
                    self.model = pickle.load(f)
                with open(vectorizer_path, 'rb') as f:
                    self.vectorizer = pickle.load(f)
                
                self.model_version = saved_version
                self.last_reload_time = datetime.now()
                print(f"Loaded model version: {saved_version}")
            else:
                # Initialize new model
                self.model = RandomForestClassifier(**self.model_params)
                self.vectorizer = TfidfVectorizer(max_features=5000)
                self.model_version = datetime.now().strftime("%Y%m%d_%H%M%S")
                print("Initialized new model")
        except Exception as e:
            print(f"Error loading model: {str(e)}")
            # Fallback to new model
            self.model = RandomForestClassifier(**self.model_params)
            self.vectorizer = TfidfVectorizer(max_features=5000)
            self.model_version = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def save_model(self):
        """
        Save model with version information
        """
        try:
            # Save model and vectorizer
            with open('sql_injection_detector.pkl', 'wb') as f:
                pickle.dump(self.model, f)
            with open('vectorizer.pkl', 'wb') as f:
                pickle.dump(self.vectorizer, f)
            
            # Save version info
            with open('model_version.txt', 'w') as f:
                f.write(self.model_version)
            
            print(f"Saved model version: {self.model_version}")
        except Exception as e:
            print(f"Error saving model: {str(e)}")
    
    def check_reload_model(self):
        """
        Check if model needs reloading
        """
        if (self.last_reload_time and 
            (datetime.now() - self.last_reload_time).total_seconds() > self.reload_interval):
            self._load_or_create_model()
            
    def extract_sql_features(self, query):
        """
        Ekstrak fitur spesifik untuk SQL Injection detection
        """
        features = {
            # Basic features
            'query_length': len(query),
            'word_count': len(query.split()),
            
            # Character-based features
            'special_char_count': sum(not c.isalnum() for c in query),
            'digit_count': sum(c.isdigit() for c in query),
            'uppercase_count': sum(c.isupper() for c in query),
            
            # SQL-specific features
            'dangerous_keywords': sum(keyword in query.upper() for keyword in [
                'UNION', 'SELECT', 'DROP', 'DELETE', 'UPDATE', 'INSERT',
                'EXEC', 'EXECUTE', 'DECLARE', 'CAST', 'CONVERT'
            ]),
            
            # Injection patterns
            'has_comment': int('--' in query or '/*' in query),
            'has_multiple_queries': int(';' in query),
            'has_union': int('UNION' in query.upper()),
            'has_or_true': int('OR' in query.upper() and ('1=1' in query or 'TRUE' in query.upper())),
            
            # String manipulation
            'single_quote_count': query.count("'"),
            'double_quote_count': query.count('"'),
            'parenthesis_balance': query.count('(') - query.count(')'),
            'semicolon_count': query.count(';'),
            
            # Advanced patterns
            'has_hex_encoding': int('0x' in query.lower()),
            'has_url_encoding': int('%20' in query or '%27' in query),
            'has_escape_chars': int('\\' in query),
            'has_batch_separator': int('GO' in query.upper() or ';' in query),
            
            # Function-based
            'has_sql_functions': sum(func in query.upper() for func in [
                'CONCAT', 'CHAR', 'SUBSTRING', 'ASCII', 'BENCHMARK', 'SLEEP'
            ])
        }
        return features

    def prepare_data(self, queries, labels=None):
        """
        Prepare data untuk training atau prediksi
        """
        # Extract manual features
        feature_list = [self.extract_sql_features(query) for query in queries]
        X_features = pd.DataFrame(feature_list)
        
        # Text vectorization
        X_text = self.vectorizer.fit_transform(queries).toarray()
        X_text_df = pd.DataFrame(X_text, columns=[f'token_{i}' for i in range(X_text.shape[1])])
        
        # Combine features
        X = pd.concat([X_features, X_text_df], axis=1)
        
        return X

    def train(self, X_train, y_train):
        """
        Train model dengan data yang sudah dipreprocess
        """
        self.model.fit(X_train, y_train)
        
    def predict(self, X):
        """
        Prediksi dengan probabilitas
        """
        return self.model.predict_proba(X)

    def evaluate(self, X_test, y_test, output_dir='results'):
        """
        Evaluasi model dan generate visualisasi
        """
        os.makedirs(output_dir, exist_ok=True)
        
        # Predictions
        y_pred = self.model.predict(X_test)
        
        # Classification report
        report = classification_report(y_test, y_pred)
        with open(os.path.join(output_dir, 'classification_report.txt'), 'w') as f:
            f.write("SQL Injection Detection Model Report\n")
            f.write("====================================\n\n")
            f.write(report)
        
        # Confusion Matrix
        cm = confusion_matrix(y_test, y_pred)
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
        plt.title('Confusion Matrix')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.savefig(os.path.join(output_dir, 'confusion_matrix.png'))
        plt.close()
        
        # Feature Importance
        feature_importance = pd.DataFrame({
            'feature': X_test.columns,
            'importance': self.model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        plt.figure(figsize=(12, 6))
        plt.bar(range(10), feature_importance['importance'][:10])
        plt.xticks(range(10), feature_importance['feature'][:10], rotation=45)
        plt.title('Top 10 Feature Importance')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'feature_importance.png'))
        plt.close()
        
        return report, cm, feature_importance

    def test_parameters(self, X_train, X_test, y_train, y_test, models_dir='models', results_dir='results'):
        """
        Test different parameter combinations and save each model
        """
        # Parameter grid yang lebih kecil untuk mengurangi beban komputasi
        param_grid = {
            'n_estimators': [100, 200, 300],  # Mengurangi jumlah opsi
            'max_depth': [10, 15, None],      # Mengurangi jumlah opsi
            'min_samples_split': [2, 10, 20], # Mengurangi jumlah opsi
            'class_weight': ['balanced']  # Hanya menggunakan balanced weight
        }
        
        # Create directories
        for dir_path in [models_dir, results_dir]:
            os.makedirs(dir_path, exist_ok=True)
        
        results = []
        best_accuracy = 0
        best_model = None
        
        # Test each parameter individually
        for param_name, param_values in param_grid.items():
            print(f"\nTesting {param_name}:")
            
            for value in param_values:
                # Base parameters
                params = {
                    'n_estimators': 200,
                    'max_depth': 15,
                    'min_samples_split': 10,
                    'class_weight': 'balanced',
                    'random_state': 42
                }
                
                # Update tested parameter
                params[param_name] = value
                
                max_retries = 3
                retry_count = 0
                success = False
                
                while not success and retry_count < max_retries:
                    try:
                        # Train model
                        start_time = time.time()
                        model = RandomForestClassifier(**params)
                        model.fit(X_train, y_train)
                        train_time = time.time() - start_time
                        
                        # Evaluate
                        y_pred = model.predict(X_test)
                        accuracy = accuracy_score(y_test, y_pred)
                        f1 = f1_score(y_test, y_pred)
                        
                        print(f"{param_name}={value}:")
                        print(f"Accuracy={accuracy:.4f}, F1={f1:.4f}")
                        print(f"Training Time={train_time:.2f}s")
                        
                        # Save results
                        results.append({
                            'parameter': param_name,
                            'value': value,
                            'accuracy': accuracy,
                            'f1_score': f1,
                            'train_time': train_time
                        })
                        
                        # Save model if best so far
                        if accuracy > best_accuracy:
                            best_accuracy = accuracy
                            best_model = {
                                'model': model,
                                'params': params.copy(),
                                'accuracy': accuracy,
                                'f1_score': f1
                            }
                        
                        success = True
                        
                    except Exception as e:
                        retry_count += 1
                        print(f"Error during training (attempt {retry_count}/{max_retries}): {str(e)}")
                        if retry_count < max_retries:
                            print("Retrying after 60 seconds...")
                            time.sleep(60)  # Wait before retry
                        else:
                            print("Max retries reached, skipping this parameter combination")
                            break
                
                # Clear memory
                gc.collect()
        
        # Save best model
        if best_model:
            model_path = os.path.join(models_dir, 'best_model.pkl')
            joblib.dump(best_model['model'], model_path)
            
            # Save best model info
            info_path = os.path.join(results_dir, 'best_model_info.txt')
            with open(info_path, 'w') as f:
                f.write("Best Model Parameters:\n")
                for param, value in best_model['params'].items():
                    f.write(f"{param}: {value}\n")
                f.write(f"\nAccuracy: {best_model['accuracy']:.4f}")
                f.write(f"\nF1 Score: {best_model['f1_score']:.4f}")
        
        # Convert results to DataFrame
        results_df = pd.DataFrame(results)
        results_df.to_csv(os.path.join(results_dir, 'parameter_results.csv'), index=False)
        
        return results_df, best_model

def train_model(X_train, y_train, params=None):
    """Train model with progress tracking"""
    if params is None:
        params = {
            'n_estimators': 200,
            'max_depth': 15,
            'min_samples_split': 2,
            'class_weight': 'balanced',
            'random_state': 42
        }
    
    try:
        print("\n=== Training Progress ===")
        total_steps = 4
        current_step = 0
        
        # Step 1: Prepare sampling pipeline
        current_step += 1
        print(f"\nStep {current_step}/{total_steps}: Preparing sampling pipeline...")
        sampling_pipeline = ImbPipeline([
            ('smote', SMOTE(random_state=42, sampling_strategy=0.8)),
            ('rus', RandomUnderSampler(random_state=42, sampling_strategy=0.9))
        ])
        
        # Step 2: Apply sampling
        current_step += 1
        print(f"\nStep {current_step}/{total_steps}: Applying data resampling...")
        start_time = time.time()
        X_resampled, y_resampled = sampling_pipeline.fit_resample(X_train, y_train)
        print(f"✓ Resampling completed in {time.time() - start_time:.2f} seconds")
        print(f"✓ Resampled data shape: {X_resampled.shape}")
        
        # Step 3: Initialize model
        current_step += 1
        print(f"\nStep {current_step}/{total_steps}: Initializing Random Forest model...")
        model = RandomForestClassifier(**params)
        print("✓ Model initialized with parameters:")
        for param, value in params.items():
            print(f"  - {param}: {value}")
        
        # Step 4: Train model
        current_step += 1
        print(f"\nStep {current_step}/{total_steps}: Training model...")
        start_time = time.time()
        model.fit(X_resampled, y_resampled)
        training_time = time.time() - start_time
        print(f"✓ Training completed in {training_time:.2f} seconds")
        
        # Quick evaluation
        train_pred = model.predict(X_resampled)
        train_accuracy = accuracy_score(y_resampled, train_pred)
        print(f"\nInitial Training Accuracy: {train_accuracy:.4f}")
        
        return model
        
    except Exception as e:
        print(f"\n❌ Error in model training: {str(e)}")
        return None

def test_parameters(X_train, y_train, X_test, y_test, param_grid=None):
    """Test different model parameters with advanced sampling and progress tracking"""
    if param_grid is None:
        param_grid = {
            'n_estimators': [100, 200, 300],
            'max_depth': [10, 15, None],
            'min_samples_split': [2, 10, 20],
            'class_weight': ['balanced']  # Hanya menggunakan balanced weight
        }
    
    best_score = 0
    best_params = None
    best_model = None
    results = []
    
    try:
        # Generate parameter combinations
        param_combinations = [dict(zip(param_grid.keys(), v)) 
                            for v in itertools.product(*param_grid.values())]
        total_combinations = len(param_combinations)
        
        print(f"\nTesting {total_combinations} parameter combinations:")
        for param_name, param_values in param_grid.items():
            print(f"{param_name}: {param_values}")
        
        for i, params in enumerate(param_combinations, 1):
            try:
                print(f"\nTesting combination {i}/{total_combinations}")
                print(f"Parameters: {params}")
                
                # Train model with current parameters
                start_time = time.time()
                model = RandomForestClassifier(**params, random_state=42)
                model.fit(X_train, y_train)
                training_time = time.time() - start_time
                
                # Evaluate
                y_pred = model.predict(X_test)
                accuracy = accuracy_score(y_test, y_pred)
                f1 = f1_score(y_test, y_pred)
                
                result = {
                    'params': str(params),
                    'accuracy': accuracy,
                    'f1_score': f1,
                    'training_time': training_time
                }
                results.append(result)
                
                print(f"F1 Score: {f1:.4f}")
                print(f"Accuracy: {accuracy:.4f}")
                print(f"Training Time: {training_time:.2f}s")
                
                # Update best model if better f1 score
                if f1 > best_score:
                    best_score = f1
                    best_params = params.copy()
                    best_model = model
                    print(f"New best model found!")
                
                # Clear memory
                gc.collect()
                
            except Exception as e:
                print(f"\nError testing parameters {params}: {str(e)}")
                continue
        
        # Save results
        results_df = pd.DataFrame(results)
        
        if len(results) > 0:
            print("\nParameter testing completed!")
            print("\nTop 5 best performing parameter combinations:")
            top_results = results_df.nlargest(5, 'f1_score')
            print(top_results[['params', 'f1_score', 'accuracy', 'training_time']].to_string())
            
            print("\nBest parameters found:")
            print(f"Parameters: {best_params}")
            print(f"Best F1 Score: {best_score:.4f}")
        
        return best_model, best_params, results_df
        
    except Exception as e:
        print(f"Error in parameter testing: {str(e)}")
        return None, None, None

def generate_normal_queries():
    """Generate contoh query SQL normal"""
    templates = [
        # Basic CRUD
        "SELECT * FROM {table} WHERE {column} = {value}",
        "INSERT INTO {table} ({columns}) VALUES ({values})",
        "UPDATE {table} SET {column} = {value} WHERE {condition}",
        "DELETE FROM {table} WHERE {condition}",
        
        # Joins
        "SELECT {columns} FROM {table1} {join_type} JOIN {table2} ON {condition}",
        "SELECT {columns} FROM {table1} t1 JOIN {table2} t2 ON {condition}",
        
        # Aggregations
        "SELECT {column}, COUNT(*) FROM {table} GROUP BY {column}",
        "SELECT {column}, {agg_func}({agg_column}) FROM {table} GROUP BY {column}",
        
        # Subqueries
        "SELECT * FROM {table} WHERE {column} > (SELECT {agg_func}({column}) FROM {table})",
        "SELECT * FROM {table} WHERE {column} IN (SELECT {column} FROM {table2})",
        
        # Parameterized queries
        "SELECT * FROM {table} WHERE {column} = ?",
        "INSERT INTO {table} ({columns}) VALUES ({placeholders})",
        
        # Complex conditions
        "SELECT * FROM {table} WHERE {condition1} AND {condition2}",
        "SELECT * FROM {table} WHERE {column} IN ({values})",
        
        # Date operations
        "SELECT * FROM {table} WHERE {date_column} >= {date}",
        "SELECT DATE({date_column}) as date, COUNT(*) FROM {table} GROUP BY date",
        
        # HAVING clause
        "SELECT {column}, COUNT(*) FROM {table} GROUP BY {column} HAVING COUNT(*) > {value}",
        "SELECT {column}, {agg_func}({agg_column}) FROM {table} GROUP BY {column} HAVING {agg_func}({agg_column}) > {value}",
        
        # ORDER BY and LIMIT
        "SELECT * FROM {table} ORDER BY {column} {direction} LIMIT {limit}",
        "SELECT {columns} FROM {table} ORDER BY {order_columns} LIMIT {offset}, {limit}"
    ]
    
    tables = ['users', 'orders', 'products', 'categories', 'customers', 'employees', 'inventory', 'logs', 'transactions']
    columns = ['id', 'name', 'email', 'status', 'created_at', 'updated_at', 'price', 'quantity', 'category_id', 'user_id']
    values = ["1", "'active'", "'pending'", "'john@email.com'", "100", "'2023-01-01'", "CURRENT_TIMESTAMP", "NULL"]
    agg_funcs = ['COUNT', 'SUM', 'AVG', 'MAX', 'MIN']
    join_types = ['INNER', 'LEFT', 'RIGHT']
    directions = ['ASC', 'DESC']
    
    queries = []
    
    # Generate queries from templates
    for template in templates:
        for _ in range(5):  # Generate 5 variations of each template
            query = template
            
            # Replace placeholders with random values
            if '{table}' in query:
                query = query.replace('{table}', random.choice(tables))
            if '{table1}' in query:
                query = query.replace('{table1}', random.choice(tables))
            if '{table2}' in query:
                query = query.replace('{table2}', random.choice(tables))
            if '{column}' in query:
                query = query.replace('{column}', random.choice(columns))
            if '{columns}' in query:
                cols = random.sample(columns, random.randint(1, 3))
                query = query.replace('{columns}', ', '.join(cols))
            if '{value}' in query:
                query = query.replace('{value}', random.choice(values))
            if '{values}' in query:
                vals = random.sample(values, random.randint(1, 3))
                query = query.replace('{values}', ', '.join(vals))
            if '{condition}' in query:
                col = random.choice(columns)
                val = random.choice(values)
                query = query.replace('{condition}', f"{col} = {val}")
            if '{agg_func}' in query:
                query = query.replace('{agg_func}', random.choice(agg_funcs))
            if '{agg_column}' in query:
                query = query.replace('{agg_column}', random.choice(columns))
            if '{join_type}' in query:
                query = query.replace('{join_type}', random.choice(join_types))
            if '{direction}' in query:
                query = query.replace('{direction}', random.choice(directions))
            if '{limit}' in query:
                query = query.replace('{limit}', str(random.randint(1, 100)))
            if '{offset}' in query:
                query = query.replace('{offset}', str(random.randint(0, 50)))
            if '{placeholders}' in query:
                num_placeholders = random.randint(1, 3)
                query = query.replace('{placeholders}', ', '.join(['?' * num_placeholders]))
            if '{date_column}' in query:
                query = query.replace('{date_column}', random.choice(['created_at', 'updated_at', 'order_date', 'timestamp']))
            if '{date}' in query:
                query = query.replace('{date}', "'2023-01-01'")
            if '{condition1}' in query:
                col = random.choice(columns)
                val = random.choice(values)
                query = query.replace('{condition1}', f"{col} = {val}")
            if '{condition2}' in query:
                col = random.choice(columns)
                val = random.choice(values)
                query = query.replace('{condition2}', f"{col} = {val}")
            if '{order_columns}' in query:
                cols = random.sample(columns, random.randint(1, 2))
                directions = random.choices(['ASC', 'DESC'], k=len(cols))
                order_by = [f"{col} {dir}" for col, dir in zip(cols, directions)]
                query = query.replace('{order_columns}', ', '.join(order_by))
            
            queries.append(query)
    
    return queries

def load_dataset(file_path):
    """Load dataset from CSV file with error handling for different formats"""
    try:
        # Try different encodings and delimiters
        encodings = ['utf-8', 'utf-16', 'utf-16le', 'utf-16be', 'latin1', 'cp1252', 'iso-8859-1']
        delimiters = [',', ';', '\t']
        df = None
        
        # First try to detect encoding
        try:
            with open(file_path, 'rb') as f:
                raw = f.read()
                if raw.startswith(b'\xff\xfe') or raw.startswith(b'\xfe\xff'):
                    # UTF-16 detected, try both little and big endian
                    for enc in ['utf-16', 'utf-16le', 'utf-16be']:
                        try:
                            df = pd.read_csv(file_path, 
                                          encoding=enc,
                                          delimiter=',',
                                          quoting=csv.QUOTE_ALL,
                                          escapechar='\\',
                                          on_bad_lines='skip',
                                          dtype=str)
                            if len(df.columns) >= 2:
                                break
                        except:
                            continue
                    if df is not None and len(df.columns) >= 2:
                        print(f"Successfully loaded {file_path} with {enc} encoding")
        except:
            pass
            
        # If UTF-16 detection failed, try other encodings
        if df is None:
            for encoding in encodings:
                for delimiter in delimiters:
                    try:
                        df = pd.read_csv(file_path, 
                                       encoding=encoding,
                                       delimiter=delimiter,
                                       quoting=csv.QUOTE_ALL,
                                       escapechar='\\',
                                       on_bad_lines='skip',
                                       dtype=str)
                        if len(df.columns) >= 2:
                            print(f"Successfully loaded {file_path} with {encoding} encoding and '{delimiter}' delimiter")
                            break
                    except Exception:
                        continue
                if df is not None and len(df.columns) >= 2:
                    break
        
        if df is None or len(df.columns) < 2:
            print(f"Error: Could not read {file_path} with any supported format")
            return None
            
        # Clean column names
        df.columns = df.columns.str.strip().str.lower()
        
        # Remove any BOM markers from column names
        df.columns = df.columns.str.replace('ÿþ', '').str.replace('þÿ', '')
        
        # Try to identify query and label columns
        query_col = None
        label_col = None
        
        # Common names for query column
        query_columns = ['query', 'sentence', 'text', 'sql', 's']
        for col in df.columns:
            if col in query_columns or 'query' in col.lower() or 'sql' in col.lower():
                query_col = col
                break
        
        # Common names for label column
        label_columns = ['label', 'class', 'is_sqli', 'injection']
        for col in df.columns:
            if col in label_columns or 'label' in col.lower() or 'class' in col.lower():
                label_col = col
                break
        
        # If columns not found, try to infer from content and position
        if query_col is None or label_col is None:
            # Check if we have exactly 2 columns
            if len(df.columns) == 2:
                # Assume first column is query and second is label
                cols = list(df.columns)
                query_col = cols[0]
                label_col = cols[1]
            else:
                # Try to find by content
                for col in df.columns:
                    if df[col].str.len().mean() > 20:  # Likely contains SQL queries
                        query_col = col
                        break
                
                # Try to find label column
                for col in reversed(df.columns):
                    if col != query_col:  # Skip query column
                        try:
                            # Try converting to numeric
                            values = pd.to_numeric(df[col].str.strip().str.extract('(\d+)', expand=False).fillna('0'))
                            if values.isin([0, 1]).all() or values.nunique() <= 10:
                                label_col = col
                                break
                        except:
                            continue
        
        if query_col is None or label_col is None:
            print(f"Error: Could not identify query and label columns in {file_path}")
            print(f"Columns found: {list(df.columns)}")
            return None
        
        # Create standardized DataFrame
        standardized_df = pd.DataFrame({
            'Sentence': df[query_col].astype(str).str.strip(),
            'Label': df[label_col]
        })
        
        # Clean and convert label to int
        # First try to extract numbers
        standardized_df['Label'] = standardized_df['Label'].str.extract('(\d+)', expand=False).fillna('0')
        # Convert to int and standardize non-zero values to 1
        standardized_df['Label'] = standardized_df['Label'].astype(int)
        standardized_df.loc[standardized_df['Label'] > 0, 'Label'] = 1
        
        # Remove empty queries and duplicates
        standardized_df = standardized_df[standardized_df['Sentence'].str.len() > 0].copy()
        standardized_df = standardized_df.drop_duplicates(subset=['Sentence'], keep='first')
        
        # Basic dataset info
        print(f"Loaded {len(standardized_df)} samples from {os.path.basename(file_path)}")
        print("Label distribution:")
        print(standardized_df['Label'].value_counts())
        
        return standardized_df
        
    except Exception as e:
        print(f"Error loading {file_path}: {str(e)}")
        return None

def save_progress(message, log_file='training_progress.log'):
    """Save progress message to log file with timestamp"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(log_file, 'a', encoding='utf-8') as f:
        f.write(f'[{timestamp}] {message}\n')
    print(message)

def train_model(X_train, y_train, params=None):
    """Train model with progress logging"""
    if params is None:
        params = {
            'n_estimators': 200,
            'max_depth': 15,
            'min_samples_split': 2,
            'class_weight': 'balanced',
            'random_state': 42
        }
    
    try:
        save_progress("\n=== Starting Model Training ===")
        
        # Step 1: Prepare sampling pipeline
        save_progress("Step 1/4: Preparing sampling pipeline")
        sampling_pipeline = ImbPipeline([
            ('smote', SMOTE(random_state=42, sampling_strategy=0.8)),
            ('rus', RandomUnderSampler(random_state=42, sampling_strategy=0.9))
        ])
        
        # Step 2: Apply sampling
        save_progress("Step 2/4: Applying data resampling")
        start_time = time.time()
        X_resampled, y_resampled = sampling_pipeline.fit_resample(X_train, y_train)
        save_progress(f"✓ Resampling completed in {time.time() - start_time:.2f} seconds")
        save_progress(f"✓ Resampled data shape: {X_resampled.shape}")
        
        # Step 3: Initialize model
        save_progress("Step 3/4: Initializing Random Forest model")
        model = RandomForestClassifier(**params)
        param_str = "\n".join([f"  - {k}: {v}" for k, v in params.items()])
        save_progress(f"Model parameters:\n{param_str}")
        
        # Step 4: Train model
        save_progress("Step 4/4: Training model")
        start_time = time.time()
        model.fit(X_resampled, y_resampled)
        training_time = time.time() - start_time
        save_progress(f"✓ Training completed in {training_time:.2f} seconds")
        
        # Evaluate training results
        train_pred = model.predict(X_resampled)
        train_accuracy = accuracy_score(y_resampled, train_pred)
        save_progress(f"Training Accuracy: {train_accuracy:.4f}")
        save_progress("=== Training Complete ===\n")
        
        return model
        
    except Exception as e:
        save_progress(f"❌ Error in model training: {str(e)}")
        return None

def main():
    log_file = f'training_progress_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
    save_progress("=== SQL Injection Detection Model Training ===", log_file)
    
    try:
        start_time = time.time()
        
        # Step 1: Load Datasets
        save_progress("Step 1/6: Loading Datasets", log_file)
        datasets = []
        dataset_files = ['sqli.csv', 'sqliv2.csv', 'sqliv3.csv', 'sqliv4.csv']
        
        for file in dataset_files:
            file_path = os.path.join('archive', file)
            save_progress(f"Loading {file}...", log_file)
            dataset = load_dataset(file_path)
            if dataset is not None:
                datasets.append(dataset)
                save_progress(f"✓ Successfully loaded {file}", log_file)
            else:
                save_progress(f"⚠ Failed to load {file}", log_file)
        
        if not datasets:
            raise Exception("No valid datasets loaded")
        
        # Step 2: Preprocess Data
        save_progress("Step 2/6: Preprocessing Data", log_file)
        combined_data = pd.concat(datasets, ignore_index=True)
        X = combined_data['Sentence']
        y = combined_data['Label']
        save_progress(f"Total samples: {len(X)}", log_file)
        save_progress(f"Label distribution:\n{y.value_counts(normalize=True)}", log_file)
        
        # Step 3: Vectorize Text
        save_progress("Step 3/6: Vectorizing Text", log_file)
        start_time_vec = time.time()
        vectorizer = TfidfVectorizer(max_features=5000)
        X_vectorized = vectorizer.fit_transform(X)
        save_progress(f"✓ Vectorization completed in {time.time() - start_time_vec:.2f} seconds", log_file)
        save_progress(f"✓ Features shape: {X_vectorized.shape}", log_file)
        
        # Step 4: Split Dataset
        save_progress("Step 4/6: Splitting Dataset", log_file)
        X_train, X_test, y_train, y_test = train_test_split(
            X_vectorized, y, test_size=0.2, random_state=42
        )
        save_progress(f"✓ Training set size: {X_train.shape[0]}", log_file)
        save_progress(f"✓ Testing set size: {X_test.shape[0]}", log_file)
        
        # Step 5: Parameter Testing
        save_progress("Step 5/6: Testing Different Parameters", log_file)
        param_grid = {
            'n_estimators': [100, 200, 300],
            'max_depth': [10, 15, None],
            'min_samples_split': [2, 5, 10],
            'class_weight': ['balanced']  # Hanya menggunakan balanced weight
        }
        
        save_progress("\nTesting parameter combinations:", log_file)
        for param, values in param_grid.items():
            save_progress(f"{param}: {values}", log_file)
        
        best_model, best_params, results_df = test_parameters(
            X_train, y_train, X_test, y_test, param_grid
        )
        
        # Step 6: Save Results
        save_progress("Step 6/6: Saving Final Results", log_file)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_dir = f'model_testing/{timestamp}'
        os.makedirs(output_dir, exist_ok=True)
        
        # Save vectorizer
        vectorizer_path = os.path.join(output_dir, 'vectorizer.joblib')
        joblib.dump(vectorizer, vectorizer_path)
        save_progress(f"✓ Saved vectorizer to: {vectorizer_path}", log_file)
        
        if best_model is not None:
            # Save best model
            model_path = os.path.join(output_dir, 'best_model.joblib')
            joblib.dump(best_model, model_path)
            
            # Save parameter testing results
            results_path = os.path.join(output_dir, 'parameter_results.csv')
            results_df.to_csv(results_path, index=False)
            
            save_progress("\nParameter Testing Results:", log_file)
            save_progress("\nTop 5 Best Performing Models:", log_file)
            top_results = results_df.nlargest(5, 'f1_score')
            save_progress(str(top_results[['params', 'f1_score', 'accuracy', 'training_time']]), log_file)
            
            save_progress("\nBest Model Performance:", log_file)
            save_progress(f"✓ Parameters: {best_params}", log_file)
            save_progress(f"✓ F1 Score: {results_df['f1_score'].max():.4f}", log_file)
            save_progress(f"✓ Accuracy: {results_df.loc[results_df['f1_score'].idxmax(), 'accuracy']:.4f}", log_file)
            save_progress(f"✓ Model saved to: {model_path}", log_file)
            save_progress(f"✓ Results saved to: {results_path}", log_file)
        
        total_time = time.time() - start_time
        save_progress(f"\n✓ Total execution time: {total_time:.2f} seconds", log_file)
        save_progress("=== Training Complete ===", log_file)
        
    except Exception as e:
        save_progress(f"❌ Error in main execution: {str(e)}", log_file)

if __name__ == "__main__":
    main()
