import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.feature_extraction.text import CountVectorizer
import matplotlib.pyplot as plt
import seaborn as sns
import os
import pickle
from datetime import datetime
import random
import re

class SQLInjectionDetector:
    def __init__(self, model_params=None):
        """
        Inisialisasi detector dengan parameter model yang bisa dikustomisasi
        """
        self.model_params = model_params if model_params else {
            'n_estimators': 200,        # Jumlah trees
            'max_depth': 15,            # Kedalaman maksimum
            'min_samples_split': 10,    # Minimum samples untuk split
            'class_weight': 'balanced', # Handle imbalanced classes
            'random_state': 42
        }
        self.model = RandomForestClassifier(**self.model_params)
        self.vectorizer = CountVectorizer(max_features=100, stop_words='english')
        
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
    """Load dataset dengan format khusus"""
    try:
        queries = []
        labels = []
        
        # Coba berbagai encoding
        encodings = ['utf-8', 'utf-16', 'latin1']
        content = None
        
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    content = f.readlines()
                break
            except UnicodeError:
                continue
        
        if not content:
            print(f"Could not read {file_path} with any encoding")
            return None
            
        # Process lines
        for line in content:
            line = line.strip()
            if not line or line.lower().startswith('sentence'):  # Skip header dan baris kosong
                continue
                
            # Cari label (1) di akhir baris
            if line.endswith(",1") or line.endswith(",1,") or line.endswith(",1,,"):
                # Ambil query (semua sebelum ,1 di akhir)
                query = line.rsplit(',1', 1)[0].strip().strip('"')
                if query:  # Pastikan query tidak kosong
                    queries.append(query)
                    labels.append(1)
        
        if not queries:
            print(f"No valid data found in {file_path}")
            return None
            
        # Generate normal queries dengan jumlah yang seimbang
        num_injection_queries = len(queries)
        normal_queries = generate_normal_queries()
        
        # Pastikan jumlah query normal mendekati jumlah query injection
        multiplier = (num_injection_queries // len(normal_queries)) + 1
        balanced_normal_queries = []
        
        for _ in range(multiplier):
            # Tambah variasi untuk setiap query normal
            for query in normal_queries:
                # Query asli
                balanced_normal_queries.append(query)
                
                # Variasi dengan case berbeda
                balanced_normal_queries.append(query.lower())
                
                # Variasi dengan spasi berbeda
                balanced_normal_queries.append(re.sub(r'\s+', ' ', query))
                
                # Variasi dengan nama tabel/kolom berbeda
                for old, new in [
                    ('users', 'accounts'),
                    ('products', 'items'),
                    ('orders', 'transactions')
                ]:
                    if old in query.lower():
                        balanced_normal_queries.append(query.lower().replace(old, new))
        
        # Ambil subset random dari query normal untuk menyeimbangkan dataset
        if len(balanced_normal_queries) > num_injection_queries:
            balanced_normal_queries = random.sample(balanced_normal_queries, num_injection_queries)
        
        # Tambahkan query normal ke dataset
        queries.extend(balanced_normal_queries)
        labels.extend([0] * len(balanced_normal_queries))
        
        # Acak urutan dataset
        combined = list(zip(queries, labels))
        random.shuffle(combined)
        queries, labels = zip(*combined)
        
        # Buat DataFrame
        df = pd.DataFrame({
            'Sentence': queries,
            'Label': labels
        })
        
        print(f"Loaded {len(df)} samples from {os.path.basename(file_path)}")
        print(f"Label distribution:\n{df['Label'].value_counts()}")
        return df
        
    except Exception as e:
        print(f"Error loading {file_path}: {str(e)}")
        return None

def main():
    # Create output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.join('B:/project besar/results', f'analysis_{timestamp}')
    os.makedirs(output_dir, exist_ok=True)
    
    # Load and combine all datasets
    print("Loading datasets...")
    datasets = []
    
    dataset_files = [
        'B:/project besar/archive/sqli.csv',
        'B:/project besar/archive/sqliv2.csv',
        'B:/project besar/archive/sqliv3.csv'
    ]
    
    for file in dataset_files:
        df = load_dataset(file)
        if df is not None:
            datasets.append(df)
    
    if not datasets:
        print("Error: No datasets could be loaded!")
        return
    
    # Combine all datasets
    data = pd.concat(datasets, ignore_index=True)
    print(f"\nTotal combined samples: {len(data)}")
    
    # Split data
    X = data['Sentence']  # Kolom query
    y = data['Label']    # Kolom label
    print(f"\nFeatures shape: {X.shape}")
    print(f"Labels shape: {y.shape}")
    print(f"\nFinal label distribution:\n{y.value_counts()}")
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Initialize detector
    print("\nInitializing detector...")
    detector = SQLInjectionDetector()
    
    # Prepare data
    print("Preparing training data...")
    X_train_prepared = detector.prepare_data(X_train)
    X_test_prepared = detector.prepare_data(X_test)
    
    # Train model
    print("Training model...")
    detector.train(X_train_prepared, y_train)
    
    # Evaluate
    print("Evaluating model...")
    report, cm, feature_importance = detector.evaluate(X_test_prepared, y_test, output_dir)
    
    # Save model
    print("Saving model...")
    with open(os.path.join(output_dir, 'sql_injection_detector.pkl'), 'wb') as f:
        pickle.dump(detector, f)
    
    print(f"\nTraining completed! Results saved in: {output_dir}")
    print("\nClassification Report:")
    print(report)

if __name__ == "__main__":
    main()
