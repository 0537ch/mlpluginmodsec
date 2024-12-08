from sqli import SQLInjectionDetector
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def train_and_save_model():
    try:
        # Initialize detector
        detector = SQLInjectionDetector()
        
        # Train with sample data
        normal_queries = [
            "SELECT * FROM users WHERE id = 1",
            "SELECT name, email FROM customers WHERE country = 'US'",
            "INSERT INTO orders (user_id, product_id) VALUES (1, 2)",
            "UPDATE users SET last_login = NOW() WHERE id = 5",
            "DELETE FROM cart WHERE user_id = 3 AND expired = true"
        ]
        
        malicious_queries = [
            "SELECT * FROM users WHERE id = 1 OR 1=1",
            "SELECT * FROM users WHERE username = '' OR '1'='1'",
            "SELECT * FROM users WHERE id = 1; DROP TABLE users;",
            "1' OR '1' = '1",
            "1' UNION SELECT username, password FROM users--",
            "admin' --",
            "admin' #",
            "' OR 1=1 #",
            "' OR 1=1 --",
            "' OR '1'='1"
        ]
        
        # Prepare training data
        X = normal_queries + malicious_queries
        y = [0] * len(normal_queries) + [1] * len(malicious_queries)
        
        # Train model
        detector.train(X, y)
        
        # Save model
        detector.save_model()
        logger.info("Model trained and saved successfully")
        
    except Exception as e:
        logger.error(f"Error training model: {str(e)}")
        raise

if __name__ == "__main__":
    train_and_save_model()
