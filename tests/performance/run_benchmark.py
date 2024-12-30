#!/usr/bin/env python3
import requests
import time
import statistics
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

class ModSecurityBenchmark:
    def __init__(self):
        self.base_url = "http://localhost"  # Sesuaikan dengan URL target
        self.results = {
            "rules": {"response_times": [], "detection_rate": 0, "false_positives": 0},
            "ml": {"response_times": [], "detection_rate": 0, "false_positives": 0}
        }
        
    def load_test_cases(self):
        """Load test cases dari file JSON"""
        with open("test_cases.json", "r") as f:
            return json.load(f)

    def single_request(self, url, payload, headers=None):
        """Melakukan single request dan mengukur waktu respons"""
        try:
            start_time = time.time()
            response = requests.post(url, data=payload, headers=headers)
            end_time = time.time()
            return {
                "response_time": end_time - start_time,
                "status_code": response.status_code,
                "blocked": response.status_code == 403
            }
        except Exception as e:
            print(f"Error in request: {e}")
            return None

    def run_test_batch(self, test_type, test_cases, concurrency=10):
        """Run batch of tests with specified concurrency"""
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = []
            for test_case in test_cases:
                payload = test_case["payload"]
                headers = test_case.get("headers", {})
                is_attack = test_case["is_attack"]
                
                future = executor.submit(
                    self.single_request, 
                    self.base_url, 
                    payload,
                    headers
                )
                futures.append((future, is_attack))

            for future, is_attack in futures:
                result = future.result()
                if result:
                    self.results[test_type]["response_times"].append(result["response_time"])
                    
                    # Update detection metrics
                    if is_attack and result["blocked"]:
                        self.results[test_type]["detection_rate"] += 1
                    elif not is_attack and result["blocked"]:
                        self.results[test_type]["false_positives"] += 1

    def generate_report(self):
        """Generate detailed performance report"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "metrics": {}
        }

        for test_type in ["rules", "ml"]:
            response_times = self.results[test_type]["response_times"]
            total_requests = len(response_times)
            
            if total_requests > 0:
                report["metrics"][test_type] = {
                    "avg_response_time": statistics.mean(response_times),
                    "median_response_time": statistics.median(response_times),
                    "min_response_time": min(response_times),
                    "max_response_time": max(response_times),
                    "detection_rate": (self.results[test_type]["detection_rate"] / total_requests) * 100,
                    "false_positive_rate": (self.results[test_type]["false_positives"] / total_requests) * 100
                }

        # Save report
        with open(f"benchmark_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", "w") as f:
            json.dump(report, f, indent=4)

        return report

    def run_benchmark(self):
        """Run complete benchmark suite"""
        print("Starting ModSecurity Benchmark...")
        
        # Load test cases
        test_cases = self.load_test_cases()
        
        # Run tests for traditional rules
        print("Testing Traditional Rules...")
        self.run_test_batch("rules", test_cases["rules_test_cases"])
        
        # Run tests for ML-based detection
        print("Testing ML-based Detection...")
        self.run_test_batch("ml", test_cases["ml_test_cases"])
        
        # Generate and print report
        report = self.generate_report()
        print("\nBenchmark Results:")
        print(json.dumps(report, indent=4))

if __name__ == "__main__":
    benchmark = ModSecurityBenchmark()
    benchmark.run_benchmark()
