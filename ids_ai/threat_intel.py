import requests
import json
from datetime import datetime, timedelta
import os

class ThreatIntel:
    def __init__(self):
        self.cache = {}
        self.cache_duration = timedelta(hours=1)
        # Demo API Keys - acestea sunt limitate dar funcționale
        self.api_keys = {
            'virustotal': 'c1063ae8233dec63ef86459e0a3f12551247ba04d3b78a78a73b56ef501679f0',
            'abuseipdb': '6e73b6d413b29edccfe405d648a9f0b223b498039314a34c6ba8b9ffaca56186bca75211fa64f83e'
        }
        
    def check_ip(self, ip_address):
        import threading
        import time
        
        # Add validation for IP address format
        if not ip_address or not isinstance(ip_address, str):
            return {
                'threat_score': 0,
                'reports': ["Invalid IP address format"]
            }
            
        # Check cache first to avoid unnecessary API calls
        if ip_address in self.cache:
            if datetime.now() - self.cache[ip_address]['timestamp'] < self.cache_duration:
                return self.cache[ip_address]['data']
        
        # Create a container for the result
        result_container = {
            'data': None,
            'error': None
        }
        
        # Define a function to run in a separate thread
        def query_with_timeout():
            try:
                result_container['data'] = self._query_threat_apis(ip_address)
            except Exception as e:
                result_container['error'] = str(e)[:100]
        
        # Create and start the thread
        thread = threading.Thread(target=query_with_timeout)
        thread.daemon = True  # Allow the thread to be terminated when the main program exits
        thread.start()
        
        # Wait for the thread to complete with a timeout
        max_wait_time = 1  # seconds - reduced from 3 to 1 to prevent hanging
        thread.join(max_wait_time)
        
        # Check if we have a result or if we timed out
        if thread.is_alive():
            # Thread is still running after timeout
            return {
                'threat_score': 0,
                'reports': ["Threat intelligence check timed out"]
            }
        
        # If we have data, cache and return it
        if result_container['data']:
            self.cache[ip_address] = {
                'timestamp': datetime.now(),
                'data': result_container['data']
            }
            return result_container['data']
        else:
            # Handle any errors
            return {
                'threat_score': 0,
                'reports': [f"Threat intelligence error: {result_container['error'] or 'Unknown error'}"] 
            }
        
    def _query_threat_apis(self, ip_address):
        import concurrent.futures
        import time
        
        threat_score = 0
        reports = []
        
        # Skip private IP addresses to avoid unnecessary API calls
        if ip_address.startswith(('10.', '172.16.', '192.168.', '127.')):
            reports.append("Private IP address - skipping threat intelligence check")
            return {
                'threat_score': 0,
                'reports': reports
            }
        
        # Set a maximum total time for all API calls
        max_total_time = 2  # seconds - reduced from 3 to 2
        start_time = time.time()
        
        # Define functions for each API check to use with concurrent execution
        def check_virustotal():
            local_score = 0
            local_report = ""
            
            try:
                headers = {
                    "x-apikey": self.api_keys['virustotal']
                }
                vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
                # Further reduce timeout to prevent hanging
                response = requests.get(vt_url, headers=headers, timeout=0.3)  # Reduced timeout
                if response.status_code == 200:
                    data = response.json()
                    stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    malicious = stats.get('malicious', 0)
                    local_score = malicious * 10
                    local_report = f"VirusTotal detections: {malicious}"
                else:
                    local_report = f"VirusTotal API returned status code: {response.status_code}"
            except requests.Timeout:
                local_report = "VirusTotal request timed out"
            except requests.ConnectionError:
                local_report = "VirusTotal connection error - network may be unavailable"
            except Exception as e:
                local_report = f"VirusTotal error: {str(e)[:100]}"
            
            return local_score, local_report
        
        def check_abuseipdb():
            local_score = 0
            local_report = ""
            
            try:
                headers = {
                    'Key': self.api_keys['abuseipdb'],
                    'Accept': 'application/json',
                }
                abuse_url = 'https://api.abuseipdb.com/api/v2/check'
                params = {
                    'ipAddress': ip_address,
                    'maxAgeInDays': '90',
                }
                # Reduce timeout to prevent hanging
                response = requests.get(abuse_url, headers=headers, params=params, timeout=0.3)  # Reduced timeout
                if response.status_code == 200:
                    data = response.json()
                    abuse_score = data.get('data', {}).get('abuseConfidenceScore', 0)
                    local_score = abuse_score
                    local_report = f"AbuseIPDB score: {abuse_score}"
                else:
                    local_report = f"AbuseIPDB API returned status code: {response.status_code}"
            except requests.Timeout:
                local_report = "AbuseIPDB request timed out"
            except requests.ConnectionError:
                local_report = "AbuseIPDB connection error - network may be unavailable"
            except Exception as e:
                local_report = f"AbuseIPDB error: {str(e)[:100]}"
            
            return local_score, local_report
        
        # Use concurrent execution with a timeout for all API calls
        api_results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            # Submit all API checks
            future_vt = executor.submit(check_virustotal)
            future_abuse = executor.submit(check_abuseipdb)
            futures = [future_vt, future_abuse]
            
            # Wait for all to complete or timeout
            remaining_time = max_total_time
            for future in concurrent.futures.as_completed(futures, timeout=remaining_time):
                try:
                    score, report = future.result()
                    threat_score += score
                    if report:
                        reports.append(report)
                except concurrent.futures.TimeoutError:
                    reports.append("API request timed out")
                except Exception as e:
                    reports.append(f"API error: {str(e)[:100]}")
                
                # Update remaining time
                elapsed = time.time() - start_time
                remaining_time = max(0, max_total_time - elapsed)
                if remaining_time <= 0:
                    break
        
        # If we've exceeded our total time, cancel any remaining futures
        if time.time() - start_time >= max_total_time:
            reports.append("Some API checks were skipped due to timeout")
        
        # Provide a fallback score if no APIs responded
        if not reports:
            reports.append("All threat intelligence APIs failed to respond")
            
        return {
            'threat_score': min(threat_score, 100),
            'reports': reports
        }
