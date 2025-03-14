from scapy.all import *
from scapy.packet import Raw
from scapy.layers.inet import IP
from scapy.layers.http import HTTP
import re
import base64

class PacketInspector:
    def __init__(self):
        self.attack_patterns = {
            'sql_injection': r'(?i)(union|select|insert|delete|from|where|drop|update|exec)',
            'xss': r'(?i)(<script|javascript:|onload=|onerror=)',
            'shell_commands': r'(?i)(bash|shell|cmd|powershell|exec|system)',
            'base64_content': r'^[A-Za-z0-9+/=]{20,}$'
        }
        
    def deep_inspect(self, packet):
        results = {
            'suspicious_patterns': [],
            'risk_score': 0,
            'encoded_content': False
        }
        
        if packet is None:
            return results
            
        try:
            # Check for payload in different ways
            payload = None
            if hasattr(packet, 'load'):
                payload = str(packet.load)
            elif hasattr(packet, 'payload'):
                payload = str(packet.payload)
            
            if payload:
                results.update(self._analyze_payload(payload))
                
            if IP in packet:
                results.update(self._analyze_headers(packet))
                
        except Exception as e:
            print(f"Packet inspection error: {str(e)}")
            
        return results
    
    def _analyze_payload(self, payload):
        findings = []
        risk_score = 0
        
        try:
            for attack_type, pattern in self.attack_patterns.items():
                if re.search(pattern, payload):
                    findings.append(attack_type)
                    risk_score += 25  # Each finding adds 25 to risk score
                    
            # Check for base64 encoded payloads
            try:
                base64.b64decode(payload)
                findings.append('base64_encoded')
                risk_score += 15
            except Exception:
                pass  # Not base64 encoded
                
        except Exception as e:
            print(f"Payload analysis error: {str(e)}")
            
        return {
            'suspicious_patterns': findings,
            'risk_score': min(risk_score, 100)  # Cap at 100
        }
        
    def _analyze_headers(self, packet):
        risk_score = 0
        try:
            unusual_ports = {6667, 4444, 31337}  # Known malicious ports
            if packet[IP].dport in unusual_ports or packet[IP].sport in unusual_ports:
                risk_score += 30
        except Exception as e:
            print(f"Header analysis error: {str(e)}")
            
        return {'risk_score': min(risk_score, 100)}
