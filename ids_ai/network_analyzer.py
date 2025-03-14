from scapy.all import sniff, conf
from scapy.layers.inet import IP
import pandas as pd
import numpy as np
from datetime import datetime
import os
import sys
import time
import socket
import threading

class NetworkAnalyzer:
    def __init__(self):
        self.packet_data = []
        self.current_df = pd.DataFrame()
        try:
            self.interface = self._get_default_interface()
            # Test if we can access network interfaces
            try:
                socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            except PermissionError:
                print("Warning: Administrator privileges required for full packet capture capabilities")
            except Exception as e:
                if "not a valid Win32 application" in str(e):
                    print("Warning: WinPcap/Npcap compatibility issue detected")
                    print("Please follow the instructions in README.md to install Npcap correctly")
                    print("You need to uninstall WinPcap and install Npcap from https://npcap.com/")
                    print("Make sure to select 'WinPcap API-compatible Mode' during installation")
        except Exception as e:
            print(f"Warning: Could not initialize network interface properly: {str(e)}")
            print("This may be due to WinPcap/Npcap issues. Please check README.md for installation instructions.")
            # Set a fallback interface to prevent crash
            self.interface = conf.iface
        
    def _get_default_interface(self):
        if os.name == 'nt':
            try:
                # Try to get the most active interface
                from scapy.arch.windows import get_windows_if_list
                ifaces = get_windows_if_list()
                if ifaces:
                    # Sort by interface metrics and status
                    active_ifaces = [i for i in ifaces if i.get('status', False)]
                    if active_ifaces:
                        return active_ifaces[0]['name']
                    else:
                        print("Warning: No active network interfaces found. Using default interface.")
            except Exception as e:
                print(f"Warning: Error detecting network interfaces: {str(e)}")
                print("This may be due to WinPcap/Npcap issues. Please check README.md for installation instructions.")
        return conf.iface
            
    def get_current_data(self):
        """Return the current packet data as a DataFrame"""
        if self.packet_data:
            self.current_df = pd.DataFrame(self.packet_data)
            # Clear processed packets to avoid memory buildup
            self.packet_data = []
            return self.current_df
        return pd.DataFrame()  # Return empty DataFrame if no new data

    def packet_callback(self, packet):
        if IP in packet:
            timestamp = datetime.now()
            packet_info = {
                'timestamp': timestamp,
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'protocol': packet[IP].proto,
                'length': len(packet),
                'ttl': packet[IP].ttl,
                'packet': packet  # Store the raw packet object
            }
            self.packet_data.append(packet_info)
    
    def start_capture(self, duration=60):
        try:
            print("\nStarting packet capture...")
            print(f"Interface: {self.interface}")
            print(f"Duration: {duration} seconds")
            print("Capturing packets... (Press Ctrl+C to stop)")
            print("-" * 50)
            
            # Clear previous packet data
            self.packet_data = []
            
            # Set a stricter maximum timeout to prevent hanging
            actual_duration = min(duration, 60)  # Max 1 minute
            
            # Create a flag for capture completion
            capture_completed = False
            capture_error = None
            capture_thread = None
            
            # Define a capture function to run in a separate thread with better error handling
            def capture_packets():
                nonlocal capture_completed, capture_error
                try:
                    # Use a filter to only capture IP packets to reduce load
                    # Set a strict timeout to prevent hanging
                    sniff(prn=self.packet_callback, 
                          timeout=actual_duration,
                          iface=self.interface,
                          filter="ip",
                          store=0)
                    capture_completed = True
                except Exception as e:
                    capture_error = e
                    capture_completed = True
            
            # Start capture in a separate thread with a timeout
            capture_thread = threading.Thread(target=capture_packets)
            capture_thread.daemon = True  # Allow the thread to be terminated when main thread exits
            capture_thread.start()
            
            # Wait for the capture to complete with a stricter timeout
            max_wait_time = actual_duration + 5  # Add only 5 seconds buffer
            start_time = time.time()
            
            # Check thread status more frequently
            check_interval = 0.2  # Check every 200ms instead of 500ms
            while not capture_completed and (time.time() - start_time) < max_wait_time:
                time.sleep(check_interval)
            
            # Check if capture completed or timed out
            if not capture_completed:
                print("\nWarning: Packet capture timed out. This may be due to WinPcap/Npcap issues.")
                print("Please check README.md for installation instructions.")
            elif capture_error:
                print(f"\nWarning: Packet capture interrupted: {str(capture_error)}")
                if "winpcap" in str(capture_error).lower() or "npcap" in str(capture_error).lower():
                    print("This error is related to WinPcap/Npcap. Please check README.md for installation instructions.")
                elif "not a valid Win32 application" in str(capture_error):
                    print("This error indicates a WinPcap/Npcap compatibility issue.")
                    print("Please uninstall WinPcap and install Npcap from https://npcap.com/")
                    print("Make sure to select 'WinPcap API-compatible Mode' during installation.")
            
            print("\nPacket capture complete")
            print(f"Captured {len(self.packet_data)} packets")
            print("-" * 50)
            
            # Handle case where no packets were captured
            if not self.packet_data:
                print("No packets were captured. This could be due to:")
                print("- No network activity on the selected interface")
                print("- Incorrect interface selection")
                print("- Packet filtering issues")
                print("- WinPcap/Npcap not installed or configured correctly")
                # Return empty DataFrame with correct columns
                return pd.DataFrame(columns=['timestamp', 'src_ip', 'dst_ip', 'protocol', 'length', 'ttl', 'packet'])
            
            return pd.DataFrame(self.packet_data)
            
        except Exception as e:
            if "permission" in str(e).lower():
                raise PermissionError("Administrator privileges required for packet capture")
            elif "winpcap" in str(e).lower() or "npcap" in str(e).lower():
                print("\nError: WinPcap/Npcap issue detected.")
                print("Please follow the instructions in README.md to install Npcap correctly.")
                # Return empty DataFrame to prevent application crash
                return pd.DataFrame(columns=['timestamp', 'src_ip', 'dst_ip', 'protocol', 'length', 'ttl', 'packet'])
            else:
                print(f"\nCapture failed: {str(e)}")
                # Return empty DataFrame to prevent application crash
                return pd.DataFrame(columns=['timestamp', 'src_ip', 'dst_ip', 'protocol', 'length', 'ttl', 'packet'])

if __name__ == "__main__":
    analyzer = NetworkAnalyzer()
    df = analyzer.start_capture(30)
    print(df.head())
