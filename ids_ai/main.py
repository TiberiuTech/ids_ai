import os
import sys
import warnings
import logging
import time
from network_analyzer import NetworkAnalyzer
from ml_model import AnomalyDetector
from visualizer import NetworkVisualizer
from database import DatabaseManager
from packet_inspector import PacketInspector
from threat_intel import ThreatIntel
from notifypy import Notify
import threading
import tkinter as tk

# Suppress absolutely all warnings
warnings.filterwarnings('ignore')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['PYTHONWARNINGS'] = 'ignore'

# Configure colored logging
try:
    import colorama
    colorama.init()
    
    class ColoredFormatter(logging.Formatter):
        COLORS = {
            'WARNING': colorama.Fore.YELLOW,
            'ERROR': colorama.Fore.RED,
            'INFO': colorama.Fore.GREEN,
            'DEBUG': colorama.Fore.BLUE
        }

        def format(self, record):
            color = self.COLORS.get(record.levelname, '')
            reset = colorama.Style.RESET_ALL
            record.msg = f"{color}{record.msg}{reset}"
            return super().format(record)

    # Set up prettier logging
    handler = logging.StreamHandler()
    handler.setFormatter(ColoredFormatter(
        '%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    ))
    logger = logging.getLogger(__name__)
    logger.handlers = [handler]
    logger.setLevel(logging.INFO)
except ImportError:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    )
    logger = logging.getLogger(__name__)

def send_notification(title, message):
    notification = Notify()
    notification.title = title
    notification.message = message
    notification.send()

def start_packet_capture(analyzer, visualizer):
    """Run packet capture in a separate thread"""
    try:
        analyzer.start_capture()
    except KeyboardInterrupt:
        print("\nStopping packet capture...")
    finally:
        analyzer.stop()

def process_network_data(analyzer, detector, visualizer, db, threat_intel):
    """Process network data and update visualization"""
    while True:
        try:
            # Get captured packets
            df = analyzer.get_current_data()
            if not df.empty:
                # Detect anomalies
                X = detector.preprocess_data(df)
                anomalies, predictions = detector.detect_anomalies(X)
                
                # Update visualization
                visualizer.update_plots(df, anomalies)
                
                # Log anomalies
                if any(anomalies):
                    logger.warning(f"Detected {sum(anomalies)} potential intrusions!")
            
            time.sleep(1)  # Update every second
            
        except Exception as e:
            logger.error(f"Data processing error: {e}")
            time.sleep(1)

def main():
    try:
        logger.info("╔══════════════════════════════════════╗")
        logger.info("║      AI-Based IDS System Started     ║")
        logger.info("╚══════════════════════════════════════╝")
        
        # Check for admin privileges
        if os.name == 'nt':
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if not is_admin:
                    logger.error("Please run the script as Administrator for full packet capture capabilities")
                    logger.error("Right-click Command Prompt/PowerShell and select 'Run as Administrator'")
                    sys.exit(1)
            except:
                logger.warning("Could not check admin privileges")

        # Initialize components
        logger.info("Initializing IDS components...")
        
        analyzer = NetworkAnalyzer()
        detector = AnomalyDetector()
        visualizer = NetworkVisualizer()
        db = DatabaseManager()
        inspector = PacketInspector()
        threat_intel = ThreatIntel()
        
        logger.info("✓ Network Analyzer initialized")
        logger.info("✓ ML Model loaded")
        logger.info("✓ Visualizer ready")
        logger.info("✓ Database connected")
        logger.info("✓ Threat Intel APIs configured")
        
        logger.info("\n🔍 Starting network monitoring...")
        logger.info("Press Ctrl+C to stop\n")
        
        # Start packet capture thread
        capture_thread = threading.Thread(
            target=start_packet_capture,
            args=(analyzer, visualizer)
        )
        capture_thread.daemon = True
        capture_thread.start()
        
        # Start data processing thread
        process_thread = threading.Thread(
            target=process_network_data,
            args=(analyzer, detector, visualizer, db, threat_intel)
        )
        process_thread.daemon = True
        process_thread.start()
        
        # Start visualization in main thread
        visualizer.start()

    except ImportError as e:
        logger.error(f"Missing required library: {str(e)}. Please check if WinPcap is installed.")
        sys.exit(1)
    except PermissionError:
        logger.error("Permission denied. Try running with administrator privileges.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        sys.exit(1)
    finally:
        if 'analyzer' in locals():
            analyzer.stop()
        if 'visualizer' in locals():
            visualizer.stop()

if __name__ == "__main__":
    main()
