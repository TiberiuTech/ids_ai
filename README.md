# AI-Based Intrusion Detection System (IDS)

## Overview
This project implements an advanced Intrusion Detection System powered by artificial intelligence. The system monitors network traffic, analyzes patterns, and detects potential security threats using machine learning algorithms.

## Features
- Real-time network traffic monitoring
- Machine learning-based anomaly detection
- Threat intelligence integration
- Comprehensive packet inspection
- Interactive visualization dashboard
- Alerting system for suspicious activities
- Database storage for historical analysis

## System Architecture
The system consists of several interconnected components:

## Dashboard Screenshot
![IDS Dashboard](https://raw.githubusercontent.com/TiberiuTech/ids_ai/main/ids.png)

*Note: To add the dashboard screenshot, upload an image to your GitHub repository and update the path in the above image link.*

## Installation

### Prerequisites
- Python 3.8 or higher
- Network monitoring privileges
- Required Python packages (listed in requirements.txt)

### Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/TiberiuTech/ids_ai.git
   cd ids_ai
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure environment variables:
   ```bash
   # Create a .env file with your configuration
   # Example:
   DB_PATH=network_events.db
   LOG_LEVEL=INFO
   ALERT_THRESHOLD=0.85
   ```

## Usage
Run the system with administrator privileges:

```bash
# On Windows
start_ids.bat

# On Linux/Mac
sudo python main.py
```

The dashboard will be accessible at http://localhost:8050 by default.

## Components
- **main.py**: Entry point and orchestration
- **network_analyzer.py**: Captures and analyzes network traffic
- **ml_model.py**: Implements machine learning for anomaly detection
- **threat_intel.py**: Integrates with threat intelligence sources
- **packet_inspector.py**: Deep packet inspection functionality
- **visualizer.py**: Dashboard and visualization components
- **database.py**: Database management and storage

## License
[MIT License](LICENSE)

## Contact
For questions or contributions, please open an issue on GitHub

---

*Note: This IDS system is designed for educational and research purposes. Always ensure you have proper authorization before monitoring any network.*
