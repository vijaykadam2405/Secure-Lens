# SOC Copilot

A comprehensive Security Operations Center (SOC) desktop application for automated log analysis, real-time threat detection, and reporting.

## Features

# SOC Copilot - Security Operations Center Assistant

SOC Copilot is a sophisticated desktop application designed to assist security analysts and IT professionals in analyzing log files, detecting security threats, and managing security operations efficiently. The application provides real-time log monitoring, threat detection, and comprehensive reporting capabilities.

## 🚀 Features

### 🔐 Authentication & User Management
- Role-based access control (Admin/User)
- Secure password hashing with bcrypt
- User management interface for administrators
- Session management and secure login

### 📊 Log Analysis
- Manual log file upload and analysis
- Real-time log file monitoring
- Pattern-based threat detection
- Automated threat severity assessment
- Contextual information extraction (IPs, timestamps, users)

### 🚨 Threat Detection
- Comprehensive threat pattern matching
- Multiple threat categories:
  - Login failures and brute force attempts
  - Privilege escalation attempts
  - Malware activity detection
  - Data exfiltration monitoring
  - Port scanning detection
  - Injection attack detection
- Automated severity assessment (Critical, High, Medium, Low)
- Detailed threat summaries and recommendations

### 📈 Real-time Monitoring
- Live log file monitoring
- Instant threat detection and alerting
- Real-time threat statistics
- Directory-based monitoring with auto-detection

### 📑 Reporting
- Generate detailed security reports
- Multiple export formats:
  - PDF reports with professional formatting
  - JSON data export
- Threat statistics and summaries
- Recommended actions for each threat
- Historical report storage and viewing

### 🖥️ User Interface
- Modern PyQt5-based desktop interface
- Intuitive tab-based navigation:
  - Log Upload: Manual file analysis
  - Monitoring: Real-time threat detection
  - Reports: Report generation and viewing
  - User Management (Admin): User administration
- Clean and professional design
- Responsive user experience




## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/soc_copilot.git
cd soc_copilot
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
# Windows
venv\Scripts\Activate.ps1
# Linux/Mac
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Start the application:
```bash
python app.py
```

2. Log in with your credentials
   - Default admin credentials: 
     - Username: admin
     - Password: admin123
   - Change the password after first login

3. Navigate through tabs:
   - Upload Tab: Select and analyze log files
   - Monitor Tab: Set up real-time log monitoring
   - Reports Tab: Generate and view security reports
   - User Management Tab (Admin): Manage system users

## 🏗️ Project Structure

```
├── app.py                  # Main application entry point
├── config/                 # Configuration files
├── core/                   # Core functionality
│   ├── base_parser.py     # Base log parsing functionality
│   ├── detectors.py       # Generic threat detectors
│   ├── file_monitor.py    # File monitoring system
│   ├── log_format_detector.py
│   ├── monitor.py         # Monitoring system
│   ├── summarizer.py      # Log summarization
│   ├── threat_detector.py # Threat detection system
│   ├── linux/            # Linux-specific implementations
│   └── windows/          # Windows-specific implementations
├── database/              # Database management
│   ├── db_init.py        # Database initialization
│   ├── migrate_monitoring.py
│   └── models.py         # Database models
├── gui/                   # GUI components
│   ├── alert_notification.py
│   ├── login_window.py
│   ├── main_window.py
│   ├── monitor_tab.py
│   ├── reports_tab.py
│   ├── upload_tab.py
│   └── user_management_tab.py
├── logs/                  # Log storage
├── reports/              # Generated reports
├── tests/                # Test suite
└── utils/                # Utility functions
    └── security.py      # Security-related utilities
```

## 🔧 Technologies Used

- **GUI Framework**: PyQt5 5.15.10
- **Database**: SQLAlchemy 2.0.22, Alembic 1.12.1
- **Security**: bcrypt 4.0.1, argon2-cffi 23.1.0, cryptography 41.0.4
- **Log Processing**: watchdog 3.0.0, python-dateutil 2.8.2
- **Report Generation**: reportlab 4.0.7, Pillow 10.0.1
- **Additional Utilities**: python-dotenv, pytz, structlog
## 💽 Database Schema

The application uses SQLAlchemy ORM with the following main models:

- **User**: Authentication and authorization
- **Log**: Log file entries and processing
- **Alert**: Security alerts and notifications
- **Report**: Generated analysis reports
- **MonitoringSession**: Log monitoring session tracking

## 🛡️ Security Features

- Password hashing using bcrypt and argon2
- Role-based access control
- Secure session management
- Encrypted data storage
- Input validation and sanitization

## 📊 Monitoring Features

- Real-time file monitoring
- Multiple concurrent monitoring sessions
- Automatic format detection
- Configurable alert thresholds
- Session persistence and recovery

## 📋 Logging and Reporting

- Structured logging using structlog
- PDF report generation
- Customizable report templates
- Historical data analysis
- Export capabilities

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ✍️ Authors

- Your Name - Initial work

## 🙏 Acknowledgments

- PyQt5 team for the GUI framework
- SQLAlchemy team for the ORM system
- All contributors and testers

## 📞 Support

For support, please open an issue in the GitHub repository or contact the development team.

---

**Note**: This project is actively maintained and welcomes contributions from the community.
