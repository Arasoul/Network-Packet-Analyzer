# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of Network Packet Analyzer
- Real-time packet capture using PyShark
- Machine learning-based packet classification
- Interactive GUI with dark theme
- Protocol distribution visualization (pie charts)
- Classification statistics (bar charts)
- Packet search functionality
- Export capabilities for analysis results
- Basic intrusion detection (IP spoofing, ARP spoofing, ICMP flood)
- Multi-interval statistics tracking
- Interactive charts with filtering options

### Features
- **Core Functionality**
  - Real-time network packet capture and analysis
  - Support for IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP, HTTPS, ARP protocols
  - Machine learning classification with fallback to rule-based classification
  - Signature-based intrusion detection

- **User Interface**
  - Modern dark-themed GUI built with tkinter
  - Interactive statistics dashboard
  - Real-time updating charts and tables
  - Packet search and filtering
  - Multiple view modes (Protocol View, Classification View)
  - Interval-based analysis

- **Visualization**
  - Pie charts for protocol distribution
  - Bar charts for classification statistics
  - Color-coded results with interactive legends
  - Real-time updating visualizations

- **Data Export**
  - Summary reports generation
  - Packet capture analysis export
  - Statistical data export

### Dependencies
- Python 3.7+
- PyShark for packet capture
- tkinter for GUI
- matplotlib for visualizations
- scikit-learn for machine learning
- NLTK for text processing
- NumPy for numerical operations

### Security
- Basic intrusion detection capabilities
- Safe packet handling and processing
- Input validation and error handling

### Documentation
- Comprehensive README with installation and usage instructions
- Contributing guidelines
- MIT License
- Setup script for easy installation
- GitHub Actions CI/CD pipeline

## [1.0.0] - 2025-01-13

### Added
- Initial stable release
- Complete packet analysis functionality
- Machine learning classification model
- Interactive GUI interface
- Documentation and setup scripts
