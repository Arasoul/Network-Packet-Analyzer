#!/usr/bin/env python3
"""
Network Packet Sniffer and Analyzer
Setup and Installation Script

This script helps set up the environment and dependencies for the packet analyzer.
"""

import subprocess
import sys
import os
from pathlib import Path

def check_python_version():
    """Check if Python version is 3.7 or higher"""
    if sys.version_info < (3, 7):
        print("❌ Python 3.7 or higher is required")
        print(f"Current version: {sys.version}")
        return False
    print(f"✅ Python version: {sys.version}")
    return True

def install_requirements():
    """Install required Python packages"""
    print("\n📦 Installing Python dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ All dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False

def check_wireshark():
    """Check if Wireshark/tshark is installed"""
    print("\n🔍 Checking for Wireshark installation...")
    
    # Common tshark paths
    possible_paths = [
        "tshark",  # In PATH
        "C:\\Program Files\\Wireshark\\tshark.exe",
        "C:\\Program Files (x86)\\Wireshark\\tshark.exe",
        "/usr/bin/tshark",  # Linux
        "/usr/local/bin/tshark",  # macOS
    ]
    
    for path in possible_paths:
        try:
            result = subprocess.run([path, "--version"], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print(f"✅ Found tshark at: {path}")
                return path
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            continue
    
    print("❌ Wireshark/tshark not found")
    print("Please install Wireshark from: https://www.wireshark.org/")
    return None

def download_nltk_data():
    """Download required NLTK data"""
    print("\n📚 Setting up NLTK data...")
    try:
        import nltk
        nltk.download('punkt', quiet=True)
        print("✅ NLTK data downloaded successfully")
        return True
    except Exception as e:
        print(f"⚠️  Could not download NLTK data: {e}")
        print("You may need to run: python -c \"import nltk; nltk.download('punkt')\"")
        return False

def create_directories():
    """Create necessary directories"""
    print("\n📁 Creating project directories...")
    directories = ['captures', 'logs', 'screenshots']
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"✅ Created directory: {directory}")

def main():
    """Main setup function"""
    print("🚀 Network Packet Analyzer Setup")
    print("=" * 40)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Install requirements
    if not install_requirements():
        print("⚠️  Some dependencies failed to install. You may need to install them manually.")
    
    # Check Wireshark
    tshark_path = check_wireshark()
    if tshark_path:
        print(f"\n📝 Update the tshark path in packet_sniffer_gui.py:")
        print(f"   pyshark.tshark.tshark_path = r\"{tshark_path}\"")
    
    # Download NLTK data
    download_nltk_data()
    
    # Create directories
    create_directories()
    
    print("\n" + "=" * 40)
    print("🎉 Setup completed!")
    print("\nTo run the application:")
    print("   python packet_sniffer_gui.py")
    print("\n⚠️  Note: You may need administrator privileges for packet capture")

if __name__ == "__main__":
    main()
