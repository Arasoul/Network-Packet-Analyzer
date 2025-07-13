# Contributing to Network Packet Analyzer

Thank you for your interest in contributing to the Network Packet Analyzer project! This document provides guidelines and information for contributors.

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Setup](#development-setup)
4. [Contributing Process](#contributing-process)
5. [Coding Standards](#coding-standards)
6. [Testing](#testing)
7. [Documentation](#documentation)

## Code of Conduct

This project follows a Code of Conduct to ensure a welcoming environment for all contributors. By participating, you agree to uphold this code.

### Our Standards

- Be respectful and inclusive
- Focus on constructive feedback
- Respect different viewpoints and experiences
- Show empathy towards others
- Use welcoming and inclusive language

## Getting Started

### Prerequisites

- Python 3.7 or higher
- Git
- Wireshark/tshark installed
- Basic knowledge of networking concepts
- Familiarity with Python and GUI development

### Areas for Contribution

We welcome contributions in the following areas:

- **Bug fixes**: Report and fix bugs
- **Feature development**: Add new functionality
- **Documentation**: Improve docs, add examples
- **Testing**: Write tests, improve coverage
- **Performance**: Optimize code performance
- **UI/UX**: Enhance user interface and experience
- **Machine Learning**: Improve classification models

## Development Setup

1. **Fork the repository**
   ```bash
   git clone https://github.com/yourusername/network-packet-analyzer.git
   cd network-packet-analyzer
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt  # Development dependencies
   ```

4. **Set up pre-commit hooks** (optional but recommended)
   ```bash
   pre-commit install
   ```

## Contributing Process

### 1. Create an Issue

Before starting work, create an issue to discuss:
- Bug reports with reproduction steps
- Feature requests with detailed descriptions
- Questions about implementation

### 2. Branch Strategy

- `main`: Stable, production-ready code
- `develop`: Development branch for integration
- `feature/feature-name`: Feature development
- `bugfix/issue-number`: Bug fixes
- `hotfix/critical-issue`: Critical fixes

### 3. Making Changes

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Follow coding standards
   - Add tests for new functionality
   - Update documentation as needed

3. **Test your changes**
   ```bash
   python -m pytest tests/
   python packet_sniffer_gui.py  # Manual testing
   ```

4. **Commit your changes**
   ```bash
   git add .
   git commit -m "feat: add new packet classification algorithm"
   ```

### 4. Commit Message Format

Use conventional commits format:
- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `style:` Code style changes
- `refactor:` Code refactoring
- `test:` Test additions/modifications
- `chore:` Maintenance tasks

### 5. Submit Pull Request

1. Push your branch to your fork
2. Create a pull request to the `develop` branch
3. Provide a clear description of changes
4. Link related issues
5. Wait for review and address feedback

## Coding Standards

### Python Style Guide

- Follow PEP 8 style guide
- Use type hints where appropriate
- Maximum line length: 88 characters (Black formatter)
- Use meaningful variable and function names

### Code Organization

```python
# Standard library imports
import os
import sys

# Third-party imports
import numpy as np
import matplotlib.pyplot as plt

# Local imports
from .utils import helper_function
```

### Documentation

- Use docstrings for all functions and classes
- Follow Google docstring format
- Include examples where helpful

```python
def classify_packet(packet_data: str) -> str:
    """
    Classify a network packet based on its content.
    
    Args:
        packet_data (str): Raw packet data as string
        
    Returns:
        str: Classification category
        
    Example:
        >>> classify_packet("TCP 192.168.1.1:80")
        "Web Traffic"
    """
    pass
```

### Error Handling

- Use specific exception types
- Provide meaningful error messages
- Log errors appropriately

```python
try:
    result = process_packet(packet)
except PacketParsingError as e:
    logger.error(f"Failed to parse packet: {e}")
    raise
```

## Testing

### Test Types

1. **Unit Tests**: Test individual functions
2. **Integration Tests**: Test component interactions
3. **GUI Tests**: Test user interface (where possible)
4. **Performance Tests**: Test performance characteristics

### Writing Tests

```python
import pytest
from packet_analyzer import classify_packet

def test_classify_tcp_packet():
    """Test TCP packet classification."""
    packet_data = "TCP 192.168.1.1:80 -> 10.0.0.1:12345"
    result = classify_packet(packet_data)
    assert result == "Web Traffic"

def test_classify_invalid_packet():
    """Test handling of invalid packet data."""
    with pytest.raises(PacketParsingError):
        classify_packet("invalid data")
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=packet_analyzer

# Run specific test file
pytest tests/test_classification.py
```

## Documentation

### Types of Documentation

1. **Code Documentation**: Docstrings and comments
2. **User Documentation**: README, usage guides
3. **API Documentation**: Function and class references
4. **Developer Documentation**: Architecture, design decisions

### Documentation Standards

- Keep documentation up-to-date with code changes
- Use clear, concise language
- Include examples and screenshots
- Test documentation examples

## Performance Considerations

- Profile code before optimizing
- Consider memory usage for large packet captures
- Use efficient algorithms for real-time processing
- Test with various network conditions

## Security Considerations

- Never commit sensitive data (credentials, keys)
- Validate all user inputs
- Follow secure coding practices
- Consider privacy implications of packet capture

## Release Process

1. Update version numbers
2. Update CHANGELOG.md
3. Create release branch
4. Test thoroughly
5. Merge to main
6. Tag release
7. Update documentation

## Questions and Support

- **Issues**: Use GitHub Issues for bug reports and feature requests
- **Discussions**: Use GitHub Discussions for questions and ideas
- **Email**: Contact maintainers for private matters

## Recognition

Contributors will be recognized in:
- README.md contributors section
- Release notes
- Project documentation

Thank you for contributing to making network analysis more accessible and powerful!
