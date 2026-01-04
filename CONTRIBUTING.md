# Contributing to nxc-enum

Thank you for your interest in contributing to nxc-enum! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Security Vulnerabilities](#security-vulnerabilities)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)
- [Development Setup](#development-setup)
- [Testing](#testing)
- [Code Style](#code-style)
- [Pull Request Process](#pull-request-process)
- [Commit Message Guidelines](#commit-message-guidelines)

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you are expected to uphold this code. Please report unacceptable behavior by opening an issue.

## Security Vulnerabilities

**Important:** nxc-enum is a security/penetration testing tool. If you discover a security vulnerability:

1. **Do NOT open a public issue**
2. Use GitHub's private vulnerability reporting feature
3. Include detailed steps to reproduce the vulnerability
4. Allow reasonable time for a fix before public disclosure

## Reporting Bugs

Before submitting a bug report:

1. Check the [existing issues](https://github.com/Real-Fruit-Snacks/nxc-enum/issues) to avoid duplicates
2. Update to the latest version to see if the issue persists
3. Collect relevant information:
   - Python version (`python3 --version`)
   - NetExec version (`nxc --version`)
   - Operating system and version
   - Complete error message or unexpected output
   - Command used (with credentials redacted)

### Bug Report Template

When opening an issue, please include:

```markdown
**Description**
A clear description of the bug.

**Steps to Reproduce**
1. Run command `python3 nxc_enum.py ...`
2. Observe error...

**Expected Behavior**
What you expected to happen.

**Actual Behavior**
What actually happened.

**Environment**
- OS: [e.g., Ubuntu 22.04, Kali 2024.1]
- Python version: [e.g., 3.10.12]
- NetExec version: [e.g., 1.1.0]
- nxc-enum version: [e.g., 1.5.1]

**Additional Context**
Any other relevant information.
```

## Suggesting Features

Feature requests are welcome! When suggesting a feature:

1. Check existing issues for similar requests
2. Clearly describe the use case and benefit
3. Consider how it fits with nxc-enum's scope (AD enumeration wrapper)
4. Provide examples of expected behavior if possible

## Development Setup

### Prerequisites

- Python 3.10 or higher
- NetExec installed and in PATH
- Git

### Setting Up Your Environment

```bash
# Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/nxc-enum.git
cd nxc-enum

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements-dev.txt

# Install in editable mode
pip install -e .

# Verify setup
python3 -c "import nxc_enum; print(nxc_enum.__version__)"
pytest tests/ -v
```

### Project Structure

```
nxc-enum/
├── nxc_enum.py           # Main entry point (standalone script)
├── nxc_enum/             # Package directory
│   ├── __init__.py       # Package init, version
│   ├── __main__.py       # Package entry point
│   ├── cli/              # Command-line interface
│   │   ├── args.py       # Argument parsing
│   │   └── main.py       # Main orchestration
│   ├── core/             # Core utilities
│   │   ├── colors.py     # Terminal colors
│   │   ├── constants.py  # Constants and regex patterns
│   │   ├── parallel.py   # Parallel execution
│   │   └── runner.py     # NetExec command runner
│   ├── enums/            # Enumeration modules
│   ├── models/           # Data models
│   ├── parsing/          # Output parsing utilities
│   ├── reporting/        # Report generation
│   └── validation/       # Credential validation
├── tests/                # Test suite
└── README.md
```

## Testing

### Running Tests

```bash
# Run all tests
pytest tests/

# Run with verbose output
pytest tests/ -v

# Run specific test file
pytest tests/test_parsing.py

# Run with coverage
pytest tests/ --cov=nxc_enum --cov-report=html
```

### Writing Tests

- Place tests in the `tests/` directory
- Name test files with `test_` prefix
- Use `unittest.TestCase` or pytest-style functions
- Test both success and error cases
- Mock external calls (NetExec) where appropriate

Example test:

```python
import unittest
from nxc_enum.parsing.nxc_output import parse_nxc_output

class TestNxcOutputParsing(unittest.TestCase):
    def test_parse_success_indicator(self):
        stdout = "[+] Authentication successful"
        results = parse_nxc_output(stdout)
        self.assertEqual(results[0], ('success', 'Authentication successful'))
```

## Code Style

This project uses the following tools for code quality:

### Black (Code Formatting)

```bash
# Format all code
black nxc_enum/ tests/

# Check without modifying
black --check nxc_enum/ tests/
```

Configuration: 100 character line length (see pyproject.toml)

### isort (Import Sorting)

```bash
# Sort imports
isort nxc_enum/ tests/

# Check without modifying
isort --check-only nxc_enum/ tests/
```

### flake8 (Linting)

```bash
# Lint code
flake8 nxc_enum/ tests/ --max-line-length=100
```

### Style Guidelines

1. **Type Hints**: Use type hints for function parameters and return values
2. **Docstrings**: Use docstrings for modules, classes, and functions
3. **Constants**: Use UPPER_CASE for constants
4. **Line Length**: Maximum 100 characters
5. **Imports**: Group and sort imports (stdlib, third-party, local)

Example:

```python
"""Module docstring describing purpose."""

from typing import Dict, List, Optional

from nxc_enum.core.colors import Colors


def process_users(
    users: Dict[str, Dict],
    include_disabled: bool = False
) -> List[str]:
    """
    Process user dictionary and return list of usernames.

    Args:
        users: Dictionary mapping username to user attributes
        include_disabled: Whether to include disabled accounts

    Returns:
        List of usernames matching criteria
    """
    result = []
    for username, attrs in users.items():
        if include_disabled or not attrs.get('disabled', False):
            result.append(username)
    return result
```

## Pull Request Process

### Before Submitting

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes with clear, atomic commits

3. Ensure all tests pass:
   ```bash
   pytest tests/ -v
   ```

4. Format and lint your code:
   ```bash
   black nxc_enum/ tests/
   isort nxc_enum/ tests/
   flake8 nxc_enum/ tests/ --max-line-length=100
   ```

5. Update documentation if needed

### Submitting the PR

1. Push your branch to your fork
2. Open a Pull Request against `main`
3. Fill out the PR template:
   - Description of changes
   - Related issue (if any)
   - Testing performed
   - Screenshots (if UI changes)

### Review Process

1. A maintainer will review your PR
2. Address any requested changes
3. Once approved, the PR will be merged
4. Your contribution will be noted in the changelog

## Commit Message Guidelines

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

### Format

```
<type>(<scope>): <subject>

[optional body]

[optional footer]
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style (formatting, no logic change)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

### Examples

```
feat(shares): add recursive share enumeration

fix(parsing): handle empty user descriptions

docs: update installation instructions for pip

test(parsing): add tests for NTLM hash detection

refactor(cache): simplify parallel cache priming logic
```

### Guidelines

- Use present tense ("add feature" not "added feature")
- Use imperative mood ("fix bug" not "fixes bug")
- Keep subject line under 50 characters
- Separate subject from body with blank line
- Reference issues in footer: `Fixes #123`

---

## Questions?

If you have questions about contributing, feel free to:

1. Open a discussion on GitHub
2. Open an issue with the "question" label

Thank you for contributing to nxc-enum!
