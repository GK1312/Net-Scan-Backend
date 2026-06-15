# Setup Guide

This document explains how to set up and run the project on Windows, macOS, and Linux.

---

# Prerequisites

Before setting up the project, ensure the following software is installed:

- Python 3.10 or later
- pip (Python package manager)

Verify your Python installation:

### Windows

```powershell
python --version
```

### macOS / Linux

```bash
python3 --version
```

Expected output:

```text
Python 3.x.x
```

If Python is not installed, download it from the official Python website.

---

# Project Structure

The project follows the structure below:

```text
project/
│
├── .venv/               # Virtual environment (generated locally)
├── main.py              # Application entry point
├── requirements.txt     # Python dependencies
├── README.md            # Project overview
└── SETUP.md             # Setup instructions
```

---

# Why Use a Virtual Environment?

A virtual environment creates an isolated Python environment for the project.

Benefits:

- Prevents dependency conflicts between projects
- Keeps project packages separate from system packages
- Makes deployment and collaboration easier
- Ensures consistent package versions across environments

---

# Windows Setup

## Step 1: Open Terminal

Open one of the following:

- Command Prompt (CMD)
- Windows Terminal
- PowerShell

Navigate to the project directory:

```powershell
cd path\to\project
```

Example:

```powershell
cd C:\Projects\MyApp
```

---

## Step 2: Create a Virtual Environment

Create a virtual environment named `.venv`:

```powershell
python -m venv .venv
```

This creates:

```text
.venv/
├── Scripts/
├── Lib/
└── pyvenv.cfg
```

---

## Step 3: Activate the Virtual Environment

### PowerShell

```powershell
.venv\Scripts\Activate.ps1
```

### Command Prompt

```cmd
.venv\Scripts\activate.bat
```

Successful activation will display:

```text
(.venv) C:\Projects\MyApp>
```

---

## Step 4: Install Dependencies

Install all packages listed in `requirements.txt`:

```powershell
pip install -r requirements.txt
```

Example output:

```text
Collecting uvicorn
Collecting fastapi
Successfully installed ...
```

---

## Step 5: Verify Installed Packages

View installed packages:

```powershell
pip list
```

or

```powershell
pip freeze
```

---

## Step 6: Run the Application

If your application starts from `main.py`:

```powershell
python main.py
```

---

## Step 7: Deactivate Environment

When finished:

```powershell
deactivate
```

---

# macOS / Linux Setup

## Step 1: Open Terminal

Navigate to the project folder:

```bash
cd /path/to/project
```

Example:

```bash
cd ~/Projects/MyApp
```

---

## Step 2: Create Virtual Environment

```bash
python3 -m venv .venv
```

---

## Step 3: Activate Virtual Environment

```bash
source .venv/bin/activate
```

You should see:

```text
(.venv) user@machine:~/MyApp$
```

---

## Step 4: Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Step 5: Verify Installation

```bash
pip list
```

or

```bash
pip freeze
```

---

## Step 6: Run Application

```bash
python main.py
```

---

## Step 7: Deactivate Environment

```bash
deactivate
```

---

# Installing New Dependencies

Whenever a new package is required:

## Install Package

Example:

```bash
pip install uvicorn
```

or

```bash
pip install requests
```

---

## Update Requirements File

After installing packages:

```bash
pip freeze > requirements.txt
```

This updates the dependency list so other developers can install the same versions.

Example:

```text
uvicorn==0.35.0
requests==2.32.4
```

---

# Updating Existing Dependencies

Upgrade a package:

```bash
pip install --upgrade package-name
```

Example:

```bash
pip install --upgrade uvicorn
```

Update requirements:

```bash
pip freeze > requirements.txt
```

---

# Recreating the Environment

If the virtual environment becomes corrupted:

Delete the environment:

### Windows

```powershell
rmdir /s /q .venv
```

### macOS / Linux

```bash
rm -rf .venv
```

Create a new one:

```bash
python -m venv .venv
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# Common Commands

## Activate Environment

### Windows

```powershell
.venv\Scripts\Activate.ps1
```

### macOS / Linux

```bash
source .venv/bin/activate
```

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Install New Package

```bash
pip install package-name
```

---

## Save Dependencies

```bash
pip freeze > requirements.txt
```

---

## Run Application

```bash
python main.py
```

---

## Deactivate Environment

```bash
deactivate
```

---

# Troubleshooting

## "python is not recognized"

Python is not installed or not added to PATH.

Verify:

```bash
python --version
```

Install Python and ensure "Add Python to PATH" is checked during installation.

---

## Activation Script Is Disabled (Windows)

Run PowerShell as Administrator:

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Then activate again:

```powershell
.venv\Scripts\Activate.ps1
```

---

## pip Command Not Found

Use:

```bash
python -m pip install -r requirements.txt
```

instead of:

```bash
pip install -r requirements.txt
```

---

# Developer Workflow

Recommended workflow when contributing:

1. Pull latest code.
2. Activate virtual environment.
3. Install dependencies.

```bash
pip install -r requirements.txt
```

4. Make changes.
5. Install any new dependencies if required.

```bash
pip install package-name
```

6. Update dependency list.

```bash
pip freeze > requirements.txt
```

7. Commit code changes.
8. Push changes to repository.

---

# Quick Start

## Windows

```powershell
git clone <repository-url>
cd <project-folder>

python -m venv .venv

.venv\Scripts\Activate.ps1

pip install -r requirements.txt

python main.py
```

## macOS / Linux

```bash
git clone <repository-url>
cd <project-folder>

python3 -m venv .venv

source .venv/bin/activate

pip install -r requirements.txt

python main.py
```

The application should now be running successfully.
