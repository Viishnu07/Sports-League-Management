# Sports League Management System

A deliberately vulnerable web application designed for cybersecurity educational workshops and CTF challenges. This application contains multiple security vulnerabilities for learning purposes.

## ⚠️ WARNING

**This application is intentionally vulnerable and should NEVER be deployed in a production environment!**

## Features

- User registration and authentication
- Team management (create, edit, view teams)
- Public scoreboard showing match results
- Admin panel for managing teams and scores
- File upload functionality

## Vulnerabilities Included

1. **SQL Injection (SQLi)** - Login and registration forms
2. **Stored Cross-Site Scripting (XSS)** - Team description field
3. **Insecure Direct Object Reference (IDOR)** - Team editing endpoint
4. **Broken Access Control** - Admin panel access
5. **File Upload RCE** - Unrestricted file uploads
6. **JWT Misconfiguration** - Weak secrets and no expiration
7. **Security Misconfiguration** - Debug mode enabled, hardcoded secrets

## Setup Instructions

### Prerequisites

- Python 3.7 or higher
- pip (Python package manager)

### Installation

1. Clone or download this repository

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Initialize the database:
```bash
python setup_db.py
```

4. Run the application:
```bash
python app.py
```

5. Access the application at `http://localhost:5000`

## Default Credentials

- **Admin**: `admin` / `admin123`
- **User**: `vish` / `vish123`
- **User**: `alice` / `alice123`
- **User**: `bob` / `bob123`

## Project Structure

```
.
├── app.py                 # Main Flask application (contains vulnerabilities)
├── setup_db.py            # Database initialization script
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── EXPLOITATION_GUIDE.md # Detailed exploitation guide
├── templates/            # HTML templates
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── edit_team.html
│   ├── scoreboard.html
│   ├── admin.html
│   └── upload.html
├── uploads/              # File upload directory (created automatically)
└── sports_league.db      # SQLite database (created automatically)
```

## Educational Use

This application is designed for:
- Cybersecurity training workshops
- CTF (Capture The Flag) competitions
- Security awareness training
- Learning web application security

## License

This project is provided for educational purposes only.

