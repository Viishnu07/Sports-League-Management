import sqlite3
import hashlib

def init_database():
    """Initialize the database with sample data"""
    conn = sqlite3.connect('sports_league.db')
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS teams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            captain_id INTEGER,
            wins INTEGER DEFAULT 0,
            losses INTEGER DEFAULT 0,
            draws INTEGER DEFAULT 0,
            FOREIGN KEY (captain_id) REFERENCES users(id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            team1_id INTEGER,
            team2_id INTEGER,
            score1 INTEGER DEFAULT 0,
            score2 INTEGER DEFAULT 0,
            date_played TEXT,
            FOREIGN KEY (team1_id) REFERENCES teams(id),
            FOREIGN KEY (team2_id) REFERENCES teams(id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS uploads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            user_id INTEGER,
            upload_date TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_message TEXT NOT NULL,
            log_type TEXT,
            log_date TEXT,
            user_id INTEGER
        )
    ''')
    
    # Clear existing data
    cursor.execute('DELETE FROM system_logs')
    cursor.execute('DELETE FROM matches')
    cursor.execute('DELETE FROM teams')
    cursor.execute('DELETE FROM users')
    
    # Insert sample users
    # VULNERABILITY: Passwords stored in plaintext (for demo purposes)
    users = [
        ('admin', 'admin123', 1),  # Admin user
        ('vish', 'vish123', 0),   # Regular user
        ('alice', 'alice123', 0),  # Regular user
        ('bob', 'bob123', 0),      # Regular user
    ]
    
    for username, password, is_admin in users:
        cursor.execute('''
            INSERT INTO users (username, password, is_admin)
            VALUES (?, ?, ?)
        ''', (username, password, is_admin))
    
    # Get user IDs
    cursor.execute("SELECT id, username FROM users")
    users_data = {row[1]: row[0] for row in cursor.fetchall()}
    
    # Insert sample teams
    teams = [
        ('Thunder FC', 'A powerful team with great offense!', users_data['vish'], 5, 2, 1),
        ('Lightning United', 'Fast and agile players!', users_data['alice'], 4, 3, 1),
        ('Storm Rovers', 'Defensive powerhouse!', users_data['bob'], 3, 4, 1),
        ('Eagles FC', 'Soaring high in the league!', None, 2, 5, 1),
    ]
    
    team_ids = []
    for name, description, captain_id, wins, losses, draws in teams:
        cursor.execute('''
            INSERT INTO teams (name, description, captain_id, wins, losses, draws)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (name, description, captain_id, wins, losses, draws))
        team_ids.append(cursor.lastrowid)
    
    # Insert sample matches
    matches = [
        (team_ids[0], team_ids[1], 3, 1, '2024-01-15'),
        (team_ids[1], team_ids[2], 2, 2, '2024-01-16'),
        (team_ids[0], team_ids[2], 4, 1, '2024-01-17'),
        (team_ids[2], team_ids[3], 1, 0, '2024-01-18'),
        (team_ids[0], team_ids[3], 2, 1, '2024-01-19'),
    ]
    
    for team1_id, team2_id, score1, score2, date_played in matches:
        cursor.execute('''
            INSERT INTO matches (team1_id, team2_id, score1, score2, date_played)
            VALUES (?, ?, ?, ?, ?)
        ''', (team1_id, team2_id, score1, score2, date_played))
    
    # Insert sample system logs
    import datetime
    sample_logs = [
        ('System initialized', 'SYSTEM', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), None),
        ('Admin user created', 'CREATE', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), users_data['admin']),
        ('Sample teams created', 'CREATE', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), None),
    ]
    
    for log_message, log_type, log_date, user_id in sample_logs:
        cursor.execute('''
            INSERT INTO system_logs (log_message, log_type, log_date, user_id)
            VALUES (?, ?, ?, ?)
        ''', (log_message, log_type, log_date, user_id))
    
    conn.commit()
    conn.close()
    print("Database initialized successfully!")
    print("\nSample credentials:")
    print("Admin: admin / admin123")
    print("User: vish / vish123")
    print("User: alice / alice123")
    print("User: bob / bob123")
    print("\n⚠️  VULNERABILITY REMINDER:")
    print("   - SQL Injection: Use ' OR '1'='1' -- in login")
    print("   - Broken Access Control: Access /admin without login")
    print("   - IDOR: Edit other teams by changing team ID in URL")
    print("   - XSS: Inject <script> tags in team description")

if __name__ == '__main__':
    init_database()

