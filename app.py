from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
import sqlite3
import os
import hashlib
import jwt
import datetime
from werkzeug.utils import secure_filename
import json

app = Flask(__name__)
app.secret_key = 'vulnerable_secret_key_12345'  # VULNERABILITY: Hardcoded secret key
app.config['DEBUG'] = True  # VULNERABILITY: Debug mode enabled in production
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['JWT_SECRET'] = 'weak_secret_key'  # VULNERABILITY: Weak JWT secret

# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'py', 'php', 'sh'}  # VULNERABILITY: Allows dangerous file types

def get_db_connection():
    conn = sqlite3.connect('sports_league.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        )
    ''')
    conn.execute('''
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
    conn.execute('''
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
    conn.execute('''
        CREATE TABLE IF NOT EXISTS uploads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            user_id INTEGER,
            upload_date TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS system_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_message TEXT NOT NULL,
            log_type TEXT,
            log_date TEXT,
            user_id INTEGER
        )
    ''')
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # VULNERABILITY: SQL Injection - Direct string concatenation in SQL query
        conn = get_db_connection()
        # This is vulnerable to SQL injection!
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        user = conn.execute(query).fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            
            # VULNERABILITY: JWT Misconfiguration - No expiration, weak secret, no algorithm specified
            payload = {
                'user_id': user['id'],
                'username': user['username'],
                'is_admin': user['is_admin']
                # Missing: 'exp' expiration claim
            }
            # Using 'none' algorithm or weak secret
            token = jwt.encode(payload, app.config['JWT_SECRET'], algorithm='HS256')
            session['jwt_token'] = token
            
            # Log successful login
            conn = get_db_connection()
            conn.execute(f"INSERT INTO system_logs (log_message, log_type, log_date, user_id) VALUES ('User {user['username']} logged in', 'LOGIN', datetime('now'), {user['id']})")
            conn.commit()
            conn.close()
            
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials!', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # VULNERABILITY: SQL Injection - Also vulnerable here
        conn = get_db_connection()
        try:
            # Still vulnerable to SQL injection
            query = f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')"
            conn.execute(query)
            conn.commit()
            conn.close()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists!', 'error')
            conn.close()
    
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    # VULNERABILITY: SQL Injection - User input in query
    user_id = session['user_id']
    is_admin = session.get('is_admin', False)
    
    # Get user's team if not admin
    team = None
    if not is_admin:
        team = conn.execute(f"SELECT * FROM teams WHERE captain_id = {user_id}").fetchone()
    
    # If admin, get all teams and matches for management
    all_teams = None
    all_matches = None
    if is_admin:
        all_teams = conn.execute("SELECT t.*, u.username as captain_name FROM teams t LEFT JOIN users u ON t.captain_id = u.id ORDER BY t.id").fetchall()
        all_matches = conn.execute("SELECT m.*, t1.name as team1_name, t2.name as team2_name FROM matches m JOIN teams t1 ON m.team1_id = t1.id JOIN teams t2 ON m.team2_id = t2.id ORDER BY m.date_played DESC").fetchall()
    
    conn.close()
    
    return render_template('dashboard.html', team=team, user=session, is_admin=is_admin, all_teams=all_teams, all_matches=all_matches)

@app.route('/edit_team/<int:team_id>', methods=['GET', 'POST'])
def edit_team(team_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        
        # VULNERABILITY: IDOR - No check if user owns this team!
        # Anyone can edit any team by changing the team_id in the URL
        query = f"UPDATE teams SET name = '{name}', description = '{description}' WHERE id = {team_id}"
        conn.execute(query)
        conn.commit()
        conn.close()
        flash('Team updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    # VULNERABILITY: IDOR - No ownership verification
    team = conn.execute(f"SELECT * FROM teams WHERE id = {team_id}").fetchone()
    conn.close()
    
    if not team:
        flash('Team not found!', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('edit_team.html', team=team)

@app.route('/scoreboard')
def scoreboard():
    conn = get_db_connection()
    teams = conn.execute("SELECT * FROM teams ORDER BY wins DESC, draws DESC").fetchall()
    matches = conn.execute("SELECT m.*, t1.name as team1_name, t2.name as team2_name FROM matches m JOIN teams t1 ON m.team1_id = t1.id JOIN teams t2 ON m.team2_id = t2.id ORDER BY m.date_played DESC").fetchall()
    conn.close()
    
    return render_template('scoreboard.html', teams=teams, matches=matches)

@app.route('/admin')
def admin():
    # VULNERABILITY: Broken Access Control - CRITICAL FLAW
    # No authentication check at all! Anyone (even unauthenticated) can access admin panel
    # The admin link is hidden in the UI, but the URL is completely unprotected
    # This allows privilege escalation from Public (Guest) to Admin
    
    conn = get_db_connection()
    teams = conn.execute("SELECT * FROM teams").fetchall()
    users = conn.execute("SELECT * FROM users WHERE is_admin = 0").fetchall()  # Get all team captains
    logs = conn.execute("SELECT * FROM system_logs ORDER BY log_date DESC LIMIT 50").fetchall()
    conn.close()
    
    # VULNERABILITY: Even if user is not logged in, they can access this page
    is_admin = session.get('is_admin', False)
    current_user = session.get('username', 'Guest')
    
    return render_template('admin.html', teams=teams, users=users, logs=logs, is_admin=is_admin, current_user=current_user)

@app.route('/admin/delete_team/<int:team_id>', methods=['POST'])
def delete_team(team_id):
    # VULNERABILITY: Broken Access Control - NO AUTHENTICATION CHECK!
    # Anyone can delete teams, even without being logged in
    # This is the main target for privilege escalation attacks
    
    conn = get_db_connection()
    # VULNERABILITY: SQL Injection - Direct string interpolation
    conn.execute(f"DELETE FROM teams WHERE id = {team_id}")
    
    # Log the action (but anyone can trigger it)
    username = session.get('username', 'Anonymous')
    conn.execute(f"INSERT INTO system_logs (log_message, log_type, log_date, user_id) VALUES ('Team {team_id} deleted by {username}', 'DELETE', datetime('now'), {session.get('user_id', 0)})")
    
    conn.commit()
    conn.close()
    flash('Team deleted successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    # VULNERABILITY: Broken Access Control - NO AUTHENTICATION CHECK!
    # Anyone can delete team captains (users), even without being logged in
    
    conn = get_db_connection()
    # VULNERABILITY: SQL Injection - Direct string interpolation
    # Also deletes associated team
    conn.execute(f"DELETE FROM teams WHERE captain_id = {user_id}")
    conn.execute(f"DELETE FROM users WHERE id = {user_id}")
    
    # Log the action
    username = session.get('username', 'Anonymous')
    conn.execute(f"INSERT INTO system_logs (log_message, log_type, log_date, user_id) VALUES ('User {user_id} deleted by {username}', 'DELETE', datetime('now'), {session.get('user_id', 0)})")
    
    conn.commit()
    conn.close()
    flash('User (Team Captain) deleted successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin/add_team', methods=['GET', 'POST'])
def add_team():
    # VULNERABILITY: Broken Access Control - Should check if user is admin
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        captain_id = request.form.get('captain_id')
        wins = request.form.get('wins', 0)
        losses = request.form.get('losses', 0)
        draws = request.form.get('draws', 0)
        
        conn = get_db_connection()
        # VULNERABILITY: SQL Injection - Direct string interpolation
        if captain_id and captain_id != 'None':
            query = f"INSERT INTO teams (name, description, captain_id, wins, losses, draws) VALUES ('{name}', '{description}', {captain_id}, {wins}, {losses}, {draws})"
        else:
            query = f"INSERT INTO teams (name, description, wins, losses, draws) VALUES ('{name}', '{description}', {wins}, {losses}, {draws})"
        
        conn.execute(query)
        
        # Log the action
        username = session.get('username', 'Anonymous')
        conn.execute(f"INSERT INTO system_logs (log_message, log_type, log_date, user_id) VALUES ('Team {name} added by {username}', 'CREATE', datetime('now'), {session.get('user_id', 0)})")
        
        conn.commit()
        conn.close()
        flash('Team added successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    # Get all users for captain selection
    conn = get_db_connection()
    users = conn.execute("SELECT * FROM users WHERE is_admin = 0 ORDER BY username").fetchall()
    conn.close()
    
    return render_template('add_team.html', users=users)

@app.route('/admin/modify_team/<int:team_id>', methods=['GET', 'POST'])
def modify_team(team_id):
    # VULNERABILITY: Broken Access Control - Should check if user is admin
    conn = get_db_connection()
    
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        captain_id = request.form.get('captain_id')
        wins = request.form.get('wins', 0)
        losses = request.form.get('losses', 0)
        draws = request.form.get('draws', 0)
        
        # VULNERABILITY: SQL Injection - Direct string interpolation
        if captain_id and captain_id != 'None':
            query = f"UPDATE teams SET name = '{name}', description = '{description}', captain_id = {captain_id}, wins = {wins}, losses = {losses}, draws = {draws} WHERE id = {team_id}"
        else:
            query = f"UPDATE teams SET name = '{name}', description = '{description}', captain_id = NULL, wins = {wins}, losses = {losses}, draws = {draws} WHERE id = {team_id}"
        
        conn.execute(query)
        
        # Log the action
        username = session.get('username', 'Anonymous')
        conn.execute(f"INSERT INTO system_logs (log_message, log_type, log_date, user_id) VALUES ('Team {team_id} ({name}) modified by {username}', 'UPDATE', datetime('now'), {session.get('user_id', 0)})")
        
        conn.commit()
        conn.close()
        flash('Team modified successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    team = conn.execute(f"SELECT * FROM teams WHERE id = {team_id}").fetchone()
    users = conn.execute("SELECT * FROM users WHERE is_admin = 0 ORDER BY username").fetchall()
    conn.close()
    
    if not team:
        flash('Team not found!', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('modify_team.html', team=team, users=users)

@app.route('/admin/add_match', methods=['GET', 'POST'])
def add_match():
    # VULNERABILITY: Broken Access Control - Should check if user is admin
    if request.method == 'POST':
        team1_id = request.form.get('team1_id')
        team2_id = request.form.get('team2_id')
        score1 = request.form.get('score1', 0)
        score2 = request.form.get('score2', 0)
        date_played = request.form.get('date_played')
        
        conn = get_db_connection()
        # VULNERABILITY: SQL Injection - Direct string interpolation
        query = f"INSERT INTO matches (team1_id, team2_id, score1, score2, date_played) VALUES ({team1_id}, {team2_id}, {score1}, {score2}, '{date_played}')"
        conn.execute(query)
        
        # Update team scores
        # VULNERABILITY: SQL Injection in score updates
        if int(score1) > int(score2):
            conn.execute(f"UPDATE teams SET wins = wins + 1 WHERE id = {team1_id}")
            conn.execute(f"UPDATE teams SET losses = losses + 1 WHERE id = {team2_id}")
        elif int(score2) > int(score1):
            conn.execute(f"UPDATE teams SET wins = wins + 1 WHERE id = {team2_id}")
            conn.execute(f"UPDATE teams SET losses = losses + 1 WHERE id = {team1_id}")
        else:
            conn.execute(f"UPDATE teams SET draws = draws + 1 WHERE id = {team1_id}")
            conn.execute(f"UPDATE teams SET draws = draws + 1 WHERE id = {team2_id}")
        
        # Log the action
        username = session.get('username', 'Anonymous')
        conn.execute(f"INSERT INTO system_logs (log_message, log_type, log_date, user_id) VALUES ('Match added: Team {team1_id} vs Team {team2_id} by {username}', 'CREATE', datetime('now'), {session.get('user_id', 0)})")
        
        conn.commit()
        conn.close()
        flash('Match added and scores updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    conn = get_db_connection()
    teams = conn.execute("SELECT * FROM teams ORDER BY name").fetchall()
    conn.close()
    
    return render_template('add_match.html', teams=teams)

@app.route('/admin/modify_match/<int:match_id>', methods=['GET', 'POST'])
def modify_match(match_id):
    # VULNERABILITY: Broken Access Control - Should check if user is admin
    conn = get_db_connection()
    
    if request.method == 'POST':
        team1_id = request.form.get('team1_id')
        team2_id = request.form.get('team2_id')
        score1 = request.form.get('score1', 0)
        score2 = request.form.get('score2', 0)
        date_played = request.form.get('date_played')
        
        # Get old match data to revert scores
        old_match = conn.execute(f"SELECT * FROM matches WHERE id = {match_id}").fetchone()
        
        # Revert old scores
        if old_match:
            old_score1 = old_match['score1']
            old_score2 = old_match['score2']
            old_team1 = old_match['team1_id']
            old_team2 = old_match['team2_id']
            
            if int(old_score1) > int(old_score2):
                conn.execute(f"UPDATE teams SET wins = wins - 1 WHERE id = {old_team1}")
                conn.execute(f"UPDATE teams SET losses = losses - 1 WHERE id = {old_team2}")
            elif int(old_score2) > int(old_score1):
                conn.execute(f"UPDATE teams SET wins = wins - 1 WHERE id = {old_team2}")
                conn.execute(f"UPDATE teams SET losses = losses - 1 WHERE id = {old_team1}")
            else:
                conn.execute(f"UPDATE teams SET draws = draws - 1 WHERE id = {old_team1}")
                conn.execute(f"UPDATE teams SET draws = draws - 1 WHERE id = {old_team2}")
        
        # VULNERABILITY: SQL Injection - Direct string interpolation
        query = f"UPDATE matches SET team1_id = {team1_id}, team2_id = {team2_id}, score1 = {score1}, score2 = {score2}, date_played = '{date_played}' WHERE id = {match_id}"
        conn.execute(query)
        
        # Update new scores
        if int(score1) > int(score2):
            conn.execute(f"UPDATE teams SET wins = wins + 1 WHERE id = {team1_id}")
            conn.execute(f"UPDATE teams SET losses = losses + 1 WHERE id = {team2_id}")
        elif int(score2) > int(score1):
            conn.execute(f"UPDATE teams SET wins = wins + 1 WHERE id = {team2_id}")
            conn.execute(f"UPDATE teams SET losses = losses + 1 WHERE id = {team1_id}")
        else:
            conn.execute(f"UPDATE teams SET draws = draws + 1 WHERE id = {team1_id}")
            conn.execute(f"UPDATE teams SET draws = draws + 1 WHERE id = {team2_id}")
        
        # Log the action
        username = session.get('username', 'Anonymous')
        conn.execute(f"INSERT INTO system_logs (log_message, log_type, log_date, user_id) VALUES ('Match {match_id} modified by {username}', 'UPDATE', datetime('now'), {session.get('user_id', 0)})")
        
        conn.commit()
        conn.close()
        flash('Match modified and scores updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    match = conn.execute(f"SELECT * FROM matches WHERE id = {match_id}").fetchone()
    teams = conn.execute("SELECT * FROM teams ORDER BY name").fetchall()
    conn.close()
    
    if not match:
        flash('Match not found!', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('modify_match.html', match=match, teams=teams)

@app.route('/admin/reset_scores', methods=['POST'])
def reset_scores():
    # VULNERABILITY: Broken Access Control - NO AUTHENTICATION CHECK!
    # Anyone can reset all league scores, even without being logged in
    
    conn = get_db_connection()
    conn.execute("UPDATE teams SET wins = 0, losses = 0, draws = 0")
    conn.execute("DELETE FROM matches")
    
    # Log the action
    username = session.get('username', 'Anonymous')
    conn.execute(f"INSERT INTO system_logs (log_message, log_type, log_date, user_id) VALUES ('All scores reset by {username}', 'RESET', datetime('now'), {session.get('user_id', 0)})")
    
    conn.commit()
    conn.close()
    flash('Scores reset successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin/logs')
def admin_logs():
    # VULNERABILITY: Broken Access Control - NO AUTHENTICATION CHECK!
    # Anyone can view system logs, even without being logged in
    # This reveals sensitive information about system activity
    
    conn = get_db_connection()
    logs = conn.execute("SELECT * FROM system_logs ORDER BY log_date DESC LIMIT 100").fetchall()
    conn.close()
    
    return render_template('admin_logs.html', logs=logs)

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected!', 'error')
            return redirect(url_for('upload_file'))
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected!', 'error')
            return redirect(url_for('upload_file'))
        
        # VULNERABILITY: File Upload RCE - No proper validation
        # Allows dangerous file types and doesn't sanitize properly
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # VULNERABILITY: Using original filename can lead to path traversal
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            # VULNERABILITY: Storing file with original extension allows execution
            conn = get_db_connection()
            conn.execute(f"INSERT INTO uploads (filename, original_filename, user_id, upload_date) VALUES ('{filename}', '{file.filename}', {session['user_id']}, datetime('now'))")
            conn.commit()
            conn.close()
            
            flash(f'File uploaded successfully: {filename}', 'success')
            return redirect(url_for('upload_file'))
        else:
            flash('Invalid file type!', 'error')
    
    conn = get_db_connection()
    uploads = conn.execute(f"SELECT * FROM uploads WHERE user_id = {session['user_id']}").fetchall()
    conn.close()
    
    return render_template('upload.html', uploads=uploads)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    # VULNERABILITY: File Upload RCE - Serves files without proper validation
    # Can execute uploaded scripts if accessed directly
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

def allowed_file(filename):
    # VULNERABILITY: File Upload RCE - Allows dangerous extensions
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/user')
def api_user():
    # VULNERABILITY: JWT Misconfiguration - Weak validation, no expiration check
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        # Try to get from session
        token = session.get('jwt_token')
    
    if not token:
        return {'error': 'No token provided'}, 401
    
    try:
        # VULNERABILITY: No algorithm specification, accepts any algorithm
        # VULNERABILITY: No expiration validation
        payload = jwt.decode(token, app.config['JWT_SECRET'], algorithms=['HS256', 'none'])
        return {'user_id': payload['user_id'], 'username': payload['username'], 'is_admin': payload.get('is_admin', 0)}
    except jwt.InvalidTokenError:
        # VULNERABILITY: Try with 'none' algorithm if HS256 fails
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            return {'user_id': payload['user_id'], 'username': payload['username'], 'is_admin': payload.get('is_admin', 0), 'warning': 'Token signature not verified'}
        except:
            return {'error': 'Invalid token'}, 401

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)  # VULNERABILITY: Debug mode and binding to all interfaces

