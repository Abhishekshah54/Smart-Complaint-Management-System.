from flask import Flask, render_template, request, redirect, session, url_for, flash
import sqlite3, os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from datetime import datetime ,timedelta
import smtplib
from email.mime.text import MIMEText
from functools import wraps
from flask import make_response
import csv
import io
from io import StringIO
from io import BytesIO
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from PyPDF2 import PdfReader, PdfWriter
from reportlab.lib.utils import ImageReader
from reportlab.platypus.flowables import KeepTogether
from PIL import Image
import pytz

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this to a strong secret key
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size

# Email configuration (example using Gmail)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_app_password'

# Create upload folder if it doesn't exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

def init_db():
    conn = sqlite3.connect('complaint.db')
    c = conn.cursor()
    
    # Users table 
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        phone TEXT,
        created_at TEXT DEFAULT (datetime('now', '+5 hours', '+30 minutes'))
        )''')

    # Updated Complaints table - matches your form exactly
    c.execute('''CREATE TABLE IF NOT EXISTS complaints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        tracking_id TEXT UNIQUE,
        department TEXT NOT NULL,
        category TEXT NOT NULL,
        priority TEXT,
        city TEXT NOT NULL,
        pincode TEXT NOT NULL, 
        locality TEXT NOT NULL,
        landmark TEXT,
        status TEXT DEFAULT 'Pending',
        image TEXT,
        description TEXT,
        rating INTEGER,      
        created_at TEXT DEFAULT (datetime('now', '+5 hours', '+30 minutes')),
        updated_at TEXT DEFAULT (datetime('now', '+5 hours', '+30 minutes')),
        FOREIGN KEY(user_id) REFERENCES users(id))''')
    
    # Complaint updates table (unchanged)
    c.execute('''CREATE TABLE IF NOT EXISTS complaint_updates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        complaint_id INTEGER,
        user_id INTEGER,
        comment TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now', '+5 hours', '+30 minutes')),
        FOREIGN KEY(complaint_id) REFERENCES complaints(id),
        FOREIGN KEY(user_id) REFERENCES users(id))''')
    
     # Create admins table with is_superadmin flag
    c.execute('''CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        phone TEXT CHECK(length(phone) = 10 AND phone GLOB '[0-9]*'),
        password TEXT NOT NULL,
        is_superadmin INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now', '+5 hours', '+30 minutes'))
            )''')
    
    c.execute("""
            CREATE TABLE IF NOT EXISTS admin_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                created_at TEXT DEFAULT (datetime('now', '+5 hours', '+30 minutes'))
            )
        """)
    
    # Add departments table
    c.execute('''CREATE TABLE IF NOT EXISTS departments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        email TEXT,
        phone TEXT,
        created_at TEXT DEFAULT (datetime('now', '+5 hours', '+30 minutes'))
    )''')
    
    # Add department-category mapping table
    c.execute('''CREATE TABLE IF NOT EXISTS department_categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        department_id INTEGER NOT NULL,
        category TEXT NOT NULL,
        FOREIGN KEY(department_id) REFERENCES departments(id),
        UNIQUE(department_id, category)
    )''')
    
    # Add department admins table
    c.execute('''CREATE TABLE IF NOT EXISTS department_admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        department_id INTEGER NOT NULL,
        admin_id INTEGER NOT NULL,
        FOREIGN KEY(department_id) REFERENCES departments(id),
        FOREIGN KEY(admin_id) REFERENCES admins(id),
        UNIQUE(department_id, admin_id)
    )''')
    
    # Add department assignment to complaints
    # c.execute('''ALTER TABLE complaints ADD COLUMN department_id INTEGER REFERENCES departments(id)''')
    
    # Create default departments if they don't exist
    default_departments = [
        ('Water Department', 'water@example.com', '1234567890'),
        ('Electricity Department', 'electricity@example.com', '1234567891'),
        ('Sanitation Department', 'sanitation@example.com', '1234567892'),
        ('Roads Department', 'roads@example.com', '1234567893'),
        ('Public Works', 'publicworks@example.com', '1234567894'),
        ('Traffic Department', 'traffic@example.com', '1234567895'),
        ('Health Department', 'health@example.com', '1234567896'),
        ('Education Department', 'education@example.com', '1234567897'),
        ('Fire and Emergency Services', 'firedept@example.com', '1234567898'),
        ('Parks and Recreation', 'parks@example.com', '1234567899'),
        ('Building and Construction', 'buildings@example.com', '1234567800'),
        ('Transport Department', 'transport@example.com', '1234567801'),
        ('Environment Department', 'environment@example.com', '1234567802'),
        ('Municipal Tax Department', 'taxdept@example.com', '1234567803'),
        ('Animal Control Department', 'animalcontrol@example.com', '1234567804')
    ]
    
    default_categories = {
        'Water Department': ['Water Supply', 'Leakage', 'Water Quality'],
        'Electricity Department': ['Power Outage', 'Street Lights', 'Electrical Hazard'],
        'Sanitation Department': ['Garbage Collection', 'Drainage', 'Public Cleanliness'],
        'Roads Department': ['Potholes', 'Road Repair', 'Traffic Signals'],
        'Public Works': ['Public Buildings', 'Parks', 'Other Infrastructure'],
        'Traffic Department': ['Illegal Parking', 'Signal Malfunction', 'Traffic Congestion'],
        'Health Department': ['Mosquito Breeding', 'Clinic Issues', 'Unhygienic Conditions'],
        'Education Department': ['School Facilities', 'Midday Meals', 'Teacher Absence'],
        'Fire and Emergency Services': ['Fire Safety Violation', 'Blocked Exits', 'Emergency Delay'],
        'Parks and Recreation': ['Park Maintenance', 'Playground Safety', 'Unauthorized Activities'],
        'Building and Construction': ['Unauthorized Construction', 'Noise Complaint', 'Building Violation'],
        'Transport Department': ['Bus Delay', 'Auto Rickshaw Issues', 'Poor Public Transport'],
        'Environment Department': ['Pollution', 'Tree Cutting', 'Waste Burning'],
        'Municipal Tax Department': ['Property Tax Dispute', 'Billing Issues', 'Duplicate Notice'],
        'Animal Control Department': ['Stray Dog Issue', 'Animal Cruelty', 'Dead Animal Removal']
    }
    
    # Create initial super admin if doesn't exist
    try:
        c.execute("SELECT 1 FROM admins WHERE email = ?", ('rmc@admin.com',))
        if not c.fetchone():
            hashed_pw = generate_password_hash('admin123')
            c.execute("""
                INSERT INTO admins (name, email, phone, password, is_superadmin)
                VALUES (?, ?, ?, ?, ?)
            """, ('Super Admin', 'rmc@admin.com', '9988776655', hashed_pw, 1))
        conn.commit()
        print("Admin inserted successfully.")

    except Exception as e:
        print(f"Error creating initial admin: {e}")
        conn.rollback()

    try:
        for dept in default_departments:
            c.execute("SELECT 1 FROM departments WHERE name = ?", (dept[0],))
            if not c.fetchone():
                c.execute("INSERT INTO departments (name, email, phone) VALUES (?, ?, ?)", dept)
        
        # Add category mappings
        for dept_name, categories in default_categories.items():
            c.execute("SELECT id FROM departments WHERE name = ?", (dept_name,))
            dept_id = c.fetchone()[0]
            
            for category in categories:
                c.execute("SELECT 1 FROM department_categories WHERE department_id = ? AND category = ?", 
                         (dept_id, category))
                if not c.fetchone():
                    c.execute("INSERT INTO department_categories (department_id, category) VALUES (?, ?)", 
                             (dept_id, category))
                    
        conn.commit()
    except Exception as e:
        print(f"Error setting up departments: {e}")
        conn.rollback()
    

    conn.commit()
    conn.close()

init_db()

# Helper functions
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def send_email(to_email, subject, body):
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = app.config['MAIL_USERNAME']
        msg['To'] = to_email
        
        with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as server:
            server.starttls()
            server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def is_logged_in_admin():
    return session.get('admin', False)

def is_superadmin():
    return session.get('is_superadmin', False)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session and 'admin' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin'):
            flash('Please log in as admin to access this page', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def superadmin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_superadmin'):
            flash('Superadmin privileges required', 'danger')
            return redirect(url_for('admin_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('user/Users_dashboard'))
    elif 'is_superadmin' in session:
        if session['is_superadmin'] == 1:
            return redirect(url_for('Superadmin_dashboard'))
        else:
            return redirect(url_for('admin_dashboard'))
        
    return render_template('index.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        phone = request.form.get('phone', '')
        
        try:
            with sqlite3.connect('complaint.db') as conn:
                c = conn.cursor()
                c.execute("INSERT INTO users (name, email, password, phone) VALUES (?, ?, ?, ?)",
                          (name, email, password, phone))
                conn.commit()
            
            # Send welcome email
            send_email(email, "Welcome to Complaint Management System",
                      f"Hello {name},\n\nThank you for registering with our complaint management system.")
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already exists. Please use a different email.', 'danger')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # Hardcoded Admin (fallback or default)
        if email == "rmc@admin.com" and password == "admin123":
            session.clear()
            session['admin'] = True
            session['admin_name'] = 'Main Admin'
            session['is_superadmin'] = True
            session['admin_id'] = 0
            flash('Superadmin login successful!', 'success')
            return redirect(url_for('Superadmin_dashboard'))
        
        with sqlite3.connect('complaint.db') as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            # Check for admin in DB
            c.execute("SELECT * FROM admins WHERE email = ?", (email,))
            admin = c.fetchone()
            
            if admin and check_password_hash(admin['password'], password):
                session.clear()
                session['admin'] = True
                session['admin_id'] = admin['id']
                session['admin_name'] = admin['name']
                session['is_superadmin'] = bool(admin['is_superadmin'])
                flash('Admin login successful!', 'success')
                return redirect(url_for('admin_dashboard'))

            # Check for user
            c.execute("SELECT * FROM users WHERE email = ?", (email,))
            user = c.fetchone()
            
            if user and check_password_hash(user['password'], password):
                session.clear()
                session['user_id'] = user['id']
                session['user_name'] = user['name']
                session['user_email'] = user['email']
                flash('Login successful!', 'success')
                return redirect(url_for('Users_dashboard'))

        flash('Invalid email or password', 'danger')
    
    return render_template('login.html')

import sqlite3
from werkzeug.security import generate_password_hash

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Validate inputs
        if not all([email, name, new_password, confirm_password]):
            flash('All fields are required!', 'danger')
            return redirect(url_for('reset_password'))

        if new_password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('reset_password'))

        if len(new_password) < 8:
            flash('Password must be at least 8 characters long!', 'danger')
            return redirect(url_for('reset_password'))

        try:
            # Connect to complaint.db
            conn = sqlite3.connect('complaint.db')
            cursor = conn.cursor()

            # Check if user exists
            cursor.execute('SELECT * FROM users WHERE email = ? AND name = ?', (email, name))
            user = cursor.fetchone()

            if user:
                # Update password
                hashed_password = generate_password_hash(new_password)
                cursor.execute('UPDATE users SET password = ? WHERE email = ?', 
                             (hashed_password, email))
                conn.commit()
                flash('Password updated successfully! You can now login.', 'success')
                return redirect(url_for('login'))
            else:
                flash('No user found with that email and name combination.', 'danger')

        except sqlite3.Error as e:
            flash('An error occurred. Please try again.', 'danger')
            print(f"Database error: {e}")
        finally:
            if conn:
                conn.close()

    return render_template('reset_password.html')

@app.route('/dashboard' , methods=['GET'])
@login_required
def Users_dashboard():
    page = request.args.get('page', 1, type=int)
    per_page = 5
    offset = (page - 1) * per_page
    
    with sqlite3.connect('complaint.db') as conn:
        c = conn.cursor()
        
        # Get total complaints count
        c.execute("SELECT COUNT(*) FROM complaints WHERE user_id=?", (session['user_id'],))
        total = c.fetchone()[0]
        
        # Get paginated complaints
        c.execute("""
            SELECT c.*, COUNT(u.id) as update_count 
            FROM complaints c 
            LEFT JOIN complaint_updates u ON c.id = u.complaint_id 
            WHERE c.user_id=? 
            GROUP BY c.id 
            ORDER BY c.created_at DESC 
            LIMIT ? OFFSET ?
        """, (session['user_id'], per_page, offset))
        complaints = c.fetchall()
        
        # Get stats for dashboard
        c.execute("""
            SELECT status, COUNT(*) 
            FROM complaints 
            WHERE user_id=? 
            GROUP BY status
        """, (session['user_id'],))
        stats = dict(c.fetchall())
    
    return render_template('user/dashboard.html', 
                         complaints=complaints,
                         stats=stats,
                         page=page,
                         per_page=per_page,
                         total=total)

@app.route('/delete_complaint/<int:complaint_id>', methods=['POST'])
@login_required
def delete_complaint(complaint_id):
    with sqlite3.connect('complaint.db') as conn:
        c = conn.cursor()
        
        # First verify the complaint belongs to the user
        c.execute("SELECT user_id FROM complaints WHERE id=?", (complaint_id,))
        result = c.fetchone()
        
        if not result or result[0] != session['user_id']:
            flash('You cannot delete this complaint', 'danger')
            return redirect(url_for('Users_dashboard'))
        
        # Delete the complaint (and any related updates due to ON DELETE CASCADE)
        c.execute("DELETE FROM complaints WHERE id=?", (complaint_id,))
        conn.commit()
    
    flash('Complaint deleted successfully', 'success')
    return redirect(url_for('Users_dashboard'))

@app.route('/rate/<tracking_id>', methods=['POST'])
def rate_complaint(tracking_id):
    rating = request.form.get('rating')
    if not rating:
        return redirect(url_for('Users_dashboard'))

    try:
        rating = int(rating)
    except ValueError:
        return redirect(url_for('Users_dashboard'))

    conn = sqlite3.connect('complaint.db')
    c = conn.cursor()
    c.execute(
        "UPDATE complaints SET rating = ? WHERE tracking_id = ?",
        (rating, tracking_id)
    )
    conn.commit()
    conn.close()

    flash(f"Thank you for rating complaint {tracking_id} with {rating} Stars!", "success")
    return redirect(url_for('Users_dashboard'))

@app.route('/get_categories')
def get_categories_user():
    department_id = request.args.get('department_id')
    if not department_id:
        return ({'error': 'Department ID is required'})
    
    conn = sqlite3.connect('complaint.db')
    cursor = conn.cursor()
    
    try:
        # Get department info
        cursor.execute("SELECT name, email, phone FROM departments WHERE id = ?", (department_id,))
        dept_data = cursor.fetchone()
        if not dept_data:
            return ({'error': 'Department not found'})
        
        # Get categories for this department
        cursor.execute("""
            SELECT id, category 
            FROM department_categories 
            WHERE department_id = ?
            ORDER BY category
        """, (department_id,))
        categories = [{'id': row[0], 'name': row[1]} for row in cursor.fetchall()]
        
        # Get department description (you might want to add this field to your departments table)
        # For now, we'll use a generic description
        dept_description = f"Handles all {dept_data[0]} related complaints"
        
        return ({
            'department_id': department_id,
            'categories': categories,
            'department_name': dept_data[0],
            'department_description': dept_description,
            'department_resolution_time': '2-5 working days'  # Could be department-specific
        })
    except Exception as e:
        print(f"Error fetching categories: {e}")
        return ({'error': 'Failed to fetch categories'})
    finally:
        conn.close()

@app.route('/file_complaint', methods=['GET', 'POST'])
@login_required
def file_complaint():
    if request.method == 'POST':
        try:
            # Get form data
            department_id = request.form['department']
            category = request.form['category']
            city = request.form['city']
            pincode = request.form['pincode']
            locality = request.form['locality']
            landmark = request.form.get('landmark', '')
            description = request.form['description']
            priority = request.form['priority'] 
            image = request.files['image']

            # Validate
            if not all([department_id, category, city, pincode, locality, description, priority]):
                flash('Please fill all required fields', 'danger')
                return redirect(url_for('file_complaint'))

            # Handle file upload
            image_filename = None
            if image and image.filename:
                if not allowed_file(image.filename):
                    flash('Invalid file type', 'danger')
                    return redirect(url_for('file_complaint'))
                
                # Get the next sequence number
                with sqlite3.connect('complaint.db') as conn:
                    c = conn.cursor()
                    c.execute("SELECT COUNT(*) FROM complaints")
                    count = c.fetchone()[0]
                    sequence_num = count + 1
                
                # Generate sequential filename
                file_ext = os.path.splitext(image.filename)[1]
                image_filename = f"COMP_{sequence_num:05d}{file_ext}"  # Formats as COMP_00001.jpg
                image_filename = secure_filename(image_filename)
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))

            # Generate tracking ID
            tracking_id = f"COMP-{uuid.uuid4().hex[:8].upper()}"
            
            # Get current timestamp
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            # Get department info
            with sqlite3.connect('complaint.db') as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                c.execute("SELECT id, name, email FROM departments WHERE id = ?", (department_id,))
                department_info = c.fetchone()

            if not department_info:
                flash('Invalid department selected', 'danger')
                return redirect(url_for('file_complaint'))

            # Insert into database
            with sqlite3.connect('complaint.db') as conn:
                c = conn.cursor()
                c.execute("""
                    INSERT INTO complaints 
                    (user_id, tracking_id, department, category, priority, city, pincode, locality, 
                     landmark, description, image, created_at) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    session['user_id'], tracking_id, department_info['name'], category, priority, city, pincode,
                    locality, landmark, description, image_filename, current_time
                ))
                conn.commit()
            
            flash(f'Complaint filed successfully at {current_time}! ', 'success')
            return redirect(url_for('Users_dashboard'))

        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
            return redirect(url_for('file_complaint'))

    # For GET request - fetch departments for dropdown
    with sqlite3.connect('complaint.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Get all departments
        c.execute("SELECT id, name FROM departments ORDER BY name")
        departments = c.fetchall()
    
    return render_template('user/file_complaint.html', departments=departments)

@app.route('/complaint/<tracking_id>')
@login_required
def view_complaint(tracking_id):
    with sqlite3.connect('complaint.db') as conn:
        conn.row_factory = sqlite3.Row  # This enables dictionary-style access
        c = conn.cursor()
        
        # Get complaint details - simplified to use the department name stored in complaints table
        c.execute("""
            SELECT c.*, u.name as user_name 
            FROM complaints c 
            JOIN users u ON c.user_id = u.id 
            WHERE c.tracking_id = ? AND (c.user_id = ? OR ?)
        """, (tracking_id, session.get('user_id', 0), session.get('admin', False)))
        complaint = c.fetchone()
        
        if not complaint:
            flash('Complaint not found or unauthorized access', 'danger')
            return redirect(url_for('Users_dashboard'))
        
        # Get updates/comments - modified to handle missing role column
        try:
            c.execute("""
                SELECT u.comment, u.created_at, us.name, us.role 
                FROM complaint_updates u 
                JOIN users us ON u.user_id = us.id 
                WHERE u.complaint_id = ? 
                ORDER BY u.created_at DESC
            """, (complaint['id'],))
        except sqlite3.OperationalError:
            # Fallback if role column doesn't exist
            c.execute("""
                SELECT u.comment, u.created_at, us.name, 'user' as role 
                FROM complaint_updates u 
                JOIN users us ON u.user_id = us.id 
                WHERE u.complaint_id = ? 
                ORDER BY u.created_at DESC
            """, (complaint['id'],))
            
        updates = c.fetchall()
    
    return render_template('admin/view_complaint.html', complaint=complaint, updates=updates)

@app.route('/reraise_complaint/<tracking_id>')
@login_required
def reraise_complaint(tracking_id):
    # Fetch the original complaint
    with sqlite3.connect('complaint.db') as conn:
        c = conn.cursor()
        c.execute("""
            SELECT * FROM complaints 
            WHERE tracking_id = ? AND user_id = ?
        """, (tracking_id, session['user_id']))
        original_complaint = c.fetchone()
        
        if not original_complaint:
            flash('Complaint not found or unauthorized access', 'danger')
            return redirect(url_for('Users_dashboard'))
        
        # Generate new tracking ID
        new_tracking_id = f"COMP-{uuid.uuid4().hex[:8].upper()}"
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Create new complaint based on original
        c.execute("""
            INSERT INTO complaints 
            (user_id, tracking_id, department, category, priority, city, pincode, locality, 
             landmark, description, status, rating, created_at) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending', ?, ?)
        """, (
            session['user_id'], 
            new_tracking_id, 
            original_complaint[3],  # department
            original_complaint[4],  # category
            original_complaint[5],  # priority
            original_complaint[6],  # city
            original_complaint[7],  # pincode
            original_complaint[8],  # locality
            original_complaint[9],  # landmark

            f"[Re-raised from {tracking_id}]\n{original_complaint[12]}",  # description
            original_complaint[13], #rating 
            current_time
        ))
        conn.commit()
        
        # Add note about re-raising
        new_complaint_id = c.lastrowid
        c.execute("""
            INSERT INTO complaint_updates (complaint_id, user_id, comment)
            VALUES (?, ?, ?)
        """, (new_complaint_id, session['user_id'], 
              f"Complaint re-raised from {tracking_id}"))
        conn.commit()
    
    flash(f'Complaint re-raised successfully with new Tracking ID: {new_tracking_id}', 'success')
    return redirect(url_for('view_complaint', tracking_id=new_tracking_id))

@app.route('/add_comment/<tracking_id>', methods=['POST'])
@login_required
def add_comment(tracking_id):
    comment = request.form.get('comment')
    
    if not comment:
        flash('Comment cannot be empty', 'danger')
        return redirect(url_for('view_complaint', tracking_id=tracking_id))
    
    with sqlite3.connect('complaint.db') as conn:
        c = conn.cursor()
        
        # Get complaint ID
        c.execute("SELECT id FROM complaints WHERE tracking_id = ?", (tracking_id,))
        complaint = c.fetchone()
        
        if not complaint:
            flash('Complaint not found', 'danger')
            return redirect(url_for('dashboard'))
        
        # Add comment
        c.execute("""
            INSERT INTO complaint_updates (complaint_id, user_id, comment) 
            VALUES (?, ?, ?)
        """, (complaint[0], session['user_id'], comment))
        conn.commit()
        
        flash('Comment added successfully', 'success')
        return redirect(url_for('view_complaint', tracking_id=tracking_id))

@app.route('/Superadmin_dashboard')
@superadmin_required
def Superadmin_dashboard():
    # Get stats for cards
    with sqlite3.connect('complaint.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # For regular admins, only show their department stats
        if not session.get('is_superadmin'):
            # Get admin's departments
            c.execute("""
                SELECT d.id, d.name 
                FROM department_admins da
                JOIN departments d ON da.department_id = d.id
                WHERE da.admin_id = ?
            """, (session['admin_id'],))
            admin_depts = c.fetchall()
            
            dept_names = [dept['name'] for dept in admin_depts]
            
            if dept_names:
                # Get stats for admin's departments
                c.execute("""
                    SELECT status, COUNT(*) 
                    FROM complaints 
                    WHERE department IN (%s)
                    GROUP BY status
                """ % ','.join(['?']*len(dept_names)), dept_names)
                stats = dict(c.fetchall())
                
                # Get top 5 recent complaints for their departments
                c.execute("""
                    SELECT c.*, u.name as user_name 
                    FROM complaints c 
                    JOIN users u ON c.user_id = u.id 
                    WHERE c.department IN (%s)
                    ORDER BY c.created_at DESC 
                    LIMIT 5
                """ % ','.join(['?']*len(dept_names)), dept_names)
                top_complaints = c.fetchall()
            else:
                # Admin has no departments assigned
                stats = {}
                top_complaints = []
        else:
            # Superadmin sees all stats
            c.execute("SELECT status, COUNT(*) FROM complaints GROUP BY status")
            stats = dict(c.fetchall())
            
            # Get top 5 recent complaints
            c.execute("""
                SELECT c.*, u.name as user_name 
                FROM complaints c 
                JOIN users u ON c.user_id = u.id 
                ORDER BY c.created_at DESC 
                LIMIT 5
            """)
            top_complaints = c.fetchall()
        
        # Get filter options for the manage page link
        if session.get('is_superadmin'):
            c.execute("SELECT DISTINCT status FROM complaints ORDER BY status")
            statuses = [row[0] for row in c.fetchall()]
            
            c.execute("SELECT DISTINCT category FROM complaints ORDER BY category")
            categories = [row[0] for row in c.fetchall()]
            
            c.execute("SELECT DISTINCT city FROM complaints ORDER BY city")
            cities = [row[0] for row in c.fetchall()]
        else:
            # For regular admins, only show options from their departments
            if dept_names:
                c.execute("""
                    SELECT DISTINCT status 
                    FROM complaints 
                    WHERE department IN (%s)
                    ORDER BY status
                """ % ','.join(['?']*len(dept_names)), dept_names)
                statuses = [row[0] for row in c.fetchall()]
                
                c.execute("""
                    SELECT DISTINCT category 
                    FROM complaints 
                    WHERE department IN (%s)
                    ORDER BY category
                """ % ','.join(['?']*len(dept_names)), dept_names)
                categories = [row[0] for row in c.fetchall()]
                
                c.execute("""
                    SELECT DISTINCT city 
                    FROM complaints 
                    WHERE department IN (%s)
                    ORDER BY city
                """ % ','.join(['?']*len(dept_names)), dept_names)
                cities = [row[0] for row in c.fetchall()]
            else:
                statuses = []
                categories = []
                cities = []
    
    return render_template('admin/Superadmin_dashboard.html',
                         top_complaints=top_complaints,
                         statuses=statuses,
                         categories=categories,
                         cities=cities,
                         stats=stats)

@app.route('/admin_dashboard')
@admin_required
def admin_dashboard():
    with sqlite3.connect('complaint.db') as conn:
        conn.row_factory = sqlite3.Row  # Enable dictionary-like access
        cursor = conn.cursor()
        
        # Get admin's assigned departments
        cursor.execute("""
            SELECT d.id, d.name
            FROM department_admins da
            JOIN departments d ON da.department_id = d.id
            WHERE da.admin_id = ?
        """, (session['admin_id'],))
        admin_depts = cursor.fetchall()
        
        dept_names = [dept['name'] for dept in admin_depts]
        
        if dept_names:
            # Get stats for admin's departments
            cursor.execute(f"""
                SELECT status, COUNT(*) as count
                FROM complaints 
                WHERE department IN ({','.join(['?']*len(dept_names))})
                GROUP BY status
            """, dept_names)
            
            stats_result = cursor.fetchall()
            stats = {row['status']: row['count'] for row in stats_result}
            
            # Get top 5 recent complaints for their departments
            cursor.execute(f"""
                SELECT c.*, u.name as user_name 
                FROM complaints c 
                JOIN users u ON c.user_id = u.id 
                WHERE c.department IN ({','.join(['?']*len(dept_names))})
                ORDER BY c.created_at DESC 
                LIMIT 5
            """, dept_names)
            top_complaints = cursor.fetchall()
            
            # Get filter options
            cursor.execute(f"""
                SELECT DISTINCT status 
                FROM complaints 
                WHERE department IN ({','.join(['?']*len(dept_names))})
                ORDER BY status
            """, dept_names)
            statuses = [row['status'] for row in cursor.fetchall()]
            
            cursor.execute(f"""
                SELECT DISTINCT category 
                FROM complaints 
                WHERE department IN ({','.join(['?']*len(dept_names))})
                ORDER BY category
            """, dept_names)
            categories = [row['category'] for row in cursor.fetchall()]
            
            cursor.execute(f"""
                SELECT DISTINCT city 
                FROM complaints 
                WHERE department IN ({','.join(['?']*len(dept_names))})
                ORDER BY city
            """, dept_names)
            cities = [row['city'] for row in cursor.fetchall()]
        else:
            stats = {}
            top_complaints = []
            statuses = []
            categories = []
            cities = []
    
    return render_template('admin/admin_dashboard.html',
                         top_complaints=top_complaints,
                         statuses=statuses,
                         categories=categories,
                         cities=cities,
                         stats=stats,
                         admin_depts=admin_depts)

@app.route('/manage_complaints')
@admin_required
def manage_complaints():
    # Existing filters
    status_filter = request.args.get('status', '')
    category_filter = request.args.get('category', '')
    city_filter = request.args.get('city', '')
    search_query = request.args.get('search', '')
    tracking_id_query = request.args.get('tracking_id', '')
    time_period = request.args.get('time_period', '')
    
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page
    
    # Build query
    query = """
        SELECT c.*, u.name as user_name 
        FROM complaints c 
        JOIN users u ON c.user_id = u.id 
        WHERE 1=1
    """
    params = []
    
    # For regular admins, filter by their departments
    if not session.get('is_superadmin'):
        with sqlite3.connect('complaint.db') as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("""
                SELECT d.name 
                FROM department_admins da
                JOIN departments d ON da.department_id = d.id
                WHERE da.admin_id = ?
            """, (session['admin_id'],))
            admin_depts = [row['name'] for row in c.fetchall()]
            
        if admin_depts:
            query += " AND c.department IN (%s)" % ','.join(['?']*len(admin_depts))
            params.extend(admin_depts)
        else:
            # Admin has no departments assigned - show nothing
            query += " AND 1=0"
    
    # Existing filter conditions
    if status_filter:
        query += " AND c.status = ?"
        params.append(status_filter)
    
    if category_filter:
        query += " AND c.category = ?"
        params.append(category_filter)
    
    if city_filter:
        query += " AND c.city = ?"
        params.append(city_filter)
    
    if search_query:
        query += " AND (c.description LIKE ? OR u.name LIKE ?)"
        params.extend([f"%{search_query}%", f"%{search_query}%"])
    
    if tracking_id_query:
        query += " AND c.tracking_id LIKE ?"
        params.append(f"%{tracking_id_query}%")
    
    # Add time period filter
    if time_period:
        today = datetime.now().date()
        if time_period == 'today':
            query += " AND DATE(c.created_at) = ?"
            params.append(today)
        elif time_period == 'week':
            query += " AND c.created_at >= ?"
            params.append(today - timedelta(days=7))
        elif time_period == 'month':
            query += " AND c.created_at >= ?"
            params.append(today - timedelta(days=30))
    
    # Add sorting and pagination
    query += " ORDER BY c.created_at DESC LIMIT ? OFFSET ?"
    params.extend([per_page, offset])
    
    with sqlite3.connect('complaint.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Get filtered complaints
        c.execute(query, params)
        complaints = c.fetchall()
        
        # Get total count for pagination - must match the WHERE conditions exactly
        count_query = "SELECT COUNT(*) FROM complaints c JOIN users u ON c.user_id = u.id WHERE 1=1"
        count_params = []
        
        # Add department filter for regular admins
        if not session.get('is_superadmin') and admin_depts:
            count_query += " AND c.department IN (%s)" % ','.join(['?']*len(admin_depts))
            count_params.extend(admin_depts)
        
        if status_filter:
            count_query += " AND c.status = ?"
            count_params.append(status_filter)
        
        if category_filter:
            count_query += " AND c.category = ?"
            count_params.append(category_filter)
        
        if city_filter:
            count_query += " AND c.city = ?"
            count_params.append(city_filter)
        
        if search_query:
            count_query += " AND (c.description LIKE ? OR u.name LIKE ?)"
            count_params.extend([f"%{search_query}%", f"%{search_query}%"])
        
        if tracking_id_query:
            count_query += " AND c.tracking_id LIKE ?"
            count_params.append(f"%{tracking_id_query}%")
        
        # Add time period filter to count query
        if time_period:
            today = datetime.now().date()
            if time_period == 'today':
                count_query += " AND DATE(c.created_at) = ?"
                count_params.append(today)
            elif time_period == 'week':
                count_query += " AND c.created_at >= ?"
                count_params.append(today - timedelta(days=7))
            elif time_period == 'month':
                count_query += " AND c.created_at >= ?"
                count_params.append(today - timedelta(days=30))
        
        c.execute(count_query, count_params)
        total = c.fetchone()[0]
        
        # Get filter options
        c.execute("SELECT DISTINCT status FROM complaints ORDER BY status")
        statuses = [row[0] for row in c.fetchall()]
        
        c.execute("SELECT DISTINCT category FROM complaints ORDER BY category")
        categories = [row[0] for row in c.fetchall()]
        
        c.execute("SELECT DISTINCT city FROM complaints ORDER BY city")
        cities = [row[0] for row in c.fetchall()]
    
    return render_template('admin/manage_complaints.html',
                         complaints=complaints,
                         statuses=statuses,
                         categories=categories,
                         cities=cities,
                         current_status=status_filter,
                         current_category=category_filter,
                         current_city=city_filter,
                         search_query=search_query,
                         tracking_id=tracking_id_query,
                         time_period=time_period,
                         page=page,
                         per_page=per_page,
                         total=total)

@app.route('/bulk-update-status', methods=['POST'])
@admin_required
def bulk_update_status():
    new_status = request.form.get('bulk_status')
    select_all = request.form.get('select_all') == '1'
    
    # Get current filter parameters
    status_filter = request.form.get('status', '')
    category_filter = request.form.get('category', '')
    city_filter = request.form.get('city', '')
    search_query = request.form.get('search', '')
    tracking_id_query = request.form.get('tracking_id', '')
    
    with sqlite3.connect('complaint.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        if select_all:
            # Get all tracking IDs based on current filters
            query = "SELECT tracking_id FROM complaints WHERE 1=1"
            params = []
            
            if status_filter:
                query += " AND status = ?"
                params.append(status_filter)
            
            if category_filter:
                query += " AND category = ?"
                params.append(category_filter)
            
            if city_filter:
                query += " AND city = ?"
                params.append(city_filter)
            
            if search_query:
                query += " AND description LIKE ?"
                params.append(f"%{search_query}%")
            
            if tracking_id_query:
                query += " AND tracking_id LIKE ?"
                params.append(f"%{tracking_id_query}%")
            
            c.execute(query, params)
            tracking_ids = [row[0] for row in c.fetchall()]
        else:
            # Get selected tracking IDs from form
            tracking_ids = request.form.getlist('tracking_ids')
        
        if not tracking_ids:
            flash('No complaints selected', 'warning')
            return redirect_to_proper_dashboard(status_filter, category_filter, city_filter, search_query, tracking_id_query)
        
        # Update status for all selected complaints
        update_query = "UPDATE complaints SET status = ? WHERE tracking_id = ?"
        for tracking_id in tracking_ids:
            c.execute(update_query, (new_status, tracking_id))
            
            # Get complaint ID for adding update comment
            c.execute("SELECT id FROM complaints WHERE tracking_id = ?", (tracking_id,))
            complaint_id = c.fetchone()[0]
            
            # Add system comment for each updated complaint
            c.execute("""
                INSERT INTO complaint_updates (complaint_id, user_id, comment) 
                VALUES (?, 0, ?)
            """, (complaint_id, f"Status changed to {new_status} in bulk update"))
        
        conn.commit()
    
    flash(f'Updated status to {new_status} for {len(tracking_ids)} complaints', 'success')
    return redirect_to_proper_dashboard(status_filter, category_filter, city_filter, search_query, tracking_id_query)

def redirect_to_proper_dashboard(status, category, city, search, tracking_id):
    """Helper function to redirect to proper dashboard based on user role"""
    if session['is_superadmin'] == 1:
        return redirect(url_for('admin/manage_complaints',
                              status=status,
                              category=category,
                              city=city,
                              search=search,
                              tracking_id=tracking_id))
    else:
        return redirect(url_for('admin/manage_complaints',
                              status=status,
                              category=category,
                              city=city,
                              search=search,
                              tracking_id=tracking_id))

@app.route('/update_status/<tracking_id>', methods=['POST'])
@admin_required
def update_status(tracking_id):
    new_status = request.form['status']
    rating = request.form.get('rating')

    with sqlite3.connect('complaint.db') as conn:
        c = conn.cursor()
        
        # Get complaint details
        c.execute("""
            SELECT c.id, c.user_id, u.email, u.name 
            FROM complaints c 
            JOIN users u ON c.user_id = u.id 
            WHERE c.tracking_id = ?
        """, (tracking_id,))
        complaint = c.fetchone()
        
        if not complaint:
            flash('Complaint not found', 'danger')
            return redirect(url_for('admin_dashboard'))
        
        # Update status and rating if provided
        if new_status.lower() == 'resolved' and rating:
            c.execute("""
                UPDATE complaints 
                SET status = ?, rating = ?, updated_at = CURRENT_TIMESTAMP 
                WHERE tracking_id = ?
            """, (new_status, rating, tracking_id))
        else:
            c.execute("""
                UPDATE complaints 
                SET status = ?, updated_at = CURRENT_TIMESTAMP 
                WHERE tracking_id = ?
            """, (new_status, tracking_id))
        
        conn.commit()
        
        # Add system comment
        c.execute("""
            INSERT INTO complaint_updates (complaint_id, user_id, comment) 
            VALUES (?, 0, ?)
        """, (complaint[0], f"Status changed to {new_status} by admin"))
        conn.commit()
        
        flash('Status updated successfully', 'success')
        
        # Check if current user is superadmin and redirect accordingly
        if session['is_superadmin'] == 1:
            return redirect(url_for('manage_complaints'))
        else:
            return redirect(url_for('manage_complaints'))
    

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def Users_profile():
    if request.method == 'POST':
        # Check if this is a password change request
        if 'current_password' in request.form:
            current_password = request.form['current_password']
            new_password = request.form['new_password']
            confirm_password = request.form['confirm_password']
            
            if new_password != confirm_password:
                flash('New passwords do not match', 'danger')
                return redirect(url_for('profile'))
            
            with sqlite3.connect('complaint.db') as conn:
                c = conn.cursor()
                c.execute("SELECT password FROM users WHERE id = ?", (session['user_id'],))
                user = c.fetchone()
                
                if not user or not check_password_hash(user[0], current_password):
                    flash('Current password is incorrect', 'danger')
                    return redirect(url_for('profile'))
                
                hashed_password = generate_password_hash(new_password)
                c.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, session['user_id']))
                conn.commit()
            
            flash('Password changed successfully', 'success')
            return redirect(url_for('Users_profile'))
        
        # Otherwise it's a profile update request
        else:
            name = request.form['name']
            email = request.form['email']
            phone = request.form['phone']
            
            try:
                with sqlite3.connect('complaint.db') as conn:
                    c = conn.cursor()
                    c.execute("""
                        UPDATE users 
                        SET name = ?, email = ?, phone = ? 
                        WHERE id = ?
                    """, (name, email, phone, session['user_id']))
                    conn.commit()
                
                session['user_name'] = name
                session['user_email'] = email
                flash('Profile updated successfully', 'success')
            except sqlite3.IntegrityError:
                flash('Email already exists. Please use a different email.', 'danger')
            
            return redirect(url_for('Users_profile'))
    
    # GET request - show profile page
    with sqlite3.connect('complaint.db') as conn:
        c = conn.cursor()
        c.execute("SELECT name, email, phone, created_at FROM users WHERE id = ?", (session['user_id'],))
        user = c.fetchone()
    
    return render_template('user/users_profile.html', user=user)

                         
@app.route('/download_all_complaints')
@admin_required
def download_all_complaints():
    with sqlite3.connect('complaint.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        # Fetch all complaints with user info
        c.execute("""
            SELECT c.*, u.name as user_name, u.email, u.phone 
            FROM complaints c 
            JOIN users u ON c.user_id = u.id
        """)
        complaints = c.fetchall()

        # Fetch all updates grouped by complaint_id
        c.execute("""
            SELECT u.complaint_id, u.comment, u.created_at, us.name 
            FROM complaint_updates u 
            JOIN users us ON u.user_id = us.id 
            ORDER BY u.created_at
        """)
        all_updates = c.fetchall()

        # Organize updates by complaint_id
        updates_by_complaint = {}
        for update in all_updates:
            updates_by_complaint.setdefault(update['complaint_id'], []).append(update)

    # Generate CSV
    output = StringIO()
    writer = csv.writer(output)

    # Write header for complaint section
    writer.writerow([
        'Tracking ID','Department','Category', 'Priority', 'Status','Rating', 'User Name', 'User Email', 'User Phone',
        'City', 'Pincode', 'Address', 'Landmark', 'Description', 'Created At', 'Updated At'
    ])

    # Write each complaint's data
    for complaint in complaints:
        writer.writerow([
            complaint['tracking_id'],
            complaint['Department'],
            complaint['category'],
            complaint['priority'],
            complaint['status'],
            complaint['rating'],
            complaint['user_name'],
            complaint['email'],
            complaint['phone'],
            complaint['city'],
            complaint['pincode'],
            complaint['locality'],
            complaint['landmark'],
            complaint['description'],
            complaint['created_at'],
            complaint['updated_at']
        ])

        # Add updates if any
        complaint_id = complaint['id']
        if complaint_id in updates_by_complaint:
            writer.writerow([])  # blank line
            writer.writerow(['Update History'])  # subheader
            writer.writerow(['Date', 'Author', 'Comment'])
            for update in updates_by_complaint[complaint_id]:
                writer.writerow([update['created_at'], update['name'], update['comment']])
            writer.writerow([])  # spacing between complaints

        writer.writerow([])  # spacing between complaints

    # Create response
    output.seek(0)
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=all_complaints.csv'
    response.headers['Content-Type'] = 'text/csv'
    return response

@app.route('/download_complaint_pdf/<tracking_id>')
@admin_required
def download_complaint_pdf(tracking_id):
    with sqlite3.connect('complaint.db') as conn:
        c = conn.cursor()
        
        # Get complaint details with user information
        c.execute("""
            SELECT 
                c.id, c.tracking_id, c.department, c.category, c.priority, c.city, c.pincode, 
                c.locality, c.landmark, c.description, c.status,c.rating,
                c.image, c.created_at, c.updated_at,
                u.name as user_name, u.email, u.phone
            FROM complaints c 
            JOIN users u ON c.user_id = u.id 
            WHERE c.tracking_id = ?
        """, (tracking_id,))
        complaint = c.fetchone()
        
        if not complaint:
            flash('Complaint not found', 'danger')
            return redirect(url_for('admin_dashboard'))
        
        # Get updates/comments
        c.execute("""
            SELECT u.comment, u.created_at, us.name 
            FROM complaint_updates u 
            JOIN users us ON u.user_id = us.id 
            WHERE u.complaint_id = ? 
            ORDER BY u.created_at
        """, (complaint[0],))
        updates = c.fetchall()
    
    # Create PDF
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    
    # Styles
    styles = getSampleStyleSheet()
    title_style = styles['Title']
    heading_style = styles['Heading2']
    body_style = styles['BodyText']
    small_style = ParagraphStyle('small', parent=styles['BodyText'], fontSize=8)
    
    # Content
    content = []
    
    # Title
    content.append(Paragraph(f"Complaint Report - {tracking_id}", title_style))
    content.append(Spacer(1, 0.25*inch))
    
    # Complaint Details
    content.append(Paragraph("Complaint Details", heading_style))
    
    # Create data for the table
    complaint_data = [
        ["Tracking ID:", complaint[1]],
        ["Department:", complaint[2]],
        ["Category:", complaint[3]],
        ["Priority:",complaint[4]],
        ["Status:", complaint[10]],
        ["Rating:",complaint[12] if complaint[12] else "Not Rated"],
        ["User:", f"{complaint[13]} ({complaint[16]}, {complaint[15]})"],
        ["Address:", f"{complaint[7]}"],
        ["Location:", f"{complaint[5]} - {complaint[6]}"],
        ["Landmark:", complaint[8] if complaint[8] else "N/A"],
        ["Filed On:", complaint[13] if complaint[13] else "N/A"],
        ["Last Updated:", complaint[14] if complaint[14] else "N/A"],
    ]
    
    # Create table
    t = Table(complaint_data, colWidths=[1.5*inch, 4*inch])
    t.setStyle(TableStyle([
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('ALIGN', (0,0), (0,-1), 'RIGHT'),
        ('TEXTCOLOR', (0,0), (0,-1), colors.grey),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    
    content.append(t)
    content.append(Spacer(1, 0.25*inch))
    
    # Description
    content.append(Paragraph("Description:", heading_style))
    content.append(Paragraph(complaint[9] or "No description provided", body_style))
    content.append(Spacer(1, 0.25*inch))
    
    # Image Handling - Simplified and Corrected
    if complaint[11]:  
        try:
            # Use the correct path from your Flask config
            upload_folder = app.config['uploads']
            image_path = os.path.join(upload_folder, complaint[11])
            
            # Verify the image exists
            if os.path.exists(image_path):
                # Try to load the image with ReportLab
                try:
                    img = Image(image_path, width=5*inch, height=3*inch)
                    img.hAlign = 'CENTER'
                    
                    content.append(Paragraph("Attached Image:", heading_style))
                    content.append(Spacer(1, 0.1*inch))
                    content.append(img)
                    content.append(Spacer(1, 0.25*inch))
                except Exception as img_error:
                    print(f"Error loading image: {img_error}")
                    content.append(Paragraph("(Image exists but could not be loaded)", small_style))
            else:
                content.append(Paragraph(f"(Image file not found at: {image_path})", small_style))
        except Exception as e:
            print(f"Error processing image path: {e}")
            content.append(Paragraph("(Error processing image)", small_style))
    
    # Updates
    if updates:
        content.append(Paragraph("Update History", heading_style))
        
        update_data = []
        for update in updates:
            update_data.append([
                Paragraph(f"<b>{update[2]}</b><br/>{update[1]}", body_style),
                Paragraph(update[0], body_style)
            ])
        
        t = Table(update_data, colWidths=[2*inch, 3.5*inch])
        t.setStyle(TableStyle([
            ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
            ('FONTSIZE', (0,0), (-1,-1), 10),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.lightgrey),
            ('BOX', (0,0), (-1,-1), 0.5, colors.lightgrey),
            ('BACKGROUND', (0,0), (0,-1), colors.aliceblue),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ]))
        
        content.append(t)
    
    # Build PDF
    doc.build(content)
    
    buffer.seek(0)
    response = make_response(buffer.getvalue())
    response.headers['Content-Disposition'] = f'attachment; filename=complaint_{tracking_id}.pdf'
    response.headers['Content-type'] = 'application/pdf'
    return response

# User Management
@app.route('/admin/users')
@superadmin_required
def admin_users():
    search = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page

    with sqlite3.connect('complaint.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Get filtered users
        query = "SELECT * FROM users WHERE 1=1"
        params = []
        
        if search:
            query += " AND (name LIKE ? OR email LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%"])
        
        query += " LIMIT ? OFFSET ?"
        params.extend([per_page, offset])
        
        c.execute(query, params)
        users = c.fetchall()
        
        # Get total count
        count_query = "SELECT COUNT(*) FROM users"
        if search:
            count_query += " WHERE (name LIKE ? OR email LIKE ?)"
            c.execute(count_query, [f"%{search}%", f"%{search}%"])
        else:
            c.execute(count_query)
        total = c.fetchone()[0]
    
    return render_template('admin/admin_users.html', 
                         users=users,
                         search=search,
                         page=page,
                         per_page=per_page,
                         total=total)

@app.route('/admin/user/<int:user_id>/toggle_admin', methods=['POST'])
@admin_required
def toggle_admin(user_id):
    with sqlite3.connect('complaint.db') as conn:
        c = conn.cursor()
        c.execute("UPDATE users SET is_admin = NOT is_admin WHERE id = ?", (user_id,))
        conn.commit()
    flash('Admin status updated', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    with sqlite3.connect('complaint.db') as conn:
        c = conn.cursor()
        
        # First delete user's complaints to maintain referential integrity
        c.execute("DELETE FROM complaints WHERE user_id = ?", (user_id,))
        c.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
    
    flash('User and associated complaints deleted', 'success')
    return redirect(url_for('admin_users'))

# download for users
@app.route('/admin/users/download-csv')
@admin_required
def download_users_csv():
    
    search = request.args.get('search', '')

    try:
        with sqlite3.connect('complaint.db') as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()

            # Select only necessary columns
            query = """
                SELECT id, name, email, phone, created_at 
                FROM users 
                WHERE 1=1
            """
            params = []
            if search:
                query += " AND (name LIKE ? OR email LIKE ?)"
                params.extend([f"%{search}%", f"%{search}%"])

            c.execute(query, params)
            users = c.fetchall()

        # Prepare CSV
        output = io.StringIO()
        output.write('\ufeff')  # UTF-8 BOM
        writer = csv.writer(output)

        # Headers
        writer.writerow(['ID', 'Name', 'Email', 'Phone', 'Registered Date'])

        # Rows
        for user in users:
            row = dict(user)
            writer.writerow([
                str(row.get('id', '')),
                str(row.get('name', '')),
                str(row.get('email', '')),
                str(row.get('phone', '')),
                str(row.get('created_at') or row.get('created') or '')
            ])

        output.seek(0)
        response = make_response(output.getvalue())
        response.headers['Content-Disposition'] = 'attachment; filename=users_export.csv'
        response.headers['Content-type'] = 'text/csv; charset=utf-8'
        return response

    except Exception as e:
        flash(f'Error generating CSV: {str(e)}', 'danger')
        return redirect(url_for('admin_users'))

# admin 
@app.route('/admin/manage')
@admin_required
@superadmin_required
def manage_admins():
    # Only superadmins can manage other admins
    if not session.get('is_superadmin'):
        flash('You do not have permission to access this page', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    with sqlite3.connect('complaint.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT id, name, email, phone, is_superadmin, created_at FROM admins")
        admins = c.fetchall()
    
    return render_template('admin/manage_admins.html', admins=admins)

@app.route('/admin/add', methods=['GET', 'POST'])
@admin_required
def add_admin():
    if not session.get('is_superadmin'):
        flash('Unauthorized access', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        is_superadmin = 1 if request.form.get('is_superadmin') else 0
        
        try:
            hashed_pw = generate_password_hash(password)
            with sqlite3.connect('complaint.db') as conn:
                c = conn.cursor()
                c.execute("INSERT INTO admins (name, email, phone, password, is_superadmin) VALUES (?, ?, ?, ?, ?)",
                         (name, email, phone, hashed_pw, is_superadmin))
                conn.commit()
            
            flash('Admin added successfully', 'success')
            return redirect(url_for('manage_admins'))
        except sqlite3.IntegrityError:
            flash('Email already exists', 'danger')
        except Exception as e:
            flash(f'Error adding admin: {str(e)}', 'danger')
    
    return render_template('admin/add_admin.html')

@app.route('/admin/edit/<int:admin_id>', methods=['GET', 'POST'])
@admin_required
def edit_admin(admin_id):
    if not session.get('is_superadmin'):
        flash('You do not have permission to access this page', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    with sqlite3.connect('complaint.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        if request.method == 'POST':
            # Handle form submission
            name = request.form['name']
            email = request.form['email']
            phone = request.form['phone']
            is_superadmin = 1 if request.form.get('is_superadmin') else 0
            password = request.form.get('password')  # Optional password change
            
            try:
                if password:
                    # Update with password change
                    hashed_pw = generate_password_hash(password)
                    c.execute("""
                        UPDATE admins 
                        SET name=?, email=?, phone=?, password=?, is_superadmin=?
                        WHERE id=?
                    """, (name, email, phone, hashed_pw, is_superadmin, admin_id))
                else:
                    # Update without password change
                    c.execute("""
                        UPDATE admins 
                        SET name=?, email=?, phone=?, is_superadmin=?
                        WHERE id=?
                    """, (name, email, phone, is_superadmin, admin_id))
                
                conn.commit()
                flash('Admin updated successfully', 'success')
                return redirect(url_for('manage_admins'))
            except sqlite3.IntegrityError:
                flash('Email already exists', 'danger')
            except Exception as e:
                flash(f'Error updating admin: {str(e)}', 'danger')
        
        # GET request - fetch admin data
        c.execute("SELECT id, name, email, phone, is_superadmin FROM admins WHERE id = ?", (admin_id,))
        admin = c.fetchone()
        
        if not admin:
            flash('Admin not found', 'danger')
            return redirect(url_for('manage_admins'))
    
    return render_template('admin/edit_admin.html', admin=admin)

@app.route('/admin/delete/<int:admin_id>', methods=['POST'])
@admin_required
def delete_admin(admin_id):
    if not session.get('is_superadmin'):
        flash('Unauthorized access', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    # Prevent deleting yourself
    if admin_id == session.get('admin_id'):
        flash('You cannot delete yourself', 'danger')
        return redirect(url_for('manage_admins'))
    
    try:
        with sqlite3.connect('complaint.db') as conn:
            c = conn.cursor()
            c.execute("DELETE FROM admins WHERE id = ?", (admin_id,))
            conn.commit()
        
        flash('Admin deleted successfully', 'success')
    except Exception as e:
        flash(f'Error deleting admin: {str(e)}', 'danger')
    
    return redirect(url_for('manage_admins'))

# departments
@app.route('/admin/departments')
@admin_required
def manage_departments():
    with sqlite3.connect('complaint.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM departments ORDER BY id")
        departments = c.fetchall()
    return render_template('admin/departments.html', departments=departments)

@app.route('/add_department', methods=['POST'])
@admin_required
def add_department():
    try:
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')

        if not name:
            flash('Department name is required', 'error')
            return redirect(url_for('manage_departments'))

        with sqlite3.connect('complaint.db') as conn:
            c = conn.cursor()
            c.execute("SELECT id FROM departments WHERE name = ?", (name,))
            if c.fetchone():
                flash('Department already exists', 'error')
                return redirect(url_for('manage_departments'))
            
            c.execute("INSERT INTO departments (name, email, phone) VALUES (?, ?, ?)", 
                     (name, email, phone))
            conn.commit()
            flash('Department added successfully', 'success')
            return redirect(url_for('manage_departments'))

    except Exception as e:
        flash(f'Error adding department: {str(e)}', 'error')
        return redirect(url_for('manage_departments'))

@app.route('/edit_department', methods=['POST'])
@admin_required
def edit_department():
    try:
        dept_id = request.form.get('dept_id')
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')

        if not all([dept_id, name]):
            flash('Department ID and name are required', 'error')
            return redirect(url_for('manage_departments'))

        with sqlite3.connect('complaint.db') as conn:
            c = conn.cursor()
            c.execute("SELECT id FROM departments WHERE name = ? AND id != ?", (name, dept_id))
            if c.fetchone():
                flash('Department name already exists', 'error')
                return redirect(url_for('manage_departments'))
            
            c.execute("UPDATE departments SET name = ?, email = ?, phone = ? WHERE id = ?",
                     (name, email, phone, dept_id))
            
            if c.rowcount == 0:
                flash('Department not found', 'error')
                return redirect(url_for('manage_departments'))
                
            conn.commit()
            flash('Department updated successfully', 'success')
            return redirect(url_for('manage_departments'))

    except Exception as e:
        flash(f'Error updating department: {str(e)}', 'error')
        return redirect(url_for('manage_departments'))

@app.route('/delete_department', methods=['POST'])
@admin_required
def delete_department():
    try:
        dept_id = request.form.get('dept_id')
        
        if not dept_id:
            flash('Department ID is required', 'error')
            return redirect(url_for('manage_departments'))

        with sqlite3.connect('complaint.db') as conn:
            c = conn.cursor()
            
            # Delete associated categories first
            c.execute("DELETE FROM department_categories WHERE department_id = ?", (dept_id,))
            
            # Update complaints - use the correct column name that exists in your database
            # Common column names might be: department_id, dept_id, or department
            c.execute("""
                UPDATE complaints 
                SET department = NULL, status = 'Unassigned'
                WHERE department = ?
            """, (dept_id,))
            
            # Delete department
            c.execute("DELETE FROM departments WHERE id = ?", (dept_id,))
            
            conn.commit()
            flash('Department deleted successfully', 'success')
            return redirect(url_for('manage_departments'))

    except Exception as e:
        flash(f'Error deleting department: {str(e)}', 'error')
        return redirect(url_for('manage_departments'))
    
# Department Categories Routes
@app.route('/admin/categories')
@admin_required
def department_categories():
    try:
        with sqlite3.connect('complaint.db') as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            # Get all departments for the filter dropdown
            c.execute("SELECT id, name FROM departments ORDER BY name")
            departments = c.fetchall()
            
            # Get all categories with department names
            c.execute("""
                SELECT dc.id, dc.department_id, dc.category, d.name as department_name
                FROM department_categories dc
                JOIN departments d ON dc.department_id = d.id
                ORDER BY d.name, dc.category
            """)
            categories = c.fetchall()
            
        return render_template('admin/department_categories.html', 
                            departments=departments, 
                            categories=categories)
    
    except Exception as e:
        flash(f'Error loading categories: {str(e)}', 'danger')
        return redirect(url_for('admin_dashboard'))


@app.route('/admin/categories/add', methods=['GET', 'POST'])
@admin_required
def add_department_category():
    try:
        with sqlite3.connect('complaint.db') as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT id, name FROM departments ORDER BY name")
            departments = c.fetchall()
    except Exception as e:
        flash(f'Error loading departments: {str(e)}', 'danger')
        return redirect(url_for('department_categories'))

    if request.method == 'GET':
        return render_template('add_categories.html', departments=departments)

    if request.method == 'POST':
        dept_id = request.form.get('dept_id')
        category = request.form.get('category_name', '').strip()
        
        if not dept_id or not category:
            flash('Department and category name are required', 'danger')
            return render_template('add_categories.html', departments=departments)
        
        if len(category) > 100:
            flash('Category name is too long (max 100 characters)', 'danger')
            return render_template('add_categories.html', departments=departments)
        
        try:
            with sqlite3.connect('complaint.db') as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                
                # Check if department exists
                c.execute("SELECT name FROM departments WHERE id = ?", (dept_id,))
                dept = c.fetchone()
                if not dept:
                    flash('Selected department does not exist', 'danger')
                    return render_template('add_categories.html', departments=departments)
                
                # Check for existing category
                c.execute("""
                    SELECT id FROM department_categories 
                    WHERE department_id = ? AND LOWER(category) = LOWER(?)
                """, (dept_id, category))
                if c.fetchone():
                    flash(f'Category "{category}" already exists in {dept["name"]}', 'danger')
                    return render_template('add_categories.html', departments=departments)
                
                # Insert new category
                c.execute("""
                    INSERT INTO department_categories (department_id, category)
                    VALUES (?, ?)
                """, (dept_id, category))
                conn.commit()
                
                flash(f'Category "{category}" added successfully to {dept["name"]}', 'success')
                return redirect(url_for('department_categories'))
                
        except sqlite3.Error as e:
            flash(f'Database error: {str(e)}', 'danger')
        except Exception as e:
            flash(f'Unexpected error: {str(e)}', 'danger')
        
        return render_template('add_categories.html', departments=departments)

# New route for edit page
@app.route('/admin/categories/edit/<int:category_id>', methods=['POST'])
@admin_required
def edit_department_category(category_id):
    dept_id = request.form.get('dept_id')
    new_category = request.form.get('category_name', '').strip()
    
    if not dept_id or not new_category:
        flash('Department and category name are required', 'danger')
        return redirect(url_for('department_categories'))
    
    try:
        with sqlite3.connect('complaint.db') as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            # Get current category info
            c.execute("""
                SELECT * FROM department_categories WHERE id = ?
            """, (category_id,))
            category = c.fetchone()
            
            if not category:
                flash('Category not found', 'danger')
                return redirect(url_for('department_categories'))
            
            # Check if new category name exists in same department
            c.execute("""
                SELECT id FROM department_categories
                WHERE department_id = ? AND LOWER(category) = LOWER(?) AND id != ?
            """, (dept_id, new_category, category_id))
            
            if c.fetchone():
                flash('Category name already exists in this department', 'danger')
                return redirect(url_for('department_categories'))
            
            # Update category
            c.execute("""
                UPDATE department_categories
                SET department_id = ?, category = ?
                WHERE id = ?
            """, (dept_id, new_category, category_id))
            
            # Update all complaints with this category name
            c.execute("""
                UPDATE complaints
                SET category = ?
                WHERE category = ?
            """, (new_category, category['category']))
            
            conn.commit()
            flash('Category updated successfully', 'success')
            
    except Exception as e:
        flash(f'Error updating category: {str(e)}', 'danger')
    
    return redirect(url_for('department_categories'))

@app.route('/admin/categories/delete/<int:category_id>', methods=['POST'])
@admin_required
def delete_department_category(category_id):
    try:
        with sqlite3.connect('complaint.db') as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            # Get category info
            c.execute("""
                SELECT * FROM department_categories WHERE id = ?
            """, (category_id,))
            category = c.fetchone()
            
            if not category:
                flash('Category not found', 'danger')
                return redirect(url_for('department_categories'))
            
            # Check if there are complaints using this category
            c.execute("""
                SELECT COUNT(*) FROM complaints WHERE category = ?
            """, (category['category'],))
            complaint_count = c.fetchone()[0]
            
            if complaint_count > 0:
                # Update complaints to Uncategorized
                c.execute("""
                    UPDATE complaints
                    SET category = 'Uncategorized'
                    WHERE category = ?
                """, (category['category'],))
            
            # Delete the category
            c.execute("""
                DELETE FROM department_categories WHERE id = ?
            """, (category_id,))
            
            conn.commit()
            flash(f'Category "{category["category"]}" deleted successfully', 'success')
            
    except Exception as e:
        flash(f'Error deleting category: {str(e)}', 'danger')
    
    return redirect(url_for('department_categories'))
        
@app.route('/admin/assign_departments', methods=['GET', 'POST'])
@admin_required
@superadmin_required
def assign_departments():
    if request.method == 'POST':
        admin_id = request.form.get('admin_id')
        department_ids = request.form.getlist('department_ids')
        
        if not admin_id or not department_ids:
            flash('Please select both an admin and at least one department', 'danger')
            return redirect(url_for('assign_departments'))
        
        try:
            with sqlite3.connect('complaint.db') as conn:
                c = conn.cursor()
                
                # First remove all existing assignments for this admin
                c.execute("DELETE FROM department_admins WHERE admin_id = ?", (admin_id,))
                
                # Add new assignments
                for dept_id in department_ids:
                    c.execute("""
                        INSERT INTO department_admins (admin_id, department_id)
                        VALUES (?, ?)
                    """, (admin_id, dept_id))
                
                conn.commit()
            
            flash('Department assignments updated successfully', 'success')
            return redirect(url_for('assign_departments'))
        
        except Exception as e:
            flash(f'Error updating assignments: {str(e)}', 'danger')
    
    # GET request - show assignment form
    with sqlite3.connect('complaint.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Get all admins (except superadmins)
        c.execute("""
            SELECT id, name, email , phone
            FROM admins 
            WHERE is_superadmin = 0
            ORDER BY name
        """)
        admins = c.fetchall()
        
        # Get all departments
        c.execute("SELECT id, name FROM departments ORDER BY name")
        departments = c.fetchall()
        
        # Get current assignments to pre-select in form
        assignments = {}
        c.execute("""
            SELECT da.admin_id, da.department_id, d.name 
            FROM department_admins da
            JOIN departments d ON da.department_id = d.id
        """)
        for row in c.fetchall():
            assignments.setdefault(row['admin_id'], []).append(row['department_id'])
    
    return render_template('admin/assign_departments.html', 
                         admins=admins, 
                         departments=departments,
                         assignments=assignments)

@app.route('/admin/get_admin_departments/<int:admin_id>')
@admin_required
def get_admin_departments(admin_id):
    with sqlite3.connect('complaint.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        c.execute("""
            SELECT d.id, d.name 
            FROM department_admins da
            JOIN departments d ON da.department_id = d.id
            WHERE da.admin_id = ?
        """, (admin_id,))
        departments = [dict(row) for row in c.fetchall()]
    
    return (departments)

@app.route('/admin/department_admins')
@admin_required
def view_department_admins():
    with sqlite3.connect('complaint.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Get all departments with their admins
        c.execute("""
            SELECT d.id as dept_id, d.name as dept_name, 
                   a.id as admin_id, a.name as admin_name, a.email
            FROM departments d
            LEFT JOIN department_admins da ON d.id = da.department_id
            LEFT JOIN admins a ON da.admin_id = a.id
            ORDER BY d.name, a.name
        """)
        results = c.fetchall()
        
        # Organize by department
        departments = {}
        for row in results:
            dept_id = row['dept_id']
            if dept_id not in departments:
                departments[dept_id] = {
                    'name': row['dept_name'],
                    'admins': []
                }
            if row['admin_id']:
                departments[dept_id]['admins'].append({
                    'id': row['admin_id'],
                    'name': row['admin_name'],
                    'email': row['email']
                })
    
    return render_template('admin/department_admins.html', departments=departments)
        
@app.route('/admin_profile')
@admin_required
def admin_profile():
    with sqlite3.connect('complaint.db') as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get admin details
        cursor.execute("""
            SELECT id, name, email, phone, is_superadmin, created_at
            FROM admins
            WHERE id = ?
        """, (session['admin_id'],))
        admin = cursor.fetchone()
    
    return render_template('admin/admin_profile.html', admin=admin)

@app.route('/update_admin_profile', methods=['POST'])
@admin_required
def update_admin_profile():
    name = request.form.get('name')
    email = request.form.get('email')
    phone = request.form.get('phone')
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    # Validate phone number length (10 digits)
    if phone and len(phone) != 10:
        flash('Phone number must be 10 digits long', 'danger')
        return redirect(url_for('admin_profile'))
    
    with sqlite3.connect('complaint.db') as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get current admin details
        cursor.execute("SELECT * FROM admins WHERE id = ?", (session['admin_id'],))
        admin = cursor.fetchone()
        
        # Validate email uniqueness (if changed)
        if email != admin['email']:
            cursor.execute("SELECT 1 FROM admins WHERE email = ? AND id != ?", (email, session['admin_id']))
            if cursor.fetchone():
                flash('Email already in use by another admin', 'danger')
                return redirect(url_for('admin_profile'))
        
        # Password change logic
        password_hash = admin['password']
        if current_password or new_password or confirm_password:
            if not (current_password and new_password and confirm_password):
                flash('All password fields are required for password change', 'danger')
                return redirect(url_for('admin_profile'))
            
            if not check_password_hash(password_hash, current_password):
                flash('Current password is incorrect', 'danger')
                return redirect(url_for('admin_profile'))
            
            if new_password != confirm_password:
                flash('New passwords do not match', 'danger')
                return redirect(url_for('admin_profile'))
            
            password_hash = generate_password_hash(new_password)
        
        # Update admin details
        cursor.execute("""
            UPDATE admins
            SET name = ?, email = ?, phone = ?, password = ?
            WHERE id = ?
        """, (name, email, phone, password_hash, session['admin_id']))
        
        conn.commit()
        
        # Log the profile update
        cursor.execute("""
            INSERT INTO admin_logs (admin_id, action, details)
            VALUES (?, ?, ?)
        """, (session['admin_id'], 'PROFILE_UPDATE', f"Admin updated their profile details"))
        
        conn.commit()
        
        flash('Profile updated successfully', 'success')
        return redirect(url_for('admin_profile'))
                
if __name__ == '__main__':
    app.run(debug=True)