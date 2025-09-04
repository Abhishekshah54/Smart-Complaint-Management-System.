# Smart-Complaint-Management-System.

A comprehensive web-based complaint management system designed for local governments to efficiently handle citizen complaints, assign them to relevant departments, and track resolution progress.

## 🌟 Features

### For Citizens
- **User Registration & Authentication**: Secure signup and login system
- **Complaint Submission**: File complaints with detailed information and image attachments
- **Complaint Tracking**: Real-time status updates with unique tracking IDs
- **Communication**: Comment system for updates and clarifications
- **Rating System**: Rate resolved complaints for feedback
- **Profile Management**: Update personal information and change passwords

### For Department Staff
- **Department-specific Dashboard**: View and manage complaints assigned to your department
- **Status Management**: Update complaint status (Pending, In Progress, Resolved, etc.)
- **Bulk Operations**: Process multiple complaints simultaneously
- **Communication Tools**: Add updates and comments to complaints
- **Export Functionality**: Download complaints as CSV or PDF reports

### For Super Administrators
- **Complete System Oversight**: Manage all complaints across all departments
- **User Management**: Administer citizen and staff accounts
- **Department Management**: Create and manage government departments
- **Category Management**: Define complaint categories for each department
- **Assignment System**: Assign departments to staff members
- **Analytics & Reporting**: Comprehensive reporting and export capabilities

## 🚀 Technology Stack

- **Backend**: Python with Flask framework
- **Database**: SQLite with SQLAlchemy-like operations
- **Frontend**: HTML5, CSS3, JavaScript with Bootstrap 5
- **Security**: Password hashing with Werkzeug, session management
- **File Handling**: Secure image uploads with validation
- **Reporting**: PDF generation with ReportLab, CSV exports

## 📋 Prerequisites

- Python 3.7+
- pip (Python package manager)

## 🛠️ Installation

1. **Clone or download the project files**
   ```bash
   git clone <repository-url>
   cd complaint-management-system
   ```

2. **Create a virtual environment (recommended)**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install required dependencies**
   ```bash
   pip install flask werkzeug reportlab PyPDF2 Pillow pytz
   ```

4. **Initialize the database**
   - The system will automatically create the database with all necessary tables on first run
   - Default super admin account will be created:
     - Email: `rmc@admin.com`
     - Password: `admin123`

5. **Configure email settings (optional)**
   - Update email configuration in the Flask app for notification features
   - Set your SMTP server details in the app configuration

6. **Run the application**
   ```bash
   python app.py
   ```

7. **Access the application**
   - Open your browser and go to `http://localhost:5000`
   - The system will automatically redirect you to the appropriate dashboard based on your login status

## 🗄️ Database Structure

The system uses the following main tables:

- **users**: Citizen accounts who file complaints
- **complaints**: Main complaints with tracking, status, and location details
- **complaint_updates**: History of updates and comments on complaints
- **admins**: System administrators and department staff
- **departments**: Government departments (Water, Sanitation, Roads, etc.)
- **department_categories**: Complaint categories for each department
- **department_admins**: Assignment of staff to departments
- **admin_logs**: Audit trail of admin activities

## 👥 User Roles

### 1. Citizens
- Register and file complaints
- Track complaint status
- Communicate with department staff
- Rate resolved complaints

### 2. Department Staff
- Manage complaints assigned to their department
- Update complaint status
- Communicate with citizens
- Generate department reports

### 3. Super Administrators
- Full system access
- Manage all users and departments
- Oversee all complaints
- System configuration and reporting

## 📝 Usage Guide

### For Citizens
1. **Register** an account using your email
2. **Login** to your account
3. **File a complaint** by providing details, location, and optional images
4. **Track your complaint** using the provided tracking ID
5. **Receive updates** and respond to department queries
6. **Rate the resolution** once your complaint is resolved

### For Department Staff
1. **Login** with your admin credentials
2. **View assigned complaints** on your dashboard
3. **Update status** as you work on complaints
4. **Add comments** to communicate with citizens
5. **Mark complaints as resolved** when completed
6. **Generate reports** for your department

### For Super Administrators
1. **Login** with super admin credentials
2. **Manage departments** and categories
3. **Assign staff** to departments
4. **Monitor system-wide** complaint statistics
5. **Generate comprehensive reports**
6. **Manage user accounts** and permissions

## 🔧 Configuration

Key configuration options in `app.py`:

- **Secret Key**: Change `app.secret_key` for production
- **Upload Settings**: Configure file upload limits and allowed extensions
- **Email Settings**: Set up SMTP for notifications
- **Database Path**: SQLite database file location

## 📊 Reporting Features

- **CSV Export**: Download complaint data in spreadsheet format
- **PDF Reports**: Generate professional complaint reports with images
- **Status Reports**: Filter and export by status, department, or time period
- **User Activity**: Export user registration and activity data

## 🔒 Security Features

- Password hashing with salt
- SQL injection prevention
- File upload validation
- Session-based authentication
- Role-based access control
- XSS protection through input sanitization

## 🚨 Troubleshooting

### Common Issues

1. **Database errors**: Delete `complaint.db` to reset the database
2. **Image upload issues**: Check folder permissions for `static/uploads`
3. **Email errors**: Verify SMTP settings or disable email features
4. **Login problems**: Reset using the default admin credentials

### Reset System
```bash
# Delete database file
rm complaint.db

# Restart application - new database will be created
python app.py
```

## 📞 Support

For technical support or questions about this complaint management system, please contact your system administrator.

## 📄 License

This project is developed for local government use. Please check with your municipality for usage rights and distribution policies.

## 🔄 Version History

- **v1.0** (Current): Initial release with core functionality
  - User registration and authentication
  - Complaint management system
  - Department assignment
  - Reporting features

---
