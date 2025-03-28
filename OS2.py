import bcrypt
import pyotp
import sqlite3
import time
import os
import shutil
import psutil
from plyer import notification  # For desktop notifications
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


# Step 1: Create a database for storing user credentials
def init_db():
    conn = sqlite3.connect('user_auth.db')
    c = conn.cursor()

    # Create the users table if it doesn't exist
    c.execute(''' 
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            salt TEXT NOT NULL,
            otp_secret TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            failed_attempts INTEGER DEFAULT 0,
            lock_time INTEGER DEFAULT 0
        );
    ''')

    conn.commit()
    conn.close()

# Step 2: Hash the password before storing
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed, salt

# Step 3: Check if the entered password matches the stored hash
def check_password(stored_hash, entered_password, salt):
    entered_hash = bcrypt.hashpw(entered_password.encode('utf-8'), salt)
    return entered_hash == stored_hash

# Step 4: Register a new user with OTP secret for MFA
def register_user(username, password, role="user"):
    hashed_password, salt = hash_password(password)
    otp_secret = pyotp.random_base32()  # Generate a random OTP secret
    conn = sqlite3.connect('user_auth.db')
    c = conn.cursor()
    c.execute('INSERT INTO users (username, hashed_password, salt, otp_secret, role) VALUES (?, ?, ?, ?, ?)',
              (username, hashed_password.decode('utf-8'), salt.decode('utf-8'), otp_secret, role))
    conn.commit()
    conn.close()
    print("User registered successfully!")

# Step 5: Login process (with OTP for 2FA)
def login_user(username, password):
    conn = sqlite3.connect('user_auth.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = c.fetchone()

    if user:
        stored_hash = user[2]
        salt = user[3]
        otp_secret = user[4]  # OTP secret stored in the database
        role = user[5]
        failed_attempts = user[6]
        lock_time = user[7]

        # Step 6: Check if account is locked
        if failed_attempts >= 3 and (time.time() - lock_time) < 300:  # 300 seconds = 5 minutes
            print("Account is temporarily locked due to multiple failed login attempts. Please try again later.")
            return False, None

        # Step 7: Check password
        if check_password(stored_hash.encode('utf-8'), password, salt.encode('utf-8')):
            # Reset failed attempts on successful login
            c.execute('UPDATE users SET failed_attempts = 0, lock_time = 0 WHERE username = ?', (username,))
            conn.commit()
            print("Password verified, please enter the OTP.")

            # Step 8: Request OTP for multi-factor authentication
            totp = pyotp.TOTP(otp_secret)  # Create a TOTP object using the user's OTP secret
            otp = totp.now()  # Generate the OTP

            # Step 9: Display the OTP in a desktop notification
            notification.notify(
                title="Your OTP Code",
                message=f"Your OTP code is: {otp}",
                timeout=5  # Time in seconds for how long the notification stays
            )
            print("OTP sent as a notification. Please check your desktop.")

            # Ask user to input the OTP
            entered_otp = input("Enter OTP from notification: ")

            if totp.verify(entered_otp):  # Verify the entered OTP against the generated OTP
                print("OTP verified, login successful!")
                return True, role
            else:
                print("Invalid or expired OTP!")
                return False, None
        else:
            # Increment failed attempts and lock account if necessary
            failed_attempts += 1
            if failed_attempts >= 3:
                lock_time = int(time.time())  # Lock account and set lock time
            c.execute('UPDATE users SET failed_attempts = ?, lock_time = ? WHERE username = ?', 
                      (failed_attempts, lock_time, username))
            conn.commit()
            print("Invalid password!")
            return False, None
    else:
        print("Username not found!")
        return False, None

# Step 10: Session Management (Tracking Logged-in Users)
active_sessions = {}

def start_session(username):
    session_id = str(time.time())  # Generate session ID based on current time
    active_sessions[session_id] = username
    print(f"Session started for {username}. Session ID: {session_id}")
    return session_id

def end_session(session_id):
    if session_id in active_sessions:
        print(f"Session for {active_sessions[session_id]} ended.")
        del active_sessions[session_id]

# New Functionality: Search Files
def search_files():
    search_term = input("Enter the name of the file to search: ")
    found_files = [file for file in os.listdir('.') if search_term.lower() in file.lower()]
    
    if found_files:
        print(f"Found the following files matching '{search_term}':")
        for file in found_files:
            print(file)
    else:
        print(f"No files found matching '{search_term}'.")

# New Functionality: Lock Account
def lock_account():
    username = input("Enter the username to lock: ")
    conn = sqlite3.connect('user_auth.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = c.fetchone()

    if user:
        c.execute('UPDATE users SET failed_attempts = 3, lock_time = ? WHERE username = ?', 
                  (int(time.time()), username))
        conn.commit()
        print(f"Account for {username} is now locked.")
    else:
        print(f"User {username} not found.")
    conn.close()

# New Functionality: Unlock Account
def unlock_account():
    username = input("Enter the username to unlock: ")
    conn = sqlite3.connect('user_auth.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = c.fetchone()

    if user:
        c.execute('UPDATE users SET failed_attempts = 0, lock_time = 0 WHERE username = ?', (username,))
        conn.commit()
        print(f"Account for {username} is now unlocked.")
    else:
        print(f"User {username} not found.")
    conn.close()

# Step 11: OS-based functionalities (File Management, Process Management, etc.)

def list_files():
    print("Listing files in current directory:")
    for file_name in os.listdir('.'):
        print(file_name)

def create_file():
    file_name = input("Enter the name of the file to create: ")
    with open(file_name, 'w') as file:
        file.write("New file created.\n")
    print(f"File '{file_name}' created.")

def delete_file():
    file_name = input("Enter the name of the file to delete: ")
    if os.path.exists(file_name):
        os.remove(file_name)
        print(f"File '{file_name}' deleted.")
    else:
        print(f"File '{file_name}' does not exist.")

def list_processes():
    print("Listing running processes:")
    for proc in psutil.process_iter(['pid', 'name']):
        print(proc.info)

def view_system_info():
    print("System Information:")
    print(f"CPU Usage: {psutil.cpu_percent(interval=1)}%")
    print(f"Memory Usage: {psutil.virtual_memory().percent}%")
    print(f"Disk Usage: {psutil.disk_usage('/').percent}%")

# New Functionality: View Active Users
def view_active_users():
    print("Active sessions/users:")
    for session_id, username in active_sessions.items():
        print(f"Session ID: {session_id}, Username: {username}")

# New Functionality: Send Email Notification
def send_email_notification():
    sender_email = input("Enter your email: ")
    receiver_email = input("Enter receiver email: ")
    subject = input("Enter email subject: ")
    body = input("Enter email body: ")
    
    # Use your app password here if 2FA is enabled
    password = input("Enter your app password (or regular password if 2FA is not enabled): ")

    message = MIMEMultipart()
    message['From'] = sender_email
    message['To'] = receiver_email
    message['Subject'] = subject
    message.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(sender_email, password)  # Use app password or regular password
            text = message.as_string()
            server.sendmail(sender_email, receiver_email, text)
        print("Email sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {e}")

# New Functionality: Backup User Data
def backup_user_data():
    print("Backing up user data...")
    shutil.copy("user_auth.db", "backup_user_auth.db")
    print("Backup completed successfully.")

# New Functionality: Monitor Running Services
def monitor_running_services():
    print("Monitoring running services...")
    for service in psutil.win_service_iter():
        print(f"Service: {service.name()} | Status: {service.status()}")

# Missing Functions Implementation
def view_logs():
    conn = sqlite3.connect('user_auth.db')
    c = conn.cursor()
    c.execute('SELECT username, failed_attempts, lock_time FROM users')
    logs = c.fetchall()
    print("\nLogin Attempt Logs:")
    for log in logs:
        print(f"User: {log[0]}, Failed Attempts: {log[1]}, Lock Time: {log[2]}")
    conn.close()

def change_role():
    username = input("Enter username to change role: ")
    new_role = input("Enter new role (user/admin): ").lower()
    if new_role not in ['user', 'admin']:
        print("Invalid role. Use 'user' or 'admin'.")
        return
    
    conn = sqlite3.connect('user_auth.db')
    c = conn.cursor()
    c.execute('UPDATE users SET role = ? WHERE username = ?', (new_role, username))
    conn.commit()
    if c.rowcount == 0:
        print("User not found.")
    else:
        print(f"Role updated to {new_role} for {username}.")
    conn.close()

def view_users():
    conn = sqlite3.connect('user_auth.db')
    c = conn.cursor()
    c.execute('SELECT username, role FROM users')
    users = c.fetchall()
    print("\nUser List:")
    for user in users:
        print(f"Username: {user[0]}, Role: {user[1]}")
    conn.close()

def reset_password():
    username = input("Enter username to reset password: ")
    new_password = input("Enter new password: ")
    
    conn = sqlite3.connect('user_auth.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    
    if user:
        hashed_password, salt = hash_password(new_password)
        c.execute('UPDATE users SET hashed_password = ?, salt = ? WHERE username = ?',
                  (hashed_password.decode('utf-8'), salt.decode('utf-8'), username))
        conn.commit()
        print(f"Password reset for {username}.")
    else:
        print("User not found.")
    conn.close()

def send_notification():
    message = input("Enter notification message: ")
    notification.notify(
        title="Admin Notification",
        message=message,
        timeout=10
    )
    print("Notification sent.")

def backup_database():
    backup_name = f"user_auth_backup_{int(time.time())}.db"
    shutil.copy("user_auth.db", backup_name)
    print(f"Database backed up as {backup_name}.")

def shutdown_system():
    confirm = input("Are you sure you want to shutdown the system? (y/n): ").lower()
    if confirm == 'y':
        if os.name == 'nt':
            os.system("shutdown /s /t 1")
        else:
            os.system("shutdown now")

def reboot_system():
    confirm = input("Are you sure you want to reboot the system? (y/n): ").lower()
    if confirm == 'y':
        if os.name == 'nt':
            os.system("shutdown /r /t 1")
        else:
            os.system("reboot")

# Step 12: User Dashboard (After Successful Login)
def user_dashboard(username, role):
    while True:
        print(f"\nWelcome {username} ({role})!")
        print("1. View Profile")
        print("2. View Files (Admin Only)")
        print("3. Create File (Admin Only)")
        print("4. Delete File (Admin Only)")
        print("5. View Running Processes (Admin Only)")
        print("6. View System Info (Admin Only)")
        print("7. View Logs (Admin Only)")
        print("8. Change Role (Admin Only)")
        print("9. View Users List (Admin Only)")
        print("10. Reset Password (Admin Only)")
        print("11. Send Notification (Admin Only)")
        print("12. Backup Database (Admin Only)")
        print("13. Shutdown System (Admin Only)")
        print("14. Reboot System (Admin Only)")
        print("15. View Active Users")
        print("16. Send Email Notification")
        print("17. Backup User Data")
        print("18. Monitor Running Services")
        print("19. Logout")
        print("20. Search Files")
        print("21. Lock Account (Admin Only)")
        print("22. Unlock Account (Admin Only)")

        choice = input("Select an option: ")

        if choice == '1':
            print(f"Username: {username}")
            print(f"Role: {role}")
        elif choice == '2' and role == 'admin':
            list_files()
        elif choice == '3' and role == 'admin':
            create_file()
        elif choice == '4' and role == 'admin':
            delete_file()
        elif choice == '5' and role == 'admin':
            list_processes()
        elif choice == '6' and role == 'admin':
            view_system_info()
        elif choice == '7' and role == 'admin':
            view_logs()
        elif choice == '8' and role == 'admin':
            change_role()
        elif choice == '9' and role == 'admin':
            view_users()
        elif choice == '10' and role == 'admin':
            reset_password()
        elif choice == '11' and role == 'admin':
            send_notification()
        elif choice == '12' and role == 'admin':
            backup_database()
        elif choice == '13' and role == 'admin':
            shutdown_system()
        elif choice == '14' and role == 'admin':
            reboot_system()
        elif choice == '15':
            view_active_users()
        elif choice == '16':
            send_email_notification()
        elif choice == '17':
            backup_user_data()
        elif choice == '18':
            monitor_running_services()
        elif choice == '19':
            print("Logging out...")
            return False  # Logout user
        elif choice == '20':
            search_files()
        elif choice == '21' and role == 'admin':
            lock_account()
        elif choice == '22' and role == 'admin':
            unlock_account()
        else:
            print("Invalid choice or permission denied.")
        return True

# Main function for the authentication system
def main():
    init_db()  # Initialize the database

    while True:
        print("\nWelcome to the User Authentication System!")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Select an option: ")

        if choice == '1':
            username = input("Enter username: ")
            password = input("Enter password: ")
            role = input("Enter role (user/admin): ")
            register_user(username, password, role)

        elif choice == '2':
            username = input("Enter username: ")
            password = input("Enter password: ")
            success, role = login_user(username, password)
            if success:
                session_id = start_session(username)
                while user_dashboard(username, role):
                    pass
                end_session(session_id)
            else:
                print("Access denied!")

        elif choice == '3':
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
