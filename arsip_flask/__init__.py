# Standard library imports
import os
import re
import secrets
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from functools import wraps
import mimetypes
import json
import uuid
import traceback

# Third-party imports
import pytz
import mysql.connector
from mysql.connector import Error, errorcode
from flask_login import current_user
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
    session,
    send_from_directory,
    current_app as app,
)
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    current_user,
    login_required,
    UserMixin,
)
from flask_wtf import FlaskForm
from flask_wtf.csrf import generate_csrf
from wtforms import (
    StringField,
    PasswordField,
    BooleanField,
    SelectField,
    TextAreaField,
    FileField,
    SubmitField,
)
from wtforms.validators import DataRequired, Email, Length, EqualTo, Regexp, Optional
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from wtforms import StringField, TextAreaField, SelectField, BooleanField
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp
from functools import wraps
from flask import redirect, url_for, flash
from flask import current_app
from dateutil.parser import parse
from flask_wtf.csrf import validate_csrf
from flask import request
import json
from decimal import Decimal
from flask import jsonify
from flask_wtf.csrf import CSRFError
from wtforms import Form, StringField, PasswordField, validators
from mysql.connector import Error as MySQL_Error
from flask import jsonify
import string
from wtforms import Form, StringField, BooleanField, HiddenField, validators
from flask import send_file
from .utils.database import get_db_connection
from .utils.logging import setup_logging
from .config import Config
from .extensions import csrf

mail = Mail()
login_manager = LoginManager()

def create_app():
    # Initialize Flask app
    app = Flask(__name__)
    app.config.from_object(Config)

    # Logging
    setup_logging(app)

    # Init extensions
    csrf.init_app(app)
    mail.init_app(app)
    login_manager.init_app(app)

    # Inisialisasi Login Manager
    login_manager.login_view = "login" # type: ignore[attr-defined]

    def get_admin_user_id():
        # Contoh sederhana mengambil user admin dari database
        conn = get_db_connection()
        admin_id = None
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
            result = cursor.fetchone()
            if result:
                admin_id = result[0]
        except Exception as e:
            app.logger.error(f"Error getting admin user id: {e}", exc_info=True)
        finally:
            cursor.close()
            if conn.is_connected():
                conn.close()
        return admin_id

    def create_notification(user_id, title, message, type, related_id):
        # Fungsi insert notifikasi ke database
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            insert_sql = """
                INSERT INTO notifications (user_id, title, message, type, related_id, created_at)
                VALUES (%s, %s, %s, %s, %s, NOW())
            """
            cursor.execute(insert_sql, (user_id, title, message, type, related_id))
            conn.commit()
        except Exception as e:
            app.logger.error(f"Failed to create notification: {e}", exc_info=True)
        finally:
            cursor.close()
            if conn.is_connected():
                conn.close()

    class DecimalEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, Decimal):
                return float(obj)
            return super().default(obj)

    class ArchiveForm(Form):
        title = StringField(
            "Title", [validators.Length(min=1, max=255), validators.DataRequired()]
        )
        user_id = SelectField("User", [validators.DataRequired()], coerce=int)
        category = StringField("Category", [validators.Length(min=0, max=100)])
        description = TextAreaField("Description", [validators.Length(min=0, max=500)])
        file = FileField("File")
        is_public = BooleanField("Is Public")

    # Fungsi untuk membersihkan file yang gagal diunggah
    def cleanup_uploaded_file(file_info):
        try:
            file_path = file_info.get("file_path")
            if file_path and os.path.exists(file_path):
                os.remove(file_path)
                app.logger.debug(f"Cleaned up file: {file_path}")
        except Exception as e:
            app.logger.error(f"Failed to clean up file {file_path}: {e}")

    def has_permission(user_id, permission):
        conn = get_db_connection()
        if not conn:
            return False
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT is_allowed FROM user_permissions WHERE user_id = %s AND permission = %s",
                (user_id, permission),
            )
            result = cursor.fetchone()
            return result and result[0] == 1
        except Error as e:
            app.logger.error(f"Permission check error: {e}")
            return False
        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

    def generate_secure_password(length=12):
        """Generate a secure random password"""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        while True:
            password = "".join(secrets.choice(alphabet) for _ in range(length))
            if (
                any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password)
                and any(c in "!@#$%^&*" for c in password)
            ):
                return password

    def allowed_file(filename):
        return (
            "." in filename
            and filename.rsplit(".", 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]
        )

    def get_file_extension(filename):
        """Get the file extension from the filename."""
        return filename.rsplit(".", 1)[1].lower() if "." in filename else None

    def generate_unique_filename(filename):
        """Generate a unique filename by appending a timestamp to the original filename."""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        name, ext = os.path.splitext(filename)

    def permission_required(permission):
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                if not current_user.is_authenticated:
                    flash("Anda harus login untuk mengakses halaman ini", "warning")
                    return redirect(
                        url_for("login", next=request.url)
                    )  # ← ganti di sini

                if current_user.is_superadmin:
                    return f(*args, **kwargs)

                try:
                    conn = get_db_connection()
                    with conn.cursor(dictionary=True) as cursor:
                        # Cek 1: Izin langsung ke user
                        cursor.execute(
                            """
                            SELECT is_allowed FROM user_permissions 
                            WHERE user_id = %s AND permission = %s
                        """,
                            (current_user.id, permission),
                        )
                        perm = cursor.fetchone()

                        # Cek 2: Izin dari role
                        if not perm:
                            cursor.execute(
                                """
                                SELECT rp.is_allowed FROM user_roles ur
                                JOIN role_permissions rp ON ur.role_id = rp.role_id
                                WHERE ur.user_id = %s AND rp.permission = %s
                            """,
                                (current_user.id, permission),
                            )
                            perm = cursor.fetchone()

                        if not perm or not perm.get("is_allowed"):
                            flash(f'Anda tidak memiliki izin "{permission}"', "danger")
                            app.logger.warning(
                                f"Permission denied for {current_user.username} - {permission}"
                            )
                            return redirect(url_for("dashboard"))

                        return f(*args, **kwargs)

                except mysql.connector.Error as err:
                    app.logger.error(f"Database error: {err}")
                    flash("Terjadi kesalahan saat memverifikasi izin", "danger")
                    return redirect(url_for("dashboard"))

                finally:
                    if conn and conn.is_connected():
                        conn.close()

            return decorated_function

        return decorator

    def is_valid_uuid(uuid_str):
        """Validate if a string is a valid UUID."""
        try:
            uuid.UUID(uuid_str)
            return True
        except ValueError:
            return False

    def check_upload_permission(user_id):
        try:
            conn = get_db_connection()
            with conn.cursor(dictionary=True) as cursor:
                # Cek permission langsung
                cursor.execute(
                    """
                    SELECT is_allowed FROM user_permissions 
                    WHERE user_id = %s AND permission = 'archive_upload'
                """,
                    (user_id,),
                )
                direct_perm = cursor.fetchone()

                if direct_perm and direct_perm["is_allowed"]:
                    return True

                # Cek permission dari role
                cursor.execute(
                    """
                    SELECT rp.is_allowed 
                    FROM user_roles ur
                    JOIN role_permissions rp ON ur.role_id = rp.role_id
                    WHERE ur.user_id = %s AND rp.permission = 'archive_upload'
                """,
                    (user_id,),
                )
                role_perm = cursor.fetchone()

                return role_perm and role_perm["is_allowed"]
        except Exception as e:
            app.logger.error(f"Permission check error: {e}")
            return False
        finally:
            if conn and conn.is_connected():
                conn.close()

    @login_manager.unauthorized_handler
    def unauthorized():
        if request.blueprint == "api":
            return jsonify({"error": "Unauthorized"}), 401
        flash("Anda harus login untuk mengakses halaman ini", "warning")
        return redirect(url_for("login", next=request.url))

    def validate_email(email):
        """Validate email format."""
        if not email:
            return False
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, email))

    def validate_password(password):
        """Validate password strength."""
        if not password or len(password) < 8:
            return False
        return (
            any(c.isupper() for c in password)
            and any(c.islower() for c in password)
            and any(c.isdigit() for c in password)
            and any(c in "!@#$%^&*()" for c in password)
        )

    def validate_username(username):
        """Validate username format."""
        if not username or len(username) < 4 or len(username) > 80:
            return False
        return bool(re.match(r"^[a-zA-Z0-9_]+$", username))

    def admin_required(f):
        """Decorator to restrict access to admin or superadmin users."""

        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or not (
                current_user.is_admin or current_user.is_superadmin
            ):
                flash("You do not have permission to access this page.", "danger")
                log_activity(
                    user_id=current_user.id if current_user.is_authenticated else None,
                    action="access_denied",
                    ip_address=request.remote_addr or "unknown",
                    user_agent=request.user_agent.string or "unknown",
                    description=f"Attempted access to {request.path}",
                )
                return redirect(url_for("login"))
            return f(*args, **kwargs)

        return decorated_function

    def allowed_file(filename, allowed_extensions=None):
        """
        Check if the file has an allowed extension.

        :param filename: str, nama file
        :param allowed_extensions: set atau list ekstensi yang diizinkan (misal {'pdf', 'docx', 'jpg'})
                                jika None, akan menggunakan nilai default dari konfigurasi aplikasi
        :return: bool, True jika ekstensi diperbolehkan, False jika tidak
        """
        if not filename or "." not in filename:
            return False

        ext = filename.rsplit(".", 1)[1].lower()

        if allowed_extensions is None:
            # Pastikan ini adalah set ekstensi yang diizinkan dari konfigurasi aplikasi (app.config)
            # Misal app.config['ALLOWED_EXTENSIONS'] sudah didefinisikan di file konfigurasi Flask Anda
            allowed_extensions = app.config.get(
                "ALLOWED_EXTENSIONS", {"pdf", "doc", "docx", "jpg", "jpeg", "png"}
            )

        return ext in allowed_extensions

    # log helper
    def log_security_event(event: str):
        with open("security.log", "a") as log_file:
            log_file.write(f"[SECURITY] {event}\n")

    # setting helper
    def get_system_setting(key: str):
        # contoh hardcoded, bisa kamu ganti akses ke file json/config lain
        settings = {"maintenance_mode": False, "max_login_attempts": 5}
        return settings.get(key, None)

    def get_user_notifications(user_id):
        """
        Ambil notifikasi untuk user tertentu dari database.
        Return list notifikasi dalam bentuk dict.
        """
        notifications = []
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            query = "SELECT id, message, is_read, created_at FROM notifications WHERE user_id = %s ORDER BY created_at DESC"
            cursor.execute(query, (user_id,))
            notifications = cursor.fetchall()
            cursor.close()
            conn.close()
        except Exception as e:
            app.logger.error(
                f"Failed to get notifications for user {user_id}: {str(e)}"
            )
        return notifications

    # Fungsi untuk mencatat aktivitas pengguna
    def log_activity(
        user_id, action, ip_address, user_agent, description, details=None
    ):
        """Log user activity to database"""
        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            if conn and conn.is_connected():
                cursor = conn.cursor()

                # Pastikan query dan parameter sesuai
                query = """
                    INSERT INTO user_logs 
                    (user_id, action, ip_address, user_agent, description, details, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """

                # Serialize details jika berupa dictionary
                details_str = (
                    json.dumps(details)
                    if details and isinstance(details, (dict, list))
                    else str(details) if details else None
                )

                # Eksekusi query dengan parameter yang sesuai
                cursor.execute(
                    query,
                    (
                        user_id,
                        action,
                        ip_address,
                        user_agent,
                        description,
                        details_str,
                        datetime.now(
                            pytz.timezone("Asia/Jakarta")
                        ),  # Gunakan timestamp yang konsisten
                    ),
                )

                conn.commit()
        except Exception as e:  # Tangkap semua exception, bukan hanya Error
            logging.error(
                f"Log activity failed - User: {user_id}, Action: {action}, Error: {str(e)}",
                exc_info=True,
            )
            # Jangan re-raise exception agar tidak mengganggu alur utama
        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

    # Fungsi untuk mencatat log sistem
    def log_system_error(module, message, ip_address=None, user_id=None, details=None):
        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            if conn and conn.is_connected():
                cursor = conn.cursor()
                query = """
                    INSERT INTO system_logs (level, module, message, ip_address, user_id, created_at)
                    VALUES (%s, %s, %s, %s, %s, NOW())
                """
                cursor.execute(
                    query,
                    (
                        "ERROR",
                        module,
                        message,
                        ip_address or "unknown",
                        user_id,
                        str(details) if details else None,
                    ),
                )
                conn.commit()
        except Error as e:
            logging.error(f"Log system error failed: {e}")
        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

    @app.context_processor
    def inject_current_year():
        """Inject current year into templates."""
        return {"current_year": datetime.now(pytz.timezone("Asia/Jakarta")).year}

    # Forms
    class LoginForm(FlaskForm):
        username = StringField(
            "Username", validators=[DataRequired(), Length(min=4, max=80)]
        )
        password = PasswordField("Password", validators=[DataRequired()])
        remember = BooleanField("Remember Me")
        submit = SubmitField("Login")

    class RegisterForm(FlaskForm):
        username = StringField(
            "Username",
            validators=[
                DataRequired(message="Username is required"),
                Length(
                    min=4,
                    max=80,
                    message="Username must be between 4 and 80 characters",
                ),
                Regexp(
                    "^[a-zA-Z0-9_]+$",
                    message="Username must contain only letters, numbers, or underscores",
                ),
            ],
        )
        email = StringField(
            "Email",
            validators=[
                DataRequired(message="Email is required"),
                Email(message="Invalid email address"),
                Length(max=120, message="Email must be less than 120 characters"),
            ],
        )
        full_name = StringField(
            "Full Name",
            validators=[
                DataRequired(message="Full name is required"),
                Length(
                    min=2,
                    max=255,
                    message="Full name must be between 2 and 255 characters",
                ),
            ],
        )
        phone = StringField(
            "Phone Number",
            validators=[
                Optional(),
                Length(max=15, message="Phone number must be at most 15 characters"),
                Regexp(
                    "^[0-9+]*$", message="Phone number must contain only digits or +"
                ),
            ],
        )
        password = PasswordField(
            "Password",
            validators=[
                DataRequired(message="Password is required"),
                Length(
                    min=8,
                    max=255,
                    message="Password must be between 8 and 255 characters",
                ),
                EqualTo("confirm_password", message="Passwords must match"),
            ],
        )
        confirm_password = PasswordField(
            "Confirm Password",
            validators=[DataRequired(message="Please confirm your password")],
        )
        submit = SubmitField("Register")

    class ArchiveUploadForm(FlaskForm):
        title = StringField("Title", validators=[DataRequired(), Length(max=255)])
        description = TextAreaField("Description", validators=[Length(max=65535)])
        category = SelectField(
            "Category",
            choices=[("document", "Document"), ("image", "Image"), ("other", "Other")],
            validators=[DataRequired()],
        )
        file = FileField("File", validators=[DataRequired()])
        is_public = BooleanField("Make Public")
        submit = SubmitField("Upload")

    class ProfileForm(FlaskForm):
        username = StringField(
            "Username",
            validators=[
                DataRequired(),
                Length(min=4, max=80),
                Regexp(
                    "^[a-zA-Z0-9_]+$",
                    message="Username must contain only letters, numbers, or underscores",
                ),
            ],
        )
        email = StringField(
            "Email", validators=[DataRequired(), Email(), Length(max=120)]
        )
        full_name = StringField(
            "Full Name", validators=[DataRequired(), Length(min=2, max=255)]
        )
        phone = StringField(
            "Phone",
            validators=[
                Optional(),
                Length(max=15),
                Regexp(
                    "^[0-9+]*$", message="Phone number must contain only digits or +"
                ),
            ],
        )
        submit = SubmitField("Update Profile")

    class ForgotPasswordForm(FlaskForm):
        email = StringField(
            "Email", validators=[DataRequired(), Email(), Length(max=120)]
        )
        submit = SubmitField("Request Reset")

    class ResetPasswordForm(FlaskForm):
        password = PasswordField(
            "New Password",
            validators=[
                DataRequired(),
                Length(min=8, max=255),
                EqualTo("confirm_password", message="Passwords must match"),
            ],
        )
        confirm_password = PasswordField(
            "Confirm Password", validators=[DataRequired()]
        )
        submit = SubmitField("Reset Password")

    class AdminUserForm(Form):
        user_id = HiddenField("User ID")  # Tambahkan ini untuk menghindari error Jinja2
        username = StringField(
            "Username", [validators.Length(min=4, max=80), validators.DataRequired()]
        )
        email = StringField("Email", [validators.Email(), validators.DataRequired()])
        full_name = StringField(
            "Full Name", [validators.Length(min=1, max=255), validators.DataRequired()]
        )
        phone = StringField(
            "Phone", [validators.Length(min=0, max=20), validators.Optional()]
        )
        is_admin = BooleanField("Is Admin")
        is_superadmin = BooleanField("Is Superadmin")
        is_active = BooleanField("Is Active")

    class ArchiveForm(Form):
        title = StringField(
            "Title", [validators.Length(min=1, max=255), validators.DataRequired()]
        )
        user_id = SelectField("User", [validators.DataRequired()], coerce=int)
        category = StringField("Category", [validators.Length(min=0, max=100)])
        tags = StringField("Tags", [validators.Length(min=0, max=255)])
        description = TextAreaField("Description", [validators.Length(min=0, max=500)])
        file = FileField("File")
        is_public = BooleanField("Is Public")

        email = StringField(
            "Email", validators=[DataRequired(), Email(), Length(max=120)]
        )
        full_name = StringField(
            "Full Name", validators=[DataRequired(), Length(min=2, max=255)]
        )
        is_admin = BooleanField("Admin")
        is_superadmin = BooleanField("Superadmin")
        submit = SubmitField("Save User")

    class SettingsForm(FlaskForm):
        key = StringField("Key", validators=[DataRequired(), Length(max=100)])
        value = TextAreaField("Value", validators=[DataRequired()])
        description = TextAreaField("Description", validators=[Length(max=65535)])
        submit = SubmitField("Save Setting")

    # User class for Flask-Login
    class User(UserMixin):
        def __init__(
            self, id, username, email, is_admin, is_superadmin, full_name, phone
        ):
            self.id = id
            self.username = username
            self.email = email
            self.is_admin = is_admin
            self.is_superadmin = is_superadmin
            self.full_name = full_name
            self.phone = phone

        def is_authenticated(self):
            return True

        def is_active(self):
            return True

        def is_anonymous(self):
            return False

        def get_id(self):
            return str(self.id)

    def get_last_login(user_id):
        conn = None
        cursor = None
        try:
            conn = (
                get_db_connection()
            )  # Pastikan fungsi ini sudah ada dan koneksi ke DB
            cursor = conn.cursor()
            query = "SELECT last_login FROM user WHERE id = %s"
            cursor.execute(query, (user_id,))
            result = cursor.fetchone()
            if result and result[0]:
                return result[0]
            else:
                return None
        except Exception as e:
            # Log error sesuai kebutuhan
            return None
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    @app.template_filter("datetimeformat")
    def datetimeformat(value, format="%d %B %Y, %H:%M"):
        """Format datetime object to string."""
        if value is None:
            return ""
        if isinstance(value, str):
            try:
                value = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return value
        return value.strftime(format)

    @login_manager.user_loader
    def load_user(user_id):
        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            if not conn:
                app.logger.error("Failed to load user: Database connection failed")
                return None

            cursor = conn.cursor(dictionary=True)

            try:
                user_id_int = int(user_id)
            except ValueError:
                app.logger.error(f"Invalid user_id: {user_id}")
                return None

            cursor.execute(
                """
                SELECT id, username, email, full_name, phone, is_admin, is_superadmin 
                FROM user 
                WHERE id = %s AND is_active = TRUE
                """,
                (user_id_int,),
            )
            user_data = cursor.fetchone()
            if user_data:
                return User(
                    id=user_data["id"],
                    username=user_data["username"],
                    email=user_data["email"],
                    is_admin=bool(user_data["is_admin"]),
                    is_superadmin=bool(user_data["is_superadmin"]),
                    full_name=user_data["full_name"],
                    phone=user_data["phone"],
                )
            else:
                app.logger.info(f"User not found or inactive for id: {user_id}")
                return None

        except Exception as e:
            app.logger.error(f"User load error: {e}")
            return None

        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    def is_valid_password(password):
        if len(password) < 8:
            return False
        if not re.search(r"[A-Z]", password):  # Huruf besar
            return False
        if not re.search(r"[a-z]", password):  # Huruf kecil
            return False
        if not re.search(r"[0-9]", password):  # Angka
            return False
        if not re.search(r"[\W_]", password):  # Karakter spesial
            return False
        return True

    # Helper function for input sanitization
    def sanitize_input(input_str):
        """
        Sanitize input string to prevent injection attacks.

        Args:
            input_str (str): Input string to sanitize

        Returns:
            str: Sanitized string or None if input is invalid
        """
        if not input_str:
            return None
        # Remove dangerous characters and limit length
        sanitized = re.sub(r"[^\w\s-]", "", input_str.strip())[:50]
        return sanitized if sanitized else None

    def get_recent_activities(cursor, user_id):
        """Get recent activities for the given user."""
        cursor.execute(
            """
            SELECT 
                id,
                action AS title,
                COALESCE(details, action) AS description,
                action AS type,
                created_at AS timestamp,
                COALESCE(
                    CASE 
                        WHEN archive_id IS NOT NULL THEN CONCAT('/archives/', archive_id)
                        WHEN user_id IS NOT NULL THEN CONCAT('/users/', user_id)
                        ELSE NULL
                    END, 
                    '#'
                ) AS link
            FROM user_logs
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT 5
        """,
            (user_id,),
        )

        activities = cursor.fetchall() or []

        # Format timestamps
        for activity in activities:
            if activity.get("timestamp"):
                activity["timestamp"] = activity["timestamp"].isoformat()

        return activities

    def get_chart_data(cursor, user_id):
        """Get archive data for chart (last 6 months)."""
        cursor.execute(
            """
            SELECT 
                DATE_FORMAT(created_at, '%%b %%Y') AS month,
                DATE_FORMAT(created_at, '%%Y-%%m') AS month_key,
                COUNT(*) AS count
            FROM archives
            WHERE user_id = %s
            AND created_at >= DATE_SUB(CURDATE(), INTERVAL 6 MONTH)
            GROUP BY month_key
            ORDER BY month_key
        """,
            (user_id,),
        )

        chart_rows = cursor.fetchall() or []

        return {
            "labels": [row["month"] for row in chart_rows],
            "data": [row["count"] for row in chart_rows],
        }

    def get_mysql_error_message(error):
        """Get user-friendly message for MySQL errors."""
        error_messages = {
            errorcode.CR_CONNECTION_ERROR: "Database connection error",
            errorcode.CR_CONN_HOST_ERROR: "Database host error",
            errorcode.ER_ACCESS_DENIED_ERROR: "Database access denied",
            errorcode.ER_BAD_DB_ERROR: "Database not found",
            errorcode.ER_DBACCESS_DENIED_ERROR: "Database access denied",
            errorcode.ER_NO_SUCH_TABLE: "Database table not found",
        }

        return error_messages.get(
            getattr(error, "errno", None), "Database operation failed"
        )

    def get_archive_stats(cursor, user_id):
        """Get archive statistics for the given user."""
        cursor.execute(
            """
            SELECT 
                COUNT(*) AS total_archives,
                SUM(CASE WHEN is_public = TRUE THEN 1 ELSE 0 END) AS public_archives,
                SUM(CASE 
                        WHEN YEAR(created_at) = YEAR(CURDATE())
                        AND MONTH(created_at) = MONTH(CURDATE()) 
                    THEN 1 ELSE 0 
                END) AS monthly_archives,
                COUNT(DISTINCT category) AS category_count
            FROM archives
            WHERE user_id = %s
        """,
            (user_id,),
        )

        result = cursor.fetchone()
        return {
            "total_archives": result["total_archives"] if result else 0,
            "public_archives": result["public_archives"] if result else 0,
            "monthly_archives": result["monthly_archives"] if result else 0,
            "category_count": result["category_count"] if result else 0,
        }

    # Routes
    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/favicon.ico")
    def favicon():
        return "", 204

    @app.route("/login", methods=["GET", "POST"])
    @csrf.exempt
    def login():
        """
        Route untuk login user.
        Melakukan autentikasi, manajemen sesi, serta logging aktivitas.
        """
        # Jika user sudah login, redirect berdasarkan peran
        if current_user.is_authenticated:
            if current_user.is_admin or current_user.is_superadmin:
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("dashboard"))

        form = LoginForm()

        if request.method == "POST":
            # Validasi form
            if not form.validate_on_submit():
                flash("Form submission invalid. Periksa kembali semua field.", "danger")
                return render_template("auth/login.html", form=form, title="Login")

            # Sanitasi input
            username = sanitize_input(form.username.data.strip())
            password = form.password.data
            ip_address = request.remote_addr or "unknown"
            user_agent = request.user_agent.string or "unknown"

            conn = None
            cursor = None

            try:
                conn = get_db_connection()
                if not conn or not conn.is_connected():
                    flash(
                        "Gagal koneksi ke database. Silakan coba lagi nanti.", "danger"
                    )
                    app.logger.error("Database connection failed during login attempt")
                    log_system_error(
                        module="Authentication",
                        message="Database connection failed during login attempt",
                        ip_address=ip_address,
                        user_id=None,
                    )
                    return render_template("auth/login.html", form=form, title="Login")

                cursor = conn.cursor(dictionary=True)
                cursor.execute(
                    """
                    SELECT id, username, email, password, is_admin, is_superadmin,
                        full_name, phone, is_active, login_attempts
                    FROM user WHERE username = %s
                    """,
                    (username,),
                )
                user = cursor.fetchone()

                if not user:
                    flash("Username atau password salah.", "danger")
                    app.logger.warning(f"Login attempt for non-existent user: {username}")
                    log_activity(
                        user_id=None,
                        action="failed_login",
                        ip_address=ip_address,
                        user_agent=user_agent,
                        description=f"Failed login attempt for non-existent user: {username}",
                    )
                    return render_template("auth/login.html", form=form, title="Login")

                if not user["is_active"]:
                    flash("Akun Anda dinonaktifkan. Hubungi administrator.", "danger")
                    app.logger.warning(f"Login attempt for inactive account: {username}")
                    log_activity(
                        user_id=user["id"],
                        action="failed_login",
                        ip_address=ip_address,
                        user_agent=user_agent,
                        description=f"Login attempt for inactive account: {username}",
                    )
                    return render_template("auth/login.html", form=form, title="Login")

                if user["login_attempts"] >= 5:
                    flash(
                        "Terlalu banyak percobaan gagal. Akun terkunci sementara.",
                        "danger",
                    )
                    app.logger.warning(
                        f"Account locked due to too many failed attempts: {username}"
                    )
                    log_activity(
                        user_id=user["id"],
                        action="failed_login",
                        ip_address=ip_address,
                        user_agent=user_agent,
                        description=f"Account locked due to too many failed attempts: {username}",
                    )
                    return render_template("auth/login.html", form=form, title="Login")

                if not check_password_hash(user["password"], password):
                    # Update login attempts
                    cursor.execute(
                        "UPDATE user SET login_attempts = login_attempts + 1 WHERE id = %s",
                        (user["id"],),
                    )
                    conn.commit()
                    flash("Username atau password salah.", "danger")
                    app.logger.warning(f"Failed login attempt: {username}")
                    log_activity(
                        user_id=user["id"],
                        action="failed_login",
                        ip_address=ip_address,
                        user_agent=user_agent,
                        description=f"Failed login attempt: {username}",
                    )
                    return render_template("auth/login.html", form=form, title="Login")

                # Autentikasi berhasil, buat objek user
                user_obj = User(
                    id=user["id"],
                    username=user["username"],
                    email=user["email"],
                    is_admin=bool(user["is_admin"]),
                    is_superadmin=bool(user["is_superadmin"]),
                    full_name=user["full_name"],
                    phone=user.get("phone"),
                )

                login_user(user_obj, remember=form.remember.data)

                # Reset login attempts dan update waktu login terakhir
                jakarta_time = datetime.now(pytz.timezone("Asia/Jakarta"))
                cursor.execute(
                    """
                    UPDATE user SET last_login = %s, login_attempts = 0 WHERE id = %s
                    """,
                    (jakarta_time, user["id"]),
                )
                conn.commit()

                # Log aktivitas login berhasil
                log_activity(
                    user_id=user["id"],
                    action="login",
                    ip_address=ip_address,
                    user_agent=user_agent,
                    description=f"Successful login for {username}",
                    details={
                        "is_admin": user["is_admin"],
                        "is_superadmin": user["is_superadmin"],
                    },
                )

                flash("Login berhasil!", "success")

                # Tentukan redirect berdasarkan peran
                next_page = request.args.get("next")
                if next_page and is_safe_url(next_page):  # Validasi URL aman
                    return redirect(next_page)
                if user["is_admin"] or user["is_superadmin"]:
                    return redirect(url_for("admin_dashboard"))
                return redirect(url_for("dashboard"))

            except mysql.connector.Error as e:
                app.logger.error(f"Login MySQL error: {e}", exc_info=True)
                log_system_error(
                    module="Authentication",
                    message=f"MySQL error during login: {str(e)}",
                    ip_address=ip_address,
                    user_id=None,
                )
                flash(f"Terjadi kesalahan database. Silakan coba lagi nanti.", "danger")
                return render_template("auth/login.html", form=form, title="Login")

            except Exception as e:
                app.logger.error(f"Login unexpected error: {e}", exc_info=True)
                log_system_error(
                    module="Authentication",
                    message=f"Unexpected error during login: {str(e)}",
                    ip_address=ip_address,
                    user_id=None,
                )
                flash(f"Terjadi kesalahan sistem. Silakan coba lagi nanti.", "danger")
                return render_template("auth/login.html", form=form, title="Login")

            finally:
                if cursor:
                    cursor.close()
                if conn and conn.is_connected():
                    conn.close()

        # Untuk method GET, tampilkan halaman login
        return render_template("auth/login.html", form=form, title="Login")

    def is_safe_url(target):
        """Validasi URL untuk mencegah redirect berbahaya."""
        from urllib.parse import urlparse, urljoin

        ref_url = urlparse(request.host_url)
        test_url = urlparse(urljoin(request.host_url, target))
        return (
            test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc
        )

    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():
        form = ForgotPasswordForm()

        if form.validate_on_submit():
            email = form.email.data
            # TODO: proses reset password, misal cek email di DB, kirim email reset link, dll
            flash("Link reset password telah dikirim ke email Anda.", "success")
            return redirect(url_for("login"))  # ganti 'login' sesuai route login Anda

        # Jika GET request atau validasi gagal, render template dengan form
        return render_template("auth/forgot_password.html", form=form)

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        form = RegisterForm()

        if form.validate_on_submit():
            # Bersihkan input
            username = sanitize_input(form.username.data.strip())
            email = sanitize_input(form.email.data.strip().lower())
            password = form.password.data
            full_name = sanitize_input(form.full_name.data.strip())
            phone = sanitize_input(form.phone.data.strip()) if form.phone.data else None

            # Proses registrasi
            conn = None
            cursor = None

            try:
                conn = get_db_connection()
                if not conn or not conn.is_connected():
                    flash("Koneksi database gagal.", "danger")
                    return render_template(
                        "auth/register.html", form=form, title="Register"
                    )

                cursor = conn.cursor(dictionary=True)

                # Cek jika username/email sudah terdaftar
                cursor.execute(
                    "SELECT id FROM user WHERE username = %s OR email = %s",
                    (username, email),
                )
                if cursor.fetchone():
                    flash("Username atau email sudah digunakan.", "danger")
                    return render_template(
                        "auth/register.html", form=form, title="Register"
                    )

                # Hash password
                password_hash = generate_password_hash(
                    password, method="pbkdf2:sha256", salt_length=16
                )

                # Timestamp dengan zona waktu Jakarta
                created_at = datetime.now(pytz.timezone("Asia/Jakarta"))

                # Masukkan user baru ke DB
                cursor.execute(
                    """
                    INSERT INTO user 
                    (username, email, password, full_name, phone, created_at, is_active, email_verified)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                    (
                        username,
                        email,
                        password_hash,
                        full_name,
                        phone,
                        created_at,
                        True,
                        False,
                    ),
                )

                user_id = cursor.lastrowid
                conn.commit()

                # Log aktivitas
                log_activity(
                    user_id=user_id,
                    action="register",
                    ip_address=request.remote_addr,
                    user_agent=request.user_agent.string,
                    description=f"User {username} berhasil registrasi",
                )

                flash("Registrasi berhasil! Silakan login.", "success")
                return redirect(url_for("login"))

            except Error as e:
                if conn:
                    conn.rollback()
                app.logger.error(f"Error registrasi: {e}")
                log_system_error("Auth", f"Registration error: {e}")
                flash("Terjadi kesalahan saat registrasi. Coba lagi nanti.", "danger")

            finally:
                if cursor:
                    cursor.close()
                if conn and conn.is_connected():
                    conn.close()

        # Tampilkan pesan error validasi form
        for field, errors in form.errors.items():
            for error in errors:
                flash(error, "danger")

        return render_template("auth/register.html", form=form, title="Register")

    @app.route("/reset_password/<token>", methods=["GET", "POST"])
    def reset_password(token):
        """
        Handle password reset using a valid token.
        Validates token expiry and password strength.
        """
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        form = ResetPasswordForm()
        conn = None
        cursor = None

        try:
            conn = get_db_connection()
            if not conn:
                flash("Database connection failed. Please try again later.", "danger")
                return redirect(url_for("forgot_password"))

            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                """
                SELECT id, username 
                FROM user 
                WHERE reset_token = %s AND reset_token_expiry > %s AND is_active = TRUE
            """,
                (token, datetime.now(pytz.timezone("Asia/Jakarta"))),
            )
            user = cursor.fetchone()

            if not user:
                flash("Invalid or expired reset token.", "danger")
                return redirect(url_for("forgot_password"))

            if form.validate_on_submit():
                password = form.password.data
                if not validate_password(password):
                    flash(
                        "Password must be at least 8 characters long and include uppercase, lowercase, numbers, and special characters.",
                        "danger",
                    )
                    return render_template(
                        "auth/reset_password.html",
                        form=form,
                        token=token,
                        title="Reset Password",
                    )

                hashed_password = generate_password_hash(
                    password, method="pbkdf2:sha256", salt_length=16
                )
                cursor.execute(
                    """
                    UPDATE user 
                    SET password = %s, reset_token = NULL, reset_token_expiry = NULL 
                    WHERE id = %s
                """,
                    (hashed_password, user["id"]),
                )
                conn.commit()

                log_activity(
                    user_id=user["id"],
                    action="password_reset",
                    ip_address=request.remote_addr or "unknown",
                    user_agent=request.user_agent.string or "unknown",
                    description=f"User {user['username']} reset their password",
                )

                flash(
                    "Your password has been successfully reset. Please login.",
                    "success",
                )
                return redirect(url_for("login"))

            return render_template(
                "auth/reset_password.html",
                form=form,
                token=token,
                title="Reset Password",
            )

        except Exception as e:
            app.logger.error(f"Password reset error: {e}", exc_info=True)
            log_system_error("Authentication", f"Password reset exception: {e}")
            flash(
                "An error occurred while processing your request. Please try again.",
                "danger",
            )
            return redirect(url_for("forgot_password"))

        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

    @app.route("/logout")
    @login_required
    def logout():
        """
        Logs out the current user and records the activity.
        """
        user_id = current_user.id
        username = current_user.username

        # Logout user session
        logout_user()

        # Log activity after logout
        log_activity(
            user_id=user_id,
            action="logout",
            ip_address=request.remote_addr or "unknown",
            user_agent=request.user_agent.string or "unknown",
            description=f"User {username} logged out.",
        )

        flash("You have been successfully logged out.", "success")
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        """
        Halaman utama dashboard pengguna.
        - Mencatat aktivitas akses pengguna.
        - Menyediakan data dashboard.
        - Menangani dan mencatat error jika terjadi.
        """
        try:
            # Detail akses pengguna
            access_details = {
                "route": request.path,
                "method": request.method,
                "referrer": request.referrer or "unknown",
            }

            # Logging aktivitas akses dashboard
            log_activity(
                user_id=current_user.id,
                action="dashboard_access",
                ip_address=request.remote_addr or "unknown",
                user_agent=request.user_agent.string or "unknown",
                description=f"Akses dashboard oleh {current_user.username}",
                details=access_details,
            )

            # Persiapan data dashboard
            dashboard_data = {
                "user": current_user,
                "title": "Dashboard",
                "csrf_token": generate_csrf(),  # pastikan csrf_token diakses sebagai string
                "last_login": get_last_login(current_user.id),
                "notifications": get_user_notifications(current_user.id),
                "current_year": datetime.now(pytz.timezone("Asia/Jakarta")).year,
            }

            return render_template("dashboard.html", **dashboard_data)

        except Exception as e:
            error_id = str(uuid.uuid4())
            user_id = getattr(current_user, "id", "unknown")
            ip_address = request.remote_addr or "unknown"

            # Logging ke file/error log
            app.logger.error(
                f"[{error_id}] Dashboard Error - User: {user_id} | IP: {ip_address} | Error: {str(e)}",
                exc_info=True,
            )

            # Logging ke sistem atau database
            log_system_error(
                module="Dashboard",
                message=f"Render error [{error_id}]: {str(e)}",
                ip_address=ip_address,
                user_id=None if user_id == "unknown" else user_id,
                details={
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "traceback": traceback.format_exc(),
                    "user_id": user_id,
                    "ip_address": ip_address,
                    "request_path": request.path if request else None,
                },
            )

            # Memberi notifikasi ke pengguna
            flash(
                f"Terjadi kesalahan saat memuat dashboard (ID: {error_id}). Silakan coba lagi.",
                "danger",
            )
            return redirect(url_for("index"))

    @app.route("/api/dashboard", methods=["GET"])
    @login_required
    def api_dashboard():
        """
        API endpoint untuk mendapatkan statistik dashboard pengguna.
        Meliputi: total arsip, arsip publik, arsip bulan ini, kategori unik,
        log aktivitas terakhir, dan data grafik arsip 6 bulan terakhir.

        Returns:
            JSON response dengan struktur:
            {
                "status": "success"/"error",
                "stats": {
                    "total_archives": int,
                    "public_archives": int,
                    "monthly_archives": int,
                    "category_count": int
                },
                "activities": [list of activity objects],
                "chart_data": {
                    "labels": [list of month names],
                    "data": [list of archive counts]
                },
                "error": string (only when status is "error")
            }
        """
        conn = None
        cursor = None
        error_id = str(uuid.uuid4())
        user_ip = request.remote_addr or "unknown"
        user_agent = request.user_agent.string or "unknown"

        try:
            # 1. Establish database connection
            conn = get_db_connection()
            if not conn or not conn.is_connected():
                logging.error(f"[{error_id}] API Dashboard: Database connection failed")
                raise RuntimeError("Database connection failed")

            cursor = conn.cursor(dictionary=True)

            # 2. Get archive statistics
            stats = get_archive_stats(cursor, current_user.id)
            # Konversi Decimal di stats
            stats = {
                k: float(v) if isinstance(v, Decimal) else v for k, v in stats.items()
            }

            # 3. Get recent activities
            activities = get_recent_activities(cursor, current_user.id)

            # 4. Get chart data
            chart_data = get_chart_data(cursor, current_user.id)

            # 5. Log successful access
            log_activity(
                user_id=current_user.id,
                action="api_dashboard",
                ip_address=user_ip,
                user_agent=user_agent,
                description=f"User {current_user.username} fetched dashboard data",
                details={
                    "stats": stats,
                    "activity_count": len(activities),
                    "chart_points": len(chart_data["labels"]),
                },
            )

            return jsonify(
                {
                    "status": "success",
                    "stats": stats,
                    "activities": activities,
                    "chart_data": chart_data,
                }
            )

        except mysql.connector.Error as e:
            logging.error(f"[{error_id}] API Dashboard MySQL error: {e}", exc_info=True)
            log_system_error(
                module="API Dashboard",
                message=f"MySQL error [{error_id}]: {str(e)}",
                ip_address=user_ip,
                user_id=current_user.id,
                details={
                    "error_type": type(e).__name__,
                    "error_code": getattr(e, "errno", None),
                    "sql_state": getattr(e, "sqlstate", None),
                },
            )

            error_msg = get_mysql_error_message(e)
            return (
                jsonify({"status": "error", "error": error_msg, "error_id": error_id}),
                500,
            )

        except Exception as e:
            logging.error(
                f"[{error_id}] API Dashboard unexpected error: {e}", exc_info=True
            )
            log_system_error(
                module="API Dashboard",
                message=f"Unexpected error [{error_id}]: {str(e)}",
                ip_address=user_ip,
                user_id=current_user.id,
                details={
                    "error_type": type(e).__name__,
                    "traceback": traceback.format_exc(),
                },
            )
            return (
                jsonify(
                    {
                        "status": "error",
                        "error": "Internal server error",
                        "error_id": error_id,
                    }
                ),
                500,
            )

        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

    @app.route("/activity", methods=["GET"])
    @app.route("/activity/<string:action_filter>", methods=["GET"])
    @login_required
    def activity(action_filter=None):
        """
        Display user activity logs with pagination and filtering for kelurahan archive system.

        Retrieves logs from user_logs and archive_access_log tables, supports pagination,
        and filters by action type (e.g., upload, download, delete).

        Args:
            action_filter (str, optional): Filter activities by action type (e.g., 'upload', 'download')
            page (int, optional): Page number for pagination (default: 1)

        Returns:
            Rendered activity.html template with activity logs or redirect on error
        """
        page = request.args.get("page", default=1, type=int)
        per_page = 10
        offset = (page - 1) * per_page

        valid_actions = [
            "login",
            "logout",
            "upload",
            "download",
            "delete",
            "view",
            "profile_update",
            "password_change",
            "view_activity",
        ]

        action_filter = sanitize_input(action_filter) if action_filter else None
        if action_filter and action_filter not in valid_actions:
            flash("Filter aksi tidak valid.", "danger")
            logging.warning(f"Invalid action filter attempted: {action_filter}")
            return redirect(url_for("activity"))

        conn = None
        cursor = None
        error_id = str(uuid.uuid4())

        try:
            conn = get_db_connection()
            if not conn or not conn.is_connected():
                flash("Gagal terhubung ke database.", "danger")
                logging.error(
                    f"[{error_id}] Activity route: Database connection failed"
                )
                log_system_error(
                    module="Activity",
                    message=f"Database connection failed [{error_id}]",
                    ip_address=request.remote_addr or "unknown",
                    user_id=current_user.id,
                    details={"route": request.path, "action_filter": action_filter},
                )
                return redirect(url_for("dashboard"))

            cursor = conn.cursor(dictionary=True)

            # Perbaikan: Ganti 'users' dengan 'user' di query
            query_params = [current_user.id, current_user.id]
            base_query = """
                SELECT 
                    id,
                    action,
                    description,
                    ip_address,
                    user_agent,
                    created_at,
                    details,
                    archive_title
                FROM (
                    SELECT 
                        ul.id,
                        ul.action,
                        ul.description,
                        ul.ip_address,
                        ul.user_agent,
                        ul.created_at,
                        ul.details,
                        a.title AS archive_title
                    FROM user_logs ul
                    LEFT JOIN archive_access_log aal 
                        ON ul.action IN ('download', 'delete', 'view')
                        AND aal.user_id = ul.user_id
                        AND aal.access_type = ul.action
                        AND ABS(TIMESTAMPDIFF(MICROSECOND, aal.access_time, ul.created_at)) < 1000000
                    LEFT JOIN archives a ON aal.archive_id = a.id
                    WHERE ul.user_id = %s
                    UNION
                    SELECT 
                        aal.id,
                        aal.access_type AS action,
                        CONCAT('User ', u.username, ' performed ', aal.access_type, ' on archive: ', COALESCE(a.title, 'Deleted Archive')) AS description,
                        aal.ip_address,
                        '' AS user_agent,
                        aal.access_time AS created_at,
                        NULL AS details,
                        a.title AS archive_title
                    FROM archive_access_log aal
                    JOIN user u ON aal.user_id = u.id
                    LEFT JOIN archives a ON aal.archive_id = a.id
                    WHERE aal.user_id = %s
                ) AS combined
            """
            count_query = """
                SELECT COUNT(*) AS total
                FROM (
                    SELECT 1 FROM user_logs ul WHERE ul.user_id = %s
                    UNION
                    SELECT 1 FROM archive_access_log aal WHERE aal.user_id = %s
                ) AS combined
            """

            if action_filter:
                base_query += " WHERE action = %s"
                count_query += " WHERE action = %s"
                query_params.append(action_filter)
                count_query_params = [current_user.id, current_user.id, action_filter]
            else:
                count_query_params = [current_user.id, current_user.id]

            cursor.execute(count_query, count_query_params)
            total_count = cursor.fetchone()["total"]
            total_pages = (total_count + per_page - 1) // per_page

            base_query += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
            query_params.extend([per_page, offset])
            cursor.execute(base_query, query_params)
            activities = cursor.fetchall()

            for activity in activities:
                if activity.get("created_at"):
                    activity["created_at"] = activity["created_at"].strftime(
                        "%d %B %Y, %H:%M"
                    )
                if activity.get("details"):
                    try:
                        activity["details"] = json.loads(activity["details"])
                    except json.JSONDecodeError:
                        activity["details"] = {"raw": activity["details"]}
                activity["archive_title"] = activity["archive_title"] or "Arsip Dihapus"

            log_activity(
                user_id=current_user.id,
                action="view_activity",
                ip_address=request.remote_addr or "unknown",
                user_agent=request.user_agent.string or "unknown",
                description=f"Pengguna {current_user.username} melihat log aktivitas halaman {page} dengan filter {action_filter or 'semua'}",
                details={
                    "page": page,
                    "total_activities": total_count,
                    "per_page": per_page,
                    "action_filter": action_filter,
                },
            )

            template_data = {
                "title": "Log Aktivitas",
                "activities": activities,
                "current_page": page,
                "total_pages": total_pages,
                "action_filter": action_filter,
                "valid_actions": valid_actions,
                "csrf_token": generate_csrf(),
                "current_year": datetime.now(pytz.timezone("Asia/Jakarta")).year,
            }

            return render_template("activity.html", **template_data)

        except mysql.connector.Error as e:
            error_details = {
                "error_type": type(e).__name__,
                "error_code": getattr(e, "errno", None),
                "sql_state": getattr(e, "sqlstate", None),
                "route": request.path,
                "action_filter": action_filter,
            }
            logging.error(
                f"[{error_id}] Activity route MySQL error: {e}", exc_info=True
            )
            log_system_error(
                module="Activity",
                message=f"MySQL error [{error_id}]: {str(e)}",
                ip_address=request.remote_addr or "unknown",
                user_id=current_user.id,
                details=error_details,
            )

            if e.errno == mysql.connector.errorcode.ER_NO_SUCH_TABLE:
                flash(
                    f"Tabel database tidak ditemukan (ID: {error_id}). Hubungi administrator.",
                    "danger",
                )
            elif e.errno == mysql.connector.errorcode.ER_ACCESS_DENIED_ERROR:
                flash(
                    f"Izin akses database ditolak (ID: {error_id}). Hubungi administrator.",
                    "danger",
                )
            else:
                flash(
                    f"Terjadi kesalahan database (ID: {error_id}). Silakan coba lagi.",
                    "danger",
                )

            return redirect(url_for("dashboard"))

        except Exception as e:
            logging.error(
                f"[{error_id}] Activity route unexpected error: {e}", exc_info=True
            )
            log_system_error(
                module="Activity",
                message=f"Unexpected error [{error_id}]: {str(e)}",
                ip_address=request.remote_addr or "unknown",
                user_id=current_user.id,
                details={"route": request.path, "action_filter": action_filter},
            )
            flash(
                f"Terjadi kesalahan sistem (ID: {error_id}). Silakan coba lagi.",
                "danger",
            )
            return redirect(url_for("dashboard"))

        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

    @app.route("/profile", methods=["GET", "POST"])
    @login_required
    def profile():
        form = ProfileForm()

        if request.method == "GET":
            # Pre-populasi data ke form saat halaman pertama kali diakses
            form.username.data = current_user.username
            form.email.data = current_user.email
            form.full_name.data = current_user.full_name
            form.phone.data = current_user.phone

        elif form.validate_on_submit():
            # Ambil dan sanitasi input dari form
            username = sanitize_input(form.username.data.strip())
            email = sanitize_input(form.email.data.strip().lower())
            full_name = sanitize_input(form.full_name.data.strip())
            phone = sanitize_input(form.phone.data.strip()) if form.phone.data else None

            # Validasi format email dan username
            if not validate_email(email):
                flash("Format email tidak valid.", "danger")
                return render_template("profile.html", form=form, title="Profile")

            if not validate_username(username):
                flash(
                    "Username harus 4–80 karakter dan hanya mengandung huruf, angka, atau underscore (_).",
                    "danger",
                )
                return render_template("profile.html", form=form, title="Profile")

            conn = None
            cursor = None

            try:
                conn = get_db_connection()
                if not conn or not conn.is_connected():
                    flash("Koneksi ke database gagal.", "danger")
                    return render_template("profile.html", form=form, title="Profile")

                cursor = conn.cursor(dictionary=True)

                # Cek apakah username/email sudah digunakan oleh user lain
                cursor.execute(
                    """
                    SELECT id FROM user
                    WHERE (username = %s OR email = %s) AND id != %s
                """,
                    (username, email, current_user.id),
                )

                if cursor.fetchone():
                    flash(
                        "Username atau email sudah digunakan oleh pengguna lain.",
                        "danger",
                    )
                    return render_template("profile.html", form=form, title="Profile")

                # Lakukan update ke database
                cursor.execute(
                    """
                    UPDATE user
                    SET username = %s,
                        email = %s,
                        full_name = %s,
                        phone = %s,
                        updated_at = %s
                    WHERE id = %s
                """,
                    (
                        username,
                        email,
                        full_name,
                        phone,
                        datetime.now(pytz.timezone("Asia/Jakarta")),
                        current_user.id,
                    ),
                )
                conn.commit()

                # Sinkronkan data user di session
                current_user.username = username
                current_user.email = email
                current_user.full_name = full_name
                current_user.phone = phone

                # Logging aktivitas
                log_activity(
                    user_id=current_user.id,
                    action="profile_update",
                    ip_address=request.remote_addr or "unknown",
                    user_agent=request.user_agent.string or "unknown",
                    description=f"User {username} updated profile",
                )

                flash("Profil berhasil diperbarui.", "success")
                return redirect(url_for("profile"))

            except Error as e:
                if conn:
                    conn.rollback()
                app.logger.error(f"Profile update MySQL error: {e}", exc_info=True)
                log_system_error("Profile Update", f"MySQL error: {e}")
                flash("Terjadi kesalahan pada database. Silakan coba lagi.", "danger")

            except Exception as e:
                app.logger.error(f"Profile update unexpected error: {e}", exc_info=True)
                log_system_error("Profile Update", f"Unexpected error: {e}")
                flash("Terjadi kesalahan tak terduga. Silakan coba lagi.", "danger")

            finally:
                if cursor:
                    cursor.close()
                if conn and conn.is_connected():
                    conn.close()

        return render_template("profile.html", form=form, title="Profile")

    @app.route("/change_password", methods=["POST"])
    @login_required
    def change_password():
        current_password = request.form.get("current_password", "").strip()
        new_password = request.form.get("new_password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        # Validasi input wajib diisi
        if not all([current_password, new_password, confirm_password]):
            flash("All fields are required.", "danger")
            return redirect(url_for("profile"))

        # Validasi password baru harus sama
        if new_password != confirm_password:
            flash("New passwords do not match.", "danger")
            return redirect(url_for("profile"))

        # Validasi aturan password baru
        if not is_valid_password(new_password):
            flash(
                "Password must be at least 8 characters with uppercase, lowercase, numbers, and special characters.",
                "danger",
            )
            return redirect(
                url_for("profile")
            )  # jangan lupa return supaya tidak lanjut ke proses berikutnya

        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            if not conn:
                flash("Database connection failed.", "danger")
                return redirect(url_for("profile"))

            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT password FROM user WHERE id = %s", (current_user.id,)
            )
            user = cursor.fetchone()

            # Validasi password saat ini benar
            if not user or not check_password_hash(user["password"], current_password):
                flash("Current password is incorrect.", "danger")
                return redirect(url_for("profile"))

            # Generate hash password baru dan update di DB
            password_hash = generate_password_hash(
                new_password, method="pbkdf2:sha256", salt_length=16
            )
            cursor.execute(
                "UPDATE user SET password = %s WHERE id = %s",
                (password_hash, current_user.id),
            )
            conn.commit()

            # Log aktivitas perubahan password
            log_activity(
                current_user.id,
                "password_change",
                request.remote_addr,
                request.user_agent.string,
                f"User {current_user.username} changed password",
            )

            flash("Password changed successfully!", "success")
            return redirect(url_for("profile"))

        except Error as e:
            if conn:
                conn.rollback()
            app.logger.error(f"Password change error: {e}")
            log_system_error("Profile", f"Password change error: {e}")
            flash("Failed to change password. Please try again.", "danger")
            return redirect(url_for("profile"))

        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

    @app.route("/api/search")
    @login_required
    def api_search():
        query = request.args.get("query", "").strip()
        if not query:
            return jsonify({"results": []})

        # Sanitasi input, misal escape karakter khusus jika perlu
        sanitized_query = sanitize_input(query)

        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            if not conn:
                return (
                    jsonify({"results": [], "error": "Database connection failed"}),
                    500,
                )

            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                """
                SELECT id, title, category, created_at 
                FROM archives 
                WHERE user_id = %s AND title LIKE %s
                ORDER BY created_at DESC
                LIMIT 20
                """,
                (current_user.id, f"%{sanitized_query}%"),
            )
            results = cursor.fetchall()

            # Log aktivitas pencarian user (optional tapi direkomendasikan)
            log_activity(
                current_user.id,
                "search_archives",
                request.remote_addr,
                request.user_agent.string,
                f"User {current_user.username} melakukan pencarian dengan query: {sanitized_query}",
            )

            return jsonify({"results": results})
        except Error as e:
            app.logger.error(f"Search error: {e}")
            log_system_error("Search", f"Search error: {e}")
            return (
                jsonify({"results": [], "error": "An error occurred while searching"}),
                500,
            )
        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

    # Archive list route
    @app.route("/archives", methods=["GET"])
    @login_required
    def archive_list():
        """
        Display a paginated list of user archives with search and filter capabilities.

        Args:
            page (int): Page number (default: 1)
            sort (str): Sort order (newest, oldest, title_asc, title_desc)
            query (str): Search query for title
            category (str): Filter by category (from archives.category ENUM)
            date_range (str): Filter by time period (today, week, month, year)

        Returns:
            Rendered archive_list.html template with archives and filters
        """
        page = request.args.get("page", default=1, type=int)
        sort = request.args.get("sort", default="newest", type=str).lower()
        query = request.args.get("query", default="", type=str).strip()
        category = request.args.get("category", default="", type=str).strip()
        date_range = request.args.get("date_range", default="", type=str).strip()
        per_page = 10
        offset = max(0, (page - 1) * per_page)  # Prevent negative offset
        error_id = str(uuid.uuid4())

        # Validate page number
        if page < 1:
            flash("Nomor halaman tidak valid.", "danger")
            return redirect(url_for("archive_list"))

        # Validate sort parameter
        sort_options = {
            "newest": "created_at DESC",
            "oldest": "created_at ASC",
            "title_asc": "title ASC",
            "title_desc": "title DESC",
        }
        order_by = sort_options.get(sort, "created_at DESC")

        # Validate category against ENUM
        valid_categories = ["document", "image", "other"]
        if category and category not in valid_categories:
            flash("Kategori tidak valid.", "danger")
            category = ""

        # Validate date_range
        valid_date_ranges = ["today", "week", "month", "year"]
        if date_range and date_range not in valid_date_ranges:
            flash("Rentang waktu tidak valid.", "danger")
            date_range = ""

        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            if not conn or not conn.is_connected():
                flash("Gagal terhubung ke database.", "danger")
                app.logger.error(f"[{error_id}] Archive list: Database connection failed")
                log_system_error(
                    module="Archive",
                    message=f"Database connection failed [{error_id}]",
                    ip_address=request.remote_addr or "unknown",
                    user_id=current_user.id,
                    details={
                        "route": request.path,
                        "sort": sort,
                        "query": query,
                        "category": category,
                    },
                )
                return render_template(
                    "archive_list.html",
                    archives=[],
                    categories=valid_categories,
                    total_pages=0,
                    current_page=page,
                    sort=sort,
                    title="Daftar Arsip",
                    query=query,
                    category=category,
                    date_range=date_range,
                    csrf_token=generate_csrf(),
                )

            cursor = conn.cursor(dictionary=True)

            # Build query with filters
            where_clause = "WHERE user_id = %s"
            params = [current_user.id]
            if query:
                where_clause += " AND title LIKE %s"
                params.append(f"%{sanitize_input(query)}%")
            if category:
                where_clause += " AND category = %s"
                params.append(category)
            if date_range:
                if date_range == "today":
                    where_clause += " AND DATE(created_at) = CURDATE()"
                elif date_range == "week":
                    where_clause += " AND created_at >= CURDATE() - INTERVAL 7 DAY"
                elif date_range == "month":
                    where_clause += " AND created_at >= CURDATE() - INTERVAL 1 MONTH"
                elif date_range == "year":
                    where_clause += " AND created_at >= CURDATE() - INTERVAL 1 YEAR"

            # Count total archives
            count_query = f"SELECT COUNT(*) AS count FROM archives {where_clause}"
            cursor.execute(count_query, params)
            total_count = cursor.fetchone()["count"]
            total_pages = max(1, (total_count + per_page - 1) // per_page)

            # Prevent excessive pages
            if page > total_pages:
                flash("Halaman tidak ditemukan.", "danger")
                return redirect(
                    url_for(
                        "archive_list",
                        page=total_pages,
                        sort=sort,
                        query=query,
                        category=category,
                        date_range=date_range,
                    )
                )

            # Fetch archives
            query = f"""
                SELECT id, title, category, file_name, file_type, file_size, created_at, is_public
                FROM archives
                {where_clause}
                ORDER BY {order_by}
                LIMIT %s OFFSET %s
            """
            params.extend([per_page, offset])
            cursor.execute(query, params)
            archives = cursor.fetchall()

            # Format file_size and created_at
            for archive in archives:
                archive["file_size"] = format_file_size(archive["file_size"])
                archive["created_at"] = archive["created_at"].strftime("%d %b %Y")

            # Use ENUM categories instead of querying
            categories = valid_categories

            # Log activity
            log_activity(
                user_id=current_user.id,
                action="view_archive_list",
                ip_address=request.remote_addr or "unknown",
                user_agent=request.user_agent.string or "unknown",
                description=f"Pengguna {current_user.username} melihat daftar arsip halaman {page} dengan urutan {sort}",
                details={
                    "page": page,
                    "sort": sort,
                    "query": query,
                    "category": category,
                    "date_range": date_range,
                    "total_count": total_count,
                },
            )

            return render_template(
                "archive_list.html",
                archives=archives,
                categories=categories,
                total_pages=total_pages,
                current_page=page,
                sort=sort,
                title="Daftar Arsip",
                query=query,
                category=category,
                date_range=date_range,
                csrf_token=generate_csrf(),
            )

        except mysql.connector.Error as e:
            error_details = {
                "error_type": type(e).__name__,
                "error_code": getattr(e, "errno", None),
                "sql_state": getattr(e, "sqlstate", None),
                "route": request.path,
                "sort": sort,
                "query": query,
                "category": category,
                "date_range": date_range,
            }
            app.logger.error(f"[{error_id}] Archive list MySQL error: {e}", exc_info=True)
            log_system_error(
                module="Archive",
                message=f"MySQL error [{error_id}]: {str(e)}",
                ip_address=request.remote_addr or "unknown",
                user_id=current_user.id,
                details=error_details,
            )

            # Handle specific MariaDB errors
            if e.errno == mysql.connector.errorcode.ER_NO_SUCH_TABLE:
                flash(
                    f"Tabel arsip tidak ditemukan (ID: {error_id}). Hubungi administrator.",
                    "danger",
                )
            elif e.errno == mysql.connector.errorcode.ER_ACCESS_DENIED_ERROR:
                flash(
                    f"Izin akses database ditolak (ID: {error_id}). Hubungi administrator.",
                    "danger",
                )
            elif e.errno == mysql.connector.errorcode.ER_BAD_FIELD_ERROR:
                flash(
                    f"Kolom database tidak valid (ID: {error_id}). Hubungi administrator.",
                    "danger",
                )
            else:
                flash(
                    f"Terjadi kesalahan database (ID: {error_id}). Silakan coba lagi.",
                    "danger",
                )

            return render_template(
                "archive_list.html",
                archives=[],
                categories=valid_categories,
                total_pages=0,
                current_page=page,
                sort=sort,
                title="Daftar Arsip",
                query=query,
                category=category,
                date_range=date_range,
                csrf_token=generate_csrf(),
            )

        except Exception as e:
            app.logger.error(
                f"[{error_id}] Archive list unexpected error: {e}", exc_info=True
            )
            log_system_error(
                module="Archive",
                message=f"Unexpected error [{error_id}]: {str(e)}",
                ip_address=request.remote_addr or "unknown",
                user_id=current_user.id,
                details={
                    "route": request.path,
                    "sort": sort,
                    "query": query,
                    "category": category,
                    "date_range": date_range,
                },
            )
            flash(
                f"Terjadi kesalahan sistem (ID: {error_id}). Silakan coba lagi.",
                "danger",
            )
            return render_template(
                "archive_list.html",
                archives=[],
                categories=valid_categories,
                total_pages=0,
                current_page=page,
                sort=sort,
                title="Daftar Arsip",
                query=query,
                category=category,
                date_range=date_range,
                csrf_token=generate_csrf(),
            )

        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

    # Helper functions
    def format_file_size(size):
        """Convert file size to human-readable format."""
        try:
            size = int(size)
            if size < 0:
                return "0 B"
            for unit in ["B", "KB", "MB", "GB"]:
                if size < 1024:
                    return f"{size:.2f} {unit}"
                size /= 1024
            return f"{size:.2f} TB"
        except (ValueError, TypeError):
            app.logger.warning(f"Invalid file_size: {size}")
            return "Unknown"

    def sanitize_input(input_str):
        """Sanitize input string to prevent injection attacks."""
        if not input_str:
            return ""
        # Remove dangerous characters and limit length
        import re

        sanitized = re.sub(r"[^\w\s-]", "", input_str.strip())[:255]
        return sanitized

    def validate_phone(phone):
        """Validate phone number format"""
        return re.match(r"^\+?[\d\s\-]{10,15}$", phone) is not None

    def validate_username(username):
        """Validate username format"""
        return re.match(r"^[a-zA-Z0-9_]{4,80}$", username) is not None

    @app.route("/archives/upload", methods=["GET", "POST"])
    @login_required
    def archive_upload():
        error_id = str(uuid.uuid4())
        app.logger.debug(f"[{error_id}] Memulai proses archive_upload")

        try:
            # Pastikan direktori Uploads ada
            os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
            app.logger.debug(f"Direktori {app.config['UPLOAD_FOLDER']} dipastikan ada")

            if request.method == "POST":
                app.logger.debug(f"[{error_id}] Menerima permintaan POST")

                # Validasi CSRF
                try:
                    validate_csrf(request.form.get("csrf_token"))
                    app.logger.debug(f"[{error_id}] CSRF token valid")
                except Exception as e:
                    app.logger.error(f"[{error_id}] CSRF validation failed: {e}")
                    flash("CSRF token tidak valid.", "danger")
                    return redirect(url_for("archive_upload"))

                # Validasi input
                title = request.form.get("title", "").strip()
                category = request.form.get("category", "").strip()
                description = request.form.get("description", "").strip()
                is_public = request.form.get("is_public", "off") == "on"

                if not title or len(title) > 255:
                    app.logger.debug(f"[{error_id}] Validasi gagal: Judul tidak valid")
                    flash("Judul wajib diisi dan maksimal 255 karakter.", "danger")
                    return redirect(url_for("archive_upload"))

                if category not in ["document", "image", "other"]:
                    app.logger.debug(f"[{error_id}] Validasi gagal: Kategori tidak valid")
                    flash("Kategori tidak valid.", "danger")
                    return redirect(url_for("archive_upload"))

                if description and len(description) > 500:
                    app.logger.debug(
                        f"[{error_id}] Validasi gagal: Deskripsi terlalu panjang"
                    )
                    flash("Deskripsi maksimal 500 karakter.", "danger")
                    return redirect(url_for("archive_upload"))

                # Validasi file
                if "file" not in request.files:
                    app.logger.debug(f"[{error_id}] Validasi gagal: Tidak ada file")
                    flash("Silakan pilih file terlebih dahulu.", "danger")
                    return redirect(url_for("archive_upload"))

                file = request.files["file"]
                if file.filename == "":
                    app.logger.debug(f"[{error_id}] Validasi gagal: Nama file kosong")
                    flash("Tidak ada file yang dipilih.", "danger")
                    return redirect(url_for("archive_upload"))

                filename = secure_filename(file.filename)
                if not allowed_file(filename):
                    app.logger.debug(
                        f"[{error_id}] Validasi gagal: Jenis file tidak diizinkan"
                    )
                    flash(
                        f'Jenis file tidak didukung. Hanya {", ".join(app.config["ALLOWED_EXTENSIONS"])} yang diperbolehkan.',
                        "danger",
                    )
                    return redirect(url_for("archive_upload"))

                file.seek(0, os.SEEK_END)
                file_size = file.tell()
                file.seek(0)
                if file_size > app.config["MAX_FILE_SIZE"]:
                    app.logger.debug(
                        f"[{error_id}] Validasi gagal: Ukuran file terlalu besar"
                    )
                    flash(
                        f'Ukuran file terlalu besar (maksimal {app.config["MAX_FILE_SIZE"] // (1024 * 1024)}MB).',
                        "danger",
                    )
                    return redirect(url_for("archive_upload"))

                # Simpan file
                unique_filename = f"{uuid.uuid4().hex}_{filename}"
                file_path = os.path.join(app.config["UPLOAD_FOLDER"], unique_filename)
                app.logger.debug(f"[{error_id}] Mencoba menyimpan file ke {file_path}")
                file.save(file_path)

                if not os.path.exists(file_path):
                    app.logger.error(
                        f"[{error_id}] Gagal menyimpan file: File tidak ditemukan di {file_path}"
                    )
                    flash("Gagal menyimpan file.", "danger")
                    return redirect(url_for("archive_upload"))
                app.logger.debug(f"[{error_id}] File berhasil disimpan ke {file_path}")

                # Simpan ke database
                conn = get_db_connection()
                if not conn or not conn.is_connected():
                    app.logger.error(f"[{error_id}] Koneksi database gagal")
                    cleanup_uploaded_file(file_path)
                    flash("Koneksi database gagal.", "danger")
                    return redirect(url_for("archive_upload"))

                cursor = conn.cursor()
                try:
                    query = """
                        INSERT INTO archives (
                            user_id, title, description, category, file_name, file_path,
                            file_type, file_size, is_public, created_at, updated_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """
                    params = (
                        current_user.id,
                        title,
                        description or None,
                        category,
                        filename,
                        file_path,
                        mimetypes.guess_type(filename)[0] or "application/octet-stream",
                        file_size,
                        is_public,
                        datetime.now(pytz.timezone("Asia/Jakarta")),
                        datetime.now(pytz.timezone("Asia/Jakarta")),
                    )
                    cursor.execute(query, params)
                    archive_id = cursor.lastrowid
                    app.logger.debug(
                        f"[{error_id}] Metadata berhasil disimpan dengan archive_id: {archive_id}"
                    )

                    # Log aktivitas
                    log_activity(
                        user_id=current_user.id,
                        action="upload_archive",
                        ip_address=request.remote_addr or "unknown",
                        user_agent=request.user_agent.string or "unknown",
                        description=f"Pengguna {current_user.username} mengunggah arsip '{title}'",
                        details={"archive_id": archive_id, "filename": filename},
                    )

                    # Simpan log akses
                    access_query = """
                        INSERT INTO archive_access_log (
                            archive_id, user_id, access_type, ip_address, access_time
                        ) VALUES (%s, %s, %s, %s, %s)
                    """
                    access_params = (
                        archive_id,
                        current_user.id,
                        "edit",
                        request.remote_addr or "unknown",
                        datetime.now(pytz.timezone("Asia/Jakarta")),
                    )
                    cursor.execute(access_query, access_params)

                    conn.commit()
                    app.logger.debug(f"[{error_id}] Transaksi database berhasil")
                    flash("Arsip berhasil diunggah.", "success")
                    return redirect(url_for("archive_list"))

                except mysql.connector.Error as e:
                    conn.rollback()
                    cleanup_uploaded_file(file_path)
                    app.logger.error(f"[{error_id}] MySQL error: {e}")
                    log_system_error(
                        module="Archive",
                        message=f"MySQL error [{error_id}]: {str(e)}",
                        ip_address=request.remote_addr or "unknown",
                        user_id=current_user.id,
                    )
                    flash(f"Gagal menyimpan arsip (ID: {error_id}).", "danger")
                    return redirect(url_for("archive_upload"))

                finally:
                    cursor.close()
                    conn.close()
                    app.logger.debug(f"[{error_id}] Koneksi database ditutup")

            # GET request - tampilkan halaman upload
            app.logger.debug(f"[{error_id}] Merender halaman archive_upload.html")
            return render_template(
                "archive_upload.html",
                title="Unggah Arsip",
                categories=["document", "image", "other"],
                csrf_token=generate_csrf(),
            )

        except Exception as e:
            app.logger.error(
                f"[{error_id}] Unexpected error in archive_upload: {e}", exc_info=True
            )
            log_system_error(
                module="Archive",
                message=f"Unexpected error [{error_id}]: {str(e)}",
                ip_address=request.remote_addr or "unknown",
                user_id=current_user.id,
            )
            flash(
                f"Terjadi kesalahan sistem (ID: {error_id}). Silakan coba lagi.",
                "danger",
            )
            return redirect(url_for("archive_upload"))

    @app.route("/archives/<int:archive_id>", methods=["GET"])
    @login_required
    def archive_detail(archive_id):
        """
        Display details of a specific archive.

        Args:
            archive_id (int): ID of the archive to display

        Returns:
            Rendered archive_detail.html template or redirect on error
        """
        conn = None
        cursor = None
        error_id = str(uuid.uuid4())

        try:
            conn = get_db_connection()
            if not conn or not conn.is_connected():
                flash("Gagal terhubung ke database.", "danger")
                app.logger.error(f"[{error_id}] Archive detail: Database connection failed")
                return redirect(url_for("archive_list"))

            cursor = conn.cursor(dictionary=True)

            # Fetch archive details
            cursor.execute(
                """
                SELECT id, title, description, category, archive_number, file_name, file_path,
                    file_type, file_size, is_public, created_at, updated_at
                FROM archives
                WHERE id = %s AND user_id = %s
                """,
                (archive_id, current_user.id),
            )
            archive = cursor.fetchone()

            if not archive:
                flash("Arsip tidak ditemukan atau Anda tidak memiliki akses.", "danger")
                return redirect(url_for("archive_list"))

            # Fetch tags
            cursor.execute(
                "SELECT tag_name FROM archive_tags WHERE archive_id = %s", (archive_id,)
            )
            tags = [row["tag_name"] for row in cursor.fetchall()]

            # Format data
            archive["file_size"] = format_file_size(archive["file_size"])
            archive["created_at"] = archive["created_at"].strftime("%d %B %Y, %H:%M")
            archive["updated_at"] = (
                archive["updated_at"].strftime("%d %B %Y, %H:%M")
                if archive["updated_at"]
                else "-"
            )

            # Log activity
            log_activity(
                user_id=current_user.id,
                action="view_archive",
                ip_address=request.remote_addr or "unknown",
                user_agent=request.user_agent.string or "unknown",
                description=f"User {current_user.username} viewed archive: {archive['title']}",
                details={"archive_id": archive_id},
            )

            return render_template(
                "archive_detail.html",
                archive=archive,
                tags=tags,
                title="Detail Arsip",
                archive_id=archive_id,
                csrf_token=generate_csrf(),
            )

        except mysql.connector.Error as e:
            app.logger.error(f"[{error_id}] Archive detail MySQL error: {e}", exc_info=True)
            log_system_error(
                module="Archive",
                message=f"MySQL error [{error_id}]: {str(e)}",
                ip_address=request.remote_addr or "unknown",
                user_id=current_user.id,
                details={"route": request.path, "archive_id": archive_id},
            )
            flash(f"Terjadi kesalahan database (ID: {error_id}).", "danger")
            return redirect(url_for("archive_list"))

        except Exception as e:
            app.logger.error(
                f"[{error_id}] Archive detail unexpected error: {e}", exc_info=True
            )
            log_system_error(
                module="Archive",
                message=f"Unexpected error [{error_id}]: {str(e)}",
                ip_address=request.remote_addr or "unknown",
                user_id=current_user.id,
                details={"route": request.path, "archive_id": archive_id},
            )
            flash(f"Terjadi kesalahan sistem (ID: {error_id}).", "danger")
            return redirect(url_for("archive_list"))

        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

    @app.route("/archives/delete/<int:id>", methods=["DELETE"])
    @login_required
    def archive_delete(id):
        error_id = str(uuid.uuid4())
        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            if not conn or not conn.is_connected():
                app.logger.error(f"[{error_id}] Archive delete: Database connection failed")
                return (
                    jsonify({"success": False, "error": "Koneksi database gagal"}),
                    500,
                )

            cursor = conn.cursor()
            cursor.execute(
                "SELECT user_id, file_path FROM archives WHERE id = %s", (id,)
            )
            archive = cursor.fetchone()
            if not archive:
                app.logger.error(f"[{error_id}] Archive not found: ID {id}")
                return (
                    jsonify({"success": False, "error": "Arsip tidak ditemukan"}),
                    404,
                )
            if archive[0] != current_user.id and not has_permission(
                current_user.id, "delete_any_archive"
            ):
                app.logger.error(
                    f"[{error_id}] User {current_user.id} not authorized to delete archive {id}"
                )
                return jsonify({"success": False, "error": "Tidak diizinkan"}), 403

            file_path = archive[1]
            if os.path.exists(file_path):
                os.remove(file_path)
                app.logger.debug(f"[{error_id}] Deleted file: {file_path}")

            cursor.execute("DELETE FROM archives WHERE id = %s", (id,))
            cursor.execute(
                "DELETE FROM archive_access_log WHERE archive_id = %s", (id,)
            )
            cursor.execute("DELETE FROM archive_category WHERE archive_id = %s", (id,))
            cursor.execute("DELETE FROM archive_tag WHERE archive_id = %s", (id,))
            conn.commit()

            log_activity(
                user_id=current_user.id,
                action="delete_archive",
                ip_address=request.remote_addr or "unknown",
                user_agent=request.user_agent.string or "unknown",
                description=f"Pengguna {current_user.username} menghapus arsip ID {id}",
                details={"archive_id": id},
            )
            app.logger.info(f"[{error_id}] Archive deleted successfully: ID {id}")
            return jsonify({"success": True, "message": "Arsip berhasil dihapus"})

        except Error as e:
            app.logger.error(f"[{error_id}] Archive delete MySQL error: {e}")
            if conn:
                conn.rollback()
            return (
                jsonify(
                    {
                        "success": False,
                        "error": f"Gagal menghapus arsip (ID: {error_id})",
                    }
                ),
                500,
            )
        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

    @app.route("/archives/download/<int:archive_id>", methods=["GET"])
    @login_required
    def download_archive(archive_id):
        """
        Download an archive file.

        Args:
            archive_id (int): ID of the archive to download

        Returns:
            File download response or redirect on error
        """
        conn = None
        cursor = None
        error_id = str(uuid.uuid4())

        try:
            conn = get_db_connection()
            if not conn or not conn.is_connected():
                flash("Gagal terhubung ke database.", "danger")
                app.logger.error(
                    f"[{error_id}] Archive download: Database connection failed"
                )
                return redirect(url_for("archive_list"))

            cursor = conn.cursor(dictionary=True)

            # Fetch archive
            cursor.execute(
                """
                SELECT file_name, file_path, title
                FROM archives
                WHERE id = %s AND user_id = %s
                """,
                (archive_id, current_user.id),
            )
            archive = cursor.fetchone()

            if not archive:
                flash("Arsip tidak ditemukan atau Anda tidak memiliki akses.", "danger")
                return redirect(url_for("archive_list"))

            # Validate file path
            file_path = os.path.join(
                current_app.config.get("UPLOAD_FOLDER", "uploads"), archive["file_path"]
            )
            if not os.path.isfile(file_path):
                flash("File arsip tidak ditemukan di server.", "danger")
                return redirect(url_for("archive_list"))

            # Log download to archive_access_log
            cursor.execute(
                """
                INSERT INTO archive_access_log (archive_id, user_id, access_type, ip_address, access_time)
                VALUES (%s, %s, %s, %s, NOW())
                """,
                (
                    archive_id,
                    current_user.id,
                    "download",
                    request.remote_addr or "unknown",
                ),
            )
            conn.commit()

            # Log activity
            log_activity(
                user_id=current_user.id,
                action="download_archive",
                ip_address=request.remote_addr or "unknown",
                user_agent=request.user_agent.string or "unknown",
                description=f"User {current_user.username} downloaded archive: {archive['title']}",
                details={"archive_id": archive_id, "filename": archive["file_name"]},
            )

            return send_from_directory(
                directory=current_app.config.get("UPLOAD_FOLDER", "uploads"),
                path=archive["file_path"],
                as_attachment=True,
                download_name=archive["file_name"],
            )

        except mysql.connector.Error as e:
            app.logger.error(
                f"[{error_id}] Archive download MySQL error: {e}", exc_info=True
            )
            log_system_error(
                module="Archive",
                message=f"MySQL error [{error_id}]: {str(e)}",
                ip_address=request.remote_addr or "unknown",
                user_id=current_user.id,
                details={"route": request.path, "archive_id": archive_id},
            )
            flash(f"Terjadi kesalahan database (ID: {error_id}).", "danger")
            return redirect(url_for("archive_list"))

        except Exception as e:
            app.logger.error(
                f"[{error_id}] Archive download unexpected error: {e}", exc_info=True
            )
            log_system_error(
                module="Archive",
                message=f"Unexpected error [{error_id}]: {str(e)}",
                ip_address=request.remote_addr or "unknown",
                user_id=current_user.id,
                details={"route": request.path, "archive_id": archive_id},
            )
            flash(f"Terjadi kesalahan sistem (ID: {error_id}).", "danger")
            return redirect(url_for("archive_list"))

        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

    # Fungsi untuk format ukuran file
    def format_file_size(size):
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB"

    def validate_csrf_token(token):
        """Validate CSRF token (placeholder implementation)."""
        from flask_wtf.csrf import validate_csrf

        try:
            validate_csrf(token)
            return True
        except:
            return False

    def generate_csrf():
        """Generate CSRF token (placeholder implementation)."""
        from flask_wtf.csrf import generate_csrf

        return generate_csrf()

    # Rute dashboard
    @app.route("/admin")
    @app.route("/admin/")
    @app.route("/admin/dashboard")
    @login_required
    @admin_required
    def admin_dashboard():
        """Admin Dashboard Route"""
        error_id = str(uuid.uuid4())
        ip_address = request.remote_addr or "unknown"
        user_agent = request.user_agent.string or "unknown"

        conn = None
        cursor = None

        try:
            conn = get_db_connection()
            if not conn or not conn.is_connected():
                app.logger.error(
                    f"[{error_id}] Admin dashboard: Database connection failed"
                )
                flash("Gagal terhubung ke database.", "danger")
                return render_template(
                    "admin_dashboard.html", dashboard_data={}, title="Admin Dashboard"
                )

            cursor = conn.cursor(dictionary=True)

            # Get dashboard statistics
            dashboard_data = {}

            # Total Users
            cursor.execute("SELECT COUNT(*) as count FROM user WHERE is_active = 1")
            dashboard_data["totalUsers"] = cursor.fetchone()["count"]

            # Total Archives
            cursor.execute("SELECT COUNT(*) as count FROM archives")
            dashboard_data["totalArchives"] = cursor.fetchone()["count"]

            # Total System Logs
            cursor.execute(
                "SELECT COUNT(*) as count FROM system_logs WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)"
            )
            dashboard_data["totalLogs"] = cursor.fetchone()["count"]

            # Unread Notifications
            cursor.execute(
                "SELECT COUNT(*) as count FROM notifications WHERE is_read = 0"
            )
            dashboard_data["totalNotifications"] = cursor.fetchone()["count"]

            # Recent System Logs (last 10)
            cursor.execute(
                """
                SELECT id, level, module, message, user_id, ip_address, created_at
                FROM system_logs 
                ORDER BY created_at DESC 
                LIMIT 10
            """
            )
            dashboard_data["recentLogs"] = cursor.fetchall()

            # Recent Notifications (last 10)
            cursor.execute(
                """
                SELECT id, user_id, message, is_read, created_at
                FROM notifications 
                ORDER BY created_at DESC 
                LIMIT 10
            """
            )
            dashboard_data["recentNotifications"] = cursor.fetchall()

            # Log activity
            log_activity(
                user_id=current_user.id,
                action="view_admin_dashboard",
                ip_address=ip_address,
                user_agent=user_agent,
                description=f"Admin {current_user.username} viewed dashboard",
                details=json.dumps({"user_count": dashboard_data["totalUsers"]}),
            )

            return render_template(
                "admin_dashboard.html",
                dashboard_data=dashboard_data,
                title="Admin Dashboard",
                csrf_token=generate_csrf(),
                current_year=datetime.now(pytz.timezone("Asia/Jakarta")).year,
            )

        except Exception as e:
            app.logger.error(f"[{error_id}] Admin dashboard error: {e}", exc_info=True)
            log_system_error(
                module="Admin Dashboard",
                message=f"Dashboard error [{error_id}]: {str(e)}",
                ip_address=ip_address,
                user_id=current_user.id,
            )
            flash(f"Terjadi kesalahan sistem (ID: {error_id}).", "danger")
            return render_template(
                "admin_dashboard.html", dashboard_data={}, title="Admin Dashboard"
            )

        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

    # ==================== USER MANAGEMENT ====================
    @app.route("/admin/users", methods=["GET", "POST"])
    @app.route("/admin/user-management", methods=["GET", "POST"])
    @login_required
    @admin_required
    def admin_user_management():
        error_id = str(uuid.uuid4())
        form = AdminUserForm()
        ip_address = request.remote_addr or "unknown"
        user_agent = request.user_agent.string or "unknown"
        current_time = datetime.now(pytz.timezone("Asia/Jakarta"))

        if request.method == "POST":
            try:
                # CSRF validation is handled by Flask-WTF form
                if not form.csrf_token.data:
                    app.logger.warning(
                        f"[{error_id}] Missing CSRF token in form submission"
                    )
                    flash("CSRF token tidak ditemukan. Silakan coba lagi.", "danger")
                    return redirect(url_for("admin_user_management"))

            except Exception as e:
                app.logger.warning(f"[{error_id}] CSRF validation failed: {e}")
                flash("CSRF token tidak valid. Silakan coba lagi.", "danger")
                return redirect(url_for("admin_user_management"))

            action = request.form.get("action")
            conn = None
            cursor = None

            try:
                conn = get_db_connection()
                cursor = conn.cursor(dictionary=True)

                if action == "delete":
                    user_id = request.form.get("user_id")
                    if not user_id or not user_id.isdigit():
                        app.logger.warning(
                            f"[{error_id}] Invalid user_id in delete request: {user_id}"
                        )
                        flash("ID pengguna tidak valid.", "danger")
                        return redirect(url_for("admin_user_management"))

                    if int(user_id) == current_user.id:
                        flash("Anda tidak dapat menghapus akun sendiri.", "danger")
                        return redirect(url_for("admin_user_management"))

                    cursor.execute(
                        "SELECT id, username, is_superadmin FROM user WHERE id = %s",
                        (user_id,),
                    )
                    user_to_delete = cursor.fetchone()
                    if not user_to_delete:
                        flash("Pengguna tidak ditemukan.", "danger")
                        return redirect(url_for("admin_user_management"))

                    if (
                        user_to_delete["is_superadmin"]
                        and not current_user.is_superadmin
                    ):
                        flash(
                            "Hanya Superadmin yang dapat menghapus pengguna Superadmin.",
                            "danger",
                        )
                        return redirect(url_for("admin_user_management"))

                    conn.start_transaction()
                    try:
                        cursor.execute(
                            "DELETE FROM user_roles WHERE user_id = %s", (user_id,)
                        )
                        cursor.execute(
                            "DELETE FROM user_permissions WHERE user_id = %s",
                            (user_id,),
                        )
                        cursor.execute(
                            "DELETE FROM user_logs WHERE user_id = %s", (user_id,)
                        )
                        cursor.execute("DELETE FROM user WHERE id = %s", (user_id,))
                        conn.commit()

                        log_activity(
                            user_id=current_user.id,
                            action="delete_user",
                            ip_address=ip_address,
                            user_agent=user_agent,
                            description=f"Admin {current_user.username} deleted user: {user_to_delete['username']}",
                            details={
                                "deleted_user_id": user_id,
                                "deleted_username": user_to_delete["username"],
                            },
                        )
                        flash("Pengguna berhasil dihapus!", "success")
                        return redirect(url_for("admin_user_management"))
                    except Exception as e:
                        conn.rollback()
                        app.logger.error(f"[{error_id}] Delete user failed: {e}")
                        flash(f"Gagal menghapus pengguna: {str(e)}", "danger")
                        return redirect(url_for("admin_user_management"))

                if form.validate_on_submit():
                    username = form.username.data.strip()
                    email = form.email.data.strip().lower()
                    full_name = form.full_name.data.strip()
                    phone = form.phone.data.strip() if form.phone.data else None
                    is_admin = bool(form.is_admin.data)
                    is_superadmin = bool(form.is_superadmin.data)
                    is_active = bool(form.is_active.data)

                    if is_superadmin and not current_user.is_superadmin:
                        flash(
                            "Hanya Superadmin yang dapat membuat pengguna Superadmin.",
                            "danger",
                        )
                        return redirect(url_for("admin_user_management"))

                    user_id = request.form.get("user_id")
                    conn.start_transaction()

                    try:
                        if user_id:
                            cursor.execute(
                                "SELECT id, username, email FROM user WHERE id = %s",
                                (user_id,),
                            )
                            existing_user = cursor.fetchone()
                            if not existing_user:
                                flash("Pengguna tidak ditemukan.", "danger")
                                return redirect(url_for("admin_user_management"))

                            cursor.execute(
                                """
                                SELECT id FROM user 
                                WHERE (username = %s OR email = %s) AND id != %s
                            """,
                                (username, email, user_id),
                            )
                            if cursor.fetchone():
                                flash("Username atau email sudah digunakan.", "danger")
                                return redirect(url_for("admin_user_management"))

                            cursor.execute(
                                """
                                UPDATE user 
                                SET username = %s, email = %s, full_name = %s, phone = %s, 
                                    is_admin = %s, is_superadmin = %s, is_active = %s, 
                                    updated_at = %s
                                WHERE id = %s
                            """,
                                (
                                    username,
                                    email,
                                    full_name,
                                    phone,
                                    is_admin,
                                    is_superadmin,
                                    is_active,
                                    current_time,
                                    user_id,
                                ),
                            )

                            log_activity(
                                user_id=current_user.id,
                                action="update_user",
                                ip_address=ip_address,
                                user_agent=user_agent,
                                description=f"Admin {current_user.username} updated user: {username}",
                                details={
                                    "username": username,
                                    "user_id": int(user_id),
                                    "changes": {
                                        "is_admin": is_admin,
                                        "is_superadmin": is_superadmin,
                                        "is_active": is_active,
                                    },
                                },
                            )
                            flash("Pengguna berhasil diperbarui!", "success")
                        else:
                            cursor.execute(
                                "SELECT id FROM user WHERE username = %s OR email = %s",
                                (username, email),
                            )
                            if cursor.fetchone():
                                flash("Username atau email sudah digunakan.", "danger")
                                return redirect(url_for("admin_user_management"))

                            temp_password = generate_secure_password()
                            password_hash = generate_password_hash(temp_password)
                            cursor.execute(
                                """
                                INSERT INTO user 
                                (username, email, password, full_name, phone, 
                                is_admin, is_superadmin, is_active, created_at)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                            """,
                                (
                                    username,
                                    email,
                                    password_hash,
                                    full_name,
                                    phone,
                                    is_admin,
                                    is_superadmin,
                                    is_active,
                                    current_time,
                                ),
                            )
                            new_user_id = cursor.lastrowid

                            log_activity(
                                user_id=current_user.id,
                                action="create_user",
                                ip_address=ip_address,
                                user_agent=user_agent,
                                description=f"Admin {current_user.username} created user: {username}",
                                details={"username": username, "user_id": new_user_id},
                            )
                            flash(
                                f"Pengguna berhasil dibuat! Kata sandi sementara: {temp_password}",
                                "success",
                            )

                        conn.commit()
                        return redirect(url_for("admin_user_management"))

                    except Exception as e:
                        conn.rollback()
                        app.logger.error(f"[{error_id}] Create/Update user failed: {e}")
                        flash(f"Gagal membuat/memperbarui pengguna: {str(e)}", "danger")
                        return redirect(url_for("admin_user_management"))

                else:
                    for field, errors in form.errors.items():
                        for error in errors:
                            flash(
                                f"{getattr(form, field).label.text}: {error}", "danger"
                            )
                    return redirect(url_for("admin_user_management"))

            except Exception as e:
                if conn and conn.in_transaction:
                    conn.rollback()
                app.logger.error(f"[{error_id}] Admin user management error: {e}")
                flash(
                    f"Terjadi kesalahan saat memproses permintaan: {str(e)}", "danger"
                )
                return redirect(url_for("admin_user_management"))

            finally:
                if cursor:
                    cursor.close()
                if conn and conn.is_connected():
                    conn.close()

        # GET REQUEST: Display user list and form
        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)

            user_id_to_edit = request.args.get("user_id")
            if user_id_to_edit and user_id_to_edit.isdigit():
                cursor.execute(
                    """
                    SELECT id, username, email, full_name, phone, 
                        is_admin, is_superadmin, is_active
                    FROM user 
                    WHERE id = %s
                """,
                    (user_id_to_edit,),
                )
                user_to_edit = cursor.fetchone()
                if user_to_edit:
                    form.user_id.data = user_to_edit["id"]
                    form.username.data = user_to_edit["username"]
                    form.email.data = user_to_edit["email"]
                    form.full_name.data = user_to_edit["full_name"]
                    form.phone.data = user_to_edit["phone"]
                    form.is_admin.data = user_to_edit["is_admin"]
                    form.is_superadmin.data = user_to_edit["is_superadmin"]
                    form.is_active.data = user_to_edit["is_active"]

            page = request.args.get("page", 1, type=int)
            per_page = 10
            offset = (page - 1) * per_page
            search_query = request.args.get("q", "").strip().lower()

            query = """
                SELECT u.id, u.username, u.email, u.full_name, u.phone, 
                    u.is_admin, u.is_superadmin, u.is_active, u.created_at
                FROM user u
                WHERE %s = '' OR 
                    u.username LIKE %s OR 
                    u.email LIKE %s OR 
                    u.full_name LIKE %s
                ORDER BY u.created_at DESC
                LIMIT %s OFFSET %s
            """
            cursor.execute(
                query,
                (
                    search_query,
                    f"%{search_query}%",
                    f"%{search_query}%",
                    f"%{search_query}%",
                    per_page,
                    offset,
                ),
            )
            users = cursor.fetchall()

            count_query = """
                SELECT COUNT(*) as total 
                FROM user 
                WHERE %s = '' OR 
                    username LIKE %s OR 
                    email LIKE %s OR 
                    full_name LIKE %s
            """
            cursor.execute(
                count_query,
                (
                    search_query,
                    f"%{search_query}%",
                    f"%{search_query}%",
                    f"%{search_query}%",
                ),
            )
            total_users = cursor.fetchone()["total"]

            log_activity(
                user_id=current_user.id,
                action="view_admin_user_management",
                ip_address=ip_address,
                user_agent=user_agent,
                description=f"Admin {current_user.username} viewed user management",
                details={"user_count": total_users, "search_query": search_query},
            )

            return render_template(
                "admin_user_management.html",
                form=form,
                users=users,
                pagination={
                    "page": page,
                    "per_page": per_page,
                    "total": total_users,
                    "pages": (total_users + per_page - 1) // per_page,
                    "search_query": search_query,
                },
                title="Admin User Management",
                current_year=datetime.now(pytz.timezone("Asia/Jakarta")).year,
            )

        except Exception as e:
            app.logger.error(f"[{error_id}] Admin user management load error: {e}")
            flash(f"Gagal memuat daftar pengguna: {str(e)}", "danger")
            return redirect(url_for("admin_dashboard"))

        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

    # ==================== ARCHIVE MANAGEMENT ====================
    @app.route("/admin/archives", methods=["GET", "POST"])
    @app.route("/admin/archive-management", methods=["GET", "POST"])
    @app.route("/admin/archives/download/<int:archive_id>", methods=["GET"])
    @login_required
    @admin_required
    def admin_archive_management(archive_id=None):
        """Admin Archive Management Route with Download Functionality"""
        error_id = str(uuid.uuid4())
        ip_address = request.remote_addr or "unknown"
        user_agent = request.user_agent.string or "unknown"

        conn = None
        cursor = None

        try:
            conn = get_db_connection()
            if not conn or not conn.is_connected():
                app.logger.error(
                    f"[{error_id}] Admin archive management: Database connection failed"
                )
                flash("Gagal terhubung ke database.", "danger")
                return render_template(
                    "admin_archive_management.html",
                    archives=[],
                    title="Archive Management",
                )

            cursor = conn.cursor(dictionary=True)

            # Handle POST requests (delete archive)
            if request.method == "POST":
                try:
                    validate_csrf(request.form.get("csrf_token"))
                except CSRFError:
                    flash("CSRF token tidak valid.", "danger")
                    return redirect(url_for("admin_archive_management"))

                action = request.form.get("action")
                archive_id = request.form.get("archive_id")

                if action == "delete" and archive_id:
                    # Get archive info before deletion
                    cursor.execute(
                        "SELECT title, user_id FROM archives WHERE id = %s",
                        (archive_id,),
                    )
                    archive_info = cursor.fetchone()

                    if archive_info:
                        # Delete archive
                        cursor.execute(
                            "DELETE FROM archives WHERE id = %s", (archive_id,)
                        )
                        conn.commit()

                        log_activity(
                            user_id=current_user.id,
                            action="delete_archive",
                            ip_address=ip_address,
                            user_agent=user_agent,
                            description=f"Admin {current_user.username} deleted archive: {archive_info['title']}",
                            details=json.dumps(
                                {
                                    "archive_id": int(archive_id),
                                    "archive_title": archive_info["title"],
                                }
                            ),
                        )
                        flash("Arsip berhasil dihapus!", "success")
                    else:
                        flash("Arsip tidak ditemukan.", "danger")

                return redirect(url_for("admin_archive_management"))

            # Handle download request
            if archive_id is not None:
                cursor.execute(
                    """
                    SELECT id, title, file_name, file_path, file_type, file_size, user_id
                    FROM archives 
                    WHERE id = %s
                """,
                    (archive_id,),
                )
                archive = cursor.fetchone()

                if not archive:
                    flash("Arsip tidak ditemukan.", "danger")
                    return redirect(url_for("admin_archive_management"))

                file_path = archive["file_path"]
                if not os.path.exists(file_path):
                    app.logger.error(f"[{error_id}] File not found: {file_path}")
                    flash("File tidak ditemukan di server.", "danger")
                    return redirect(url_for("admin_archive_management"))

                # Log download activity
                log_activity(
                    user_id=current_user.id,
                    action="download_archive",
                    ip_address=ip_address,
                    user_agent=user_agent,
                    description=f"Admin {current_user.username} downloaded archive: {archive['title']}",
                    details=json.dumps(
                        {
                            "archive_id": archive["id"],
                            "archive_title": archive["title"],
                            "file_name": archive["file_name"],
                            "file_type": archive["file_type"],
                            "file_size": archive["file_size"],
                        }
                    ),
                )

                try:
                    return send_file(
                        file_path,
                        as_attachment=True,
                        download_name=archive["file_name"],
                        mimetype=archive["file_type"],
                    )
                except Exception as e:
                    app.logger.error(
                        f"[{error_id}] Failed to send file: {e}", exc_info=True
                    )
                    flash(f"Gagal mengunduh file (ID: {error_id}).", "danger")
                    return redirect(url_for("admin_archive_management"))

            # GET request: Load archives
            cursor.execute(
                """
                SELECT a.id, a.title, a.description, a.category, a.file_name, a.file_type, 
                    a.file_size, a.is_public, a.created_at, u.username as uploader
                FROM archives a
                LEFT JOIN user u ON a.user_id = u.id
                ORDER BY a.created_at DESC
            """
            )
            archives = cursor.fetchall()

            # Log activity
            log_activity(
                user_id=current_user.id,
                action="view_admin_archive_management",
                ip_address=ip_address,
                user_agent=user_agent,
                description=f"Admin {current_user.username} viewed archive management",
                details=json.dumps({"archive_count": len(archives)}),
            )

            return render_template(
                "admin_archive_management.html",
                archives=archives,
                title="Archive Management",
                csrf_token=generate_csrf(),
                current_year=datetime.now(pytz.timezone("Asia/Jakarta")).year,
            )

        except Exception as e:
            app.logger.error(
                f"[{error_id}] Admin archive management error: {e}", exc_info=True
            )
            log_system_error(
                module="Admin Archive Management",
                message=f"Error [{error_id}]: {str(e)}",
                ip_address=ip_address,
                user_id=current_user.id,
            )
            flash(f"Terjadi kesalahan sistem (ID: {error_id}).", "danger")
            return render_template(
                "admin_archive_management.html", archives=[], title="Archive Management"
            )

        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

    # ==================== SYSTEM SETTINGS ====================
    @app.route("/admin/settings", methods=["GET", "POST"])
    @app.route("/admin/system-settings", methods=["GET", "POST"])
    @login_required
    @admin_required
    def admin_system_settings():
        """Admin System Settings Route"""
        error_id = str(uuid.uuid4())
        ip_address = request.remote_addr or "unknown"
        user_agent = request.user_agent.string or "unknown"

        conn = None
        cursor = None

        try:
            conn = get_db_connection()
            if not conn or not conn.is_connected():
                app.logger.error(
                    f"[{error_id}] Admin system settings: Database connection failed"
                )
                flash("Gagal terhubung ke database.", "danger")
                return render_template(
                    "admin_system_settings.html", settings=[], title="System Settings"
                )

            cursor = conn.cursor(dictionary=True)

            # Handle POST requests (update settings)
            if request.method == "POST":
                try:
                    validate_csrf(request.form.get("csrf_token"))
                except CSRFError:
                    flash("CSRF token tidak valid.", "danger")
                    return redirect(url_for("admin_system_settings"))

                setting_key = request.form.get("key")
                setting_value = request.form.get("value")
                setting_description = request.form.get("description", "")

                if setting_key and setting_value:
                    current_time = datetime.now(pytz.timezone("Asia/Jakarta"))

                    # Check if setting exists
                    cursor.execute(
                        "SELECT id FROM system_settings WHERE key = %s", (setting_key,)
                    )
                    existing = cursor.fetchone()

                    if existing:
                        # Update existing setting
                        cursor.execute(
                            """
                            UPDATE system_settings 
                            SET value = %s, description = %s, updated_at = %s 
                            WHERE key = %s
                        """,
                            (
                                setting_value,
                                setting_description,
                                current_time,
                                setting_key,
                            ),
                        )
                        action_msg = "updated"
                    else:
                        # Create new setting
                        cursor.execute(
                            """
                            INSERT INTO system_settings (key, value, description, created_at)
                            VALUES (%s, %s, %s, %s)
                        """,
                            (
                                setting_key,
                                setting_value,
                                setting_description,
                                current_time,
                            ),
                        )
                        action_msg = "created"

                    conn.commit()

                    log_activity(
                        user_id=current_user.id,
                        action="update_system_settings",
                        ip_address=ip_address,
                        user_agent=user_agent,
                        description=f"Admin {current_user.username} {action_msg} system setting: {setting_key}",
                        details=json.dumps(
                            {
                                "key": setting_key,
                                "value": setting_value,
                                "action": action_msg,
                            }
                        ),
                    )

                    flash(f"Pengaturan sistem berhasil {action_msg}!", "success")
                else:
                    flash("Key dan value harus diisi.", "danger")

                return redirect(url_for("admin_system_settings"))

            # GET request: Load settings
            cursor.execute(
                """
                SELECT id, key, value, description, created_at, updated_at
                FROM system_settings
                ORDER BY key ASC
            """
            )
            settings = cursor.fetchall()

            # Log activity
            log_activity(
                user_id=current_user.id,
                action="view_admin_system_settings",
                ip_address=ip_address,
                user_agent=user_agent,
                description=f"Admin {current_user.username} viewed system settings",
                details=json.dumps({"settings_count": len(settings)}),
            )

            return render_template(
                "admin_system_settings.html",
                settings=settings,
                title="System Settings",
                csrf_token=generate_csrf(),
                current_year=datetime.now(pytz.timezone("Asia/Jakarta")).year,
            )

        except Exception as e:
            app.logger.error(
                f"[{error_id}] Admin system settings error: {e}", exc_info=True
            )
            log_system_error(
                module="Admin System Settings",
                message=f"Error [{error_id}]: {str(e)}",
                ip_address=ip_address,
                user_id=current_user.id,
            )
            flash(f"Terjadi kesalahan sistem (ID: {error_id}).", "danger")
            return render_template(
                "admin_system_settings.html", settings=[], title="System Settings"
            )

        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

    # ==================== API ENDPOINTS ====================
    @app.route("/api/admin/dashboard-stats")
    @login_required
    @admin_required
    def api_admin_dashboard_stats():
        """API endpoint for dashboard statistics"""
        conn = None
        cursor = None

        try:
            conn = get_db_connection()
            if not conn or not conn.is_connected():
                return jsonify({"error": "Database connection failed"}), 500

            cursor = conn.cursor(dictionary=True)

            # Get statistics
            stats = {}

            cursor.execute("SELECT COUNT(*) as count FROM user WHERE is_active = 1")
            stats["totalUsers"] = cursor.fetchone()["count"]

            cursor.execute("SELECT COUNT(*) as count FROM archives")
            stats["totalArchives"] = cursor.fetchone()["count"]

            cursor.execute(
                "SELECT COUNT(*) as count FROM system_logs WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)"
            )
            stats["totalLogs"] = cursor.fetchone()["count"]

            cursor.execute(
                "SELECT COUNT(*) as count FROM notifications WHERE is_read = 0"
            )
            stats["totalNotifications"] = cursor.fetchone()["count"]

            return jsonify(stats)

        except Exception as e:
            app.logger.error(f"API dashboard stats error: {e}")
            return jsonify({"error": "Internal server error"}), 500

        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

    @app.route("/api/admin/recent-logs")
    @login_required
    @admin_required
    def api_admin_recent_logs():
        """API endpoint for recent logs"""
        conn = None
        cursor = None

        try:
            conn = get_db_connection()
            if not conn or not conn.is_connected():
                return jsonify({"error": "Database connection failed"}), 500

            cursor = conn.cursor(dictionary=True)

            cursor.execute(
                """
                SELECT id, level, module, message, user_id, ip_address, 
                    DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as created_at
                FROM system_logs 
                ORDER BY created_at DESC 
                LIMIT 20
            """
            )
            logs = cursor.fetchall()

            return jsonify({"logs": logs})

        except Exception as e:
            app.logger.error(f"API recent logs error: {e}")
            return jsonify({"error": "Internal server error"}), 500

        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

    @app.route("/api/admin/recent-notifications")
    @login_required
    @admin_required
    def api_admin_recent_notifications():
        """API endpoint for recent notifications"""
        conn = None
        cursor = None

        try:
            conn = get_db_connection()
            if not conn or not conn.is_connected():
                return jsonify({"error": "Database connection failed"}), 500

            cursor = conn.cursor(dictionary=True)

            cursor.execute(
                """
                SELECT id, user_id, message, is_read, related_url,
                    DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as created_at
                FROM notifications 
                ORDER BY created_at DESC 
                LIMIT 20
            """
            )
            notifications = cursor.fetchall()

            return jsonify({"notifications": notifications})

        except Exception as e:
            app.logger.error(f"API recent notifications error: {e}")
            return jsonify({"error": "Internal server error"}), 500

        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

    @app.route("/api/notifications/<int:notification_id>/mark-read", methods=["PUT"])
    @login_required
    @admin_required
    def api_mark_notification_read(notification_id):
        """API endpoint to mark notification as read"""
        conn = None
        cursor = None

        try:
            conn = get_db_connection()
            if not conn or not conn.is_connected():
                return jsonify({"error": "Database connection failed"}), 500

            cursor = conn.cursor(dictionary=True)

            # Update notification
            cursor.execute(
                """
                UPDATE notifications 
                SET is_read = 1, read_at = %s 
                WHERE id = %s
            """,
                (datetime.now(pytz.timezone("Asia/Jakarta")), notification_id),
            )

            conn.commit()

            if cursor.rowcount > 0:
                return jsonify(
                    {"success": True, "message": "Notification marked as read"}
                )
            else:
                return jsonify({"error": "Notification not found"}), 404

        except Exception as e:
            app.logger.error(f"API mark notification read error: {e}")
            return jsonify({"error": "Internal server error"}), 500

        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

    # Error Handlers
    @app.errorhandler(400)
    def bad_request(e):
        log_system_error("System", f"Bad request: {str(e)}")
        return render_template("errors/400.html", title="Bad Request"), 400

    @app.errorhandler(403)
    def forbidden(e):
        log_system_error("System", f"Forbidden: {str(e)}")
        return render_template("errors/403.html", title="Forbidden"), 403

    @app.errorhandler(404)
    def not_found(e):
        log_system_error("System", f"Not found: {str(e)}")
        return render_template("errors/404.html", title="Not Found"), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        app.logger.error(f"Internal server error: {str(e)}")
        log_system_error("System", f"Internal server error: {str(e)}")
        return render_template("errors/500.html", title="Internal Server Error"), 500

    return app
