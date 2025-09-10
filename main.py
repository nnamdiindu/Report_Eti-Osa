import os
from datetime import datetime, timezone
from dotenv import load_dotenv
from flask import Flask, redirect, render_template, url_for, request, flash, Response, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import Mapped, mapped_column, DeclarativeBase, relationship
from flask_login import login_required, login_user, current_user, LoginManager, logout_user, UserMixin
from sqlalchemy import String, Integer, ForeignKey, Float, LargeBinary, select, DateTime
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)

load_dotenv()

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DB_URI")
app.secret_key = os.environ.get("SECRET_KEY")

login_manager = LoginManager()
login_manager.init_app(app)


class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
db.init_app(app)


class Reports(db.Model):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(String(2000), nullable=False)  # Increased length
    location: Mapped[str] = mapped_column(String(2000), nullable=False)
    area: Mapped[str] = mapped_column(String(100), nullable=False)
    priority: Mapped[str] = mapped_column(String(20), nullable=False, default='medium')
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey('user.id'), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    status: Mapped[str] = mapped_column(String(50), nullable=False, default='pending')

    # Relationship to files
    files: Mapped[list["ReportFiles"]] = relationship("ReportFiles", back_populates="report",
                                                      cascade="all, delete-orphan")
    user: Mapped["User"] = relationship("User", back_populates="reports")


class ReportFiles(db.Model):
    __tablename__ = "report_files"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    report_id: Mapped[int] = mapped_column(Integer, ForeignKey('reports.id'), nullable=False)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    mimetype: Mapped[str] = mapped_column(String(100), nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, nullable=False)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    # Relationship back to report
    report: Mapped["Reports"] = relationship("Reports", back_populates="files")


# Update User model to include relationship to reports
class User(UserMixin, db.Model):
    __tablename__ = "user"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    full_name: Mapped[str] = mapped_column(String(200), nullable=False)
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False)
    phone: Mapped[str] = mapped_column(String(20))
    password: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    address: Mapped[str] = mapped_column(String(1000), nullable=False)

    # Relationship to reports
    reports: Mapped[list["Reports"]] = relationship("Reports", back_populates="user")

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

with app.app_context():
    db.create_all()


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    # Returns current year on footer
    year = datetime.now().strftime("%Y")

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirmPassword")

        user = db.session.execute(db.select(User).where(User.email == email)).scalar()

        if user:
            flash("You've already signed up, please login.")
            return redirect(url_for("login"))

        if password != confirm_password:
            flash("Passwords do not match, please try again")
            return redirect(url_for("register"))

        hashed_and_salted_password = generate_password_hash(
            password=password,
            method="pbkdf2:sha256",
            salt_length=8
        )
        new_user = User(
            full_name=request.form.get("full_name").title(),
            email=email,
            phone=request.form.get("phone"),
            password=hashed_and_salted_password,
            address=request.form.get("address")
        )
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        return redirect(url_for("dashboard"))
    return render_template("register.html", current_user=current_user, year=year)

@app.route("/login", methods=["GET", "POST"])
def login():
    # Returns current year on footer
    year = datetime.now().strftime("%Y")
    if request.method == "POST":
        email = request.form.get("email")

        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        if user:
            if check_password_hash(user.password, request.form.get("password")):
                login_user(user)
                if user.id == 1:
                    return redirect(url_for("admin_dashboard"))
                else:
                    return redirect(url_for("dashboard"))
            else:
                flash("Incorrect password, please try again.")
                return redirect(url_for("login"))
        else:
            flash("Email does not exist, please try again")
            return redirect(url_for("login"))

    return render_template("login.html", current_user=current_user, year=year)

@app.route("/dashboard")
@login_required
def dashboard():
    """Display current user's reports with files"""
    reports = db.session.execute(
        db.select(Reports).where(Reports.user_id == current_user.id).order_by(Reports.created_at.desc())
    ).scalars().all()

    """Display current user's pending reports"""
    pending = db.session.execute(
        db.select(Reports).where(Reports.user_id == current_user.id).order_by(Reports.status)
    ).scalars().all()

    return render_template("dashboard.html", reports=reports, pending=pending, current_user=current_user)


@app.route("/report_issue", methods=["GET", "POST"])
@login_required
def report_issue():
    if request.method == "POST":
        # Get form data
        category = request.form.get("category")
        description = request.form.get("description")
        location = request.form.get("location")
        area = request.form.get("area")
        priority = request.form.get("priority", 'medium')

        # Handle multiple file uploads
        uploaded_files = request.files.getlist("file")

        # Validate required fields
        if not all([category, description, location, area]):
            flash("Please fill in all required fields.")
            return redirect(url_for("report_issue"))

        # Process and validate files
        valid_files = []
        if uploaded_files:
            allowed_extensions = {
                'image': ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp'],
                'video': ['mp4', 'avi', 'mov', 'wmv', 'flv', 'webm', 'mkv']
            }
            max_file_size = 10 * 1024 * 1024  # 10MB in bytes
            max_files = 5  # Limit number of files

            if len([f for f in uploaded_files if f.filename != '']) > max_files:
                flash(f"You can upload a maximum of {max_files} files.")
                return redirect(url_for("report_issue"))

            for uploaded_file in uploaded_files:
                if uploaded_file.filename != '':
                    # Validate file type
                    file_extension = uploaded_file.filename.rsplit('.', 1)[
                        1].lower() if '.' in uploaded_file.filename else ''

                    is_valid_file = (
                            file_extension in allowed_extensions['image'] or
                            file_extension in allowed_extensions['video']
                    )

                    if not is_valid_file:
                        flash(
                            f"Invalid file type for {uploaded_file.filename}. Please upload only image or video files.")
                        return redirect(url_for("report_issue"))

                    # Check file size
                    file_data = uploaded_file.read()
                    file_size = len(file_data)

                    if file_size > max_file_size:
                        flash(f"File {uploaded_file.filename} is too large. Please upload files smaller than 10MB.")
                        return redirect(url_for("report_issue"))

                    # Store valid file info
                    valid_files.append({
                        'filename': uploaded_file.filename,
                        'data': file_data,
                        'mimetype': uploaded_file.mimetype,
                        'size': file_size
                    })

        try:
            # Create new report
            new_report = Reports(
                category=category,
                description=description,
                location=location,
                area=area,
                priority=priority,
                user_id=current_user.id
            )

            db.session.add(new_report)
            db.session.flush()  # This assigns an ID to new_report without committing

            # Add files if any exist
            for file_info in valid_files:
                file_record = ReportFiles(
                    report_id=new_report.id,
                    filename=file_info['filename'],
                    data=file_info['data'],
                    mimetype=file_info['mimetype'],
                    file_size=file_info['size']
                )
                db.session.add(file_record)

            db.session.commit()

            if valid_files:
                flash(f"Report successfully submitted with {len(valid_files)} file(s).")
            else:
                flash("Report successfully submitted.")

        except Exception as e:
            db.session.rollback()
            flash("An error occurred while submitting your report. Please try again.")
            print(f"Database error: {e}")

        return redirect(url_for("report_issue"))

    return render_template("report_issue.html", current_user=current_user)


# Updated route to serve files
@app.route("/file/<int:file_id>")
@login_required
def get_file(file_id):
    """Serve files stored in the database"""
    file_record = db.get_or_404(ReportFiles, file_id)

    return Response(
        file_record.data,
        mimetype=file_record.mimetype,
        headers={
            'Content-Disposition': f'inline; filename="{file_record.filename}"'
        }
    )


@app.route("/my_reports", methods=["GET", "POST"])
@login_required
def user_reports():
    """Display current user's reports with files"""
    selected_category = None  # Default for GET requests
    # GET request - show all reports
    all_reports = db.session.execute(
        db.select(Reports)
        .where(Reports.user_id == current_user.id)
        .order_by(Reports.created_at.desc())
    ).scalars().all()

    pending_reports = db.session.execute(
        db.select(Reports)
        .where(Reports.user_id == current_user.id)
        .where(Reports.status == "pending")
        .order_by(Reports.created_at.desc())
    ).scalars().all()

    resolved_reports = db.session.execute(
        db.select(Reports)
        .where(Reports.user_id == current_user.id)
        .where(Reports.status == "resolved")
        .order_by(Reports.created_at.desc())
    ).scalars().all()

    in_progress_reports = db.session.execute(
        db.select(Reports)
        .where(Reports.user_id == current_user.id)
        .where(Reports.status == "progress")
        .order_by(Reports.created_at.desc())
    ).scalars().all()

    if request.method == "POST":
        work_category = request.form.get("category")
        selected_category = work_category  # Store the selected category

        if work_category and work_category != "reports":  # "reports" means "All Reports"
            # Filter reports based on dropdown selection
            reports = db.session.execute(
                db.select(Reports)
                .where(Reports.user_id == current_user.id)
                .where(Reports.status == work_category)
                .order_by(Reports.created_at.desc())
            ).scalars().all()
        else:
            # Show all reports
            reports = db.session.execute(
                db.select(Reports)
                .where(Reports.user_id == current_user.id)
                .order_by(Reports.created_at.desc())
            ).scalars().all()


    return render_template("user_report.html",
                           current_user=current_user,
                           reports=reports,
                           all_reports=all_reports,
                           in_progress_reports=in_progress_reports,
                           resolved_reports=resolved_reports,
                           pending_reports=pending_reports,
                           selected_category=selected_category)

@app.route("/profile")
@login_required
def profile():
    """Display current user's reports with files"""
    reports = db.session.execute(
        db.select(Reports).where(Reports.user_id == current_user.id).order_by(Reports.created_at.desc())
    ).scalars().all()

    """Display current user's pending reports"""
    pending = db.session.execute(
    db.select(Reports)
    .where(Reports.user_id == current_user.id)
    .where(Reports.status == 'pending')
    .order_by(Reports.status)
).scalars().all()
    return render_template("profile.html", reports=reports, pending=pending, current_user=current_user)

@app.route("/edit_profile", methods=["POST"])
@login_required  # Add this decorator since you're using current_user
def edit_profile():
    if request.method == "POST":
        try:
            # Get JSON data from the request
            data = request.get_json()

            if not data:
                return jsonify({
                    'success': False,
                    'message': 'No data provided'
                }), 400

            # Validate and update user fields
            full_name = data.get('name', '').strip()  # Note: changed from 'full_name' to 'name' to match your JS
            email = data.get('email', '').strip()
            phone = data.get('phone', '').strip()
            address = data.get('address', '').strip()

            # Basic validation
            if not full_name:
                return jsonify({
                    'success': False,
                    'message': 'Name is required'
                }), 400

            if not email:
                return jsonify({
                    'success': False,
                    'message': 'Email is required'
                }), 400

            # Check if email is valid (basic check)
            import re
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email):
                return jsonify({
                    'success': False,
                    'message': 'Please enter a valid email address'
                }), 400

            # Check if email already exists for another user
            existing_user = User.query.filter(User.email == email, User.id != current_user.id).first()
            if existing_user:
                return jsonify({
                    'success': False,
                    'message': 'This email address is already in use'
                }), 400

            # Update current user's fields
            current_user.full_name = full_name  # Make sure this matches your User model field name
            current_user.email = email
            current_user.phone = phone
            current_user.address = address

            # Save changes to database
            db.session.commit()

            return jsonify({
                'success': True,
                'message': 'Profile updated successfully',
                'data': {
                    'full_name': current_user.full_name,
                    'email': current_user.email,
                    'phone': current_user.phone,
                    'address': current_user.address
                }
            })

        except Exception as e:
            # Rollback any database changes in case of error
            db.session.rollback()

            return jsonify({
                'success': False,
                'message': f'An error occurred while updating profile: {str(e)}'
            }), 500

@app.route("/admin", methods=["GET", "POST"])
def admin_dashboard():
    reports = db.session.execute(
        db.select(Reports).order_by(Reports.created_at.desc())
    ).scalars().all()

    pending = db.session.execute(
        db.select(Reports)
        .where(Reports.status == 'pending')
        .order_by(Reports.status)
    ).scalars().all()

    resolved = db.session.execute(
        db.select(Reports)
        .where(Reports.status == 'resolved')
        .order_by(Reports.status)
    ).scalars().all()

    progress = db.session.execute(
        db.select(Reports)
        .where(Reports.status == 'progress')
        .order_by(Reports.status)
    ).scalars().all()
    return render_template("admin.html", all_reports=reports, pending=pending,
                           resolved=resolved, progress=progress)

@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    pass

@app.route("/notifications", methods=["GET", "POST"])
def notifications():
    if request.method == "POST":
        request.form.get("")
    return render_template("notifications.html", current_user=current_user)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))



if __name__ == "__main__":
    app.run(debug=True)