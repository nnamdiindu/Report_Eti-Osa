import os
from datetime import datetime, timezone
from dotenv import load_dotenv
from flask import Flask, redirect, render_template, url_for, request, flash, Response, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import Mapped, mapped_column, DeclarativeBase, relationship
from flask_login import login_required, login_user, current_user, LoginManager, logout_user, UserMixin
from sqlalchemy import String, Integer, ForeignKey, Float, LargeBinary, select, DateTime, Boolean
from werkzeug.security import generate_password_hash, check_password_hash
from enum import Enum as PyEnum


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


class NotificationType(PyEnum):
    REPORT_RECEIVED = "report_received"
    STATUS_UPDATE = "status_update"
    ISSUE_RESOLVED = "issue_resolved"
    NEW_COMMENT = "new_comment"
    COMPLETION_DELAYED = "completion_delayed"
    REPORT_ASSIGNED = "report_assigned"


class Notification(db.Model):
    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey('user.id'), nullable=False)
    report_id: Mapped[int] = mapped_column(Integer, ForeignKey('reports.id'), nullable=True)
    type: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    message: Mapped[str] = mapped_column(String(500), nullable=False)
    is_read: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="notifications")
    report: Mapped["Report"] = relationship("Report", back_populates="notifications")


class Report(db.Model):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(String(2000), nullable=False)
    location: Mapped[str] = mapped_column(String(2000), nullable=False)
    area: Mapped[str] = mapped_column(String(100), nullable=False)
    priority: Mapped[str] = mapped_column(String(20), nullable=False, default='medium')
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey('user.id'), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    status: Mapped[str] = mapped_column(String(50), nullable=False, default='pending')
    progress: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    team_assigned_to: Mapped[str] = mapped_column(String(100), nullable=False, default="Unassigned")

    # Relationships
    files: Mapped[list["ReportFiles"]] = relationship("ReportFiles", back_populates="report",
                                                      cascade="all, delete-orphan")
    user: Mapped["User"] = relationship("User", back_populates="reports")
    notifications: Mapped[list["Notification"]] = relationship("Notification", back_populates="report",
                                                              cascade="all, delete-orphan")


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
    report: Mapped["Report"] = relationship("Report", back_populates="files")


class User(UserMixin, db.Model):
    __tablename__ = "user"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    full_name: Mapped[str] = mapped_column(String(200), nullable=False)
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False)
    phone: Mapped[str] = mapped_column(String(20))
    password: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    address: Mapped[str] = mapped_column(String(1000), nullable=False)

    # Relationships
    reports: Mapped[list["Report"]] = relationship("Report", back_populates="user")
    notifications: Mapped[list["Notification"]] = relationship("Notification", back_populates="user",
                                                               cascade="all, delete-orphan")



@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

with app.app_context():
    db.create_all()

def create_notification(user_id, report_id, notification_type, title, message):
    # Create a new notification for a user
    try:
        notification = Notification(
            user_id=user_id,
            report_id=report_id,
            type=notification_type.value,
            title=title,
            message=message
        )

        db.session.add(notification)
        db.session.commit()
        return notification

    except Exception as e:
        db.session.rollback()
        print(f"Error creating notification: {e}")
        return None


def get_user_notifications(user_id, limit=None):
    # Get all notifications for a user, ordered by newest first
    stmt = (
        db.select(Notification)
        .where(Notification.user_id == user_id)
        .order_by(Notification.created_at.desc())
    )
    if limit:
        stmt = stmt.limit(limit)

    query = db.session.execute(stmt)
    return query.scalars().all()


def get_all_user_reports():
    all_user_reports = db.session.execute(
        db.select(Report).where(Report.user_id == current_user.id).order_by(Report.created_at.desc())
    ).scalars().all()
    return all_user_reports

def get_all_reports():
    all_reports = db.session.execute(
        db.select(Report).order_by(Report.created_at.desc())
    ).scalars().all()
    return all_reports

def get_specific_status_reports(status):
    specific_reports = db.session.execute(
        db.select(Report)
        .where(Report.user_id == current_user.id)
        .where(Report.status == f"{status}")
        .order_by(Report.created_at.desc())
    ).scalars().all()
    return specific_reports

def get_all_specific_status_reports(status):
    all_specific_reports = db.session.execute(
        db.select(Report)
        .where(Report.status == f"{status}")
        .order_by(Report.created_at.desc())
    ).scalars().all()
    return all_specific_reports

def get_all_user_notifications():
    all_user_notifications = db.session.execute(
        db.select(Notification)
        .where(Notification.user_id == current_user.id)
        .order_by(Notification.created_at.desc())
    ).scalars().all()
    return all_user_notifications


def time_ago(timestamp):
    try:
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        diff = now - timestamp

        seconds = diff.total_seconds()
        minutes = seconds / 60
        hours = minutes / 60
        days = hours / 24

        if seconds < 60:
            return f"{int(seconds)} seconds ago"
        elif minutes < 60:
            return f"{int(minutes)} minutes ago"
        elif hours < 24:
            return f"{int(hours)} hours ago"
        else:
            return f"{int(days)} days ago"
    except Exception:
        return "Invalid date"

# Register the filter
app.jinja_env.filters['timeago'] = time_ago


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
    reports = get_all_user_reports()

    """Display current user's pending reports"""
    pending_reports = get_specific_status_reports("pending")

    """Display current user's resolved reports"""
    resolved_reports = get_specific_status_reports("resolved")

    """Display current user's in_progress reports"""
    in_progress_reports = get_specific_status_reports("progress")

    return render_template("dashboard.html", reports=reports, pending_reports=pending_reports,
                           resolved_reports=resolved_reports, in_progress_reports=in_progress_reports,
                           current_user=current_user)


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
            new_report = Report(
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

            # Create notification for report received
            create_notification(
                user_id=current_user.id,
                report_id=new_report.id,
                notification_type=NotificationType.REPORT_RECEIVED,
                title="Report Received",
                message=f"Thank you for reporting the {category.lower()}. We'll review it within 2 business days."
            )

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
    reports = get_all_user_reports()

    # GET request - show all reports
    all_reports = get_all_user_reports()

    pending_reports = get_specific_status_reports("pending")

    resolved_reports = get_specific_status_reports("resolved")

    in_progress_reports = get_specific_status_reports("progress")

    if request.method == "POST":
        work_category = request.form.get("category")
        selected_category = work_category  # Store the selected category

        if work_category and work_category != "reports":  # "reports" means "All Reports"
            # Filter reports based on dropdown selection
            reports = get_specific_status_reports(work_category)
        else:
            # Show all reports
            reports = get_all_user_reports()

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
    reports = get_all_user_reports()

    """Display current user's pending reports"""
    pending = get_specific_status_reports("pending")

    resolved_reports = get_specific_status_reports("resolved")

    return render_template("profile.html", reports=reports, pending=pending,
                           resolved_reports=resolved_reports, current_user=current_user)

@app.route("/edit_profile", methods=["POST"])
@login_required
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
            current_user.full_name = full_name
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
@login_required
def admin_dashboard():
    all_reports = get_all_reports()

    all_pending = get_all_specific_status_reports("pending")

    all_resolved = get_all_specific_status_reports("resolved")

    all_progress = get_all_specific_status_reports("progress")

    return render_template("admin.html", all_reports=all_reports, pending=all_pending,
                           resolved=all_resolved, progress=all_progress)


@app.route('/update_report/<int:report_id>', methods=['POST'])
@login_required
def update_report(report_id):
    """Update a specific report - fixed version"""
    try:
        data = request.get_json()

        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400

        # Find the specific report to update
        report = db.get_or_404(Report, report_id)

        # Check if user has permission (admin or report owner)
        if current_user.id != 1 and current_user.id != report.user_id:
            return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403

        # Extract and validate data from request
        report_status = data.get("status", "").strip().lower()
        report_progress = int(data.get("progress", "").strip())

        # report_priority = data.get("priority", "").strip().lower()
        # report_title = data.get("title", "").strip()
        # report_description = data.get("description", "").strip()

        # Validate status values
        valid_statuses = ['pending', 'assigned', 'progress', 'resolved', 'closed']
        # valid_priorities = ['low', 'medium', 'high', 'critical']

        # Update the report fields
        if report_status and report_status in valid_statuses:
            report.status = report_status


        # if report_priority and report_priority in valid_priorities:
        #     report.priority = report_priority
        #
        # if report_title:
        #     report.category = report_title  # Assuming title maps to category
        #
        # if report_description:
        #     report.description = report_description

        #Update report progress in dB
        report.progress = report_progress

        # Create notification for report status update
        create_notification(
            user_id=report.user_id,
            report_id=report.id,
            notification_type=NotificationType.STATUS_UPDATE,
            title="Report Status Updated",
            message=f"Your {report.category} report on {report.location} has been marked as {report.status}."
        )

        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'Report updated successfully',
            'data': {
                'id': report.id,
                'status': report.status,
                'progress': report.progress
                # 'priority': report.priority,
                # 'category': report.category
            }
        })

    except Exception as e:
        print(f"Error updating report: {e}")
        db.session.rollback()
        return jsonify({'status': 'error', 'message': f'Failed to update report: {str(e)}'}), 500


# @app.route('/assign_report/<int:report_id>', methods=['POST'])
# @login_required
# def assign_report(report_id):
#     """Assign a report to a team - fixed version"""
#     try:
#         data = request.get_json()
#         if not data:
#             return jsonify({'status': 'error', 'message': 'No data provided'}), 400
#
#         # Find the specific report
#         report = db.get_or_404(Reports, report_id)
#
#         # Check if user is admin
#         if current_user.id != 1:
#             return jsonify({'status': 'error', 'message': 'Unauthorized - Admin access required'}), 403
#
#         # Extract assignment data
#         team = data.get("team", "").strip()
#         priority = data.get("priority", "").strip().lower()
#         deadline = data.get("deadline", "").strip()
#         notes = data.get("notes", "").strip()
#
#         # Update report with assignment info
#         if priority in ['low', 'medium', 'high', 'critical']:
#             report.priority = priority
#
#         # For now, we'll store team info in status or create a new field
#         # You might want to add an 'assigned_team' field to your Reports model
#         if team:
#             # Update status to assigned when team is assigned
#             report.status = 'assigned'
#
#         # You could add these fields to your Reports model:
#         # report.assigned_team = team
#         # report.deadline = datetime.strptime(deadline, '%Y-%m-%d') if deadline else None
#         # report.assignment_notes = notes
#
#         db.session.commit()
#
#         return jsonify({
#             'status': 'success',
#             'message': f'Report assigned successfully to {team}',
#             'data': {
#                 'id': report.id,
#                 'status': report.status,
#                 'priority': report.priority
#             }
#         })
#
#     except Exception as e:
#         print(f"Error assigning report: {e}")
#         db.session.rollback()
#         return jsonify({'status': 'error', 'message': f'Failed to assign report: {str(e)}'}), 500

@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    pass

@app.route("/notifications")
def notifications():
    user_notifications = get_all_user_notifications()
    return render_template("notifications.html", notifications=user_notifications, current_user=current_user)


@app.route("/mark_all_notifications_read", methods=["POST"])
@login_required
def mark_all_notifications_read():
    try:
        # Update all unread notifications for the current user
        notifications = db.session.execute(
            db.select(Notification)
            .where(Notification.user_id == current_user.id)
            .where(Notification.is_read == False)
        ).scalars().all()

        for notification in notifications:
            notification.is_read = True

        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Marked {len(notifications)} notifications as read'
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'Error marking notifications as read: {str(e)}'
        }), 500


@app.route("/mark_notification_read/<int:notification_id>", methods=["POST"])
@login_required
def mark_notification_read(notification_id):
    try:
        notification = db.get_or_404(Notification, notification_id)

        # Verify the notification belongs to the current user
        if notification.user_id != current_user.id:
            return jsonify({
                'success': False,
                'message': 'Unauthorized'
            }), 403

        notification.is_read = True
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Notification marked as read'
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'Error marking notification as read: {str(e)}'
        }), 500


@app.route("/delete_notification/<int:notification_id>", methods=["DELETE"])
@login_required
def delete_notification(notification_id):
    try:
        notification = db.get_or_404(Notification, notification_id)

        # Verify the notification belongs to the current user
        if notification.user_id != current_user.id:
            return jsonify({
                'success': False,
                'message': 'Unauthorized'
            }), 403

        db.session.delete(notification)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Notification deleted'
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'Error deleting notification: {str(e)}'
        }), 500


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))



if __name__ == "__main__":
    app.run(debug=True)