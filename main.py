import os
from datetime import datetime, timezone
from dotenv import load_dotenv
from flask import Flask, redirect, render_template, url_for, request, flash
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

class User(UserMixin, db.Model):
    __tablename__ = "user"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    first_name: Mapped[str] = mapped_column(String(100), nullable=False)
    last_name: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False)
    phone: Mapped[str] = mapped_column(String(20))
    password: Mapped[str] = mapped_column(String(255), nullable=False)
    create_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

class Reports(db.Model):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(String(200), nullable=False)
    location: Mapped[str] = mapped_column(String(2000), nullable=False)
    filename: Mapped[str] = mapped_column(String(100), nullable=False)
    data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    mimetype: Mapped[str] = mapped_column(String(100), nullable=False)  # Fixed missing type annotation


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
            first_name=request.form.get("fname"),
            last_name=request.form.get("lname"),
            email=email,
            phone=request.form.get("phone"),
            password=hashed_and_salted_password
        )
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        return redirect(url_for("index"))
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
    return render_template("dashboard.html", current_user=current_user)

@app.route("/report_issue", methods=["GET", "POST"])
@login_required
def report_issue():
    if request.method == "POST":
        category = request.form.get("category")
        location = request.form.get("location")
        area = request.form.get("area")
        priority = request.form.get("priority")
        description = request.form.get("description")
        file = request.form.get("file")

        print(category, location, area, priority, description, file)


    return render_template("report_issue.html")

@app.route("/my_report")
def user_reports():
    return render_template("user_report.html")

@app.route("/profile")
def profile():
    return render_template("profile.html")

@app.route("/notifications")
def notifications():
    return render_template("notifications.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))



if __name__ == "__main__":
    app.run(debug=True)