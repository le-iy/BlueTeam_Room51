from __future__ import annotations

import os
import sqlite3
from functools import wraps
from pathlib import Path
from typing import Callable

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash #added plaintext pass


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('student','faculty','admin')),
    full_name TEXT NOT NULL, email TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS students (
    id INTEGER PRIMARY KEY, user_id INTEGER UNIQUE NOT NULL, student_number TEXT UNIQUE NOT NULL,
    program TEXT NOT NULL, year_level INTEGER NOT NULL, section TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS faculty (
    id INTEGER PRIMARY KEY, user_id INTEGER UNIQUE NOT NULL, employee_number TEXT UNIQUE NOT NULL,
    department TEXT NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS subjects (
    id INTEGER PRIMARY KEY, code TEXT UNIQUE NOT NULL, name TEXT NOT NULL, units INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS enrollments (
    id INTEGER PRIMARY KEY, student_id INTEGER NOT NULL, subject_id INTEGER NOT NULL,
    semester TEXT NOT NULL, school_year TEXT NOT NULL, status TEXT NOT NULL,
    FOREIGN KEY(student_id) REFERENCES students(id), FOREIGN KEY(subject_id) REFERENCES subjects(id)
);
CREATE TABLE IF NOT EXISTS grades (
    id INTEGER PRIMARY KEY, enrollment_id INTEGER UNIQUE NOT NULL, grade TEXT NOT NULL,
    remarks TEXT NOT NULL, updated_by INTEGER, FOREIGN KEY(enrollment_id) REFERENCES enrollments(id)
);
CREATE TABLE IF NOT EXISTS class_schedules (
    id INTEGER PRIMARY KEY, subject_id INTEGER NOT NULL, section TEXT NOT NULL,
    day TEXT NOT NULL, start_time TEXT NOT NULL, end_time TEXT NOT NULL, room TEXT NOT NULL,
    FOREIGN KEY(subject_id) REFERENCES subjects(id)
);
CREATE TABLE IF NOT EXISTS faculty_subjects (
    faculty_id INTEGER NOT NULL, subject_id INTEGER NOT NULL, section TEXT NOT NULL,
    PRIMARY KEY(faculty_id, subject_id, section), FOREIGN KEY(faculty_id) REFERENCES faculty(id),
    FOREIGN KEY(subject_id) REFERENCES subjects(id)
);
"""


SEED_USERS = [
    (1, "alex.rivera", "BlueTeam101!", "student", "Alex Rivera", "alex.rivera@example.test"),
    (2, "bea.santos", "BlueTeam102!", "student", "Bea Santos", "bea.santos@example.test"),
    (3, "morgan.lee", "Faculty2026!", "faculty", "Morgan Lee", "morgan.lee@example.test"),
    (4, "jordan.reyes", "Admin2026!", "admin", "Jordan Reyes", "jordan.reyes@example.test"),
]


def connect(path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def seed_database(path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = connect(path)
    conn.executescript(SCHEMA)
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        users = []
        for user in SEED_USERS:
            users.append((*user[:2], generate_password_hash(user[2]), *user[3:])) #added plaintext pass
        conn.executemany("INSERT INTO users(id,username,password,role,full_name,email) VALUES (?,?,?,?,?,?)", users)
        conn.executemany("INSERT INTO students VALUES (?,?,?,?,?,?)", [(1, 1, "BP-2026-001", "BS Cybersecurity", 3, "CS3-A"), (2, 2, "BP-2026-002", "BS Cybersecurity", 3, "CS3-A")])
        conn.executemany("INSERT INTO faculty VALUES (?,?,?,?)", [(1, 3, "FAC-026", "Computing and Information Sciences")])
        conn.executemany("INSERT INTO subjects VALUES (?,?,?,?)", [(1, "CYB301", "Secure Software Development", 3), (2, "CYB302", "Network Defense", 3), (3, "CAP401", "Capstone Project 1", 3)])
        conn.executemany("INSERT INTO enrollments VALUES (?,?,?,?,?,?)", [(1, 1, 1, "1st Semester", "2026-2027", "Enrolled"), (2, 1, 3, "1st Semester", "2026-2027", "Enrolled"), (3, 2, 1, "1st Semester", "2026-2027", "Enrolled")])
        conn.executemany("INSERT INTO grades VALUES (?,?,?,?,?)", [(1, 1, "1.25", "Excellent progress", 3), (2, 2, "1.50", "On track", 3), (3, 3, "1.75", "Good progress", 3)])
        conn.executemany("INSERT INTO class_schedules VALUES (?,?,?,?,?,?,?)", [(1, 1, "CS3-A", "Monday", "09:00", "12:00", "Room 401"), (2, 3, "CS3-A", "Wednesday", "13:00", "16:00", "Lab 2")])
        conn.executemany("INSERT INTO faculty_subjects VALUES (?,?,?)", [(1, 1, "CS3-A"), (1, 3, "CS3-A")])

#added plaintext pass
    existing_users = conn.execute(
        "SELECT id, password FROM users"
    ).fetchall()

    for existing_user in existing_users:
        stored_password = existing_user["password"]

        if not stored_password.startswith(("scrypt:", "pbkdf2:")):
            hashed_password = generate_password_hash(stored_password)

            conn.execute(
                "UPDATE users SET password = ? WHERE id = ?",
                (hashed_password, existing_user["id"])
            )
#----
    
    conn.commit()
    conn.close()


def create_app(mode: str = "vulnerable", database_path: str | Path | None = None) -> Flask:
    app = Flask(__name__, template_folder=str(Path(__file__).parent / "templates"), static_folder=str(Path(__file__).parent / "static"))
    app.config.update(SECRET_KEY=os.environ.get("BP_SIS_SECRET", "local-training-secret"), BP_SIS_MODE=mode)
    path = Path(database_path or (Path(__file__).parent.parent / mode / "data" / "bp_sis.sqlite3"))
    seed_database(path)
    app.bp_sis_database_path = str(path)

    def get_db() -> sqlite3.Connection:
        if "db" not in g: g.db = connect(path)
        return g.db

    @app.teardown_appcontext
    def close_db(_error=None):
        conn = g.pop("db", None)
        if conn is not None: conn.close()

    @app.context_processor
    def inject_globals():
        return {"current_user": current_user(), "mode": mode}

    def login_required(view: Callable):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if current_user() is None:
                return redirect(url_for("login", next=request.path))
            return view(*args, **kwargs)
        return wrapped

    def roles(*allowed: str):
        def decorator(view: Callable):
            @wraps(view)
            @login_required
            def wrapped(*args, **kwargs):
                if current_user()["role"] not in allowed: abort(403)
                return view(*args, **kwargs)
            return wrapped
        return decorator

    def current_user():
        user_id = session.get("user_id")
        if not user_id: return None
        return get_db().execute("SELECT * FROM users WHERE id = ? AND active = 1", (user_id,)).fetchone()

    @app.route("/")
    def index():
        return redirect(url_for("dashboard")) if current_user() else redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username, password = request.form.get("username", ""), request.form.get("password", "")
            conn = get_db()
            user = conn.execute("SELECT * FROM users WHERE username = ? AND active = 1", (username,)).fetchone()
            valid = bool(user and check_password_hash(user["password"], password)) #added plaintext pass
            if valid:
                session.clear(); session["user_id"] = user["id"]
                return redirect(url_for("dashboard"))
            flash("Invalid username or password.", "error")
        return render_template("login.html")

    @app.post("/logout")
    def logout():
        session.clear(); return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        user = current_user(); conn = get_db()
        stats = {}
        if user["role"] == "student":
            student = conn.execute("SELECT * FROM students WHERE user_id = ?", (user["id"],)).fetchone()
            stats["student"] = student
            stats["grades"] = conn.execute("SELECT g.grade FROM grades g JOIN enrollments e ON e.id=g.enrollment_id WHERE e.student_id=?", (student["id"],)).fetchall()
        elif user["role"] == "faculty":
            stats["subjects"] = conn.execute("SELECT s.* FROM subjects s JOIN faculty_subjects fs ON fs.subject_id=s.id JOIN faculty f ON f.id=fs.faculty_id WHERE f.user_id=?", (user["id"],)).fetchall()
        else:
            stats["users"] = conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
        return render_template("dashboard.html", stats=stats)

    @app.route("/student/profile")
    @roles("student")
    def student_profile():
        user = current_user(); conn = get_db()
        requested = request.args.get("record_id")
        # INTENTIONAL IDOR: record_id is trusted instead of bound to the logged-in student.
        record_id = requested or conn.execute("SELECT id FROM students WHERE user_id=?", (user["id"],)).fetchone()["id"]
        student = conn.execute("SELECT s.*, u.full_name, u.email FROM students s JOIN users u ON u.id=s.user_id WHERE s.id=?", (record_id,)).fetchone()
        if not student: abort(404) #added IDOR
        if student["user_id"] != user["id"]:
            abort(403)
        return render_template("student_profile.html", student=student)

    @app.route("/student/records")
    @roles("student")
    def student_records():
        user = current_user(); conn = get_db()
        student = conn.execute("SELECT * FROM students WHERE user_id=?", (user["id"],)).fetchone()
        rows = conn.execute("SELECT s.code, s.name, e.semester, e.school_year, g.grade, g.remarks FROM enrollments e JOIN subjects s ON s.id=e.subject_id LEFT JOIN grades g ON g.enrollment_id=e.id WHERE e.student_id=?", (student["id"],)).fetchall()
        schedules = conn.execute("SELECT s.code, s.name, c.day, c.start_time, c.end_time, c.room FROM class_schedules c JOIN subjects s ON s.id=c.subject_id WHERE c.section=?", (student["section"],)).fetchall()
        return render_template("student_records.html", rows=rows, schedules=schedules)

    @app.route("/faculty/subjects")
    @roles("faculty")
    def faculty_subjects():
        user = current_user(); conn = get_db()
        rows = conn.execute("SELECT s.code, s.name, fs.section FROM subjects s JOIN faculty_subjects fs ON fs.subject_id=s.id JOIN faculty f ON f.id=fs.faculty_id WHERE f.user_id=?", (user["id"],)).fetchall()
        return render_template("table.html", title="Assigned subjects", columns=["Code", "Subject", "Section"], rows=rows, values=lambda r: [r["code"], r["name"], r["section"]])

    @app.route("/faculty/students")
    @roles("faculty")
    def faculty_students():
        term = request.args.get("q", "")
        conn = get_db()
        # INTENTIONAL SQL INJECTION: the search term is concatenated into SQL.
        query = "SELECT s.id, s.student_number, u.full_name, s.program, s.section, e.id AS enrollment_id, sub.code, g.grade FROM students s JOIN users u ON u.id=s.user_id LEFT JOIN enrollments e ON e.student_id=s.id LEFT JOIN subjects sub ON sub.id=e.subject_id LEFT JOIN grades g ON g.enrollment_id=e.id WHERE s.student_number LIKE ? OR u.full_name LIKE ?"
        try: rows = conn.execute(query, (f"%{term}%", f"%{term}%")).fetchall()
        except sqlite3.Error: rows = []
        return render_template("faculty_students.html", rows=rows, term=term)

    @app.post("/faculty/grades/<int:enrollment_id>")
    @roles("faculty")
    def update_grade(enrollment_id: int):
        conn = get_db(); grade = request.form.get("grade", "").strip(); remarks = request.form.get("remarks", "").strip()
        conn.execute("UPDATE grades SET grade=?, remarks=?, updated_by=? WHERE enrollment_id=?", (grade, remarks, current_user()["id"], enrollment_id)); conn.commit()
        flash("Grade updated.", "success"); return redirect(url_for("faculty_students"))

    @app.route("/admin/users")
    @roles("admin")
    def admin_users():
        users = get_db().execute("SELECT id, username, full_name, email, role, active FROM users ORDER BY id").fetchall()
        return render_template("admin_users.html", users=users)

    @app.route("/admin/records")
    @roles("admin")
    def admin_records():
        conn = get_db()
        students = conn.execute("SELECT u.full_name, u.email, s.student_number, s.program, s.year_level, s.section FROM students s JOIN users u ON u.id=s.user_id ORDER BY s.student_number").fetchall()
        faculty = conn.execute("SELECT u.full_name, u.email, f.employee_number, f.department FROM faculty f JOIN users u ON u.id=f.user_id ORDER BY f.employee_number").fetchall()
        return render_template("admin_records.html", students=students, faculty=faculty)

    @app.post("/admin/users/<int:user_id>/role")
    @roles("admin")
    def update_role(user_id: int):
        role = request.form.get("role", "student")
        if role not in {"student", "faculty", "admin"}: abort(400)
        conn = get_db(); conn.execute("UPDATE users SET role=? WHERE id=?", (role, user_id)); conn.commit(); flash("Role updated.", "success")
        return redirect(url_for("admin_users"))

    @app.errorhandler(403)
    def forbidden(_error): return render_template("error.html", code=403, message="You are not authorized to view this page."), 403

    @app.errorhandler(404)
    def not_found(_error): return render_template("error.html", code=404, message="The requested record was not found."), 404

    return app
