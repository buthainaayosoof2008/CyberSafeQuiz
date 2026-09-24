from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash
)

import mysql.connector
from mysql.connector import Error
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import re
import secrets


app = Flask(__name__)

# Secret key for Flask sessions
app.secret_key = "CyberSafeQuiz-Secret-Key-2026"


# =========================================================
# DATABASE CONFIGURATION
# =========================================================

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",
    "database": "cybersafe_quiz_db"
}


def get_db_connection():
    try:
        connection = mysql.connector.connect(**DB_CONFIG)

        if connection.is_connected():
            return connection

    except Error as e:
        print("Database connection error:", e)

    return None


# =========================================================
# CSRF PROTECTION
# =========================================================

def get_csrf_token():

    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)

    return session["csrf_token"]


@app.context_processor
def inject_csrf_token():

    return {
        "csrf_token": get_csrf_token()
    }


def validate_csrf():

    token = request.form.get("csrf_token")

    return (
        token
        and token == session.get("csrf_token")
    )


# =========================================================
# LOGIN PROTECTION
# =========================================================

def login_required(route_function):

    @wraps(route_function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:

            flash(
                "Please login to continue.",
                "warning"
            )

            return redirect(
                url_for("login")
            )

        return route_function(*args, **kwargs)

    return wrapper


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    if "user_id" in session:

        return redirect(
            url_for("dashboard")
        )

    return redirect(
        url_for("login")
    )


# =========================================================
# REGISTER
# =========================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        if not validate_csrf():

            flash(
                "Invalid request. Please try again.",
                "danger"
            )

            return redirect(
                url_for("register")
            )

        username = request.form.get(
            "username",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        # Required fields
        if not username or not email or not password or not confirm_password:

            flash(
                "All fields are required.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        # Username validation
        if len(username) < 3 or len(username) > 100:

            flash(
                "Username must contain 3 to 100 characters.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        # Email validation
        if not re.match(
            r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
            email
        ):

            flash(
                "Please enter a valid email address.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        # Password validation
        if len(password) < 6:

            flash(
                "Password must contain at least 6 characters.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        # Confirm password
        if password != confirm_password:

            flash(
                "Passwords do not match.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        connection = get_db_connection()

        if connection is None:

            flash(
                "Unable to connect to database.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        cursor = connection.cursor()

        try:

            cursor.execute(
                """
                SELECT id
                FROM users
                WHERE email = %s
                """,
                (email,)
            )

            existing_user = cursor.fetchone()

            if existing_user:

                flash(
                    "Email is already registered.",
                    "warning"
                )

                return render_template(
                    "register.html"
                )

            # Hash password before storing
            hashed_password = generate_password_hash(
                password
            )

            cursor.execute(
                """
                INSERT INTO users
                (
                    username,
                    email,
                    password
                )
                VALUES
                (
                    %s,
                    %s,
                    %s
                )
                """,
                (
                    username,
                    email,
                    hashed_password
                )
            )

            connection.commit()

            flash(
                "Registration successful. Please login.",
                "success"
            )

            return redirect(
                url_for("login")
            )

        except Error as e:

            connection.rollback()

            print(
                "Registration error:",
                e
            )

            flash(
                "Registration failed.",
                "danger"
            )

        finally:

            cursor.close()
            connection.close()

    return render_template(
        "register.html"
    )


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if "user_id" in session:

        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":

        if not validate_csrf():

            flash(
                "Invalid request. Please try again.",
                "danger"
            )

            return redirect(
                url_for("login")
            )

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        if not email or not password:

            flash(
                "Email and password are required.",
                "danger"
            )

            return render_template(
                "login.html"
            )

        connection = get_db_connection()

        if connection is None:

            flash(
                "Unable to connect to database.",
                "danger"
            )

            return render_template(
                "login.html"
            )

        cursor = connection.cursor(
            dictionary=True
        )

        try:

            cursor.execute(
                """
                SELECT
                    id,
                    username,
                    email,
                    password
                FROM users
                WHERE email = %s
                """,
                (email,)
            )

            user = cursor.fetchone()

            if user and check_password_hash(
                user["password"],
                password
            ):

                session.clear()

                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["email"] = user["email"]

                session["csrf_token"] = secrets.token_hex(32)

                flash(
                    "Login successful.",
                    "success"
                )

                return redirect(
                    url_for("dashboard")
                )

            flash(
                "Invalid email or password.",
                "danger"
            )

        except Error as e:

            print(
                "Login error:",
                e
            )

            flash(
                "Login failed.",
                "danger"
            )

        finally:

            cursor.close()
            connection.close()

    return render_template(
        "login.html"
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(
        url_for("login")
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
@login_required
def dashboard():

    connection = get_db_connection()

    if connection is None:

        flash(
            "Unable to connect to database.",
            "danger"
        )

        return render_template(
            "dashboard.html",
            question_count=0,
            user_count=0,
            attempt_count=0,
            recent_attempts=[]
        )

    cursor = connection.cursor(
        dictionary=True
    )

    try:

        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM questions
            """
        )

        question_count = cursor.fetchone()["total"]

        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM users
            """
        )

        user_count = cursor.fetchone()["total"]

        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM quiz_attempts
            """
        )

        attempt_count = cursor.fetchone()["total"]

        cursor.execute(
            """
            SELECT
                quiz_attempts.score,
                quiz_attempts.total_questions,
                quiz_attempts.attempt_date,
                users.username
            FROM quiz_attempts
            INNER JOIN users
                ON quiz_attempts.user_id = users.id
            ORDER BY quiz_attempts.attempt_date DESC
            LIMIT 5
            """
        )

        recent_attempts = cursor.fetchall()

    except Error as e:

        print(
            "Dashboard error:",
            e
        )

        question_count = 0
        user_count = 0
        attempt_count = 0
        recent_attempts = []

    finally:

        cursor.close()
        connection.close()

    return render_template(
        "dashboard.html",
        question_count=question_count,
        user_count=user_count,
        attempt_count=attempt_count,
        recent_attempts=recent_attempts
    )


# =========================================================
# QUIZ
# =========================================================

@app.route("/quiz")
@login_required
def quiz():

    connection = get_db_connection()

    if connection is None:

        flash(
            "Unable to connect to database.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    cursor = connection.cursor(
        dictionary=True
    )

    try:

        cursor.execute(
            """
            SELECT
                id,
                question,
                option_a,
                option_b,
                option_c,
                option_d
            FROM questions
            ORDER BY id ASC
            """
        )

        questions = cursor.fetchall()

    except Error as e:

        print(
            "Quiz loading error:",
            e
        )

        questions = []

    finally:

        cursor.close()
        connection.close()

    if not questions:

        flash(
            "No quiz questions are available.",
            "warning"
        )

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "quiz.html",
        questions=questions
    )


# =========================================================
# SUBMIT QUIZ
# =========================================================

@app.route("/submit_quiz", methods=["POST"])
@login_required
def submit_quiz():

    if not validate_csrf():

        flash(
            "Invalid request. Please try again.",
            "danger"
        )

        return redirect(
            url_for("quiz")
        )

    connection = get_db_connection()

    if connection is None:

        flash(
            "Unable to connect to database.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    cursor = connection.cursor(
        dictionary=True
    )

    try:

        cursor.execute(
            """
            SELECT
                id,
                correct_answer
            FROM questions
            ORDER BY id ASC
            """
        )

        questions = cursor.fetchall()

        score = 0

        for question in questions:

            question_id = question["id"]

            selected_answer = request.form.get(
                f"question_{question_id}"
            )

            if selected_answer == question["correct_answer"]:

                score += 1

        total_questions = len(questions)

        cursor.close()

        insert_cursor = connection.cursor()

        insert_cursor.execute(
            """
            INSERT INTO quiz_attempts
            (
                user_id,
                score,
                total_questions
            )
            VALUES
            (
                %s,
                %s,
                %s
            )
            """,
            (
                session["user_id"],
                score,
                total_questions
            )
        )

        connection.commit()

        insert_cursor.close()

        percentage = 0

        if total_questions > 0:

            percentage = round(
                (score / total_questions) * 100
            )

        return render_template(
            "result.html",
            score=score,
            total_questions=total_questions,
            percentage=percentage
        )

    except Error as e:

        connection.rollback()

        print(
            "Quiz submission error:",
            e
        )

        flash(
            "Unable to submit quiz.",
            "danger"
        )

        return redirect(
            url_for("quiz")
        )

    finally:

        try:
            connection.close()
        except:
            pass


# =========================================================
# VIEW QUESTIONS
# =========================================================

@app.route("/questions")
@login_required
def questions():

    connection = get_db_connection()

    if connection is None:

        flash(
            "Unable to connect to database.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    cursor = connection.cursor(
        dictionary=True
    )

    try:

        cursor.execute(
            """
            SELECT *
            FROM questions
            ORDER BY id DESC
            """
        )

        question_list = cursor.fetchall()

    except Error as e:

        print(
            "Question loading error:",
            e
        )

        question_list = []

    finally:

        cursor.close()
        connection.close()

    return render_template(
        "questions.html",
        questions=question_list
    )


# =========================================================
# ADD QUESTION
# =========================================================

@app.route(
    "/questions/add",
    methods=["GET", "POST"]
)
@login_required
def add_question():

    if request.method == "POST":

        if not validate_csrf():

            flash(
                "Invalid request. Please try again.",
                "danger"
            )

            return redirect(
                url_for("add_question")
            )

        question = request.form.get(
            "question",
            ""
        ).strip()

        option_a = request.form.get(
            "option_a",
            ""
        ).strip()

        option_b = request.form.get(
            "option_b",
            ""
        ).strip()

        option_c = request.form.get(
            "option_c",
            ""
        ).strip()

        option_d = request.form.get(
            "option_d",
            ""
        ).strip()

        correct_answer = request.form.get(
            "correct_answer",
            ""
        ).strip().upper()

        if not all([
            question,
            option_a,
            option_b,
            option_c,
            option_d,
            correct_answer
        ]):

            flash(
                "All fields are required.",
                "danger"
            )

            return render_template(
                "add_question.html"
            )

        if correct_answer not in [
            "A",
            "B",
            "C",
            "D"
        ]:

            flash(
                "Invalid correct answer.",
                "danger"
            )

            return render_template(
                "add_question.html"
            )

        if len(question) > 1000:

            flash(
                "Question is too long.",
                "danger"
            )

            return render_template(
                "add_question.html"
            )

        connection = get_db_connection()

        if connection is None:

            flash(
                "Unable to connect to database.",
                "danger"
            )

            return render_template(
                "add_question.html"
            )

        cursor = connection.cursor()

        try:

            cursor.execute(
                """
                INSERT INTO questions
                (
                    question,
                    option_a,
                    option_b,
                    option_c,
                    option_d,
                    correct_answer
                )
                VALUES
                (
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s
                )
                """,
                (
                    question,
                    option_a,
                    option_b,
                    option_c,
                    option_d,
                    correct_answer
                )
            )

            connection.commit()

            flash(
                "Question added successfully.",
                "success"
            )

            return redirect(
                url_for("questions")
            )

        except Error as e:

            connection.rollback()

            print(
                "Add question error:",
                e
            )

            flash(
                "Unable to add question.",
                "danger"
            )

        finally:

            cursor.close()
            connection.close()

    return render_template(
        "add_question.html"
    )


# =========================================================
# EDIT QUESTION
# =========================================================

@app.route(
    "/questions/edit/<int:question_id>",
    methods=["GET", "POST"]
)
@login_required
def edit_question(question_id):

    connection = get_db_connection()

    if connection is None:

        flash(
            "Unable to connect to database.",
            "danger"
        )

        return redirect(
            url_for("questions")
        )

    cursor = connection.cursor(
        dictionary=True
    )

    if request.method == "POST":

        if not validate_csrf():

            cursor.close()
            connection.close()

            flash(
                "Invalid request. Please try again.",
                "danger"
            )

            return redirect(
                url_for(
                    "edit_question",
                    question_id=question_id
                )
            )

        question = request.form.get(
            "question",
            ""
        ).strip()

        option_a = request.form.get(
            "option_a",
            ""
        ).strip()

        option_b = request.form.get(
            "option_b",
            ""
        ).strip()

        option_c = request.form.get(
            "option_c",
            ""
        ).strip()

        option_d = request.form.get(
            "option_d",
            ""
        ).strip()

        correct_answer = request.form.get(
            "correct_answer",
            ""
        ).strip().upper()

        if not all([
            question,
            option_a,
            option_b,
            option_c,
            option_d,
            correct_answer
        ]):

            flash(
                "All fields are required.",
                "danger"
            )

        elif correct_answer not in [
            "A",
            "B",
            "C",
            "D"
        ]:

            flash(
                "Invalid correct answer.",
                "danger"
            )

        else:

            try:

                cursor.execute(
                    """
                    UPDATE questions
                    SET
                        question = %s,
                        option_a = %s,
                        option_b = %s,
                        option_c = %s,
                        option_d = %s,
                        correct_answer = %s
                    WHERE id = %s
                    """,
                    (
                        question,
                        option_a,
                        option_b,
                        option_c,
                        option_d,
                        correct_answer,
                        question_id
                    )
                )

                connection.commit()

                flash(
                    "Question updated successfully.",
                    "success"
                )

                cursor.close()
                connection.close()

                return redirect(
                    url_for("questions")
                )

            except Error as e:

                connection.rollback()

                print(
                    "Edit question error:",
                    e
                )

                flash(
                    "Unable to update question.",
                    "danger"
                )

    cursor.execute(
        """
        SELECT *
        FROM questions
        WHERE id = %s
        """,
        (question_id,)
    )

    question_data = cursor.fetchone()

    cursor.close()
    connection.close()

    if not question_data:

        flash(
            "Question not found.",
            "warning"
        )

        return redirect(
            url_for("questions")
        )

    return render_template(
        "edit_question.html",
        question=question_data
    )


# =========================================================
# DELETE QUESTION
# =========================================================

@app.route(
    "/questions/delete/<int:question_id>",
    methods=["POST"]
)
@login_required
def delete_question(question_id):

    if not validate_csrf():

        flash(
            "Invalid request. Please try again.",
            "danger"
        )

        return redirect(
            url_for("questions")
        )

    connection = get_db_connection()

    if connection is None:

        flash(
            "Unable to connect to database.",
            "danger"
        )

        return redirect(
            url_for("questions")
        )

    cursor = connection.cursor()

    try:

        cursor.execute(
            """
            DELETE FROM questions
            WHERE id = %s
            """,
            (question_id,)
        )

        connection.commit()

        flash(
            "Question deleted successfully.",
            "success"
        )

    except Error as e:

        connection.rollback()

        print(
            "Delete question error:",
            e
        )

        flash(
            "Unable to delete question.",
            "danger"
        )

    finally:

        cursor.close()
        connection.close()

    return redirect(
        url_for("questions")
    )


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )
    