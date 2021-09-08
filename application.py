from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///mybooks.db")


@app.route("/")
@login_required
def index():
    """Show my books"""
    books = db.execute("SELECT * FROM books WHERE user_id = ?", session["user_id"])

    return render_template("index.html", books=books)


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    """Add a book"""
    if request.method == "POST":

        if not request.form.get("title"):
            return apology("Missing title")

        if not request.form.get("writer"):
            return apology("Missing writer")


        #row = db.execute("SELECT * FROM books WHERE id = ?", session["user_id"])
        title = request.form.get("title")
        writer = request.form.get("writer")
        status = "Library"
        who = "-"
        date = "-"

        db.execute("INSERT INTO books (title, writer, status, who, date, user_id) VALUES(?, ?, ?, ?, ?, ?)",
                   title, writer, status, who, date, session["user_id"])


        flash('Added!')
        # Redirect user to home page
        return redirect("/")
    else:
        return render_template("add.html")

@app.route("/lend", methods=["GET", "POST"])
@login_required
def lend():
    if request.method == "POST":

        if not request.form.get("title"):
            return apology("Missing title")

        if not request.form.get("who"):
            return apology("Missing who")

        title = request.form.get("title")
        who = request.form.get("who")
        status = "Lent"

        db.execute("UPDATE books SET status = ?, who = ?, date = CURRENT_DATE WHERE user_id = ? AND title = ?", status, who, session["user_id"], title)

        flash('Lent!')
        # Redirect user to home page
        return redirect("/lend")

    else:
        """Show books to be lent"""
        books = db.execute("SELECT * FROM books WHERE user_id = ?", session["user_id"])

        status = "Lent"
        rows = db.execute("SELECT * FROM books WHERE user_id = ? AND status = ?", session["user_id"], status)

        return render_template("lend.html", rows=rows, books=books)


@app.route("/return", methods=["GET", "POST"])
@login_required
def returned():
    if request.method == "POST":

        if not request.form.get("title"):
            return apology("Missing title")

        title = request.form.get("title")
        status = "Library"
        who = "-"
        date = "-"

        db.execute("UPDATE books SET status = ?, who = ?, date = ? WHERE user_id = ? AND title = ?", status, who, date, session["user_id"], title)

        flash('Returned!')
        # Redirect user to home page
        return redirect("/")

    else:
        """Show lent books"""
        status = "Lent"
        books = db.execute("SELECT * FROM books WHERE user_id = ? AND status = ?", session["user_id"], status)

        return render_template("return.html", books=books)


@app.route("/delete", methods=["GET", "POST"])
@login_required
def delete():
    if request.method == "POST":

        if not request.form.get("title"):
            return apology("Missing title")

        title = request.form.get("title")

        db.execute("DELETE FROM books WHERE user_id = ? AND title = ?", session["user_id"], title)

        flash('Deleted!')
        # Redirect user to home page
        return redirect("/")

    else:
        """Show books"""
        books = db.execute("SELECT * FROM books WHERE user_id = ?", session["user_id"])

        return render_template("delete.html", books=books)



@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username:
            return apology("must provide username")

        if not password:
            return apology("must provide password")

        elif password != confirmation:
            return apology("passwords do not match")

        try:
            id = db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, generate_password_hash(password))
        except ValueError:
            return apology("username already exists")

        # Remember that user logged in
        session["user_id"] = id

        return redirect("/")

    else:
        return render_template("register.html")



@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    """Change Password"""

    if request.method == "POST":

        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not password:
            return apology("must provide password")

        elif password != confirmation:
            return apology("passwords do not match")

        db.execute("UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(password), session["user_id"])

        flash("Password changed")
        return redirect("/")

    else:
        return render_template("password.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
