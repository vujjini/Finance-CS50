import os
# pk_2fed9b6e191d4288b71675a7fe20be1d
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from helpers import apology, login_required, lookup, usd

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


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    if request.method == 'GET':
        n = db.execute("SELECT COUNT(DISTINCT symbol) FROM transactions WHERE user_id = ? AND type = 'buy'",
                       session["user_id"])[0]["COUNT(DISTINCT symbol)"]
        portfolio = db.execute("SELECT * FROM transactions WHERE user_id = ? AND type = 'buy' GROUP BY symbol", session["user_id"])
        for i in range(n):
            portfolio[i]["shares_left"] = db.execute(
                "SELECT DISTINCT shares_left FROM transactions WHERE symbol LIKE ? AND user_id = ? AND type = 'buy'", portfolio[i]["symbol"], session["user_id"])[0]["shares_left"]

        print(portfolio)
        money_left = round(db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"], 3)
        return render_template("index.html", n=n, portfolio=portfolio, lookup=lookup, cash=money_left, int=int)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == 'GET':
        return render_template("buy.html")

    if request.method == 'POST':
        user_id = session["user_id"]
        symbols = []
        for i in range(len(db.execute("SELECT DISTINCT(symbol) FROM transactions WHERE user_id = 2"))):
            symbols.append(db.execute("SELECT DISTINCT(symbol) FROM transactions WHERE user_id = 2")[i]["symbol"])
        print(symbols)
        symbol = request.form.get("symbol").upper()
        shares = float(request.form.get("shares"))
        quote = lookup(symbol)
        if not symbol:
            return apology("specify a symbol")
        elif not shares:
            return apology("specify the number of shares")
        elif not quote:
            return apology("symbol does not exist")
        elif shares <= 0:
            return apology("shares must be greater than or equal to 1")
        money_left = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        if symbol in symbols:
            og_shares = db.execute("SELECT shares_left FROM transactions WHERE symbol LIKE ? AND user_id = ? AND type = 'buy'",
                                   symbol, session["user_id"])[0]["shares_left"]
        else:
            og_shares = 0
        print(og_shares)
        cost = shares*quote.get("price")
        if cost > money_left:
            return apology("not enough money in your account")
        else:
            money_left = money_left - cost
            db.execute("UPDATE users SET cash = ? WHERE id = ?", money_left, user_id)
            db.execute("UPDATE transactions SET shares_left = ? WHERE user_id = ? AND symbol = ? AND type = 'buy'",
                       og_shares + shares, session["user_id"], symbol)
            db.execute("INSERT INTO transactions (user_id, symbol, name, shares, shares_left, price, type, time) VALUES(?, ?, ?, ?, ?, ?, 'buy', ?)",
                       user_id, symbol, quote.get("name"), shares, shares, quote.get("price"), datetime.now())
            return redirect("/")


@app.route("/history")
@login_required
def history():
    n = len(db.execute("SELECT * FROM transactions WHERE user_id = ?", session["user_id"]))
    history = db.execute("SELECT * FROM transactions WHERE user_id = ?", session["user_id"])
    return render_template("history.html", history=history, n=n)


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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == 'GET':
        return render_template("quote.html")

    if request.method == 'POST':
        symbol = request.form.get("symbol").upper()
        quote = lookup(symbol)
        if not symbol:
            return apology("input a symbol")
        elif not quote:
            return apology("symbol does'nt exist")
        else:
            name = quote.get("name")
            price = quote.get("price")
            return render_template("quoted.html", symbol=symbol, name=name, price=price)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == 'GET':
        return render_template("register.html")

    if request.method == 'POST':
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        # hash the provided password
        hashed_password = generate_password_hash(password)
        usernames = db.execute("SELECT username FROM users WHERE username = ?", username)
        # if the user hit submit without providing the necessary details
        if not username and not password and not confirmation:
            return apology("provide login credentials")
        elif not username:
            return apology("provide a username")
        elif not password:
            return apology("provide a password")
        elif not confirmation:
            return apology("confirm password")
        # if the username already exists in the database
        elif len(usernames) == 1:
            return apology("username already taken")
        # if the password and the confirm password do not match
        elif password != confirmation:
            return apology("confirm password doesn't match with the password")
        # add the provided credentials into the database
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hashed_password)

    return redirect("/login")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == 'GET':
        symbols = db.execute("SELECT DISTINCT(symbol) FROM transactions WHERE user_id = 2")
        n = len(symbols)
        return render_template("sell.html", n=n, symbols=symbols)
    if request.method == 'POST':
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        og_shares = db.execute("SELECT DISTINCT shares_left FROM transactions WHERE symbol LIKE ? AND user_id = ? AND type = 'buy'",
                            symbol, session["user_id"])[0]["shares_left"]
        if shares > og_shares:
            return apology("Number of shares exceeded the original shares")
        returns = lookup(symbol)["price"]*shares
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash + returns, session["user_id"])
        db.execute("INSERT INTO transactions (user_id, symbol, name, shares, price, type, time) VALUES(?, ?, ?, ?, ?, 'sell', ?)",
                   session["user_id"], symbol, lookup(symbol)["name"], shares, lookup(symbol)["price"], datetime.now())
        db.execute("UPDATE transactions SET shares_left = ? WHERE user_id = ? AND symbol = ? AND type = 'buy'",
                   og_shares - shares, session["user_id"], symbol)
        return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
