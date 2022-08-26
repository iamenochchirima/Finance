import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    user_id = session["user_id"]
    stocks = db.execute("SELECT symbol, name, SUM(shares) as totalShares, price FROM transactions WHERE user_id = ? GROUP BY symbol", user_id)
    cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

    total = cash

    for stock in stocks:
        total += stock["totalShares"] * stock["price"]

    return render_template("index.html", stocks = stocks, cash = cash, usd = usd, total = total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method =="POST":
        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares")
        stock_item = lookup(symbol)

        if not symbol:
            return apology("Symbol required")

        if not shares:
            return apology("Shares required")

        if int(shares) < 1:
            return apology("Shares must be a positive integer")

        if not stock_item:
            return apology("Invalid symbol")

        user_id = session["user_id"]
        name = stock_item["name"]
        price = stock_item["price"]

        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        buying_price = (int(shares) * price)

        if buying_price > cash:
            return apology("Insufficient Cash")
        else:
            db.execute("UPDATE users SET cash = ? WHERE id = ?", cash - buying_price, user_id)
            db.execute("INSERT INTO transactions (user_id, name, shares, price, type, symbol) VALUES(?, ?, ?, ?, ?, ?)",
            user_id, name, shares, price, "bought", symbol)

        return redirect("/")
    else:
        return render_template("buy.html")

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]
    history = db.execute("SELECT name, symbol, shares, price, type, transacted FROM transactions WHERE user_id = ? ORDER BY transacted", user_id)
    return render_template("history.html", history = history, usd = usd)


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
    """Get stock quote."""
    if request.method =="POST":
        symbol = request.form.get("symbol")

        if not symbol:
            return apology("Symbol required")

        stock_item = lookup(symbol)

        if not stock_item:
            return apology("Invalid symbol")

        return render_template("quoted.html", stock_item=stock_item)
    else:
        return render_template("quote.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    #User reached route via post
    if request.method == "POST":

        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        hash = generate_password_hash(password)
        username = request.form.get("username")

        #Ensure username was submitted
        if not username:
            return apology("must provide username")

        #Ensure password was submitted
        elif not password:
            return apology("must provide password")

        #Ensure confirmation was submitted
        elif not confirmation:
            return apology("must provide confirmation")

        #Ensure passwords submitted matches
        elif (len(password) != len(confirmation)):
            return apology("passwords must be same")

        #Ensure the username entered is not already taken
        rows = db.execute("SELECT * FROM users WHERE username=?", username)
        if len(rows) != 0:
            return apology("Username already taken")

        new = db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hash)

        session["user_id"] = new

        return redirect("/")

    else:
        return render_template("register.html")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    user_id = session["user_id"]
    """Sell shares of stock"""
    if request.method == "POST":

        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        if not symbol:
            return apology("Symbol required")

        if not shares:
            return apology("Shares required")

        if int(shares) < 1:
            return apology("Shares must be a positive integer")

        stock_name = lookup(symbol)["name"]
        stock_price = lookup(symbol)["price"]

        available_shares = db.execute("SELECT shares FROM transactions WHERE user_id = ? AND symbol = ? GROUP BY symbol", user_id, symbol)[0]["shares"]

        if int(shares) > available_shares:
            return apology("Not enough shares")

        cash = db.execute("SELECT cash FROM users WHERE id =?", user_id)[0]["cash"]
        sold_price = int(shares) * stock_price
        db.execute("UPDATE users SET cash = ? WHERE id =?", cash + sold_price, user_id)
        db.execute("INSERT INTO transactions (user_id, name, shares, price, type, symbol) VALUES(?, ?, ?, ?, ?, ?)",
            user_id, stock_name, -int(shares), sold_price, "sold", symbol)

        return redirect("/")
    else:
        symbols = db.execute("SELECT symbol FROM transactions WHERE user_id =? GROUP BY symbol", user_id)
        return render_template("sell.html", symbols = symbols)
