import os
import string

from datetime import datetime
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd


# Configure application
app = Flask(__name__)


# Set HSTS header after each request
@app.after_request
def add_hsts_header(response):
    response.headers[
        "Strict-Transport-Security"
    ] = "max-age=31536000; includeSubDomains; preload"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


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
    user_id = int(session["user_id"])
    user_cash = float(db.execute(
            "SELECT cash FROM users WHERE id = ?", (session["user_id"])
        )[0]["cash"])
    stocks_data = db.execute("SELECT * FROM ownership JOIN stocks ON ownership.stock_id = stocks.stock_id WHERE user_id = ?", user_id)
    total_stock_value = 0
    for stock_data in stocks_data:
        stock_data["price"] = lookup(stock_data["stock_symbol"])["price"]
        stock_price_float = float(stock_data["price"]) * stock_data["quantity"]
        stock_data["total"] = usd(stock_price_float)
        total_stock_value += stock_price_float

    total = total_stock_value + user_cash
    user_cash = usd(user_cash)
    total = usd(total)
    return render_template("index.html", stocks_data=stocks_data, user_cash=user_cash,total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    def validate_input(symbol, stock_info, shares_str):
        if not symbol:
            return apology("please enter stock symbol")
        elif not stock_info:
            return apology("Invalid stock symbol")
        elif not shares_str:
            return apology("please enter number of shares")
        elif not shares_str.isdigit() or not float(shares_str) == int(shares_str):
            return apology("shares need to be a positive whole number")
        shares = int(shares_str)
        if shares <= 0:
            return apology("minimum 1 share")

    if request.method == "POST":
        symbol = (request.form.get("symbol")).upper()
        stock_info = lookup(symbol)
        shares_str = request.form.get("shares")
        validation_result = validate_input(symbol, stock_info, shares_str)

        if validation_result is not None:
            return validation_result
        shares = int(shares_str)
        price_per_share = float(stock_info["price"])
        user_cash_list = db.execute(
            "SELECT cash FROM users WHERE id = ?", (session["user_id"])
        )
        user_cash = float(user_cash_list[0]["cash"])
        cost_of_stock = price_per_share * shares
        user_id = int(session["user_id"])
        # check if user has enough cash
        if user_cash < cost_of_stock:
            return apology("not enough cash")
        # do this on the user side too

        # see if the stock in the the database
        stock_lookup = db.execute(
            "SELECT stock_id FROM stocks WHERE stock_symbol = ?", symbol
        )
        # if not in the database then add it into the stock database
        if not stock_lookup:
            db.execute("INSERT INTO stocks (stock_symbol) VALUES (?)", symbol)
            stock_lookup = db.execute(
                "SELECT stock_id FROM stocks WHERE stock_symbol = ?", symbol
            )

        stock_id = int(stock_lookup[0]["stock_id"])
        # add it into stock ownership of this user if they don't have it already
        # if owner does not have it:
        ownership_lookup = db.execute(
            "SELECT stock_id FROM ownership WHERE stock_id = ? AND user_id = ?",
            stock_id,
            user_id,
        )
        if not ownership_lookup:
            db.execute(
                "INSERT INTO ownership (user_id, stock_id, quantity) VALUES (?,?,?)",
                user_id,
                stock_id,
                shares,
            )
        # if they do have it, update the amount
        else:
            db.execute(
                "UPDATE ownership SET quantity = quantity + ? WHERE user_id = ? AND stock_id = ?",
                shares,
                user_id,
                stock_id,
            )
        # minus the owner's cash
        updated_cash = user_cash - price_per_share * shares
        db.execute("UPDATE users SET cash = ? WHERE id = ?", updated_cash, user_id)
        # add this transaction into history
        db.execute(
        "INSERT INTO transactions (user_id, stock_id, quantity, price) VALUES (?,?,?,?)",
        user_id,
        stock_id,
        shares,
        usd(stock_info["price"]),
    )
        flash('Bought')
        return redirect("/")
    # route via get
    else:
        return render_template("buy.html")


'''@app.route("/test")
def test():
    user_id = int(session["user_id"])
    test = db.execute(
        "SELECT * FROM ownership JOIN stocks ON ownership.stock_id = stocks.stock_id WHERE user_id = ?",
        user_id,
    )

    return render_template("test.html", test=test)'''


@app.route("/history")
@login_required
def history():
    user_id = int(session["user_id"])
    histories = db.execute(
        "SELECT * FROM transactions JOIN stocks ON transactions.stock_id = stocks.stock_id WHERE user_id = ?",
        user_id,
    )
    return render_template("history.html", histories=histories)


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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
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
    if request.method == "POST":
        symbol = request.form.get("quote")
        if not symbol:
            return apology("Need to enter stock symbol")
        else:
            stock_info = lookup(symbol)
            if not stock_info:
                return apology("invlaid symbol")
            else:
                return render_template(
                    "quoted.html",
                    company_name=stock_info["name"],
                    company_symbol=stock_info["symbol"],
                    price_per_share=usd(stock_info["price"]),
                )
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect("/")

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        existing_user = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )
        if not request.form.get("username"):
            return apology("must provide username", 403)
        elif not password:
            return apology("must provide password", 403)
        elif not request.form.get("confirmPassword"):
            return apology("must re-enter password", 403)
        elif existing_user:
            return apology(
                "this username already exist, please choose another", 403
            )
        elif request.form.get("confirmPassword") != request.form.get("password"):
            return apology("passwords words must match", 403)
        elif (
            len(password) < 8
            or not any(char.isupper() for char in password)
            or not any(char.islower() for char in password)
            or not any(char.isdigit() for char in password)
            or not any(char in string.punctuation for char in password)
        ):
            return apology(
                "Passwords must be 8 to 16 digits long, containing at least 1 upper case letter and 1 lower case letter, one numeric digit, and one special character (example: @$!%*?&)",
                403,
            )

        else:
            db.execute(
                "INSERT INTO users (username, hash) VALUES (?, ?)",
                username,
                generate_password_hash(password),
            )
            user = db.execute("SELECT id FROM users WHERE username = ?", username)
            session["user_id"] = user[0]["id"]
            flash("Registered!")
            return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    def validate_input(stock_entered, shares_str, stocks_owned_info):
        if not stock_entered:
            return apology("must enter stock symbol")
        elif stock_entered not in stocks_owned:
            return apology("can not sell stocks that you do not own")
        elif not shares_str:
            return apology("please enter number of shares")
        elif not shares_str.isdigit():
            return apology("shares need to be a number")
        elif not float(shares_str) == int(shares_str):
            return apology("shares need to be a positive integer")
        shares_entered = int(shares_str)
        if shares_entered <= 0:
            return apology("minimum 1 share")
        shares_owned = 0

        for stock_info in stocks_owned_info:
            if stock_info["stock_symbol"] == stock_entered:
                shares_owned = int(stock_info["quantity"])
                if shares_entered > shares_owned:
                    return apology(f"do not own enough shares of {stock_entered}")

    user_id = int(session["user_id"])
    stocks_owned = []
    stocks_owned_info = db.execute(
        "SELECT * FROM ownership JOIN stocks ON ownership.stock_id = stocks.stock_id WHERE user_id = ?",
        user_id,
    )
    for stock in stocks_owned_info:
        stocks_owned.append(stock["stock_symbol"])
    if request.method == "POST":
        stock_entered = request.form.get("stocks_selected")
        shares_str = request.form.get("shares")
        validation_result = validate_input(stock_entered, shares_str, stocks_owned_info)
        if validation_result is not None:
            return validation_result

        user_cash = float(db.execute(
            "SELECT cash FROM users WHERE id = ?", (session["user_id"])
        )[0]["cash"])

        stock_id = int(db.execute(
            "SELECT stock_id FROM stocks WHERE stock_symbol = ?", stock_entered
        )[0]["stock_id"])
        shares = int(shares_str)
        stock_info = lookup(stock_entered)
        price_per_share = float(stock_info["price"])
        #update ownerships number of shares
        db.execute(
                "UPDATE ownership SET quantity = quantity - ? WHERE user_id = ? AND stock_id = ?",
                shares,
                user_id,
                stock_id,
            )
        # update the owner's cash
        updated_cash = user_cash + price_per_share * shares
        db.execute("UPDATE users SET cash = ? WHERE id = ?", updated_cash, user_id)
        # add this transaction into history
        db.execute(
        "INSERT INTO transactions (user_id, stock_id, quantity, price) VALUES (?,?,?,?)",
        user_id,
        stock_id,
        -shares,
        usd(stock_info["price"]),
    )
        flash('Sold')
        return redirect("/")
    else:
        return render_template("sell.html", stocks_owned=stocks_owned)
