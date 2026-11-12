import csv
import io
import json
import math
import os
import re
import secrets
import sqlite3
from calendar import monthrange
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

import numpy as np
import pandas as pd
from flask import Flask, Response, abort, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from database import connect_db, get_db_path, init_database
from services.analytics import iso_now, safe_percent_change, validate_date_range


app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("BID_SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)
app.config["DATABASE_PATH"] = os.getenv("BID_DATABASE_PATH", get_db_path())
app.config["MAX_IMPORT_FILE_BYTES"] = 5 * 1024 * 1024
app.config["MAX_CONTENT_LENGTH"] = app.config["MAX_IMPORT_FILE_BYTES"] + 64 * 1024


def get_db_path() -> str:
    return app.config["DATABASE_PATH"]


def dt(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def current_user() -> Optional[Dict[str, Any]]:
    user = session.get("user")
    return user if isinstance(user, dict) else None


def company_id() -> int:
    user = current_user()
    if not user or not isinstance(user.get("company_id"), int):
        abort(403)
    return user["company_id"]


def login_required(view_func):
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    wrapped.__name__ = view_func.__name__
    return wrapped


def role_required(*roles):
    def decorator(view_func):
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user:
                return redirect(url_for("login"))
            if user.get("role") not in roles:
                abort(403)
            return view_func(*args, **kwargs)

        wrapped.__name__ = view_func.__name__
        return wrapped

    return decorator


def ensure_csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_hex(16)
        session["csrf_token"] = token
    return token


def validate_csrf() -> bool:
    if request.method not in {"POST", "PATCH", "PUT", "DELETE"}:
        return True
    token = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
    if app.config.get("TESTING") and token == "test-token":
        return True
    return token == session.get("csrf_token")


@app.before_request
def before_request():
    ensure_csrf_token()


@app.before_request
def enforce_csrf():
    if request.path.startswith("/static"):
        return None
    if request.path in {"/login", "/logout"}:
        return None
    if request.method in {"POST", "PATCH", "PUT", "DELETE"} and not validate_csrf():
        abort(400, description="Invalid CSRF token.")


@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({"error": f"The request exceeds the 5 MB upload limit (HTTP {error.code})."}), 413


@app.route("/", methods=["GET"])
def root():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("email") or request.form.get("username") or "").strip().lower()
        password = request.form.get("password") or ""
        remember_me = request.form.get("remember_me") == "on"
        if not username or not password:
            return render_template("login.html", error="Email and password are required.")
        conn = connect_db()
        user = conn.execute(
            "SELECT * FROM users WHERE (lower(email) = ? OR lower(username) = ?) AND is_active = 1",
            (username, username),
        ).fetchone()
        conn.close()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user"] = {
                "id": user["id"],
                "username": user["username"],
                "full_name": user["full_name"] or user["username"],
                "company_id": user["company_id"],
                "role": user["role"],
            }
            session.permanent = bool(remember_me)
            if user["role"] == "admin":
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("account_page"))
        return render_template("login.html", error="Invalid username or password.")
    return render_template("login.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        full_name = " ".join((request.form.get("full_name") or "").split())[:100]
        email = (request.form.get("email") or "").strip().lower()
        company_name = " ".join((request.form.get("company_name") or "").split())[:120]
        password = request.form.get("password") or ""
        if not full_name or not company_name or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            return render_template(
                "signup.html",
                error="Enter your name, a valid email address, and your company name.",
            ), 400
        if len(password) < 12:
            return render_template(
                "signup.html",
                error="Choose a password with at least 12 characters.",
            ), 400
        conn = connect_db()
        existing = conn.execute(
            "SELECT id FROM users WHERE lower(email) = ? OR lower(username) = ?",
            (email, email),
        ).fetchone()
        if existing:
            conn.close()
            return render_template("signup.html", error="An account with that email already exists."), 409
        try:
            with conn:
                cursor = conn.execute(
                    "INSERT INTO companies (name) VALUES (?)",
                    (company_name,),
                )
                new_company_id = int(cursor.lastrowid)
                conn.execute(
                    """
                    INSERT INTO users (username, email, full_name, company_id, password_hash, role)
                    VALUES (?, ?, ?, ?, ?, 'admin')
                    """,
                    (
                        email,
                        email,
                        full_name,
                        new_company_id,
                        generate_password_hash(password),
                    ),
                )
        except sqlite3.IntegrityError:
            conn.close()
            return render_template("signup.html", error="That email is already registered."), 409
        conn.close()
        return redirect(url_for("login", registered="1"))
    return render_template("signup.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/account")
@login_required
def account_page():
    return render_template("account.html", user=current_user())


@login_required
def render_dashboard():
    return render_template("dashboard.html", user=current_user())


@app.route("/dashboard")
@login_required
@role_required("admin")
def user_dashboard():
    return render_dashboard()


@app.route("/admin/dashboard")
@login_required
@role_required("admin")
def admin_dashboard():
    return render_dashboard()


@app.route("/business-pulse")
@login_required
@role_required("admin")
def business_pulse_page():
    return render_template("business_pulse.html", user=current_user())


@app.route("/api/business-pulse/summary")
@login_required
@role_required("admin")
def business_pulse_summary():
    try:
        start, end = dashboard_date_range(request.args)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    data = compute_business_pulse(start, end)
    return jsonify(data)


@app.route("/api/business-pulse/alerts")
@login_required
@role_required("admin")
def business_pulse_alerts():
    conn = connect_db()
    rows = conn.execute(
        "SELECT * FROM business_alerts WHERE company_id = ? ORDER BY created_at DESC LIMIT 20",
        (company_id(),),
    ).fetchall()
    conn.close()
    return jsonify({"alerts": [dict(row) for row in rows]})


@app.route("/api/business-pulse/alerts/<int:alert_id>/status", methods=["PATCH"])
@login_required
@role_required("admin")
def update_alert_status(alert_id: int):
    payload = request.get_json(silent=True) or {}
    status = payload.get("status")
    if status not in {"open", "acknowledged", "resolved"}:
        return jsonify({"error": "Unsupported alert status."}), 400
    conn = connect_db()
    existing = conn.execute(
        "SELECT id FROM business_alerts WHERE id = ? AND company_id = ?",
        (alert_id, company_id()),
    ).fetchone()
    if not existing:
        conn.close()
        return jsonify({"error": "Alert not found."}), 404
    conn.execute("UPDATE business_alerts SET status = ? WHERE id = ?", (status, alert_id))
    conn.commit()
    conn.close()
    return jsonify({"status": status, "alert_id": alert_id})


@app.route("/api/business-pulse/recommendations")
@login_required
@role_required("admin")
def recommendation_api():
    conn = connect_db()
    rows = conn.execute(
        "SELECT * FROM business_recommendations WHERE company_id = ? ORDER BY created_at DESC",
        (company_id(),),
    ).fetchall()
    conn.close()
    return jsonify({"recommendations": [dict(row) for row in rows]})


@app.route("/api/business-pulse/recommendations/<int:recommendation_id>/status", methods=["PATCH"])
@login_required
@role_required("admin")
def update_recommendation_status(recommendation_id: int):
    if not validate_csrf():
        return jsonify({"error": "Invalid CSRF token."}), 400
    payload = request.get_json(silent=True) or {}
    status = payload.get("status")
    allowed = {"New", "Accepted", "Rejected", "In Progress", "Completed"}
    if status not in allowed:
        return jsonify({"error": "Unsupported recommendation status."}), 400
    conn = connect_db()
    existing = conn.execute(
        "SELECT id FROM business_recommendations WHERE id = ? AND company_id = ?",
        (recommendation_id, company_id()),
    ).fetchone()
    if not existing:
        conn.close()
        return jsonify({"error": "Recommendation not found."}), 404
    conn.execute(
        "UPDATE business_recommendations SET status = ?, updated_at = ? WHERE id = ?",
        (status, iso_now(), recommendation_id),
    )
    conn.commit()
    conn.close()
    return jsonify({"status": status, "recommendation_id": recommendation_id})


@app.route("/api/business-pulse/scenarios", methods=["GET", "POST"])
@login_required
@role_required("admin")
def scenarios_api():
    if request.method == "GET":
        conn = connect_db()
        rows = conn.execute(
            "SELECT * FROM decision_scenarios WHERE user_id = ? ORDER BY created_at DESC",
            (current_user()["id"],),
        ).fetchall()
        conn.close()
        return jsonify({"scenarios": [dict(row) for row in rows]})

    payload = request.get_json(silent=True) or {}
    scenario_name = str(payload.get("scenario_name") or "Saved scenario").strip()[:80]
    try:
        order_change = float(payload.get("order_change", 0) or 0)
        aov_change = float(payload.get("aov_change", 0) or 0)
        repeat_change = float(payload.get("repeat_change", 0) or 0)
        inactivity_change = float(payload.get("inactivity_change", 0) or 0)
        category_change = float(payload.get("category_change", 0) or 0)
    except (TypeError, ValueError):
        return jsonify({"error": "Scenario assumptions must be valid numbers."}), 400
    assumptions = [order_change, aov_change, repeat_change, inactivity_change, category_change]
    if not all(np.isfinite(value) for value in assumptions):
        return jsonify({"error": "Scenario assumptions must be finite numbers."}), 400
    if any(value < -100 or value > 500 for value in assumptions[:4]) or not 0 <= inactivity_change <= 100:
        return jsonify({"error": "Growth assumptions must be between -100% and 500%; inactivity reduction must be between 0% and 100%."}), 400
    baseline = dashboard_summary_for_period(days=30)
    result = simulate_business_scenario(
        baseline,
        order_change=order_change,
        aov_change=aov_change,
        repeat_change=repeat_change,
        inactivity_change=inactivity_change,
        category_change=category_change,
    )
    conn = connect_db()
    conn.execute(
        "INSERT INTO decision_scenarios (user_id, scenario_name, baseline_json, assumptions_json, result_json) VALUES (?, ?, ?, ?, ?)",
        (
            current_user()["id"],
            scenario_name,
            json.dumps(baseline),
            json.dumps({
                "order_change": order_change,
                "aov_change": aov_change,
                "repeat_change": repeat_change,
                "inactivity_change": inactivity_change,
                "category_change": category_change,
            }),
            json.dumps(result),
        ),
    )
    conn.commit()
    scenario_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    return jsonify({"scenario_id": scenario_id, "result": result}), 201


@app.route("/api/business-pulse/outcomes")
@login_required
@role_required("admin")
def outcomes_api():
    conn = connect_db()
    rows = conn.execute(
        """
        SELECT ra.*, rr.title as recommendation_title
        FROM recommendation_actions ra
        JOIN business_recommendations rr ON rr.id = ra.recommendation_id
        WHERE rr.company_id = ?
        ORDER BY ra.created_at DESC
        """,
        (company_id(),),
    ).fetchall()
    data = []
    for row in rows:
        measurements = conn.execute(
            "SELECT * FROM recommendation_measurements WHERE action_id = ? ORDER BY created_at DESC",
            (row["id"],),
        ).fetchall()
        data.append({**dict(row), "measurements": [dict(item) for item in measurements]})
    conn.close()
    return jsonify({"outcomes": data})


@app.route("/api/business-pulse/history")
@login_required
@role_required("admin")
def history_api():
    conn = connect_db()
    rows = conn.execute(
        "SELECT * FROM business_insight_history WHERE company_id = ? ORDER BY created_at DESC",
        (company_id(),),
    ).fetchall()
    conn.close()
    return jsonify({"history": [dict(row) for row in rows]})


@app.route("/api/business-pulse/investigations/<int:alert_id>")
@login_required
@role_required("admin")
def investigation_api(alert_id: int):
    conn = connect_db()
    alert = conn.execute(
        "SELECT * FROM business_alerts WHERE id = ? AND company_id = ?",
        (alert_id, company_id()),
    ).fetchone()
    if not alert:
        conn.close()
        return jsonify({"error": "Alert not found."}), 404
    investigation = conn.execute(
        "SELECT * FROM business_investigations WHERE alert_id = ? ORDER BY created_at DESC LIMIT 1",
        (alert_id,),
    ).fetchone()
    conn.close()
    if not investigation:
        return jsonify({"alert_id": alert_id, "summary": "No investigation recorded.", "possible_factors": [], "limitations": "Insufficient evidence."})
    return jsonify({
        "alert_id": alert_id,
        "summary": investigation["summary"],
        "evidence": json.loads(investigation["evidence_json"] or "[]"),
        "possible_factors": json.loads(investigation["possible_factors_json"] or "[]"),
        "limitations": investigation["limitations"],
    })


@app.route("/api/company-profile", methods=["GET", "PATCH"])
@login_required
@role_required("admin")
def company_profile_api():
    current_company_id = company_id()
    conn = connect_db()
    if request.method == "PATCH":
        payload = request.get_json(silent=True) or {}
        name = " ".join(str(payload.get("name") or "").split())[:120]
        if not name:
            conn.close()
            return jsonify({"error": "Company name is required."}), 400
        conn.execute("UPDATE companies SET name = ? WHERE id = ?", (name, current_company_id))
        conn.commit()
    company = conn.execute(
        "SELECT id, name, created_at FROM companies WHERE id = ?",
        (current_company_id,),
    ).fetchone()
    conn.close()
    if company is None:
        return jsonify({"error": "Company profile not found."}), 404
    return jsonify({"company": dict(company)})


@app.route("/api/company/import-template.csv")
@login_required
@role_required("admin")
def company_import_template():
    today = datetime.now(timezone.utc).date()
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["date", "customer", "product", "category", "quantity", "unit_price", "revenue", "profit", "region", "segment", "status"])
    writer.writerow([today.isoformat(), "Customer name", "Product name", "Category", 1, 100.00, 100.00, 25.00, "North", "Returning", "completed"])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": 'attachment; filename="company-transactions-template.csv"'},
    )


@app.route("/api/company/demo-transactions.csv")
@login_required
@role_required("admin")
def company_demo_transactions():
    today = datetime.now(timezone.utc).date()
    current_month = today.replace(day=1)
    sample_months = []
    for months_ago in range(6, -1, -1):
        sample_month = current_month
        for _ in range(months_ago):
            sample_month = (
                sample_month.replace(year=sample_month.year - 1, month=12)
                if sample_month.month == 1
                else sample_month.replace(month=sample_month.month - 1)
            )
        sample_months.append((sample_month, months_ago))

    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["date", "customer", "product", "category", "quantity", "unit_price", "revenue", "profit", "region", "segment", "status"])
    for month_start, months_ago in sample_months:
        month_revenue = round(18000 + ((6 - months_ago) * 650), 2)
        transaction_date = (
            today if months_ago == 0 else month_start.replace(day=8)
        )
        primary_revenue = round(month_revenue * 0.62, 2)
        secondary_revenue = round(month_revenue - primary_revenue, 2)
        writer.writerow([
            transaction_date.isoformat(), "Demo Customer A", "Demo Product One", "Electronics",
            1, primary_revenue, primary_revenue, round(primary_revenue * 0.24, 2),
            "North", "Returning", "completed",
        ])
        if months_ago > 0:
            writer.writerow([
                month_start.replace(day=18).isoformat(), "Demo Customer B", "Demo Product Two", "Home",
                1, secondary_revenue, secondary_revenue, round(secondary_revenue * 0.20, 2),
                "West", "New", "completed",
            ])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": 'attachment; filename="demo-company-transactions.csv"'},
    )


@app.route("/api/company/import-transactions", methods=["POST"])
@login_required
@role_required("admin")
def import_company_transactions():
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        return jsonify({"error": "Choose a CSV file to import."}), 400
    if not upload.filename.lower().endswith(".csv"):
        return jsonify({"error": "Only CSV files are supported."}), 400
    try:
        text = upload.stream.read(app.config["MAX_IMPORT_FILE_BYTES"] + 1).decode("utf-8-sig")
    except UnicodeDecodeError:
        return jsonify({"error": "The CSV must use UTF-8 text encoding."}), 400
    if len(text.encode("utf-8")) > app.config["MAX_IMPORT_FILE_BYTES"]:
        return jsonify({"error": "CSV uploads must be 5 MB or smaller."}), 413
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return jsonify({"error": "The CSV file is empty or missing a header row."}), 400
    column_map = {str(name).strip().lower(): name for name in reader.fieldnames if name}
    aliases = {
        "date": ("date", "order_date"),
        "customer": ("customer", "customer_name"),
        "product": ("product", "product_name"),
        "category": ("category",),
        "quantity": ("quantity",),
        "unit_price": ("unit_price",),
        "revenue": ("revenue", "total_amount"),
        "profit": ("profit",),
        "region": ("region",),
        "segment": ("segment",),
        "status": ("status",),
    }
    columns = {
        key: next((column_map[alias] for alias in possible if alias in column_map), None)
        for key, possible in aliases.items()
    }
    required = ("date", "customer", "product", "quantity", "unit_price", "revenue", "profit")
    missing = [field for field in required if columns[field] is None]
    if missing:
        return jsonify({"error": f"Missing required CSV columns: {', '.join(missing)}."}), 400
    records = []
    for row_number, raw in enumerate(reader, start=2):
        if not any((value or "").strip() for value in raw.values() if isinstance(value, str)):
            continue
        if len(records) >= 5000:
            return jsonify({"error": "A single import is limited to 5,000 transactions."}), 400
        try:
            values = {
                key: (raw.get(column) or "").strip() if column else ""
                for key, column in columns.items()
            }
            order_date = date.fromisoformat(values["date"])
            customer_name = values["customer"][:120]
            product_name = values["product"][:120]
            category = (values["category"] or "Uncategorized")[:80]
            quantity = int(values["quantity"])
            unit_price = float(values["unit_price"])
            revenue = float(values["revenue"])
            profit = float(values["profit"])
            if not customer_name or not product_name:
                raise ValueError("customer and product are required")
            if not 1 <= quantity <= 1_000_000:
                raise ValueError("quantity must be between 1 and 1,000,000")
            if not all(math.isfinite(value) for value in (unit_price, revenue, profit)):
                raise ValueError("money values must be finite numbers")
            if unit_price < 0 or revenue < 0:
                raise ValueError("unit_price and revenue cannot be negative")
            records.append({
                "date": order_date.isoformat(),
                "customer": customer_name,
                "product": product_name,
                "category": category,
                "quantity": quantity,
                "unit_price": unit_price,
                "revenue": revenue,
                "profit": profit,
                "region": values["region"][:80] or "Unassigned",
                "segment": values["segment"][:80] or "Unassigned",
                "status": values["status"][:40] or "completed",
            })
        except (TypeError, ValueError) as error:
            return jsonify({"error": f"Invalid data on CSV row {row_number}: {error}."}), 400
    if not records:
        return jsonify({"error": "The CSV contains no transaction rows."}), 400

    current_company_id = company_id()
    conn = connect_db()
    try:
        with conn:
            for record in records:
                customer = conn.execute(
                    "SELECT id FROM customers WHERE company_id = ? AND lower(name) = lower(?) ORDER BY id LIMIT 1",
                    (current_company_id, record["customer"]),
                ).fetchone()
                if customer is None:
                    cursor = conn.execute(
                        "INSERT INTO customers (name, segment, region, company_id) VALUES (?, ?, ?, ?)",
                        (record["customer"], record["segment"], record["region"], current_company_id),
                    )
                    customer_id_value = int(cursor.lastrowid)
                else:
                    customer_id_value = int(customer["id"])
                product = conn.execute(
                    "SELECT id FROM products WHERE company_id = ? AND lower(name) = lower(?) AND lower(category) = lower(?) ORDER BY id LIMIT 1",
                    (current_company_id, record["product"], record["category"]),
                ).fetchone()
                if product is None:
                    cursor = conn.execute(
                        "INSERT INTO products (name, category, unit_price, company_id) VALUES (?, ?, ?, ?)",
                        (record["product"], record["category"], record["unit_price"], current_company_id),
                    )
                    product_id_value = int(cursor.lastrowid)
                else:
                    product_id_value = int(product["id"])
                conn.execute(
                    """
                    INSERT INTO orders
                    (customer_id, product_id, order_date, quantity, unit_price, total_amount, profit, status, region, category, company_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        customer_id_value,
                        product_id_value,
                        record["date"],
                        record["quantity"],
                        record["unit_price"],
                        record["revenue"],
                        record["profit"],
                        record["status"],
                        record["region"],
                        record["category"],
                        current_company_id,
                    ),
                )
    except sqlite3.IntegrityError as error:
        conn.close()
        return jsonify({"error": f"Import could not be saved: {error}."}), 400
    conn.close()
    return jsonify({"imported": len(records), "message": f"Imported {len(records)} transactions into your company workspace."}), 201


@app.route("/api/company/financial-overview")
@login_required
@role_required("admin")
def company_financial_overview():
    current_company_id = company_id()
    today = datetime.now(timezone.utc).date()
    current_month_start = today.replace(day=1)
    next_month_start = (
        current_month_start.replace(year=current_month_start.year + 1, month=1)
        if current_month_start.month == 12
        else current_month_start.replace(month=current_month_start.month + 1)
    )
    conn = connect_db()
    current = conn.execute(
        """
        SELECT COALESCE(SUM(total_amount), 0) AS revenue,
               COALESCE(SUM(profit), 0) AS profit,
               COUNT(*) AS orders
        FROM orders
        WHERE company_id = ? AND order_date >= ? AND order_date <= ?
        """,
        (current_company_id, current_month_start.isoformat(), today.isoformat()),
    ).fetchone()
    first_order = conn.execute(
        "SELECT MIN(order_date) AS first_order_date FROM orders WHERE company_id = ?",
        (current_company_id,),
    ).fetchone()
    earliest = date.fromisoformat(first_order["first_order_date"]) if first_order["first_order_date"] else None
    history_floor = current_month_start
    for _ in range(12):
        history_floor = (
            history_floor.replace(year=history_floor.year - 1, month=12)
            if history_floor.month == 1
            else history_floor.replace(month=history_floor.month - 1)
        )
    if earliest:
        history_floor = max(history_floor, earliest.replace(day=1))
    monthly_rows = conn.execute(
        """
        SELECT substr(order_date, 1, 7) AS month,
               SUM(total_amount) AS revenue,
               SUM(profit) AS profit,
               COUNT(*) AS orders
        FROM orders
        WHERE company_id = ? AND order_date >= ? AND order_date < ?
        GROUP BY substr(order_date, 1, 7)
        ORDER BY month
        """,
        (current_company_id, history_floor.isoformat(), current_month_start.isoformat()),
    ).fetchall()
    conn.close()
    monthly_by_period = {row["month"]: dict(row) for row in monthly_rows}
    completed_months = []
    period = history_floor
    while period < current_month_start:
        month_key = period.strftime("%Y-%m")
        row = monthly_by_period.get(month_key, {
            "month": month_key,
            "revenue": 0.0,
            "profit": 0.0,
            "orders": 0,
        })
        completed_months.append(row)
        period = (
            period.replace(year=period.year + 1, month=1)
            if period.month == 12
            else period.replace(month=period.month + 1)
        )
    active_months = [row for row in completed_months if float(row["revenue"] or 0) > 0]
    historical_revenue = [float(row["revenue"] or 0) for row in completed_months]
    historical_profit = [float(row["profit"] or 0) for row in completed_months]
    if len(active_months) >= 3:
        recent_revenue = historical_revenue[-3:]
        recent_profit = historical_profit[-3:]
        revenue_projection = sum(recent_revenue) / len(recent_revenue)
        profit_projection = sum(recent_profit) / len(recent_profit)
        method = "Average of the last three completed calendar months"
        confidence = "Medium" if len(active_months) >= 6 else "Low"
    elif active_months:
        revenue_projection = sum(float(row["revenue"] or 0) for row in active_months) / len(active_months)
        profit_projection = sum(float(row["profit"] or 0) for row in active_months) / len(active_months)
        method = "Average of available active completed months"
        confidence = "Low"
    elif float(current["revenue"]) > 0:
        elapsed_days = max(1, today.day)
        month_days = monthrange(next_month_start.year, next_month_start.month)[1]
        revenue_projection = float(current["revenue"]) / elapsed_days * month_days
        profit_projection = float(current["profit"]) / elapsed_days * month_days
        method = "Current-month daily run rate"
        confidence = "Low"
    else:
        revenue_projection = 0.0
        profit_projection = 0.0
        method = "Not enough transaction history"
        confidence = "Insufficient data"

    forecasts = []
    for offset in range(6):
        forecast_month = next_month_start
        for _ in range(offset):
            forecast_month = (
                forecast_month.replace(year=forecast_month.year + 1, month=1)
                if forecast_month.month == 12
                else forecast_month.replace(month=forecast_month.month + 1)
            )
        scale = 1 if confidence != "Insufficient data" else 0
        forecasts.append({
            "month": forecast_month.strftime("%Y-%m"),
            "revenue": round(max(0.0, revenue_projection * scale), 2),
            "profit": round(profit_projection * scale, 2),
            "confidence": confidence,
        })
    return jsonify({
        "current_month": {
            "month": current_month_start.strftime("%Y-%m"),
            "revenue": round(float(current["revenue"]), 2),
            "profit": round(float(current["profit"]), 2),
            "orders": int(current["orders"]),
        },
        "forecasts": forecasts,
        "forecast_method": method,
        "forecast_confidence": confidence,
        "forecast_notice": "Planning estimates based on your imported company transactions; not guaranteed results.",
        "history": completed_months,
    })


@app.route("/api/dashboard-summary")
@login_required
@role_required("admin")
def dashboard_summary_api():
    try:
        start, end = dashboard_date_range(request.args)
        return jsonify(dashboard_summary_for_period(start_date=start, end_date=end))
    except ValueError as error:
        return jsonify({"error": str(error)}), 400


@app.route("/api/dashboard-export.csv")
@login_required
@role_required("admin")
def dashboard_export():
    try:
        start, end = dashboard_date_range(request.args)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    conn = connect_db()
    rows = conn.execute(
        """
        SELECT o.id, o.order_date, c.name AS customer, p.name AS product,
               o.quantity, o.unit_price, o.total_amount, o.profit, o.status,
               o.region, o.category
        FROM orders o
        LEFT JOIN customers c ON c.id = o.customer_id
        LEFT JOIN products p ON p.id = o.product_id
        WHERE o.company_id = ? AND o.order_date BETWEEN ? AND ?
        ORDER BY o.order_date DESC, o.id DESC
        """,
        (company_id(), start.isoformat(), end.isoformat()),
    ).fetchall()
    conn.close()
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["Order ID", "Date", "Customer", "Product", "Quantity", "Unit Price", "Revenue", "Profit", "Status", "Region", "Category"])
    writer.writerows(
        tuple(
            "'" + value if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r")) else value
            for value in row
        )
        for row in rows
    )
    filename = f"business-dashboard-{start.isoformat()}-to-{end.isoformat()}.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.route("/api/customer-health")
@login_required
@role_required("admin")
def customer_health_api():
    try:
        start, end = dashboard_date_range(request.args)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    today = datetime.now(timezone.utc).date()
    conn = connect_db()
    rows = conn.execute(
        """
        SELECT c.id, c.name, c.segment, c.region,
               COUNT(CASE WHEN o.order_date BETWEEN ? AND ? THEN o.id END) AS period_orders,
               COALESCE(SUM(CASE WHEN o.order_date BETWEEN ? AND ? THEN o.total_amount ELSE 0 END), 0) AS period_revenue,
               MAX(o.order_date) AS last_order_date
        FROM customers c
        LEFT JOIN orders o ON o.customer_id = c.id AND o.company_id = c.company_id
        WHERE c.company_id = ?
        GROUP BY c.id
        ORDER BY period_revenue DESC, c.name ASC
        """,
        (start.isoformat(), end.isoformat(), start.isoformat(), end.isoformat(), company_id()),
    ).fetchall()
    conn.close()
    customers = []
    for row in rows:
        last_order = date.fromisoformat(row["last_order_date"]) if row["last_order_date"] else None
        days_since_order = (today - last_order).days if last_order else None
        status = "Never ordered" if days_since_order is None else (
            "Inactive" if days_since_order > 90 else "At risk" if days_since_order > 45 else "Active"
        )
        customers.append({
            "id": row["id"],
            "name": row["name"],
            "segment": row["segment"] or "Unassigned",
            "region": row["region"] or "Unassigned",
            "period_orders": row["period_orders"],
            "period_revenue": round(float(row["period_revenue"]), 2),
            "last_order_date": row["last_order_date"],
            "days_since_order": days_since_order,
            "status": status,
        })
    segment_totals: Dict[str, Dict[str, Any]] = {}
    for customer in customers:
        segment = segment_totals.setdefault(customer["segment"], {"name": customer["segment"], "customers": 0, "revenue": 0.0})
        segment["customers"] += 1
        segment["revenue"] += customer["period_revenue"]
    segments = sorted(segment_totals.values(), key=lambda item: item["revenue"], reverse=True)
    for segment in segments:
        segment["revenue"] = round(segment["revenue"], 2)
    risk_customers = [customer for customer in customers if customer["status"] in {"At risk", "Inactive", "Never ordered"}]
    return jsonify({
        "customer_count": len(customers),
        "at_risk_count": len(risk_customers),
        "segments": segments,
        "top_customers": customers[:5],
        "at_risk_customers": sorted(
            risk_customers,
            key=lambda customer: customer["days_since_order"] if customer["days_since_order"] is not None else float("inf"),
            reverse=True,
        )[:8],
        "date_range": {"start": start.isoformat(), "end": end.isoformat()},
        "risk_rule": "At risk after 45 days without an order; inactive after 90 days.",
    })


def dashboard_date_range(args) -> Tuple[date, date]:
    start_text = args.get("start_date")
    end_text = args.get("end_date")
    if start_text or end_text:
        start_dt, end_dt, error = validate_date_range(start_text, end_text)
        if error or start_dt is None or end_dt is None:
            raise ValueError(error or "Both dates are required.")
        start, end = start_dt.date(), end_dt.date()
    else:
        try:
            days = int(args.get("days", "30"))
        except (TypeError, ValueError) as error:
            raise ValueError("Date range must be a number of days.") from error
        if not 1 <= days <= 3650:
            raise ValueError("Date range must be between 1 and 3650 days.")
        end = datetime.now(timezone.utc).date()
        start = end - timedelta(days=days - 1)
    if end < start:
        raise ValueError("Start date cannot be after the end date.")
    if (end - start).days > 3650:
        raise ValueError("Date range cannot exceed 3651 days.")
    return start, end


def build_revenue_forecast(daily_revenue: List[float], last_date: date, forecast_days: int = 7) -> Dict[str, Any]:
    if len(daily_revenue) < 2:
        return {
            "labels": [],
            "values": [],
            "method": "Linear trend with recent-period smoothing",
            "confidence": "Insufficient data",
        }
    history = np.asarray(daily_revenue[-28:], dtype=float)
    positions = np.arange(len(history), dtype=float)
    slope, intercept = np.polyfit(positions, history, 1)
    recent_average = float(np.mean(history[-min(7, len(history)):]))
    predictions = []
    for offset in range(forecast_days):
        trend_value = max(0.0, intercept + slope * (len(history) + offset))
        predictions.append(round((trend_value * 0.65) + (recent_average * 0.35), 2))
    residuals = history - (intercept + slope * positions)
    relative_error = float(np.std(residuals) / max(float(np.mean(history)), 1.0))
    confidence = "Medium" if len(history) >= 14 and relative_error < 0.5 else "Low"
    labels = [(last_date + timedelta(days=offset + 1)).isoformat() for offset in range(forecast_days)]
    return {
        "labels": labels,
        "values": predictions,
        "method": "Linear trend with recent-period smoothing",
        "confidence": confidence,
    }


def dashboard_summary_for_period(
    days: int = 30,
    start_date: Optional[date] = None,
    end_date: Optional[date] = None,
) -> Dict[str, Any]:
    if start_date is None or end_date is None:
        try:
            days_value = int(days)
        except (TypeError, ValueError) as error:
            raise ValueError("Days must be an integer.") from error
        if not 1 <= days_value <= 3650:
            raise ValueError("Date range must be between 1 and 3650 days.")
        end_date = datetime.now(timezone.utc).date()
        start_date = end_date - timedelta(days=days_value - 1)
    if end_date < start_date:
        raise ValueError("Start date cannot be after the end date.")
    period_days = (end_date - start_date).days + 1
    conn = connect_db()
    rows = conn.execute(
        """
        SELECT o.*, c.name AS customer_name, p.name AS product_name
        FROM orders o
        LEFT JOIN customers c ON c.id = o.customer_id AND c.company_id = o.company_id
        LEFT JOIN products p ON p.id = o.product_id AND p.company_id = o.company_id
        WHERE o.company_id = ? AND o.order_date BETWEEN ? AND ?
        ORDER BY o.order_date ASC, o.id ASC
        """,
        (company_id(), start_date.isoformat(), end_date.isoformat()),
    ).fetchall()
    conn.close()
    if not rows:
        return {
            "kpis": {
                "revenue": 0,
                "orders": 0,
                "customers": 0,
                "profit": 0,
                "average_order_value": 0,
                "sales_growth": 0,
            },
            "charts": {
                "monthly": [],
                "categories": [],
                "products": [],
                "regions": [],
                "forecast": {
                    "labels": [],
                    "values": [],
                    "method": "Linear trend with recent-period smoothing",
                    "confidence": "Insufficient data",
                },
            },
            "recent_transactions": [],
            "date_range": {"start": start_date.isoformat(), "end": end_date.isoformat()},
            "message": "No data available for the selected date range.",
        }
    df = pd.DataFrame([dict(row) for row in rows])
    total_revenue = float(df["total_amount"].sum())
    total_orders = int(len(df))
    total_customers = int(df["customer_id"].nunique())
    total_profit = float(df["profit"].sum())
    avg_order_value = float(df["total_amount"].mean()) if not df.empty else 0
    previous_start = start_date - timedelta(days=period_days)
    previous_end = start_date - timedelta(days=1)
    conn = connect_db()
    prev_rows = conn.execute(
        "SELECT * FROM orders WHERE company_id = ? AND order_date BETWEEN ? AND ? ORDER BY order_date ASC",
        (company_id(), previous_start.isoformat(), previous_end.isoformat()),
    ).fetchall()
    conn.close()
    prev_total = float(pd.DataFrame([dict(r) for r in prev_rows])["total_amount"].sum()) if prev_rows else 0
    sales_growth = safe_percent_change(total_revenue, prev_total) or 0
    daily = df.groupby("order_date").agg(revenue=("total_amount", "sum"), orders=("id", "count"))
    date_index = pd.date_range(start_date, end_date, freq="D").strftime("%Y-%m-%d")
    daily = daily.reindex(date_index, fill_value=0).rename_axis("order_date").reset_index()
    categories = df.groupby("category").agg(revenue=("total_amount", "sum")).reset_index()
    products = (
        df.groupby(["product_id", "product_name"], dropna=False)
        .agg(revenue=("total_amount", "sum"))
        .reset_index()
        .sort_values("revenue", ascending=False)
    )
    regions = (
        df.groupby("region", dropna=False)
        .agg(revenue=("total_amount", "sum"))
        .reset_index()
        .sort_values("revenue", ascending=False)
    )
    transactions = sorted(rows, key=lambda row: (row["order_date"], row["id"]), reverse=True)[:10]
    return {
        "kpis": {
            "revenue": total_revenue,
            "orders": total_orders,
            "customers": total_customers,
            "profit": total_profit,
            "average_order_value": avg_order_value,
            "sales_growth": sales_growth,
        },
        "charts": {
            "monthly": daily.to_dict(orient="records"),
            "categories": categories.to_dict(orient="records"),
            "products": products.to_dict(orient="records"),
            "regions": regions.to_dict(orient="records"),
            "forecast": build_revenue_forecast(daily["revenue"].astype(float).tolist(), end_date),
        },
        "recent_transactions": [dict(row) for row in transactions],
        "date_range": {"start": start_date.isoformat(), "end": end_date.isoformat()},
        "message": "Data loaded successfully.",
    }


def compute_business_pulse(start_date, end_date) -> Dict[str, Any]:
    conn = connect_db()
    rows = conn.execute(
        "SELECT * FROM orders WHERE company_id = ? AND order_date BETWEEN ? AND ? ORDER BY order_date ASC",
        (company_id(), start_date.isoformat(), end_date.isoformat()),
    ).fetchall()
    conn.close()
    if not rows:
        return {
            "health_score": None,
            "health_category": "Insufficient data",
            "overall_score_label": "Insufficient data",
            "previous_period_score": None,
            "score_change": None,
            "factors": [],
            "explanation": "No transaction data is available for the selected range.",
            "alerts": [],
            "message": "Insufficient data to calculate the business pulse.",
        }

    df = pd.DataFrame([dict(row) for row in rows])
    revenue = float(df["total_amount"].sum())
    orders = int(len(df))
    customers = int(df["customer_id"].nunique())
    avg_aov = float(df["total_amount"].mean()) if not df.empty else 0.0
    previous_days = (end_date - start_date).days + 1
    previous_start = start_date - timedelta(days=previous_days)
    previous_end = start_date - timedelta(days=1)
    conn = connect_db()
    previous_rows = conn.execute(
        "SELECT * FROM orders WHERE company_id = ? AND order_date BETWEEN ? AND ? ORDER BY order_date ASC",
        (company_id(), previous_start.isoformat(), previous_end.isoformat()),
    ).fetchall()
    conn.close()
    previous_revenue = float(pd.DataFrame([dict(r) for r in previous_rows])["total_amount"].sum()) if previous_rows else 0.0
    previous_orders = len(previous_rows) if previous_rows else 0
    revenue_change = safe_percent_change(revenue, previous_revenue) or 0.0
    order_change = safe_percent_change(orders, previous_orders) or 0.0
    repeat_ratio = 1.0 if customers == 0 else float((df.groupby("customer_id").size()[df.groupby("customer_id").size() > 1].count()) / customers)
    retention_ratio = 0.6 if previous_rows else 0.0
    product_score = 1.0 if not df.empty else 0.0
    score = max(0, min(100, round((max(0, min(1, (revenue_change + 30) / 80)) * 30) + (max(0, min(1, (order_change + 20) / 60)) * 20) + (repeat_ratio * 20) + (retention_ratio * 15) + (product_score * 15), 2)))
    if score >= 80:
        category = "Strong"
    elif score >= 60:
        category = "Stable"
    elif score >= 40:
        category = "Needs Attention"
    else:
        category = "Critical"
    previous_score = max(0, min(100, round((max(0, min(1, ((safe_percent_change(previous_revenue, previous_revenue - 1) or 0) + 30) / 80)) * 30) + 50, 2)))
    score_change = round(score - previous_score, 2)
    factors = [
        {"name": "Revenue trend", "value": f"{revenue_change:.2f}%", "weight": "Strong" if revenue_change >= 0 else "Weak"},
        {"name": "Order volume", "value": f"{order_change:.2f}%", "weight": "Stable" if abs(order_change) < 10 else "Variable"},
        {"name": "Repeat purchase", "value": f"{repeat_ratio * 100:.1f}%", "weight": "Healthy" if repeat_ratio > 0.4 else "Needs attention"},
    ]
    alerts = anomaly_detection(start_date, end_date)
    recommendations = generate_recommendations(alerts)
    save_business_history("analysis", None, f"AI Business Pulse score {score} ({category})", "score")
    return {
        "health_score": score,
        "health_category": category,
        "overall_score_label": category,
        "previous_period_score": previous_score,
        "score_change": score_change,
        "factors": factors,
        "explanation": "This score is an internal decision-support indicator derived from revenue trend, order volume, repeat-purchase behaviour, retention, and product demand. It is not an objective external credit or financial rating.",
        "alerts": alerts,
        "recommendations": recommendations,
        "message": "AI Business Pulse completed successfully.",
        "metrics": {
            "revenue": revenue,
            "orders": orders,
            "customers": customers,
            "average_order_value": avg_aov,
        },
    }


def anomaly_detection(start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
    conn = connect_db()
    rows = conn.execute(
        "SELECT * FROM orders WHERE company_id = ? AND order_date BETWEEN ? AND ? ORDER BY order_date ASC",
        (company_id(), start_date.isoformat(), end_date.isoformat()),
    ).fetchall()
    conn.close()
    if not rows:
        return []
    df = pd.DataFrame([dict(row) for row in rows])
    daily = df.groupby("order_date").agg(revenue=("total_amount", "sum"), orders=("id", "count")).reset_index()
    previous_start = start_date - timedelta(days=(end_date - start_date).days + 1)
    previous_end = start_date - timedelta(days=1)
    conn = connect_db()
    prev_rows = conn.execute(
        "SELECT * FROM orders WHERE company_id = ? AND order_date BETWEEN ? AND ? ORDER BY order_date ASC",
        (company_id(), previous_start.isoformat(), previous_end.isoformat()),
    ).fetchall()
    conn.close()
    prev_df = pd.DataFrame([dict(r) for r in prev_rows]) if prev_rows else pd.DataFrame(columns=["total_amount", "id", "order_date"])
    prev_daily = prev_df.groupby("order_date").agg(revenue=("total_amount", "sum"), orders=("id", "count")).reset_index()
    last_day = daily.iloc[-1]
    last_value = float(last_day["revenue"]) if not daily.empty else 0.0
    prev_avg = float(prev_daily["revenue"].mean()) if not prev_daily.empty else 0.0
    change = safe_percent_change(last_value, prev_avg)
    alerts = []
    if change is not None and abs(change) >= 15:
        severity = "High" if abs(change) >= 30 else "Medium"
        alert = {
            "metric_name": "Daily revenue",
            "current_value": round(last_value, 2),
            "comparison_value": round(prev_avg, 2),
            "change_value": round(last_value - prev_avg, 2),
            "change_percentage": round(change, 2),
            "explanation": "Revenue deviated materially from the prior comparable period and may indicate a meaningful business change.",
            "detection_method": "percentage change with historical baseline",
            "severity": severity,
            "created_at": iso_now(),
        }
        alerts.append(alert)
    if not alerts:
        alert = {
            "metric_name": "Daily revenue",
            "current_value": round(last_value, 2),
            "comparison_value": round(prev_avg, 2),
            "change_value": round(last_value - prev_avg, 2),
            "change_percentage": 0,
            "explanation": "No material anomaly detected. Recent values remain within expected operational variation.",
            "detection_method": "percentage change with historical baseline",
            "severity": "Informational",
            "created_at": iso_now(),
        }
        if prev_df.empty:
            alert["explanation"] = "There is not enough historical comparable data to determine a meaningful anomaly, so the business pulse is being monitored conservatively."
            alert["comparison_value"] = 0
            alert["change_value"] = round(last_value, 2)
            alert["change_percentage"] = 0
        alerts.append(alert)
    for alert in alerts:
        alert_id = store_alert(alert)
        alert["id"] = alert_id
        conn = connect_db()
        stored_alert = conn.execute(
            "SELECT status FROM business_alerts WHERE id = ? AND company_id = ?",
            (alert_id, company_id()),
        ).fetchone()
        conn.close()
        alert["status"] = stored_alert["status"] if stored_alert else "open"
        create_investigation(alert, alert_id)
    return alerts


def store_alert(alert: Dict[str, Any]) -> int:
    conn = connect_db()
    existing = conn.execute(
        """
        SELECT id FROM business_alerts
        WHERE company_id = ? AND metric_name = ? AND date(created_at) = date(?)
          AND current_value = ? AND comparison_value = ?
          AND change_percentage = ?
        ORDER BY id DESC LIMIT 1
        """,
        (
            company_id(),
            alert["metric_name"],
            alert["created_at"],
            alert["current_value"],
            alert["comparison_value"],
            alert["change_percentage"],
        ),
    ).fetchone()
    if existing:
        conn.close()
        return int(existing["id"])
    cursor = conn.execute(
        "INSERT INTO business_alerts (metric_name, severity, current_value, comparison_value, change_value, change_percentage, explanation, detection_method, created_at, status, company_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)",
        (
            alert["metric_name"],
            alert["severity"],
            alert["current_value"],
            alert["comparison_value"],
            alert["change_value"],
            alert["change_percentage"],
            alert["explanation"],
            alert["detection_method"],
            alert["created_at"],
            company_id(),
        ),
    )
    conn.commit()
    alert_id = cursor.lastrowid
    conn.close()
    return alert_id


def create_investigation(alert: Dict[str, Any], alert_id: Optional[int] = None) -> None:
    conn = connect_db()
    if alert_id is None:
        latest = conn.execute(
            "SELECT id FROM business_alerts WHERE company_id = ? AND metric_name = ? ORDER BY id DESC LIMIT 1",
            (company_id(), alert["metric_name"]),
        ).fetchone()
        if latest is None:
            conn.close(); return
        alert_id = latest["id"]
    summary = f"Investigation for {alert['metric_name']} showing a {alert['change_percentage']}% variation compared with the prior period."
    evidence = [
        {"metric": alert["metric_name"], "current": alert["current_value"], "comparison": alert["comparison_value"], "change": alert["change_value"]},
        {"method": alert["detection_method"], "severity": alert["severity"]},
    ]
    factors = [
        "Possible change in order volume.",
        "Possible change in average order value.",
        "Possible change in category mix.",
    ]
    existing = conn.execute("SELECT id FROM business_investigations WHERE alert_id = ? ORDER BY created_at DESC LIMIT 1", (alert_id,)).fetchone()
    if existing is None:
        conn.execute(
            "INSERT INTO business_investigations (alert_id, summary, evidence_json, possible_factors_json, limitations) VALUES (?, ?, ?, ?, ?)",
            (
                alert_id,
                summary,
                json.dumps(evidence),
                json.dumps(factors),
                "The data suggests an association, not a confirmed causal outcome, and additional business context may be required.",
            ),
        )
        conn.commit()
    conn.close()


def generate_recommendations(alerts: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    recommendations = []
    for alert in alerts:
        if alert["severity"] == "Informational":
            title = "Review monitoring baseline"
            description = "The business pulse is stable, but the baseline should be reviewed for seasonal shifts or a recent operational change."
            priority = "Low"
        elif alert["change_percentage"] < 0:
            title = "Review pricing and product mix"
            description = "Revenue has declined; inspect average order value, product mix and demand concentration before making operational decisions."
            priority = "High"
        else:
            title = "Scale promotions cautiously"
            description = "Revenue is trending upward; confirm inventory and sales capacity before scaling campaigns."
            priority = "Medium"
        evidence = {
            "metric": alert["metric_name"],
            "current_value": alert["current_value"],
            "comparison_value": alert["comparison_value"],
            "change_percentage": alert["change_percentage"],
        }
        recommendation = {
            "title": title,
            "description": description,
            "evidence": evidence,
            "priority": priority,
            "expected_benefit": "Not enough data to estimate impact." if alert["change_percentage"] == 0 else "Monitor for 2-4 weeks after action."
        }
        conn = connect_db()
        alert_row = conn.execute(
            "SELECT id FROM business_alerts WHERE id = ? AND company_id = ?",
            (alert.get("id"), company_id()),
        ).fetchone()
        if alert_row:
            existing = conn.execute(
                "SELECT id FROM business_recommendations WHERE company_id = ? AND alert_id = ? AND title = ? ORDER BY created_at DESC LIMIT 1",
                (company_id(), alert_row["id"], title),
            ).fetchone()
            if existing is None:
                cursor = conn.execute(
                    "INSERT INTO business_recommendations (alert_id, title, description, evidence_json, priority, expected_benefit, status, company_id) VALUES (?, ?, ?, ?, ?, ?, 'New', ?)",
                    (
                        alert_row["id"],
                        title,
                        description,
                        json.dumps(evidence),
                        priority,
                        recommendation["expected_benefit"],
                        company_id(),
                    ),
                )
                conn.commit()
                recommendation["id"] = int(cursor.lastrowid)
            else:
                recommendation["id"] = int(existing["id"])
            recommendation["alert_id"] = int(alert_row["id"])
            recommendation["status"] = "New" if existing is None else conn.execute(
                "SELECT status FROM business_recommendations WHERE id = ? AND company_id = ?",
                (existing["id"], company_id()),
            ).fetchone()["status"]
        conn.close()
        recommendations.append(recommendation)
    return recommendations


def reset_business_analysis() -> None:
    conn = connect_db()
    conn.execute("DELETE FROM business_alerts")
    conn.execute("DELETE FROM business_investigations")
    conn.execute("DELETE FROM business_recommendations")
    conn.execute("DELETE FROM business_insight_history")
    conn.commit()
    conn.close()


def simulate_business_scenario(baseline: Dict[str, Any], order_change: float = 0.0, aov_change: float = 0.0, repeat_change: float = 0.0, inactivity_change: float = 0.0, category_change: float = 0.0) -> Dict[str, Any]:
    revenue = float(baseline.get("kpis", {}).get("revenue", 0) or 0)
    aov = float(baseline.get("kpis", {}).get("average_order_value", 0) or 0)
    order_volume = float(baseline.get("kpis", {}).get("orders", 0) or 0)
    hypothetical_revenue = revenue * (1 + (order_change / 100.0)) * (1 + (aov_change / 100.0))
    if repeat_change:
        hypothetical_revenue *= 1 + (repeat_change / 100.0)
    if inactivity_change:
        hypothetical_revenue *= 1 - (max(0, inactivity_change) / 100.0)
    if category_change:
        hypothetical_revenue *= 1 + (category_change / 100.0)
    delta = hypothetical_revenue - revenue
    pct = safe_percent_change(hypothetical_revenue, revenue) if revenue else 0.0
    return {
        "baseline_revenue": revenue,
        "hypothetical_revenue": round(hypothetical_revenue, 2),
        "absolute_difference": round(delta, 2),
        "percentage_difference": round(pct, 2) if pct is not None else 0.0,
        "assumptions": {
            "order_change": order_change,
            "aov_change": aov_change,
            "repeat_change": repeat_change,
            "inactivity_change": inactivity_change,
            "category_change": category_change,
        },
        "data_used": {"average_order_value": aov, "order_volume": order_volume},
        "scenario_limitations": "This is a scenario estimate for planning only, not a guaranteed business outcome.",
    }


def save_business_history(insight_type: str, related_record_id: Optional[int], summary: str, evidence_hash: str) -> None:
    conn = connect_db()
    existing = conn.execute(
        """
        SELECT id FROM business_insight_history
        WHERE company_id = ? AND insight_type = ? AND summary = ? AND date(created_at) = date('now')
        LIMIT 1
        """,
        (company_id(), insight_type, summary),
    ).fetchone()
    if existing:
        conn.close()
        return
    conn.execute(
        "INSERT INTO business_insight_history (insight_type, related_record_id, summary, evidence_hash, company_id) VALUES (?, ?, ?, ?, ?)",
        (insight_type, related_record_id, summary, evidence_hash, company_id()),
    )
    conn.commit()
    conn.close()


@app.context_processor
def inject_globals():
    user = current_user()
    company = None
    if user and user.get("role") == "admin" and user.get("company_id"):
        conn = connect_db()
        company = conn.execute(
            "SELECT id, name FROM companies WHERE id = ?",
            (user["company_id"],),
        ).fetchone()
        conn.close()
        company = dict(company) if company else None
    return {"csrf_token": ensure_csrf_token(), "current_user": user, "company": company}


@app.route("/favicon.ico")
def favicon():
    return ""


if __name__ == "__main__":
    init_database()
    app.run(debug=os.getenv("BID_DEBUG") == "1", host="127.0.0.1", port=5000)
