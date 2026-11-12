import os
import sqlite3
from datetime import datetime, timedelta, timezone

from werkzeug.security import generate_password_hash


DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "data", "business_dashboard.db")


def get_db_path() -> str:
    return os.getenv("BID_DATABASE_PATH", DEFAULT_DB_PATH)


def connect_db(db_path: str | None = None) -> sqlite3.Connection:
    target = db_path or get_db_path()
    os.makedirs(os.path.dirname(target), exist_ok=True)
    conn = sqlite3.connect(target)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_database(db_path: str | None = None) -> None:
    path = db_path or get_db_path()
    conn = connect_db(path)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS companies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT,
            full_name TEXT,
            company_id INTEGER NOT NULL DEFAULT 1 REFERENCES companies(id),
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','user')),
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT,
            segment TEXT,
            region TEXT,
            company_id INTEGER NOT NULL DEFAULT 1 REFERENCES companies(id),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            unit_price REAL NOT NULL,
            company_id INTEGER NOT NULL DEFAULT 1 REFERENCES companies(id),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            order_date TEXT NOT NULL,
            quantity INTEGER NOT NULL CHECK(quantity >= 0),
            unit_price REAL NOT NULL,
            total_amount REAL NOT NULL,
            profit REAL NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'completed',
            region TEXT,
            category TEXT,
            company_id INTEGER NOT NULL DEFAULT 1 REFERENCES companies(id),
            FOREIGN KEY(customer_id) REFERENCES customers(id),
            FOREIGN KEY(product_id) REFERENCES products(id)
        );

        CREATE TABLE IF NOT EXISTS business_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            metric_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            current_value REAL,
            comparison_value REAL,
            change_value REAL,
            change_percentage REAL,
            explanation TEXT NOT NULL,
            detection_method TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            status TEXT NOT NULL DEFAULT 'open',
            company_id INTEGER NOT NULL DEFAULT 1 REFERENCES companies(id)
        );

        CREATE TABLE IF NOT EXISTS business_investigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER,
            summary TEXT NOT NULL,
            evidence_json TEXT,
            possible_factors_json TEXT,
            limitations TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(alert_id) REFERENCES business_alerts(id)
        );

        CREATE TABLE IF NOT EXISTS business_recommendations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            evidence_json TEXT,
            priority TEXT NOT NULL,
            expected_benefit TEXT,
            status TEXT NOT NULL DEFAULT 'New',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            company_id INTEGER NOT NULL DEFAULT 1 REFERENCES companies(id),
            FOREIGN KEY(alert_id) REFERENCES business_alerts(id)
        );

        CREATE TABLE IF NOT EXISTS decision_scenarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            scenario_name TEXT NOT NULL,
            baseline_json TEXT NOT NULL,
            assumptions_json TEXT NOT NULL,
            result_json TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS recommendation_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recommendation_id INTEGER NOT NULL,
            owner_user_id INTEGER NOT NULL,
            start_date TEXT,
            completion_date TEXT,
            action_description TEXT,
            status TEXT NOT NULL DEFAULT 'New',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(recommendation_id) REFERENCES business_recommendations(id),
            FOREIGN KEY(owner_user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS recommendation_measurements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action_id INTEGER NOT NULL,
            metric_name TEXT NOT NULL,
            baseline_value REAL,
            followup_value REAL,
            baseline_start_date TEXT,
            baseline_end_date TEXT,
            followup_start_date TEXT,
            followup_end_date TEXT,
            measured_change REAL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(action_id) REFERENCES recommendation_actions(id)
        );

        CREATE TABLE IF NOT EXISTS business_insight_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            insight_type TEXT NOT NULL,
            related_record_id INTEGER,
            summary TEXT NOT NULL,
            evidence_hash TEXT,
            company_id INTEGER NOT NULL DEFAULT 1 REFERENCES companies(id),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_orders_date ON orders(order_date);
        CREATE INDEX IF NOT EXISTS idx_orders_customer ON orders(customer_id);
        CREATE INDEX IF NOT EXISTS idx_orders_product ON orders(product_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_metric ON business_alerts(metric_name);
        CREATE INDEX IF NOT EXISTS idx_recommendations_status ON business_recommendations(status);
        """
    )
    conn.execute(
        "INSERT OR IGNORE INTO companies (id, name) VALUES (1, 'Demo Company')"
    )
    for table, column_definition in (
        ("users", "email TEXT"),
        ("users", "full_name TEXT"),
        ("users", "company_id INTEGER NOT NULL DEFAULT 1"),
        ("customers", "company_id INTEGER NOT NULL DEFAULT 1"),
        ("products", "company_id INTEGER NOT NULL DEFAULT 1"),
        ("orders", "company_id INTEGER NOT NULL DEFAULT 1"),
        ("business_alerts", "company_id INTEGER NOT NULL DEFAULT 1"),
        ("business_recommendations", "company_id INTEGER NOT NULL DEFAULT 1"),
        ("business_insight_history", "company_id INTEGER NOT NULL DEFAULT 1"),
    ):
        column_name = column_definition.split()[0]
        columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        if column_name not in columns:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column_definition}")
    conn.execute(
        "UPDATE users SET email = lower(username) || '@local.test' WHERE email IS NULL OR email = ''"
    )
    conn.execute(
        "UPDATE users SET full_name = username WHERE full_name IS NULL OR full_name = ''"
    )
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email)")
    conn.commit()
    conn.close()
    seed_default_users()
    seed_demo_data()


def seed_default_users() -> None:
    conn = connect_db()
    existing = conn.execute("SELECT username FROM users").fetchall()
    if not existing:
        conn.execute(
            "INSERT INTO users (username, email, full_name, company_id, password_hash, role) VALUES (?, ?, ?, 1, ?, ?)",
            ("admin", "admin@local.test", "Demo Administrator", generate_password_hash("admin123"), "admin"),
        )
        conn.execute(
            "INSERT INTO users (username, email, full_name, company_id, password_hash, role) VALUES (?, ?, ?, 1, ?, ?)",
            ("user", "user@local.test", "Demo User", generate_password_hash("user123"), "user"),
        )
        conn.commit()
    conn.close()


def seed_demo_data() -> None:
    conn = connect_db()
    customer_count = conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0]
    product_count = conn.execute("SELECT COUNT(*) FROM products").fetchone()[0]
    order_count = conn.execute("SELECT COUNT(*) FROM orders").fetchone()[0]
    if customer_count == 0:
        customers = [
            ("Ava Patel", "ava@example.com", "VIP", "North"),
            ("Marcus Reed", "marcus@example.com", "Returning", "South"),
            ("Elena Gomez", "elena@example.com", "New", "West"),
            ("Noah Kim", "noah@example.com", "Corporate", "East"),
            ("Priya Singh", "priya@example.com", "Returning", "Central"),
            ("Leah Brown", "leah@example.com", "VIP", "North"),
            ("Omar Hassan", "omar@example.com", "Returning", "South"),
            ("Sofia Wu", "sofia@example.com", "New", "West"),
            ("Daniel Ortiz", "daniel@example.com", "Corporate", "East"),
            ("Maya Chen", "maya@example.com", "Returning", "Central"),
        ]
        conn.executemany(
            "INSERT INTO customers (name, email, segment, region, company_id) VALUES (?, ?, ?, ?, 1)",
            customers,
        )
    if product_count == 0:
        products = [
            ("Laptop Pro 14", "Electronics", 1200.0),
            ("Wireless Mouse", "Accessories", 49.99),
            ("Office Chair", "Furniture", 180.0),
            ("Desk Lamp", "Office", 65.0),
            ("Monitor 27\"", "Electronics", 320.0),
            ("Mechanical Keyboard", "Accessories", 110.0),
            ("Standing Desk", "Furniture", 540.0),
            ("Notebook Set", "Office", 28.0),
            ("Travel Backpack", "Accessories", 89.0),
            ("Projector", "Electronics", 480.0),
        ]
        conn.executemany(
            "INSERT INTO products (name, category, unit_price, company_id) VALUES (?, ?, ?, 1)",
            products,
        )
    if order_count == 0:
        base_date = datetime.now(timezone.utc).date() - timedelta(days=180)
        product_rows = conn.execute("SELECT id, category, unit_price FROM products WHERE company_id = 1").fetchall()
        for day_offset in range(180):
            current_date = base_date + timedelta(days=day_offset)
            for purchase_index in range(4):
                product = product_rows[(day_offset + purchase_index) % len(product_rows)]
                customer_id = (day_offset + purchase_index) % 10 + 1
                quantity = 1 if (day_offset + purchase_index) % 5 else 2
                unit_price = float(product["unit_price"])
                total_amount = round(unit_price * quantity * (1 + ((day_offset % 9) / 100)), 2)
                profit = round(total_amount * 0.25, 2)
                if day_offset >= 150:
                    total_amount *= 0.8
                    profit *= 0.8
                conn.execute(
                    "INSERT INTO orders (customer_id, product_id, order_date, quantity, unit_price, total_amount, profit, status, region, category, company_id) VALUES (?, ?, ?, ?, ?, ?, ?, 'completed', ?, ?, 1)",
                    (
                        customer_id,
                        product["id"],
                        current_date.isoformat(),
                        quantity,
                        unit_price,
                        round(total_amount, 2),
                        round(profit, 2),
                        ["North", "South", "West", "East", "Central"][customer_id % 5],
                        product["category"],
                    ),
                )
        conn.commit()
    conn.close()
