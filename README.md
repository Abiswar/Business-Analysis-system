# AI Business Intelligence Dashboard

This project is a Flask and SQLite business intelligence dashboard with email/password registration, private company workspaces, administrator-only financial data, and an explainable business forecast.

## Features
- Separate sign-up and sign-in pages using email (including Gmail) and password; new registrations create a company admin workspace
- Company-scoped records: admins see only financial/customer data tied to their company; non-admin accounts cannot access company analytics
- Admin-managed company name and CSV transaction import (5 MB / 5,000-row limits, validated and saved atomically)
- Current-calendar-month revenue, profit, and order totals
- Six-month revenue and profit outlook based on the company’s completed-month transaction history, with the method and confidence displayed
- Responsive daily sales dashboard with category, top-product, and regional views
- Custom date ranges, comparable-period KPIs, actual recent order details, and filtered CSV export
- Customer segment summaries, churn-watch indicators, and alerts with acknowledge/resolve controls
- AI Business Pulse, explainable recommendations, outcome history, and saved scenario simulations
- Automated pytest coverage for financial calculations, signup, data isolation, CSV imports, and authorization

## Setup
1. Create or activate the project environment.
2. Install dependencies: `pip install -r requirements.txt`
3. Run the app: `python app.py`
4. Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.
5. Create a company workspace from **Create your company workspace**, or use the local demo admin:
   - Email: `admin@local.test` (the legacy username `admin` also works)
   - Password: `admin123`

The local server binds to `127.0.0.1:5000` and runs without the interactive debugger by default. Set `BID_DEBUG=1` only when you need Flask's development debugger. Set `BID_SECRET_KEY` to a persistent random secret before using the application outside local development.

After signing in, use **Company workspace → Download CSV template**. Fill in the template with the company's actual transactions, then import it from the admin dashboard. Each company name is a workspace label, not a connection to that company's private financial systems. No public-company sales data is looked up by name.

## Files
- `app.py`: main Flask application and database setup
- `templates/`: Jinja templates for login, dashboard and analytics pages
- `static/css/style.css`: styling for the dashboard and login screen
- `tests/test_app.py`: automated validation for the dashboard and analytics features

## Notes
- The app uses a local SQLite database at `data/business_dashboard.db`.
- Secrets should be set through environment variables such as `BID_SECRET_KEY` and `BID_DATABASE_PATH`.
- This project intentionally avoids paid AI APIs and uses explainable local analytics and rule-based detection.
- New company accounts require passwords of at least 12 characters. Configure `BID_SECRET_KEY` to keep sessions persistent across restarts.
- Revenue/profit projections are planning estimates derived from imported transactions, not guaranteed results, accounting advice, or an external financial rating. Confidence and the projection method are shown with the outlook.
- Churn-watch thresholds are transparent: at risk after 45 days and inactive after 90 days without an order.
