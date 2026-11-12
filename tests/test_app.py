import json
import csv
import os
import re
from io import BytesIO
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app import app, connect_db, init_database, safe_percent_change, simulate_business_scenario


@pytest.fixture
def client():
    os.environ["BID_DATABASE_PATH"] = os.path.join(os.getcwd(), "data", "test_dashboard.db")
    init_database()
    app.config["TESTING"] = True
    with app.test_client() as client:
        client.post('/login', data={'email': 'admin@local.test', 'password': 'admin123'})
        yield client


def test_unauthenticated_access_rejected(client):
    client.get('/logout')
    response = client.get('/dashboard')
    assert response.status_code == 302


def test_admin_user_can_access_admin_dashboard(client):
    response = client.post('/login', data={'username': 'admin', 'password': 'admin123'}, follow_redirects=False)
    assert response.status_code == 302
    assert response.headers['Location'] == '/admin/dashboard'


def test_normal_user_cannot_access_admin_dashboard(client):
    client.get('/logout')
    response = client.post('/login', data={'username': 'user', 'password': 'user123'}, follow_redirects=False)
    assert response.status_code == 302
    response = client.get('/admin/dashboard', follow_redirects=False)
    assert response.status_code == 403
    for path in (
        '/dashboard',
        '/business-pulse',
        '/api/dashboard-summary',
        '/api/dashboard-export.csv',
        '/api/customer-health',
        '/api/company/financial-overview',
        '/api/company-profile',
        '/api/company/import-template.csv',
        '/api/business-pulse/summary',
        '/api/business-pulse/alerts',
        '/api/business-pulse/recommendations',
        '/api/business-pulse/scenarios',
        '/api/business-pulse/outcomes',
        '/api/business-pulse/history',
        '/api/business-pulse/investigations/1',
    ):
        assert client.get(path).status_code == 403
    assert client.post(
        '/api/company/import-transactions',
        headers={'X-CSRFToken': 'test-token'},
    ).status_code == 403


def test_empty_dataset_message(client):
    conn = connect_db()
    conn.execute('DELETE FROM orders')
    conn.commit()
    conn.close()
    response = client.get('/api/dashboard-summary?days=30')
    assert response.status_code == 200
    payload = response.get_json()
    assert payload['message'] == 'No data available for the selected date range.'


def test_revenue_calculation_is_correct(client):
    conn = connect_db()
    conn.execute('DELETE FROM orders')
    today = datetime.now(timezone.utc).date()
    conn.execute(
        "INSERT INTO orders (customer_id, product_id, order_date, quantity, unit_price, total_amount, profit, status, region, category) VALUES (?, ?, ?, ?, ?, ?, ?, 'completed', 'North', 'Electronics')",
        (1, 1, today.isoformat(), 2, 100, 200, 50)
    )
    conn.execute(
        "INSERT INTO orders (customer_id, product_id, order_date, quantity, unit_price, total_amount, profit, status, region, category) VALUES (?, ?, ?, ?, ?, ?, ?, 'completed', 'North', 'Electronics')",
        (2, 1, (today - timedelta(days=1)).isoformat(), 1, 80, 80, 20)
    )
    conn.commit()
    conn.close()
    response = client.get('/api/dashboard-summary?days=30')
    payload = response.get_json()
    assert payload['kpis']['revenue'] == 280.0
    assert payload['kpis']['orders'] == 2


def test_percentage_change_handles_zero_baseline():
    assert safe_percent_change(10, 0) is None


def test_anomaly_detection_identifies_construction_anomaly(client):
    response = client.get('/api/business-pulse/summary?days=30')
    payload = response.get_json()
    assert 'alerts' in payload
    assert isinstance(payload['alerts'], list)


def test_investigation_has_supporting_evidence(client):
    response = client.get('/api/business-pulse/investigations/1')
    payload = response.get_json()
    assert 'evidence' in payload


def test_recommendations_have_valid_explanations(client):
    response = client.get('/api/business-pulse/recommendations')
    payload = response.get_json()
    assert payload['recommendations']
    assert 'description' in payload['recommendations'][0]


def test_what_if_calculation_is_correct():
    baseline = {'kpis': {'revenue': 1000, 'average_order_value': 50, 'orders': 20}}
    result = simulate_business_scenario(baseline, order_change=10, aov_change=0)
    assert result['baseline_revenue'] == 1000
    assert result['hypothetical_revenue'] == 1100.0


def test_saved_scenarios_persist_after_application_restart(client):
    response = client.post('/api/business-pulse/scenarios', json={'scenario_name': 'Persist test', 'order_change': 5, 'aov_change': 2, 'repeat_change': 0, 'inactivity_change': 0, 'category_change': 0}, headers={'X-CSRFToken': 'test-token'})
    assert response.status_code == 201
    data = json.loads(response.data)
    assert data['scenario_id']


def test_recommendation_status_change_is_saved(client):
    client.post('/login', data={'username': 'admin', 'password': 'admin123'}, follow_redirects=False)
    response = client.patch('/api/business-pulse/recommendations/1/status', json={'status': 'Accepted'}, headers={'X-CSRFToken': 'test-token'})
    assert response.status_code == 200


def test_invalid_api_request_returns_error(client):
    response = client.get('/api/business-pulse/recommendations/999999')
    assert response.status_code == 404


def test_dashboard_date_filters_apply_consistently(client):
    response = client.get('/api/dashboard-summary?days=7')
    assert response.status_code == 200


def test_login_role_restriction_for_user(client):
    client.get('/logout')
    client.post('/login', data={'username': 'user', 'password': 'user123'}, follow_redirects=False)
    response = client.get('/admin/dashboard', follow_redirects=False)
    assert response.status_code == 403


def test_dashboard_summary_includes_forecast_and_real_transactions(client):
    response = client.get('/api/dashboard-summary?days=30')
    assert response.status_code == 200
    payload = response.get_json()
    assert len(payload['charts']['forecast']['labels']) == 7
    assert len(payload['charts']['forecast']['values']) == 7
    assert payload['recent_transactions']
    transaction = payload['recent_transactions'][0]
    assert transaction['id']
    assert transaction['customer_name']
    assert transaction['product_name']


def test_dashboard_custom_date_range_and_csv_export(client):
    today = datetime.now(timezone.utc).date().isoformat()
    summary = client.get(f'/api/dashboard-summary?start_date={today}&end_date={today}')
    assert summary.status_code == 200
    assert summary.get_json()['date_range'] == {'start': today, 'end': today}

    export = client.get(f'/api/dashboard-export.csv?start_date={today}&end_date={today}')
    assert export.status_code == 200
    assert export.mimetype == 'text/csv'
    assert b'Order ID,Date,Customer,Product' in export.data


def test_dashboard_rejects_invalid_date_range(client):
    response = client.get('/api/dashboard-summary?days=0')
    assert response.status_code == 400
    assert response.get_json()['error']


def test_alert_status_can_be_acknowledged(client):
    summary = client.get('/api/business-pulse/summary?days=30').get_json()
    alert_id = summary['alerts'][0]['id']
    response = client.patch(
        f'/api/business-pulse/alerts/{alert_id}/status',
        json={'status': 'acknowledged'},
        headers={'X-CSRFToken': 'test-token'},
    )
    assert response.status_code == 200
    assert response.get_json()['status'] == 'acknowledged'


def test_scenario_rejects_non_numeric_assumptions(client):
    response = client.post(
        '/api/business-pulse/scenarios',
        json={'order_change': 'not-a-number'},
        headers={'X-CSRFToken': 'test-token'},
    )
    assert response.status_code == 400


def test_customer_health_includes_segments_and_retention_status(client):
    response = client.get('/api/customer-health?days=90')
    assert response.status_code == 200
    payload = response.get_json()
    assert payload['customer_count'] > 0
    assert payload['segments']
    assert payload['top_customers'][0]['status'] in {'Active', 'At risk', 'Inactive', 'Never ordered'}
    assert '45 days' in payload['risk_rule']


def test_signup_and_import_are_isolated_to_company_admin(client):
    client.get('/logout')
    email = f'owner-{uuid4().hex}@example.com'
    signup_page = client.get('/signup')
    token = re.search(rb'name="csrf_token" value="([^"]+)"', signup_page.data).group(1).decode()
    response = client.post(
        '/signup',
        data={
            'csrf_token': token,
            'full_name': 'New Owner',
            'email': email,
            'company_name': 'Example Store',
            'password': 'long-enough-password',
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    login_response = client.post(
        '/login',
        data={'email': email, 'password': 'long-enough-password'},
        follow_redirects=False,
    )
    assert login_response.status_code == 302
    assert login_response.headers['Location'] == '/admin/dashboard'

    before_import = client.get('/api/dashboard-summary?days=30').get_json()
    assert before_import['kpis']['revenue'] == 0
    token = re.search(rb'name="csrf-token" content="([^"]+)"', client.get('/dashboard').data).group(1).decode()
    import_response = client.post(
        '/api/company/import-transactions',
        data={
            'file': (BytesIO(
                b'date,customer,product,category,quantity,unit_price,revenue,profit,region,segment,status\n'
                b'2026-11-10,New Customer,New Product,Home,2,50,100,20,West,New,completed\n'
            ), 'transactions.csv'),
        },
        headers={'X-CSRFToken': token},
        content_type='multipart/form-data',
    )
    assert import_response.status_code == 201
    assert import_response.get_json()['imported'] == 1
    summary = client.get('/api/dashboard-summary?start_date=2026-11-10&end_date=2026-11-10').get_json()
    assert summary['kpis']['revenue'] == 100
    assert summary['recent_transactions'][0]['customer_name'] == 'New Customer'
    assert client.get('/api/company-profile').get_json()['company']['name'] == 'Example Store'


def test_signup_rejects_short_password(client):
    client.get('/logout')
    signup_page = client.get('/signup')
    token = re.search(rb'name="csrf_token" value="([^"]+)"', signup_page.data).group(1).decode()
    response = client.post(
        '/signup',
        data={
            'csrf_token': token,
            'full_name': 'New Owner',
            'email': 'short@example.com',
            'company_name': 'Example Store',
            'password': 'short',
        },
    )
    assert response.status_code == 400
    assert b'at least 12 characters' in response.data


def test_company_financial_overview_includes_next_six_months(client):
    response = client.get('/api/company/financial-overview')
    assert response.status_code == 200
    payload = response.get_json()
    assert payload['current_month']['month']
    assert len(payload['forecasts']) == 6
    assert {'month', 'revenue', 'profit', 'confidence'} <= payload['forecasts'][0].keys()


def test_admin_can_download_working_demo_csv(client):
    response = client.get('/api/company/demo-transactions.csv')
    assert response.status_code == 200
    assert response.mimetype == 'text/csv'
    assert 'demo-company-transactions.csv' in response.headers['Content-Disposition']
    rows = list(csv.DictReader(response.get_data(as_text=True).splitlines()))
    assert len(rows) == 13
    assert {'date', 'customer', 'product', 'quantity', 'unit_price', 'revenue', 'profit'} <= rows[0].keys()
    assert all(row['customer'].startswith('Demo Customer') for row in rows)


def test_importing_demo_csv_populates_monthly_financial_outlook(client):
    demo_csv = client.get('/api/company/demo-transactions.csv').data
    response = client.post(
        '/api/company/import-transactions',
        data={'file': (BytesIO(demo_csv), 'demo-company-transactions.csv')},
        headers={'X-CSRFToken': 'test-token'},
        content_type='multipart/form-data',
    )
    assert response.status_code == 201
    assert response.get_json()['imported'] == 13
    overview = client.get('/api/company/financial-overview').get_json()
    assert overview['current_month']['revenue'] > 0
    assert overview['current_month']['profit'] > 0
    assert len(overview['forecasts']) == 6
    assert all(month['revenue'] > 0 and month['profit'] > 0 for month in overview['forecasts'])


def test_regular_user_cannot_download_demo_company_data(client):
    client.get('/logout')
    response = client.post('/login', data={'email': 'user@local.test', 'password': 'user123'})
    assert response.status_code == 302
    assert client.get('/api/company/demo-transactions.csv').status_code == 403
