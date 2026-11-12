const filterForm = document.getElementById('date-filter-form');
const daysInput = document.getElementById('days');
const startInput = document.getElementById('start-date');
const endInput = document.getElementById('end-date');
const messageBox = document.getElementById('dashboard-message');
const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';
const chartInstances = new Map();
const chartColors = ['#6478f5', '#16b894', '#f4a340', '#ef6b78', '#9a72e8', '#38a8c8'];

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[character]);
}

function money(value) {
  return '$' + Number(value || 0).toLocaleString(undefined, {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2
  });
}

function dateValue(date) {
  return date.toISOString().slice(0, 10);
}

function setDefaultRange(days) {
  const end = new Date();
  const start = new Date(end);
  start.setDate(start.getDate() - Number(days) + 1);
  startInput.value = dateValue(start);
  endInput.value = dateValue(end);
}

function currentParams() {
  const params = new URLSearchParams();
  if (startInput.value && endInput.value) {
    params.set('start_date', startInput.value);
    params.set('end_date', endInput.value);
  } else {
    params.set('days', daysInput.value || '30');
  }
  return params;
}

function showMessage(message, isError = false) {
  messageBox.textContent = message;
  messageBox.hidden = !message;
  messageBox.classList.toggle('error', isError);
}

async function fetchJson(url) {
  const response = await fetch(url, { headers: { Accept: 'application/json' } });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || 'The dashboard request could not be completed.');
  }
  return payload;
}

function drawChart(id, config) {
  const canvas = document.getElementById(id);
  if (!window.Chart || !canvas) return;
  if (chartInstances.has(id)) chartInstances.get(id).destroy();
  chartInstances.set(id, new Chart(canvas, config));
}

function renderCharts(summary) {
  const historical = summary.charts.monthly || [];
  const forecast = summary.charts.forecast || { labels: [], values: [] };
  const labels = historical.map(item => item.order_date).concat(forecast.labels || []);
  const revenueValues = historical.map(item => Number(item.revenue || 0));
  const forecastValues = new Array(Math.max(0, historical.length - 1)).fill(null)
    .concat(revenueValues.length ? [revenueValues[revenueValues.length - 1]] : [])
    .concat(forecast.values || []);

  drawChart('monthlyChart', {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label: 'Actual revenue',
          data: revenueValues.concat(new Array((forecast.labels || []).length).fill(null)),
          borderColor: '#6478f5',
          backgroundColor: 'rgba(100,120,245,.13)',
          fill: true,
          tension: .32,
          pointRadius: 0
        },
        {
          label: '7-day outlook',
          data: forecastValues,
          borderColor: '#16b894',
          borderDash: [6, 5],
          tension: .32,
          pointRadius: 2
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { intersect: false, mode: 'index' },
      plugins: { legend: { position: 'bottom' } },
      scales: { y: { beginAtZero: true, ticks: { callback: value => money(value) } } }
    }
  });

  const categories = summary.charts.categories || [];
  drawChart('categoryChart', {
    type: 'doughnut',
    data: {
      labels: categories.map(item => item.category || 'Uncategorized'),
      datasets: [{ data: categories.map(item => item.revenue), backgroundColor: chartColors, borderWidth: 0 }]
    },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom' } } }
  });

  const products = (summary.charts.products || []).slice(0, 6);
  drawChart('productChart', {
    type: 'bar',
    data: {
      labels: products.map(item => item.product_name || `Product ${item.product_id}`),
      datasets: [{ label: 'Revenue', data: products.map(item => item.revenue), backgroundColor: chartColors }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: { x: { beginAtZero: true, ticks: { callback: value => money(value) } } }
    }
  });

  const regions = summary.charts.regions || [];
  drawChart('regionChart', {
    type: 'bar',
    data: {
      labels: regions.map(item => item.region || 'Unassigned'),
      datasets: [{ label: 'Revenue', data: regions.map(item => item.revenue), backgroundColor: '#8b9af7' }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: { y: { beginAtZero: true, ticks: { callback: value => money(value) } } }
    }
  });
}

function renderTransactions(transactions) {
  const rows = transactions || [];
  document.getElementById('recent-transactions-body').innerHTML = rows.length
    ? rows.map(order => `
      <tr>
        <td>#${escapeHtml(order.id)}</td>
        <td>${escapeHtml(order.order_date)}</td>
        <td>${escapeHtml(order.customer_name || 'Unknown customer')}</td>
        <td>${escapeHtml(order.product_name || 'Unknown product')}</td>
        <td>${money(order.total_amount)}</td>
        <td><span class="badge">${escapeHtml(order.status)}</span></td>
      </tr>
    `).join('')
    : '<tr><td colspan="6" class="empty-state">No transactions found in this date range.</td></tr>';
}

function renderAlerts(alerts) {
  const items = (alerts || []).slice(0, 4);
  document.getElementById('dashboard-alerts').innerHTML = items.length
    ? items.map(alert => {
      const state = String(alert.status || 'open').toLowerCase();
      const nextStatus = state === 'open' ? 'acknowledged' : 'resolved';
      const buttonText = state === 'open' ? 'Acknowledge' : state === 'acknowledged' ? 'Resolve' : 'Resolved';
      return `
        <article class="alert-item severity-${escapeHtml(String(alert.severity || 'informational').toLowerCase())}">
          <div class="alert-title-row">
            <strong>${escapeHtml(alert.metric_name)}</strong>
            <span class="badge">${escapeHtml(alert.severity)} · ${escapeHtml(state)}</span>
          </div>
          <p>${escapeHtml(alert.explanation)}</p>
          <small>${Number(alert.change_percentage || 0).toFixed(2)}% change · Current ${money(alert.current_value)}</small>
          ${state === 'resolved' ? '' : `<button class="small-btn alert-status-button" data-alert-id="${Number(alert.id)}" data-status="${nextStatus}">${buttonText}</button>`}
        </article>`;
    }).join('')
    : '<p class="empty-state">No alerts for this period.</p>';
}

function renderPulse(pulse) {
  document.getElementById('pulse-summary').innerHTML = `
    <div class="pulse-summary-grid">
      <div class="pulse-score-box">
        <span class="mini-label">Health score</span>
        <strong class="score-display">${escapeHtml(pulse.health_score ?? 'N/A')}</strong>
        <small>${escapeHtml(pulse.health_category || 'Insufficient data')}</small>
      </div>
      <div class="pulse-insights">
        <h4>Decision-support summary</h4>
        <p>${escapeHtml(pulse.explanation || pulse.message || 'No analysis is available for this range.')}</p>
        <a href="/business-pulse" class="text-link">Explore alerts, recommendations &amp; scenarios</a>
      </div>
    </div>`;
}

function renderCustomerHealth(data) {
  const topCustomers = data.top_customers || [];
  document.getElementById('at-risk-count').textContent =
    `${data.at_risk_count || 0} at risk of ${data.customer_count || 0} customers`;
  document.getElementById('top-customers-body').innerHTML = topCustomers.length
    ? topCustomers.map(customer => `
      <tr>
        <td>${escapeHtml(customer.name)}</td>
        <td>${escapeHtml(customer.segment)}</td>
        <td>${Number(customer.period_orders || 0).toLocaleString()}</td>
        <td>${money(customer.period_revenue)}</td>
        <td><span class="badge health-${escapeHtml(customer.status.toLowerCase().replace(/ /g, '-'))}">${escapeHtml(customer.status)}</span></td>
      </tr>
    `).join('')
    : '<tr><td colspan="5" class="empty-state">No customers found.</td></tr>';
  const atRisk = data.at_risk_customers || [];
  document.getElementById('churn-watch-list').innerHTML = atRisk.length
    ? atRisk.map(customer => `
      <article class="risk-customer">
        <div><strong>${escapeHtml(customer.name)}</strong><small>${escapeHtml(customer.segment)} · ${escapeHtml(customer.region)}</small></div>
        <span class="badge health-${escapeHtml(customer.status.toLowerCase().replace(/ /g, '-'))}">${customer.days_since_order === null ? 'No orders' : `${customer.days_since_order} days`}</span>
      </article>
    `).join('')
    : '<p class="empty-state">No customers currently meet the churn-watch rules.</p>';
}

function renderFinancialOverview(data) {
  document.getElementById('current-month-revenue').textContent = money(data.current_month.revenue);
  document.getElementById('current-month-profit').textContent = money(data.current_month.profit);
  document.getElementById('current-month-orders').textContent = Number(data.current_month.orders || 0).toLocaleString();
  document.getElementById('monthly-forecast-confidence').textContent =
    `Forecast confidence: ${data.forecast_confidence}`;
  document.getElementById('forecast-notice').textContent =
    `${data.forecast_method}. ${data.forecast_notice}`;
  document.getElementById('monthly-forecast-body').innerHTML = (data.forecasts || []).map(item => `
    <tr>
      <td>${escapeHtml(item.month)}</td>
      <td>${money(item.revenue)}</td>
      <td>${money(item.profit)}</td>
      <td><span class="badge">${escapeHtml(item.confidence)}</span></td>
    </tr>
  `).join('') || '<tr><td colspan="4" class="empty-state">Not enough transactions to prepare an outlook.</td></tr>';
}

async function loadDashboard() {
  showMessage('Loading your latest business data…');
  const params = currentParams();
  try {
    const [summary, pulse, customerHealth, financialOverview] = await Promise.all([
      fetchJson(`/api/dashboard-summary?${params}`),
      fetchJson(`/api/business-pulse/summary?${params}`),
      fetchJson(`/api/customer-health?${params}`),
      fetchJson('/api/company/financial-overview')
    ]);
    document.getElementById('kpi-revenue').textContent = money(summary.kpis.revenue);
    document.getElementById('kpi-orders').textContent = Number(summary.kpis.orders || 0).toLocaleString();
    document.getElementById('kpi-customers').textContent = Number(summary.kpis.customers || 0).toLocaleString();
    document.getElementById('kpi-profit').textContent = money(summary.kpis.profit);
    document.getElementById('kpi-aov').textContent = money(summary.kpis.average_order_value);
    document.getElementById('kpi-growth').textContent = `${Number(summary.kpis.sales_growth || 0).toFixed(2)}%`;
    document.getElementById('forecast-confidence').textContent =
      `Forecast confidence: ${(summary.charts.forecast || {}).confidence || 'Insufficient data'}`;
    renderCharts(summary);
    renderTransactions(summary.recent_transactions);
    renderAlerts(pulse.alerts);
    renderPulse(pulse);
    renderCustomerHealth(customerHealth);
    renderFinancialOverview(financialOverview);
    showMessage(summary.message === 'No data available for the selected date range.'
      ? 'No sales data is available for this range. Try a wider date range.'
      : `Updated ${new Date().toLocaleTimeString()} · ${summary.date_range.start} to ${summary.date_range.end}`);
  } catch (error) {
    showMessage(error.message, true);
  }
}

filterForm.addEventListener('submit', event => {
  event.preventDefault();
  if (!startInput.value || !endInput.value) {
    showMessage('Choose both a start and end date.', true);
    return;
  }
  const params = currentParams();
  window.history.replaceState({}, '', `${window.location.pathname}?${params}`);
  loadDashboard();
});

daysInput.addEventListener('change', () => setDefaultRange(daysInput.value));

document.getElementById('export-button').addEventListener('click', () => {
  window.location.assign(`/api/dashboard-export.csv?${currentParams()}`);
});

document.getElementById('company-profile-form').addEventListener('submit', async event => {
  event.preventDefault();
  const nameInput = document.getElementById('company-name');
  try {
    const response = await fetch('/api/company-profile', {
      method: 'PATCH',
      headers: {'Content-Type': 'application/json', 'X-CSRFToken': csrfToken},
      body: JSON.stringify({name: nameInput.value})
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || 'Could not save company details.');
    document.getElementById('company-name-heading').textContent = payload.company.name;
    showMessage('Company profile updated.');
  } catch (error) {
    showMessage(error.message, true);
  }
});

document.getElementById('transaction-import-form').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const status = document.getElementById('import-status');
  const formData = new FormData(form);
  status.classList.remove('error-text');
  status.textContent = 'Validating and importing transactions…';
  try {
    const response = await fetch('/api/company/import-transactions', {
      method: 'POST',
      headers: {'X-CSRFToken': csrfToken},
      body: formData
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || 'Could not import transactions.');
    status.textContent = payload.message;
    form.reset();
    await loadDashboard();
  } catch (error) {
    status.textContent = error.message;
    status.classList.add('error-text');
  }
});

document.getElementById('dashboard-alerts').addEventListener('click', async event => {
  const button = event.target.closest('[data-alert-id]');
  if (!button) return;
  button.disabled = true;
  try {
    const response = await fetch(`/api/business-pulse/alerts/${button.dataset.alertId}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
      body: JSON.stringify({ status: button.dataset.status })
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || 'Could not update alert status.');
    await loadDashboard();
  } catch (error) {
    button.disabled = false;
    showMessage(error.message, true);
  }
});

const query = new URLSearchParams(window.location.search);
if (query.has('start_date') && query.has('end_date')) {
  startInput.value = query.get('start_date');
  endInput.value = query.get('end_date');
} else {
  const initialDays = ['7', '30', '90', '365'].includes(query.get('days')) ? query.get('days') : '30';
  daysInput.value = initialDays;
  setDefaultRange(initialDays);
}
loadDashboard();
