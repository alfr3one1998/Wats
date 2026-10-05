const state = {
  contacts: [],
  selectedPhone: null,
  filter: 'all',
  query: '',
  webhookUrl: '',
  dashboardLoaded: false
};

const $ = (selector) => document.querySelector(selector);
const loginView = $('#loginView');
const dashboardView = $('#dashboardView');
const contactsTable = $('#contactsTable');
const emptyState = $('#emptyState');
const detailEmpty = $('#detailEmpty');
const detailContent = $('#detailContent');
const setupDialog = $('#setupDialog');
const demoDialog = $('#demoDialog');

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function initials(value) {
  const text = String(value || 'ع').trim();
  return [...text][0] || 'ع';
}

function formatNumber(value) {
  return new Intl.NumberFormat('ar-SA').format(Number(value || 0));
}

function formatDate(value, withTime = true) {
  if (!value) return '—';
  const options = withTime
    ? { dateStyle: 'medium', timeStyle: 'short' }
    : { dateStyle: 'medium' };
  return new Intl.DateTimeFormat('ar-SA', options).format(new Date(value));
}

function relativeTime(value) {
  const seconds = Math.max(0, Math.round((Date.now() - Number(value || 0)) / 1000));
  if (seconds < 60) return 'الآن';
  if (seconds < 3600) return `منذ ${Math.floor(seconds / 60)} د`;
  if (seconds < 86400) return `منذ ${Math.floor(seconds / 3600)} س`;
  return formatDate(value, false);
}

async function request(url, options = {}) {
  const response = await fetch(url, {
    credentials: 'same-origin',
    headers: { 'content-type': 'application/json', ...(options.headers || {}) },
    ...options
  });
  const contentType = response.headers.get('content-type') || '';
  const body = contentType.includes('application/json') ? await response.json() : null;
  if (!response.ok) {
    const error = new Error(body?.error || 'تعذر إكمال الطلب.');
    error.status = response.status;
    throw error;
  }
  return body;
}

function setMessage(element, message = '', success = false) {
  element.textContent = message;
  element.classList.toggle('success', Boolean(message && success));
}

function renderStats(stats) {
  $('#statContacts').textContent = formatNumber(stats.contacts);
  $('#statMessages').textContent = formatNumber(stats.messages);
  $('#statToday').textContent = formatNumber(stats.new_today);
  $('#statNamed').textContent = formatNumber(stats.named);
}

function renderConnection(connection) {
  state.webhookUrl = connection.webhook_url;
  const strip = $('#connectionStrip');
  const text = $('#connectionText');
  strip.classList.toggle('not-ready', !connection.ready);
  text.textContent = connection.ready
    ? 'الربط مؤمّن وجاهز لاستقبال رسائل WhatsApp Business.'
    : 'اللوحة جاهزة، باقي تربط Webhook في إعدادات WhatsApp Business.';
}

function renderContacts() {
  contactsTable.innerHTML = state.contacts
    .map((contact) => {
      const selected = state.selectedPhone === contact.phone ? 'is-selected' : '';
      return `
        <tr class="${selected}" data-phone="${escapeHtml(contact.phone)}" tabindex="0">
          <td>
            <div class="person-cell">
              <span class="avatar">${escapeHtml(initials(contact.display_name))}</span>
              <span>
                <strong>${escapeHtml(contact.display_name)}</strong>
                <small>+${escapeHtml(contact.phone)}</small>
              </span>
            </div>
          </td>
          <td>
            <span class="message-preview">${escapeHtml(contact.last_message_preview || 'رسالة جديدة')}</span>
            <span class="time-label">${escapeHtml(relativeTime(contact.last_message_at))}</span>
          </td>
          <td><span class="count-pill">${formatNumber(contact.total_messages)}</span></td>
          <td><button class="row-arrow" type="button" aria-label="عرض ${escapeHtml(contact.display_name)}">‹</button></td>
        </tr>`;
    })
    .join('');
  emptyState.classList.toggle('is-hidden', state.contacts.length > 0);
}

async function loadDashboard() {
  const params = new URLSearchParams({ filter: state.filter });
  if (state.query) params.set('q', state.query);
  const data = await request(`/api/dashboard?${params}`);
  state.contacts = data.contacts;
  renderStats(data.stats);
  renderConnection(data.connection);
  renderContacts();
  state.dashboardLoaded = true;
}

function openDetail(contact, messages) {
  state.selectedPhone = contact.phone;
  $('#detailAvatar').textContent = initials(contact.display_name);
  $('#detailName').textContent = contact.display_name;
  const phoneLink = $('#detailPhone');
  phoneLink.textContent = `+${contact.phone}`;
  phoneLink.href = `https://wa.me/${contact.phone}`;
  $('#detailFirstMessage').textContent = formatDate(contact.first_message_at, false);
  $('#detailMessageCount').textContent = `${formatNumber(contact.total_messages)} رسالة`;
  $('#selectedPhone').value = contact.phone;
  $('#customName').value = contact.custom_name || '';
  $('#labelsInput').value = (contact.labels || []).join('، ');
  $('#messageCountLabel').textContent = `${formatNumber(messages.length)} آخر رسالة`;
  $('#messagesList').innerHTML = messages.length
    ? messages
        .map(
          (message) => `
          <li>
            <p>${escapeHtml(message.body || 'رسالة جديدة')}</p>
            <time>${escapeHtml(formatDate(message.timestamp))}</time>
          </li>`
        )
        .join('')
    : '<li><p>لا توجد رسائل مسجلة بعد.</p></li>';
  setMessage($('#customerMessage'));
  detailEmpty.classList.add('is-hidden');
  detailContent.classList.remove('is-hidden');
  renderContacts();
}

async function selectContact(phone) {
  try {
    const data = await request(`/api/contacts/${encodeURIComponent(phone)}`);
    openDetail(data.contact, data.messages);
  } catch (error) {
    alert(error.message);
  }
}

async function addDemoMessage() {
  const phone = $('#demoPhone').value;
  const name = $('#demoName').value;
  const message = $('#demoMessage').value;
  const target = $('#demoMessageStatus');
  setMessage(target);
  try {
    const data = await request('/api/demo/inbound', {
      method: 'POST',
      body: JSON.stringify({ phone, name, message })
    });
    demoDialog.close();
    $('#demoForm').reset();
    await loadDashboard();
    await selectContact(data.contact.phone);
  } catch (error) {
    setMessage(target, error.message);
  }
}

async function initialize() {
  try {
    const session = await request('/api/session');
    if (!session.authenticated) return;
    loginView.classList.add('is-hidden');
    dashboardView.classList.remove('is-hidden');
    await loadDashboard();
  } catch (error) {
    console.error(error);
  }
}

$('#loginForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const message = $('#loginMessage');
  setMessage(message);
  try {
    await request('/api/login', {
      method: 'POST',
      body: JSON.stringify({ password: $('#password').value })
    });
    $('#password').value = '';
    loginView.classList.add('is-hidden');
    dashboardView.classList.remove('is-hidden');
    await loadDashboard();
  } catch (error) {
    setMessage(message, error.message);
  }
});

$('#logoutButton').addEventListener('click', async () => {
  await request('/api/logout', { method: 'POST' });
  state.selectedPhone = null;
  dashboardView.classList.add('is-hidden');
  loginView.classList.remove('is-hidden');
});

$('#copyWebhookButton').addEventListener('click', async () => {
  if (!state.webhookUrl) return;
  try {
    await navigator.clipboard.writeText(state.webhookUrl);
    const button = $('#copyWebhookButton');
    const original = button.textContent;
    button.textContent = 'تم النسخ ✓';
    setTimeout(() => { button.textContent = original; }, 1600);
  } catch {
    prompt('انسخ رابط الربط:', state.webhookUrl);
  }
});

$('#showSetupButton').addEventListener('click', () => setupDialog.showModal());
$('#closeSetupButton').addEventListener('click', () => setupDialog.close());
$('#demoButton').addEventListener('click', () => demoDialog.showModal());
$('#closeDemoButton').addEventListener('click', () => demoDialog.close());
$('#demoForm').addEventListener('submit', (event) => {
  event.preventDefault();
  addDemoMessage();
});

contactsTable.addEventListener('click', (event) => {
  const row = event.target.closest('tr[data-phone]');
  if (row) selectContact(row.dataset.phone);
});
contactsTable.addEventListener('keydown', (event) => {
  if ((event.key === 'Enter' || event.key === ' ') && event.target.closest('tr[data-phone]')) {
    event.preventDefault();
    selectContact(event.target.closest('tr[data-phone]').dataset.phone);
  }
});

let searchTimer;
$('#searchInput').addEventListener('input', (event) => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(async () => {
    state.query = event.target.value.trim();
    await loadDashboard();
  }, 260);
});

document.querySelectorAll('.filter-tab').forEach((button) => {
  button.addEventListener('click', async () => {
    state.filter = button.dataset.filter;
    document.querySelectorAll('.filter-tab').forEach((item) => {
      const active = item === button;
      item.classList.toggle('is-active', active);
      item.setAttribute('aria-selected', String(active));
    });
    await loadDashboard();
  });
});

$('#customerForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const phone = $('#selectedPhone').value;
  if (!phone) return;
  const message = $('#customerMessage');
  setMessage(message);
  try {
    const data = await request(`/api/contacts/${encodeURIComponent(phone)}`, {
      method: 'PATCH',
      body: JSON.stringify({
        custom_name: $('#customName').value,
        labels: $('#labelsInput').value
      })
    });
    setMessage(message, 'تم حفظ بيانات العميل.', true);
    await loadDashboard();
    const detail = await request(`/api/contacts/${encodeURIComponent(data.contact.phone)}`);
    openDetail(detail.contact, detail.messages);
  } catch (error) {
    setMessage(message, error.message);
  }
});

initialize();
