const serviceState = document.querySelector('#service-state');
const healthButton = document.querySelector('#health-check');
const healthResult = document.querySelector('#health-result');

async function readJSON(path) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch(path, { headers: { Accept: 'application/json' }, signal: controller.signal });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } finally {
    clearTimeout(timeout);
  }
}

async function refreshServiceState() {
  try {
    const status = await readJSON('/api/v1/status');
    serviceState.textContent = `${status.lifecycle} · ${status.version}`;
  } catch {
    serviceState.textContent = 'Service unavailable';
  }
}

healthButton.addEventListener('click', async () => {
  healthButton.disabled = true;
  healthResult.textContent = 'Checking…';
  try {
    const result = await readJSON('/healthz');
    healthResult.textContent = result.status === 'ok' ? 'Service is responding.' : 'Service returned an unexpected state.';
  } catch {
    healthResult.textContent = 'The service could not be reached.';
  } finally {
    healthButton.disabled = false;
  }
});

refreshServiceState();
