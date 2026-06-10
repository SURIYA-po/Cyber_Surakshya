const resultsEl = document.getElementById('results');

async function postJson(payload) {
  const resp = await fetch('/predict', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload)
  });
  return resp.json();
}

document.getElementById('predict-json').addEventListener('click', async () => {
  const txt = document.getElementById('json-input').value.trim();
  if (!txt) { resultsEl.textContent = 'Enter JSON'; return; }
  let payload;
  try { payload = JSON.parse(txt); } catch(e) { resultsEl.textContent = 'Invalid JSON: ' + e; return; }
  resultsEl.textContent = 'Waiting...';
  const out = await postJson(payload);
  resultsEl.textContent = JSON.stringify(out, null, 2);
});

document.getElementById('predict-csv').addEventListener('click', async () => {
  const f = document.getElementById('csv-file').files[0];
  if (!f) { resultsEl.textContent = 'Select CSV file'; return; }
  const form = new FormData();
  form.append('file', f);
  resultsEl.textContent = 'Uploading...';
  const resp = await fetch('/predict/csv', { method: 'POST', body: form });
  const out = await resp.json();
  resultsEl.textContent = JSON.stringify(out, null, 2);
});

document.getElementById('predict-zeek').addEventListener('click', async () => {
  const f = document.getElementById('zeek-file').files[0];
  if (!f) { resultsEl.textContent = 'Select Zeek conn.log file'; return; }
  const form = new FormData();
  form.append('file', f);
  resultsEl.textContent = 'Uploading...';
  const resp = await fetch('/predict/zeek', { method: 'POST', body: form });
  const out = await resp.json();
  resultsEl.textContent = JSON.stringify(out, null, 2);
});
