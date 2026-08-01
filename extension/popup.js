// Popup PhishGuard AI : demande l'extraction au content script,
// envoie le courriel à l'API locale, affiche le verdict traçable.

const API = 'http://localhost:8000/api/analyze';
const VERDICTS = {
  phishing: ['v-phishing', 'PHISHING'],
  suspicious: ['v-suspicious', 'SUSPECT'],
  legitimate: ['v-legitimate', 'LÉGITIME'],
};

const $ = (sel) => document.querySelector(sel);
const esc = (s) =>
  String(s ?? '').replace(/[&<>"]/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

async function extractFromActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) throw new Error('Onglet actif introuvable.');
  const resp = await chrome.tabs.sendMessage(tab.id, { type: 'EXTRACT_EMAIL' })
    .catch(() => null);
  if (!resp) {
    throw new Error("Ouvrez Gmail ou Outlook Web, puis un courriel, avant d'analyser.");
  }
  if (!resp.ok) throw new Error(resp.error);
  return resp.email;
}

function render(result) {
  const [cls, label] = VERDICTS[result.verdict] || VERDICTS.legitimate;
  const segs = result.signals
    .map((s) => `<div class="seg" style="width:${s.weight}%"
                      title="${esc(s.name)} +${s.weight}"></div>`)
    .join('');
  const items = result.signals
    .map((s) => `<li><code>${esc(s.rule_id)}</code>${esc(s.name)}
                 <span class="w">+${s.weight}</span></li>`)
    .join('');
  $('#result').innerHTML = `
    <p><span class="badge ${cls}">${label} · ${result.final_score}/100</span></p>
    <div class="track">${segs}</div>
    ${items ? `<ul>${items}</ul>` : '<p>Aucune règle déclenchée.</p>'}
    <p class="expl">${esc(result.llm.explanation)}</p>`;
}

$('#scan').addEventListener('click', async () => {
  const btn = $('#scan');
  btn.disabled = true;
  btn.textContent = 'Analyse en cours…';
  $('#result').innerHTML = '';
  try {
    const email = await extractFromActiveTab();
    const res = await fetch(API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(email),
    });
    if (!res.ok) throw new Error(`API locale : erreur ${res.status}`);
    render(await res.json());
  } catch (err) {
    $('#result').innerHTML =
      `<p class="err">${esc(err.message)}</p>` +
      `<p class="err">Vérifiez que le backend tourne : <code>uvicorn app.api.main:app</code></p>`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Analyser le courriel ouvert';
  }
});
