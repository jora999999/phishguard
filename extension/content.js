// PhishGuard AI — content script.
// Extrait le courriel actuellement OUVERT dans Gmail ou Outlook Web.
// Aucune lecture automatique : l'extraction n'a lieu qu'à la demande du popup
// (message EXTRACT_EMAIL), déclenchée par un clic de l'utilisateur.

function extractLinks(container) {
  const links = [];
  const linkTexts = [];
  container.querySelectorAll('a[href^="http"]').forEach((a) => {
    links.push(a.href);
    linkTexts.push((a.textContent || '').trim());
  });
  return { links, linkTexts };
}

function extractGmail() {
  // Vue "conversation ouverte" de Gmail.
  const subject = document.querySelector('h2.hP')?.textContent?.trim() || '';
  const senderEl = document.querySelector('.gD'); // span porteur de l'adresse
  const sender = senderEl?.getAttribute('email') || '';
  const senderDisplay = senderEl?.getAttribute('name') || senderEl?.textContent?.trim() || '';
  const bodyEl = document.querySelector('div.a3s'); // corps du dernier message affiché
  if (!bodyEl) return null;
  const { links, linkTexts } = extractLinks(bodyEl);
  const attachments = [...document.querySelectorAll('span.aV3')]
    .map((el) => el.textContent.trim())
    .filter(Boolean);
  return {
    subject,
    sender,
    sender_display: senderDisplay,
    body_text: bodyEl.innerText || '',
    links,
    link_texts: linkTexts,
    attachments,
  };
}

function extractOutlook() {
  // Vue "lecture" d'Outlook Web (outlook.live.com / outlook.office.com).
  const pane = document.querySelector('[role="main"]');
  if (!pane) return null;
  const subject =
    pane.querySelector('[role="heading"]')?.textContent?.trim() ||
    document.title.split(' - ')[0] ||
    '';
  // L'adresse expéditeur apparaît dans l'infobulle/aria du bloc "From".
  const fromEl = pane.querySelector('span[aria-label*="@"], [title*="@"]');
  const raw = fromEl?.getAttribute('aria-label') || fromEl?.getAttribute('title') || '';
  const sender = (raw.match(/[\w.+-]+@[\w.-]+\.\w+/) || [''])[0];
  const senderDisplay = fromEl?.textContent?.trim() || '';
  const bodyEl = pane.querySelector('[aria-label="Corps du message"], [aria-label="Message body"], .allowTextSelection');
  if (!bodyEl) return null;
  const { links, linkTexts } = extractLinks(bodyEl);
  return {
    subject,
    sender,
    sender_display: senderDisplay,
    body_text: bodyEl.innerText || '',
    links,
    link_texts: linkTexts,
    attachments: [],
  };
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type !== 'EXTRACT_EMAIL') return;
  const host = location.hostname;
  let email = null;
  try {
    if (host.includes('mail.google.com')) email = extractGmail();
    else if (host.includes('outlook')) email = extractOutlook();
  } catch (err) {
    sendResponse({ ok: false, error: String(err) });
    return true;
  }
  if (!email || !email.body_text) {
    sendResponse({
      ok: false,
      error: "Aucun courriel ouvert détecté. Ouvrez d'abord un message.",
    });
  } else {
    sendResponse({ ok: true, email });
  }
  return true; // canal asynchrone
});
