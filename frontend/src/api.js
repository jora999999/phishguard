// Client API minimal — toutes les routes du backend au même endroit.
const BASE = '/api'

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, options)
  if (!res.ok) throw new Error(`API ${res.status} : ${await res.text()}`)
  return res.json()
}

export const api = {
  health: () => request('/health'),
  analyze: (email) =>
    request('/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(email),
    }),
  analyzeBatch: (files) => {
    const form = new FormData()
    files.forEach((f) => form.append('files', f))
    return request('/analyze/batch', { method: 'POST', body: form })
  },
  listAnalyses: () => request('/analyses'),
  getAnalysis: (id) => request(`/analyses/${id}`),
  reportUrl: (id, format) => `${BASE}/analyses/${id}/report.${format}`,
}
