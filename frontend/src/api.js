// Client API minimal — toutes les routes du backend au même endroit.
// En dev: proxy Vite vers http://localhost:8000
// En prod: utilise VITE_API_URL (défini dans .env ou via la plateforme)
const BASE = import.meta.env.VITE_API_URL || '/api'

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
