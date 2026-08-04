import { useState } from 'react'
import { api } from '../api.js'

const SAMPLE = {
  subject: 'URGENT : votre compte Desjardins sera suspendu dans 24 heures',
  sender: 'securite@desjardlns.com',
  sender_display: 'Desjardins Sécurité',
  reply_to: '',
  body_text:
    'Cher client, nous avons détecté une activité inhabituelle. Confirmez votre mot de passe ' +
    'dans les 24 heures sinon votre compte sera suspendu : ' +
    '<a href="https://desjardlns.com/verify">https://desjardins.com/securite</a>',
  attachments: '',
}

export default function AnalyzeForm() {
  const [form, setForm] = useState({
    subject: '',
    sender: '',
    sender_display: '',
    reply_to: '',
    body_text: '',
    attachments: '',
  })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const set = (field) => (e) => setForm({ ...form, [field]: e.target.value })

  const submit = async () => {
    setBusy(true)
    setError('')
    try {
      const result = await api.analyze({
        ...form,
        attachments: form.attachments
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
      })
      window.location.hash = `#/detail/${result.analysis_id}`
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="panel form-panel">
      <div className="panel-head">
        <h1>Analyser un courriel</h1>
        <button className="btn btn-quiet" onClick={() => setForm(SAMPLE)}>
          Remplir avec un exemple synthétique
        </button>
      </div>

      <div className="grid-2">
        <label>
          Objet
          <input value={form.subject} onChange={set('subject')} placeholder="Objet du courriel" />
        </label>
        <label>
          Expéditeur (adresse réelle)
          <input value={form.sender} onChange={set('sender')} placeholder="nom@domaine.com" />
        </label>
        <label>
          Nom affiché
          <input
            value={form.sender_display}
            onChange={set('sender_display')}
            placeholder="Ex. : Desjardins Sécurité"
          />
        </label>
        <label>
          Reply-To (si différent)
          <input value={form.reply_to} onChange={set('reply_to')} placeholder="Optionnel" />
        </label>
      </div>

      <label>
        Corps du message (texte ou HTML — les liens sont extraits automatiquement)
        <textarea rows={9} value={form.body_text} onChange={set('body_text')} />
      </label>

      <label>
        Pièces jointes (noms de fichiers, séparés par des virgules)
        <input
          value={form.attachments}
          onChange={set('attachments')}
          placeholder="Ex. : facture.pdf.exe, releve.docm"
        />
      </label>

      {error && <p className="error-inline">{error}</p>}

      <button className="btn btn-primary" onClick={submit} disabled={busy || !form.body_text}>
        {busy ? 'Analyse en cours…' : 'Lancer l’analyse'}
      </button>
    </section>
  )
}
