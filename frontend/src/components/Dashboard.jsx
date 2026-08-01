import { useEffect, useState } from 'react'
import { api } from '../api.js'
import { VerdictBadge } from './ScoreBar.jsx'

export default function Dashboard() {
  const [analyses, setAnalyses] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    api
      .listAnalyses()
      .then(setAnalyses)
      .catch((e) => setError(e.message))
  }, [])

  if (error)
    return (
      <div className="panel error">
        Le backend ne répond pas ({error}). Démarrez-le avec
        <code> uvicorn app.api.main:app --port 8000</code> puis rechargez.
      </div>
    )
  if (!analyses) return <div className="panel">Chargement des analyses…</div>

  const counts = { phishing: 0, suspicious: 0, legitimate: 0 }
  analyses.forEach((a) => (counts[a.verdict] += 1))

  return (
    <section>
      <div className="stat-row">
        <div className="stat v-phishing">
          <strong>{counts.phishing}</strong>
          <span>phishing</span>
        </div>
        <div className="stat v-suspicious">
          <strong>{counts.suspicious}</strong>
          <span>suspects</span>
        </div>
        <div className="stat v-legitimate">
          <strong>{counts.legitimate}</strong>
          <span>légitimes</span>
        </div>
        <div className="stat">
          <strong>{analyses.length}</strong>
          <span>analyses au total</span>
        </div>
      </div>

      {analyses.length === 0 ? (
        <div className="panel empty">
          Aucune analyse pour l'instant. Lancez-en une depuis
          «&nbsp;Analyser un courriel&nbsp;» ou «&nbsp;Analyse par lot&nbsp;».
        </div>
      ) : (
        <div className="panel">
          <table className="analyses">
            <thead>
              <tr>
                <th>Objet</th>
                <th>Expéditeur</th>
                <th>Signaux</th>
                <th>Verdict</th>
                <th aria-label="Actions"></th>
              </tr>
            </thead>
            <tbody>
              {analyses.map((a) => (
                <tr key={a.analysis_id}>
                  <td className="cell-subject">{a.subject || '(sans objet)'}</td>
                  <td className="mono">{a.sender}</td>
                  <td>{a.signal_count}</td>
                  <td>
                    <VerdictBadge verdict={a.verdict} score={a.final_score} />
                  </td>
                  <td>
                    <a className="btn btn-quiet" href={`#/detail/${a.analysis_id}`}>
                      Voir le détail
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}
