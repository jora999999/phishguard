import { useState } from 'react'
import { api } from '../api.js'
import { VerdictBadge } from './ScoreBar.jsx'

export default function BatchUpload() {
  const [files, setFiles] = useState([])
  const [report, setReport] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const run = async () => {
    setBusy(true)
    setError('')
    try {
      setReport(await api.analyzeBatch(files))
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <section>
      <div className="panel form-panel">
        <h1>Analyse par lot</h1>
        <p className="muted">
          Déposez plusieurs fichiers <code>.eml</code>, <code>.json</code> ou{' '}
          <code>.txt</code> : chaque courriel est analysé et un rapport agrégé est produit.
        </p>
        <input
          type="file"
          multiple
          accept=".eml,.json,.txt"
          onChange={(e) => setFiles([...e.target.files])}
        />
        {error && <p className="error-inline">{error}</p>}
        <button
          className="btn btn-primary"
          onClick={run}
          disabled={busy || files.length === 0}
        >
          {busy ? 'Analyse en cours…' : `Analyser ${files.length} fichier(s)`}
        </button>
      </div>

      {report && (
        <>
          <div className="stat-row">
            <div className="stat v-phishing">
              <strong>{report.aggregate.phishing}</strong>
              <span>phishing</span>
            </div>
            <div className="stat v-suspicious">
              <strong>{report.aggregate.suspicious}</strong>
              <span>suspects</span>
            </div>
            <div className="stat v-legitimate">
              <strong>{report.aggregate.legitimate}</strong>
              <span>légitimes</span>
            </div>
            <div className="stat">
              <strong>{report.aggregate.avg_score}</strong>
              <span>score moyen</span>
            </div>
          </div>

          <div className="panel">
            <table className="analyses">
              <thead>
                <tr>
                  <th>Fichier</th>
                  <th>Signaux</th>
                  <th>Verdict</th>
                  <th aria-label="Actions"></th>
                </tr>
              </thead>
              <tbody>
                {report.results.map((r) => (
                  <tr key={r.analysis_id}>
                    <td className="mono">{r.file}</td>
                    <td>{r.signal_count}</td>
                    <td>
                      <VerdictBadge verdict={r.verdict} score={r.final_score} />
                    </td>
                    <td>
                      <a className="btn btn-quiet" href={`#/detail/${r.analysis_id}`}>
                        Détail
                      </a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {report.errors.length > 0 && (
              <p className="error-inline">
                {report.errors.length} fichier(s) en erreur :{' '}
                {report.errors.map((e) => e.file).join(', ')}
              </p>
            )}
          </div>
        </>
      )}
    </section>
  )
}
