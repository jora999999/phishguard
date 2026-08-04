import { useEffect, useState } from 'react'
import { api } from '../api.js'
import ScoreBar, { VerdictBadge } from './ScoreBar.jsx'

export default function Detail({ analysisId }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    api
      .getAnalysis(analysisId)
      .then(setData)
      .catch((e) => setError(e.message))
  }, [analysisId])

  if (error) return <div className="panel error">Analyse introuvable ({error}).</div>
  if (!data) return <div className="panel">Chargement…</div>

  return (
    <section>
      <div className="panel detail-head">
        <div>
          <p className="eyebrow">Analyse {data.analysis_id} · {data.analyzed_at}</p>
          <h1>{data.subject || '(sans objet)'}</h1>
          <p className="mono muted">
            {data.sender_display && `${data.sender_display} · `}
            {data.sender}
            {data.reply_to && ` · Reply-To : ${data.reply_to}`}
          </p>
        </div>
        <div className="detail-actions">
          <VerdictBadge verdict={data.verdict} score={data.final_score} />
          <div className="export-group">
            <a className="btn btn-quiet" href={api.reportUrl(data.analysis_id, 'md')} download>
              Exporter en Markdown
            </a>
            <a className="btn btn-primary" href={api.reportUrl(data.analysis_id, 'pdf')} download>
              Exporter en PDF
            </a>
          </div>
        </div>
      </div>

      <div className="panel">
        <h2>Traçabilité du score</h2>
        <p className="muted">
          Score des règles : <strong>{data.rules_score}/100</strong> · Ajustement LLM :{' '}
          <strong>
            {data.llm.adjustment >= 0 ? '+' : ''}
            {data.llm.adjustment}
          </strong>{' '}
          (modèle : <code>{data.llm.model}</code>) → score final{' '}
          <strong>{data.final_score}/100</strong>
        </p>
        <ScoreBar
          signals={data.signals}
          rulesScore={data.rules_score}
          llmAdjustment={data.llm.adjustment}
        />
      </div>

      <div className="panel">
        <h2>Signaux détectés ({data.signals.length})</h2>
        {data.signals.length === 0 ? (
          <p className="muted">Aucune règle déclenchée : aucun indicateur de phishing connu.</p>
        ) : (
          <ul className="signal-list">
            {data.signals.map((s) => (
              <li key={s.rule_id}>
                <div className="signal-head">
                  <code className="rule-id">{s.rule_id}</code>
                  <strong>{s.name}</strong>
                  <span className="weight">+{s.weight}</span>
                  {data.llm.validated_rules.includes(s.rule_id) && (
                    <span className="validated" title="Signal confirmé par la couche LLM">
                      ✓ validé LLM
                    </span>
                  )}
                </div>
                <p className="evidence mono">{s.evidence}</p>
                <p className="muted">{s.description}</p>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="panel">
        <h2>Explication</h2>
        <p>{data.llm.explanation}</p>
        {data.llm.recommendations.length > 0 && (
          <>
            <h2>Recommandations</h2>
            <ol className="recos">
              {data.llm.recommendations.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ol>
          </>
        )}
      </div>

      <div className="panel">
        <h2>Corps du message analysé</h2>
        <pre className="body-view">{data.body_text}</pre>
      </div>
    </section>
  )
}
