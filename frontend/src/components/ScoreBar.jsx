// Barre de traçabilité : l'élément signature du dashboard.
// Le score n'est PAS une jauge opaque : chaque segment est une règle,
// sa largeur est son poids. L'explicabilité EST l'interface.

const VERDICT_META = {
  phishing: { label: 'Phishing', className: 'v-phishing' },
  suspicious: { label: 'Suspect', className: 'v-suspicious' },
  legitimate: { label: 'Légitime', className: 'v-legitimate' },
}

export function VerdictBadge({ verdict, score }) {
  const meta = VERDICT_META[verdict] ?? VERDICT_META.legitimate
  return (
    <span className={`badge ${meta.className}`}>
      {meta.label} · {score}/100
    </span>
  )
}

export default function ScoreBar({ signals, rulesScore, llmAdjustment = 0, compact = false }) {
  const total = Math.min(100, rulesScore + Math.max(0, llmAdjustment))
  return (
    <div className={`scorebar ${compact ? 'scorebar-compact' : ''}`}>
      <div
        className="scorebar-track"
        role="img"
        aria-label={`Score ${total} sur 100, ${signals.length} règle(s) déclenchée(s)`}
      >
        {signals.map((s) => (
          <div
            key={s.rule_id}
            className="scorebar-seg"
            style={{ width: `${s.weight}%` }}
            title={`${s.name} (+${s.weight}) — ${s.evidence}`}
          >
            {!compact && s.weight >= 12 && <span>+{s.weight}</span>}
          </div>
        ))}
        {llmAdjustment > 0 && (
          <div
            className="scorebar-seg scorebar-llm"
            style={{ width: `${llmAdjustment}%` }}
            title={`Ajustement LLM : +${llmAdjustment}`}
          />
        )}
      </div>
      {!compact && (
        <div className="scorebar-legend">
          {signals.length === 0
            ? 'Aucune règle déclenchée'
            : signals.map((s) => `${s.rule_id} +${s.weight}`).join(' · ')}
          {llmAdjustment !== 0 && ` · LLM ${llmAdjustment > 0 ? '+' : ''}${llmAdjustment}`}
        </div>
      )}
    </div>
  )
}
