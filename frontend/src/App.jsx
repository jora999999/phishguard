import { useEffect, useState } from 'react'
import Dashboard from './components/Dashboard.jsx'
import AnalyzeForm from './components/AnalyzeForm.jsx'
import Detail from './components/Detail.jsx'
import BatchUpload from './components/BatchUpload.jsx'

// Routage par hash maison : #/, #/analyze, #/batch, #/detail/<id>.
// Volontairement sans react-router : trois routes ne justifient pas la dépendance.
function useHashRoute() {
  const [hash, setHash] = useState(window.location.hash || '#/')
  useEffect(() => {
    const onChange = () => setHash(window.location.hash || '#/')
    window.addEventListener('hashchange', onChange)
    return () => window.removeEventListener('hashchange', onChange)
  }, [])
  return hash
}

const NAV = [
  { hash: '#/', label: 'Tableau de bord' },
  { hash: '#/analyze', label: 'Analyser un courriel' },
  { hash: '#/batch', label: 'Analyse par lot' },
]

export default function App() {
  const hash = useHashRoute()
  const detailId = hash.startsWith('#/detail/') ? hash.slice('#/detail/'.length) : null

  return (
    <div className="shell">
      <header className="topbar">
        <a className="brand" href="#/">
          <span className="brand-mark" aria-hidden="true">▲</span>
          <span>
            PhishGuard <em>AI</em>
            <small>Analyse de phishing explicable</small>
          </span>
        </a>
        <nav aria-label="Navigation principale">
          {NAV.map((item) => (
            <a
              key={item.hash}
              href={item.hash}
              className={hash === item.hash ? 'active' : ''}
            >
              {item.label}
            </a>
          ))}
        </nav>
      </header>

      <main>
        {detailId ? (
          <Detail analysisId={detailId} />
        ) : hash === '#/analyze' ? (
          <AnalyzeForm />
        ) : hash === '#/batch' ? (
          <BatchUpload />
        ) : (
          <Dashboard />
        )}
      </main>

      <footer className="footnote">
        Projet défensif · données synthétiques uniquement · le score est la somme
        traçable des règles déclenchées, l'ajustement LLM est borné à ±15.
      </footer>
    </div>
  )
}
