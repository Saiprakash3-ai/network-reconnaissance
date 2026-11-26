import { useEffect, useState } from 'react'
import TopologyGraph from './topology/TopologyGraph'

type Job = { id: number; profile: string; status: string; targets: string[]; summary?: any }

export default function App() {
  const [jobs, setJobs] = useState<Job[]>([])
  const [health, setHealth] = useState<string>('unknown')
  const [selectedJob, setSelectedJob] = useState<number | null>(null)
  const [elements, setElements] = useState<any[] | undefined>(undefined)
  const [error, setError] = useState<string>('')

  useEffect(() => {
    fetch('/api/health').then(r => r.json()).then(d => setHealth(d.status)).catch(() => setHealth('offline'))
    fetch('/api/jobs').then(r => r.json()).then(d => setJobs(d.jobs || [])).catch(() => setJobs([]))
  }, [])

  useEffect(() => {
    if (!selectedJob) { setElements(undefined); return }
    fetch(`/api/jobs/${selectedJob}/topology`)
      .then(r => r.json())
      .then(d => {
        const els = [...(d.elements?.nodes || []), ...(d.elements?.edges || [])]
        setElements(els)
        setError('')
      })
      .catch(e => setError(String(e)))
  }, [selectedJob])

  return (
    <div style={{ fontFamily: 'system-ui, sans-serif', padding: 24, background: '#0b1020', color: '#e6edf3', minHeight: '100vh' }}>
      <h1 style={{ marginBottom: 0 }}>Network Reconnaissance</h1>
      <p style={{ opacity: 0.85 }}>Local-first Advanced Network Reconnaissance & Intelligence Laboratory</p>
      <p><strong>API health:</strong> {health} <span style={{ marginLeft: 16, fontSize: 12, opacity: 0.7 }}>Authorized lab targets only • private-lab-only by default</span></p>

      <div style={{ display: 'grid', gridTemplateColumns: '340px 1fr', gap: 16 }}>
        <div>
          <h2>Recent Jobs</h2>
          <div style={{ background: '#111827', padding: 12, borderRadius: 8, maxHeight: 420, overflow: 'auto' }}>
            {jobs.length === 0 && <div style={{ opacity: 0.7 }}>No jobs yet. Use CLI or API to create one.</div>}
            {jobs.map(j => (
              <button key={j.id} onClick={() => setSelectedJob(j.id)} style={{
                display: 'block', width: '100%', textAlign: 'left', marginBottom: 8, padding: 10,
                borderRadius: 6, border: selectedJob === j.id ? '1px solid #60a5fa' : '1px solid #334155',
                background: selectedJob === j.id ? '#172554' : '#0f172a', color: '#e6edf3', cursor: 'pointer'
              }}>
                <div><strong>#{j.id}</strong> {j.profile} <span style={{ opacity: 0.8 }}>({j.status})</span></div>
                <div style={{ fontSize: 12, opacity: 0.75 }}>{(j.targets || []).join(', ')}</div>
              </button>
            ))}
          </div>
        </div>
        <div>
          <h2>Topology {selectedJob ? `(Job ${selectedJob})` : '(Sample)'}</h2>
          {error && <div style={{ color: '#fca5a5' }}>{error}</div>}
          <TopologyGraph elements={elements} />
        </div>
      </div>
      <p style={{ opacity: 0.7, marginTop: 24, fontSize: 13 }}>
        Safety: no automatic exploitation, no credential harvesting, no unauthorized access. All scans are scope-validated and audit logged.
      </p>
    </div>
  )
}
