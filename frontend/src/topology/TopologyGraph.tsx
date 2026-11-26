import { useEffect, useRef } from 'react'
import cytoscape, { ElementDefinition } from 'cytoscape'

type Props = {
  elements?: ElementDefinition[]
}

const fallback: ElementDefinition[] = [
  { data: { id: 'lab', label: 'Authorized Lab', type: 'network' } },
  { data: { id: 'host1', label: '192.168.56.20', type: 'host' } },
  { data: { id: 'svc1', label: 'ssh:22', type: 'service' } },
  { data: { id: 'e1', source: 'lab', target: 'host1' } },
  { data: { id: 'e2', source: 'host1', target: 'svc1' } },
]

function colorFor(type?: string): string {
  switch (type) {
    case 'network': return '#0f766e'
    case 'host': return '#2563eb'
    case 'port': return '#7c3aed'
    case 'service': return '#0891b2'
    case 'finding': return '#dc2626'
    default: return '#475569'
  }
}

export default function TopologyGraph({ elements }: Props) {
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!ref.current) return
    const cy = cytoscape({
      container: ref.current,
      elements: elements && elements.length ? elements : fallback,
      style: [
        {
          selector: 'node',
          style: {
            label: 'data(label)',
            color: '#e5e7eb',
            'font-size': 10,
            'text-wrap': 'wrap',
            'text-max-width': 80,
            'background-color': (ele: any) => colorFor(ele.data('type')),
            width: 28,
            height: 28,
          },
        },
        { selector: 'edge', style: { 'line-color': '#64748b', width: 1.5, 'curve-style': 'bezier' } },
      ],
      layout: { name: 'cose', animate: false, fit: true, padding: 20 },
    })
    return () => cy.destroy()
  }, [elements])

  return <div ref={ref} style={{ width: '100%', height: 420, border: '1px solid #334155', borderRadius: 8, background: '#020617' }} />
}
