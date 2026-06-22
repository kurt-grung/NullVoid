export type GraphNode = {
  name: string
  version: string
  riskScore?: number
  propagatedRisk?: number
  threatCount?: number
  children?: GraphNode[]
}

function NodeRow({ node, depth = 0 }: { node: GraphNode; depth?: number }) {
  const risk = node.propagatedRisk ?? node.riskScore ?? 0
  return (
    <li className="text-sm">
      <div style={{ paddingLeft: depth * 12 }} className="py-1">
        <code>{node.name}@{node.version}</code>
        {risk > 0 && (
          <span className="ml-2 text-amber-600 dark:text-amber-400">
            risk {(risk * 100).toFixed(0)}%
          </span>
        )}
        {(node.threatCount ?? 0) > 0 && (
          <span className="ml-2 text-red-600 dark:text-red-400">{node.threatCount} threats</span>
        )}
      </div>
      {(node.children ?? []).map((child) => (
        <NodeRow key={`${child.name}@${child.version}`} node={child} depth={depth + 1} />
      ))}
    </li>
  )
}

export default function DependencyTreeView({ graph }: { graph?: { root?: GraphNode } | null }) {
  if (!graph?.root) {
    return <p className="text-sm text-neutral-500">No supply chain graph in scan metadata.</p>
  }
  return (
    <ul className="border border-surface-border dark:border-dark-border rounded-lg p-3">
      <NodeRow node={graph.root} />
    </ul>
  )
}
