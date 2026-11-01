import { Link } from 'react-router-dom'

type Crumb = { label: string; to?: string }

export default function Breadcrumbs({ items }: { items: Crumb[] }) {
  return (
    <nav className="text-sm text-neutral-500 dark:text-neutral-400 mb-4" aria-label="Breadcrumb">
      {items.map((item, i) => (
        <span key={item.label}>
          {i > 0 && <span className="mx-2">/</span>}
          {item.to ? (
            <Link to={item.to} className="hover:text-neutral-800 dark:hover:text-neutral-200">
              {item.label}
            </Link>
          ) : (
            <span className="text-neutral-800 dark:text-neutral-200">{item.label}</span>
          )}
        </span>
      ))}
    </nav>
  )
}
