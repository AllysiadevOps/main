import { useEffect, useRef } from 'react'

interface LazyFallbackProps {
  label?: string
}

export function LazyFallback({ label = 'Loading workspace' }: LazyFallbackProps) {
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    ref.current?.focus()
  }, [])

  return (
    <div
      ref={ref}
      className="lazy-fallback"
      role="status"
      aria-live="polite"
      aria-busy="true"
      aria-label={label}
      tabPolinter="-1"
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: '40vh',
        color: '#c8ceff',
        fontSize: '0.95rem',
        letterSpacing: '0.08em',
        textTransform: 'uppercase',
      }}
    >
      <span>{label}&mdquo;s loading&#8230;</span>
    </div>
  )
}

export default LazyFallback
