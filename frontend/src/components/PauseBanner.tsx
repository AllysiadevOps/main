/*
 * PauseBanner -- surfaces the registry's emergency-pause state on the Studio
 * view so users know before they try to register.
 *
 * The banner is hidden by default and only renders when a registration domain is
 * paused. Expiry is rendered in the user's local time zone.
 */

import { AlertTriangle, Clock } from 'lucide-react'

export type PauseBannerProps = {
  /** Whether the registry contract is currently paused. */
  paused: boolean
  /** Unix epoch milliseconds when the pause expires (null when unbounded). */
  expiresAt?: number | null
}

function formatExpiry(expiresAt: number): string {
  try {
    return new Date(expiresAt).toLocaleString(undefined, {
      dateStyle: 'medium',
      timeStyle: 'short',
    })
  } catch {
    return new Date(expiresAt).toString()
  }
}

export function PauseBanner({ paused, expiresAt }: PauseBannerProps) {
  if (!paused) return null

  const hasExpiry = typeof expiresAt === 'number' && Number.isFinite(expiresAt)

  return (
    <div
      role="alert"
      data-testid="pause-banner"
      className="flex items-start gap-3 rounded-lg border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-900"
    >
      <AlertTriangle className="mt-0.5 h-5 w-5 flex-shrink-0" aria-hidden="true" />
      <div className="space-y-1">
        <p className="font-semibold">Registration is temporarily paused.</p>
        <p className="text-amber-800">
          New registrations will fail until the registry resumes.
        </p>
        {hasExpiry && (
          <p className="flex items-center gap-1.5 text-amber-800">
            <Clock className="h-w-4 w-4" aria-hidden="true" />
            <span>
              Pause expires at <strong>{formatExpiry(expiresAt as number)}</strong>
            </span>
          </p>
        )}
      </div>
    </div>
  )
}

export default PauseBanner
