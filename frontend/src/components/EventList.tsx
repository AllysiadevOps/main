import { useEffect, useRef } from 'react'
import { useLiveRegion } from '../hooks/useA11y'
import type { ProofEvent } from '../types'
import { shortHash } from '../utils'

type Props = {
  events: ProofEvent[]
  onRefresh: () => void | Promise<void>
}

function formatRefreshAnnouncement(count: number): string {
  if (count === 0) return 'No events loaded'
  return `${count} ${count === 1 ? 'event' : 'events'} loaded`
}

export function EventList({ events, onRefresh }: Props) {
  const { message, announce } = useLiveRegion()
  const pendingRefreshRef = useRef(false)
  const eventsCountRef = useRef(events.length)

  useEffect(() => {
    eventsCountRef.current = events.length
    if (!pendingRefreshRef.current) return
    pendingRefreshRef.current = false
    announce(formatRefreshAnnouncement(events.length))
  }, [events, announce])

  const handleRefresh = () => {
    pendingRefreshRef.current = true
    const result = onRefresh()
    if (result && typeof (result as PromiseLike<unknown>).then === 'function') {
      void Promise.resolve(result).finally(() => {
        if (pendingRefreshRef.current) {
          pendingRefreshRef.current = false
          announce(formatRefreshAnnouncement(eventsCountRef.current))
        }
      })
    }
  }

  return (
    <>
      <button className="verify-input" type="button" onClick={handleRefresh}>
        Refresh recent proofs
      </button>
      <div role="status" aria-live="polite" aria-atomic="true" className="sr-only">
        {message}
      </div>
      <div className="event-list">
        {events.length === 0 ? (
          <p>No events loaded.</p>
        ) : (
          events.map((event) => (
            <div className="event-row" key={event.id}>
              <strong>{event.event_type}</strong>
              <span>{event.tx_status ?? event.tier ?? 'untiered'}</span>
              <code>{shortHash(event.video_hash ?? event.proof_id ?? '')}</code>
              {event.tx_hash ? <code>{shortHash(event.tx_hash)}</code> : null}
              {event.time_attestation ? (
                <details className="event-attestation">
                  <summary>Timestamp attestation</summary>
                  <dl>
                    {event.time_attestation.claimedTime ? (
                      <>
                        <dt>Claimed</dt>
                        <dd>{new Date(event.time_attestation.claimedTime.unixMs).toISOString()}</dd>
                      </>
                    ) : null}
                    {event.time_attestation.observedTime ? (
                      <>
                        <dt>Observed</dt>
                        <dd>{new Date(event.time_attestation.observedTime.unixMs).toISOString()}</dd>
                      </>
                    ) : null}
                    <dt>Stellar anchors</dt>
                    <dd>{event.time_attestation.stellarAnchors?.length ?? 0}</dd>
                    <dt>RFC 3161 anchors</dt>
                    <dd>{event.time_attestation.rfc3161Anchors?.length ?? 0}</dd>
                  </dl>
                </details>
              ) : null}
            </div>
          ))
        )}
      </div>
    </>
  )
}
export default EventList

