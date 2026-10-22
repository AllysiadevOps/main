import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { ProofEvent } from '../types';
import EventList, { Event } from './EventList';

const makeEvent = (overrides: Partial<ProofEvent> = {}): ProofEvent => ({
  id: 1,
  event_type: 'registered',
  file_name: null,
  video_hash: '0xabcdef1234567890abcdef1234567890abcdef1234567890',
  proof_id: 'proof-1',
  tx_hash: '0xabcdef1234567890abcdef1234567890abcdef1234567890',
  tx_status: 'confirmed',
  tier: 'silent',
  created_at: '2026-01-01T00:00:00Z',
  ...overrides,
})

describe('EventList', () => {
  it('renders the ISO string for a valid claimed time', () => {
    const events: Event[] = [
      {
        id: 'valid',
        title: 'Valid event',
        time_attestation: {
          claimedTime: { unixMs: 1700000000000 },
          observedTime: { unixMs: 1700000000000 },
        },
      },
    ];

    render(<EventList events={events} />);

    const expected = new Date(1700000000000).toISOString();
    expect(screen.getAllByText(expected).length).toBe(2);
  });

  it('renders a placeholder for a non-finite claimed time', () => {
    const events: Event[] = [
      {
        id: 'invalid',
        title: 'Invalid event',
        time_attestation: {
          claimedTime: { unixMs: NaN },
          observedTime: null,
        },
      },
    ];

    render(<EventList events={events} />);

    expect(screen.getByText('invalid time')).toBeTruthy();
  });

  it('renders a user-facing refresh button label without internal infrastructure names', () => {
    render(<EventList events={[]} onRefresh={() => {}} />)
    const button = screen.getByRole('button', { name: 'Refresh recent proofs' })
    expect(button).toBeInTheDocument()
    expect(button).not.toHaveTextContent(/neondb/i)
  })

  it('does not announce before refresh is triggered', () => {
    render(<EventList events={[makeEvent()]} onRefresh={() => {}} />)
    const liveRegion = screen.getByRole('status')
    expect(liveRegion).toHaveAttribute('aria-live', 'polite')
    expect(liveRegion).toHaveTextContent('')
  })

  it('announces "N events loaded" once per refresh when events are loaded', () => {
    const events = [makeEvent({ id: 1 }), makeEvent({ id: 2 })]
    const onRefresh = vi.fn()
    const { rerender } = render(<EventList events={[]} onRefresh={onRefresh} />)

    fireEvent.click(screen.getByRole('button', { name: 'Refresh recent proofs' }))
    expect(onRefresh).toHaveBeenCalledTimes(1)

    rerender(<EventList events={events} onRefresh={onRefresh} />)

    const liveRegion = screen.getByRole('status')
    expect(liveRegion).toHaveAttribute('aria-live', 'polite')
    expect(liveRegion).toHaveTextContent('2 events loaded')

    // Subsequent unrelated rerenders do not re-trigger the announcement
    rerender(<EventList events={[makeEvent({ id: 1 })]} onRefresh={onRefresh} />)
    expect(liveRegion).toHaveTextContent('2 events loaded')
  })

  it('announces "1 event loaded" for a single event after refresh', () => {
    const onRefresh = vi.fn()
    const { rerender } = render(<EventList events={[]} onRefresh={onRefresh} />)

    fireEvent.click(screen.getByRole('button', { name: 'Refresh recent proofs' }))
    rerender(<EventList events={[makeEvent({ id: 1 })]} onRefresh={onRefresh} />)

    expect(screen.getByRole('status')).toHaveTextContent('1 event loaded')
  })

  it('announces "No events loaded" via polite live region when refresh returns zero events', () => {
    const onRefresh = vi.fn()
    const { rerender } = render(<EventList events={[makeEvent()]} onRefresh={onRefresh} />)

    fireEvent.click(screen.getByRole('button', { name: 'Refresh recent proofs' }))
    rerender(<EventList events={[]} onRefresh={onRefresh} />)

    const liveRegion = screen.getByRole('status')
    expect(liveRegion).toHaveAttribute('aria-live', 'polite')
    expect(liveRegion).toHaveTextContent('No events loaded')
  })
})