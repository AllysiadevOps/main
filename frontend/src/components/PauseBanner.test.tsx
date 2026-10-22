import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { PauseBanner } from './PauseBanner'

describe('PauseBanner', () => {
  it('hides the banner when not paused', () => {
    render(<PauseBanner paused={false} expiresAt={null} />)
    expect(screen.queryByTestId('pause-banner')).not.toBeInTheDocument()
  })

  it('shows the banner and local expiry time when paused', () => {
    const expiresAt = new Date('2030-01-02T03:04:05Z').getTime()
    render(<PauseBanner paused={true} expiresAt={expiresAt} />)

    const banner = screen.getByTestId('pause-banner')
    expect(banner).toBeInTheDocument()
    expect(banner).toHaveTextContent(/Registration is temporarily paused/)

    // Expiry is rendered in the local time zone.
    const local = new Date(expiresAt).toLocaleString(undefined, {
      dateStyle: 'medium',
      timeStyle: 'short',
    })
    expect(banner).toHaveTextContent(new RegExp(local.replace(/[.*?()[[*^$|\\\\/]/g, '\\$&')))
  })

  it('hides the banner when the pause state read fails (null)', () => {
    render(<PauseBanner paused={Boolean(null)} expiresAt={null} />)
    expect(screen.queryByTestId('pause-banner')).not.toBeInTheDocument()
  })

  it('renders without an expiry time when none is provided', () => {
    render(<PauseBanner paused={true} expiresAt={null} />)
    const banner = screen.getByTestId('pause-banner')
    expect(banner).toBeInTheDocument()
    expect(banner).not.toHaveTextContent(/Pause expires at/)
  })
})
