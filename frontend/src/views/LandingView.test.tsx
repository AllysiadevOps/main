import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { LandingView } from './LandingView'

// Mock WebGL background components to ensure tests run reliably without WebGL support
vi.mock('../components/EvilEye', () => ({
  default: () => <div data-testid="mock-evil-eye" />,
}))

vi.mock('../components/PrismaticBurst', () => ({
  default: () => <div data-testid="mock-prismatic-burst" />,
}))

describe('LandingView', () => {
  it('renders primary calls to action and accessible headings without WebGL dependencies', () => {
    const handleOpenStudio = vi.fn()
    const handleOpenVerify = vi.fn()

    render(
      <LandingView
        onOpenStudio={handleOpenStudio}
        onOpenVerify={handleOpenVerify}
      />,
    )

    // Heading hierarchy checks
    const h1 = screen.getByRole('heading', { level: 1 })
    expect(h1).toHaveTextContent(/evidence integrity for silent witnesses/i)

    const h2 = screen.getByRole('heading', { level: 2 })
    expect(h2).toHaveTextContent(/how it works/i)

    // Ensure only expected headings exist
    const headings = screen.getAllByRole('heading')
    expect(headings).toHaveLength(2)

    // Primary calls to action exist
    const beginButton = screen.getByRole('button', { name: /begin evidence flow/i })
    expect(beginButton).toBeInTheDocument()

    const verifyButton = screen.getByRole('button', { name: /verify an artifact/i })
    expect(verifyButton).toBeInTheDocument()

    // Key protocol specifications and technical strip
    expect(screen.getByRole('group', { name: /protocol status/i })).toBeInTheDocument()
    expect(screen.getByLabelText(/technical specification/i)).toBeInTheDocument()
    expect(screen.getByRole('img', { name: /harpocrates protocol workflow/i })).toBeInTheDocument()
  })

  it('invokes navigation callback when "Begin evidence flow" is clicked', async () => {
    const user = userEvent.setup()
    const handleOpenStudio = vi.fn()
    const handleOpenVerify = vi.fn()

    render(
      <LandingView
        onOpenStudio={handleOpenStudio}
        onOpenVerify={handleOpenVerify}
      />,
    )

    const beginButton = screen.getByRole('button', { name: /begin evidence flow/i })
    await user.click(beginButton)

    expect(handleOpenStudio).toHaveBeenCalledTimes(1)
    expect(handleOpenVerify).not.toHaveBeenCalled()
  })

  it('invokes navigation callback when "Verify an artifact" is clicked', async () => {
    const user = userEvent.setup()
    const handleOpenStudio = vi.fn()
    const handleOpenVerify = vi.fn()

    render(
      <LandingView
        onOpenStudio={handleOpenStudio}
        onOpenVerify={handleOpenVerify}
      />,
    )

    const verifyButton = screen.getByRole('button', { name: /verify an artifact/i })
    await user.click(verifyButton)

    expect(handleOpenVerify).toHaveBeenCalledTimes(1)
    expect(handleOpenStudio).not.toHaveBeenCalled()
  })

  it('supports keyboard navigation and activation for all calls to action', async () => {
    const user = userEvent.setup()
    const handleOpenStudio = vi.fn()
    const handleOpenVerify = vi.fn()

    render(
      <LandingView
        onOpenStudio={handleOpenStudio}
        onOpenVerify={handleOpenVerify}
      />,
    )

    const beginButton = screen.getByRole('button', { name: /begin evidence flow/i })
    const verifyButton = screen.getByRole('button', { name: /verify an artifact/i })

    beginButton.focus()
    expect(beginButton).toHaveFocus()
    await user.keyboard('{Enter}')
    expect(handleOpenStudio).toHaveBeenCalledTimes(1)

    verifyButton.focus()
    expect(verifyButton).toHaveFocus()
    await user.keyboard('{Enter}')
    expect(handleOpenVerify).toHaveBeenCalledTimes(1)
  })

  describe('reduced-motion behaviour', () => {
    it('defines prefers-reduced-motion media query rules covering landing page elements', () => {
      const appCss = readFileSync(join(__dirname, '..', 'App.css'), 'utf8')

      // Assert that reduced-motion rules exist in stylesheet
      expect(appCss).toMatch(/@media\s*\(prefers-reduced-motion:\s*reduce\)/)

      // Ensure landing page elements have animations disabled under reduced motion
      const reducedMotionBlock = appCss.slice(appCss.indexOf('@media (prefers-reduced-motion: reduce)'))
      expect(reducedMotionBlock).toMatch(/\.flow-connector\s*\{[^}]*animation:\s*none/i)
      expect(reducedMotionBlock).toMatch(/\.hero-copy\s+h1[^}]*animation:\s*none/i)
      expect(reducedMotionBlock).toMatch(/\.hero-actions[^}]*animation:\s*none/i)
    })
  })
})
