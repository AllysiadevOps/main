export const COMPATIBILITY_RELEASE_ID = 'harpocrates-1.0.0'
export const COMPATIBILITY_NETWORK = 'testnet'

export interface ReleaseCompatibilityResult {
  compatible: boolean
  expectedReleaseId: string
  expectedNetwork: string
  configuredReleaseId: string
  configuredNetwork: string
  message?: string
}

/** Check compatibility without throwing an error. */
export function checkReleaseCompatibility(env?: { releaseId?: string; network?: string }): ReleaseCompatibilityResult {
  const envReleaseId =
    env?.releaseId ??
    (typeof process !== 'undefined' && process.env?.VITE_HARPOCRATES_RELEASE_ID
      ? process.env.VITE_HARPOCRATES_RELEASE_ID
      : undefined) ??
    import.meta.env.VITE_HARPOCRATES_RELEASE_ID ??
    COMPATIBILITY_RELEASE_ID

  const envNetwork =
    env?.network ??
    (typeof process !== 'undefined' && process.env?.VITE_HARPOCRATES_RELEASE_NETWORK
      ? process.env.VITE_HARPOCRATES_RELEASE_NETWORK
      : undefined) ??
    import.meta.env.VITE_HARPOCRATES_RELEASE_NETWORK ??
    COMPATIBILITY_NETWORK

  const configuredReleaseId = envReleaseId
  const configuredNetwork = envNetwork

  const compatible = configuredReleaseId === COMPATIBILITY_RELEASE_ID && configuredNetwork === COMPATIBILITY_NETWORK

  const result: ReleaseCompatibilityResult = {
    compatible,
    expectedReleaseId: COMPATIBILITY_RELEASE_ID,
    expectedNetwork: COMPATIBILITY_NETWORK,
    configuredReleaseId,
    configuredNetwork,
  }

  if (!compatible) {
    result.message = `Incompatible release configuration. Expected release "${COMPATIBILITY_RELEASE_ID}" on network "${COMPATIBILITY_NETWORK}", but configured with release "${configuredReleaseId}" on network "${configuredNetwork}".`
  }

  return result
}

/** Fail closed before a proof or transaction can cross a release boundary. */
export function assertReleaseCompatibility(): void {
  const result = checkReleaseCompatibility()
  if (!result.compatible) {
    throw new Error(result.message ?? 'This frontend is not configured for the approved Harpocrates compatibility release.')
  }
}
