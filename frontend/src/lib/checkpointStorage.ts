import { safeLocalStorage } from './safeLocalStorage';

export interface CheckpointEnvelope<T> {
  version: number;
  workflowId: string;
  stepId: string;
  timestamp: number;
  data: T;
}

export interface CheckpointStorageOptions {
  storage?: Storage;
  now?: () => number;
  keyPrefix?: string;
}

const CURRENT_VERSION = 1;
const DEFAULT_PREFIX = 'checkpoint:';

export class CheckpointStorage<T = unknown> {
  private readonly storage: Storage;
  private readonly now: () => number;
  private readonly keyPrefix: string;

  constructor(options: CheckpointStorageOptions = {}) {
    this.storage = options.storage ?? safeLocalStorage;
    this.now = options.now ?? (() => Date.now());
    this.keyPrefix = options.keyPrefix ?? DEFAULT_PREFIX;
  }

  private keyFor(workflowId: string, stepId: string): string {
    return `${this.keyPrefix}${workflowId}:${stepId}`;
  }

  /**
   * Persist a checkpoint envelope. Quota and other storage errors are
   * swallowed so the workflow can continue without a checkpoint.
   */
  save(workflowId: string, stepId: string, data: T): boolean {
    const envelope: CheckpointEnvelope<T> = {
      version: CURRENT_VERSION,
      workflowId,
      stepId,
      timestamp: this.now(),
      data,
    };

    let serialized: string;
    try {
      serialized = JSON.stringify(envelope);
    } catch {
      // Unserializable data - discard rather than throw.
      return false;
    }

    try {
      this.storage.setItem(this.keyFor(workflowId, stepId), serialized);
      return true;
    } catch {
      // QuotaExceededError or any other storage failure must not break
      // the workflow. Drop the checkpoint and report failure.
      return false;
    }
  }

  /**
   * Load a checkpoint. Returns null for any corrupt, tampered, or
   * incompatible envelope. Corrupt checkpoints are discarded.
   */
  load(workflowId: string, stepId: string): T | null {
    const key = this.keyFor(workflowId, stepId);

    let raw: string | null;
    try {
      raw = this.storage.getItem(key);
    } catch {
      return null;
    }

    if (raw == null) {
      return null;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      // Truncated / invalid JSON.
      this.discard(key);
      return null;
    }

    if (!this.isValidEnvelope(parsed, workflowId, stepId)) {
      this.discard(key);
      return null;
    }

    return (parsed as CheckpointEnvelope<T>).data;
  }

  remove(workflowId: string, stepId: string): void {
    this.discard(this.keyFor(workflowId, stepId));
  }

  private discard(key: string): void {
    try {
      this.storage.removeItem(key);
    } catch {
      // Ignore: failure to remove must not throw to the caller.
    }
  }

  private isValidEnvelope(
    value: unknown,
    workflowId: string,
    stepId: string,
  ): value is CheckpointEnvelope<T> {
    if (typeof value !== 'object' || value === null) {
      return false;
    }

    const env = value as Record<string, unknown>;

    if (env.version !== CURRENT_VERSION) {
      return false;
    }
    if (env.workflowId !== workflowId) {
      return false;
    }
    if (env.stepId !== stepId) {
      return false;
    }
    if (typeof env.timestamp !== 'number' || !Number.isFinite(env.timestamp)) {
      return false;
    }
    if (!('data' in env)) {
      return false;
    }

    return true;
  }
}
