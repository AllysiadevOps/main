import { describe, it, expect, beforeEach, vi } from 'vitest';
import { CheckpointStorage } from './checkpointStorage';

function createMockStorage(): Storage {
  const map = new Map<string, string>();
  const storage: Storage = {
    get length() {
      return map.size;
    },
    clear() {
      map.clear();
    },
    getItem(key: string) {
      return map.has(key) ? map.get(key)! : null;
    },
    key(index: number) {
      return Array.from(map.keys())[index] ?? null;
    },
    removeItem(key: string) {
      map.delete(key);
    },
    setItem(key: string, value: string) {
      map.set(key, value);
    },
  };
  return storage;
}

describe('CheckpointStorage', () => {
  let storage: Storage;
  let checkpoints: CheckpointStorage<{ cursor: number }>;

  beforeEach(() => {
    storage = createMockStorage();
    checkpoints = new CheckpointStorage({
      storage,
      now: () => 1700000000000,
    });
  });

  it('round-trips a checkpoint', () => {
    expect(checkpoints.save('wf', 'step-1', { cursor: 42 })).toBe(true);
    expect(checkpoints.load('wf', 'step-1')).toEqual({ cursor: 42 });
  });

  it('returns null when no checkpoint exists', () => {
    expect(checkpoints.load('wf', 'step-1')).toBe(null);
  });

  it('discards truncated JSON', () => {
    storage.setItem(
      'checkpoint:wf:step-1',
      '{"version":1,"workflowId":"wf',
    );
    expect(checkpoints.load('wf', 'step-1')).toBeNull();
    expect(storage.getItem('checkpoint:wf:step-1')).toBe(null);
  });

  it('discards wrong envelope version', () => {
    storage.setItem(
      'checkpoint:wf:step-1',
      JSON.stringify({
        version: 99,
        workflowId: 'wf',
        stepId: 'step-1',
        timestamp: 1700000000000,
        data: { cursor: 42 },
      }),
    );
    expect(checkpoints.load('wf', 'step-1')).toBeNull();
    expect(storage.getItem('checkpoint:wf:step-1')).toBe(null);
  });

  it('discards tampered workflowId', () => {
    storage.setItem(
      'checkpoint:wf:step-1',
      JSON.stringify({
        version: 1,
        workflowId: 'other',
        stepId: 'step-1',
        timestamp: 1700000000000,
        data: { cursor: 42 },
      }),
    );
    expect(checkpoints.load('wf', 'step-1')).toBeNull();
  });

  it('discards tampered stepId', () => {
    storage.setItem(
      'checkpoint:wf:step-1',
      JSON.stringify({
        version: 1,
        workflowId: 'wf',
        stepId: 'step-2',
        timestamp: 1700000000000,
        data: { cursor: 42 },
      }),
    );
    expect(checkpoints.load('wf', 'step-1')).toBeNull();
  });

  it('discards envelope with invalid timestamp', () => {
    storage.setItem(
      'checkpoint:wf:step-1',
      JSON.stringify({
        version: 1,
        workflowId: 'wf',
        stepId: 'step-1',
        timestamp: 'not-a-number',
        data: { cursor: 42 },
      }),
    );
    expect(checkpoints.load('wf', 'step-1')).toBeNull();
  });

  it('discards envelope missing data', () => {
    storage.setItem(
      'checkpoint:wf:step-1',
      JSON.stringify({
        version: 1,
        workflowId: 'wf',
        stepId: 'step-1',
        timestamp: 1700000000000,
      }),
    );
    expect(checkpoints.load('wf', 'step-1')).toBeNull();
  });

  it('discards envelope that is not an object', () => {
    storage.setItem('checkpoint:wf:step-1', '42');
    expect(checkpoints.load('wf', 'step-1')).toBeNull();
  });

  it('swallows QuotaExceededError on save', () => {
    const error = new Error('quota');
    error.name = 'QuotaExceededError';
    const spy = vi.spyOn(storage, 'setItem').mockImplementation(() => {
      throw error;
    });

    expect(() => checkpoints.save('wf', 'step-1', { cursor: 42 })).not.toThrow();
    expect(checkpoints.save('wf', 'step-2', { cursor: 43 })).toBe(false);
    expect(spy).toHaveBeenCalled();
  });

  it('save returns false when data is unserializable', () => {
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    const store = new CheckpointStorage<unknown>({ storage });
    expect(store.save('wf', 'step-1', circular)).toBe(false);
  });

  it('swallows getItem errors on load', () => {
    vi.spyOn(storage, 'getItem').mockImplementation(() => {
      throw new Error('storage unavailable');
    });
    expect(checkpoints.load('wf', 'step-1')).toBe(null);
  });

  it('remove deletes the checkpoint', () => {
    checkpoints.save('wf', 'step-1', { cursor: 42 });
    checkpoints.remove('wf', 'step-1');
    expect(checkpoints.load('wf', 'step-1')).toBe(null);
  });
});
