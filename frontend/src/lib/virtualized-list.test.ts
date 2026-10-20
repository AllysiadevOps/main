import { describe, it, expect } from 'vitest';
import { VirtualizedList } from './virtualized-list';
import type { LineageNode, VirtualizationConfig } from '../types/lineage';

describe('VirtualizedList windowing math', () => {
  const createMockNode = (id: string): LineageNode => ({
    id,
    type: 'proof',
    label: `Node ${id}`,
    metadata: {},
    timestamp: 1000,
    status: 'active',
    childrenIds: [],
  });

  const createMockNodes = (count: number): LineageNode[] =>
    Array.from({ length: count }, (_, i) => createMockNode(`node-${i}`));

  const defaultConfig: VirtualizationConfig = {
    containerHeight: 200,
    itemHeight: 40,
    overscanCount: 2,
    threshold: 10,
  };

  describe('empty list', () => {
    it('handles empty list without virtualization', () => {
      const list = new VirtualizedList(defaultConfig, []);

      expect(list.shouldVirtualize).toBe(false);
      expect(list.startIndex).toBe(0);
      expect(list.endIndex).toBe(0);
      expect(list.visibleItems).toEqual([]);
      expect(list.getVisibleNodeIds()).toEqual([]);
      expect(list.totalHeight).toBe(0);
      expect(list.offsetY).toBe(0);
    });

    it('handles empty list when threshold is 0 (virtualization active)', () => {
      const configZeroThreshold: VirtualizationConfig = {
        ...defaultConfig,
        threshold: -1,
      };
      const list = new VirtualizedList(configZeroThreshold, []);

      expect(list.shouldVirtualize).toBe(true);
      expect(list.startIndex).toBe(0);
      expect(list.endIndex).toBe(0);
      expect(list.visibleItems).toEqual([]);
      expect(list.getVisibleNodeIds()).toEqual([]);
      expect(list.totalHeight).toBe(0);
      expect(list.offsetY).toBe(0);
    });
  });

  describe('below virtualization threshold', () => {
    it('renders all items when count is less than or equal to threshold', () => {
      const items = createMockNodes(10);
      const list = new VirtualizedList(defaultConfig, items);

      expect(list.shouldVirtualize).toBe(false);
      expect(list.startIndex).toBe(0);
      expect(list.endIndex).toBe(10);
      expect(list.visibleItems).toHaveLength(10);
      expect(list.getVisibleNodeIds()).toEqual(items.map((node) => node.id));
      expect(list.totalHeight).toBe(400);
      expect(list.offsetY).toBe(0);
    });
  });

  describe('first page (at top of list with scroll = 0)', () => {
    it('computes correct visible range without negative indices when overscan is configured', () => {
      // containerHeight = 200, itemHeight = 40 => visibleCount = ceil(200/40) = 5
      // overscanCount = 2, scrollTop = 0 => floor(0/40) = 0
      // startIndex = max(0, 0 - 2) = 0 (prevents negative index)
      // endIndex = min(100, 0 + 5 + 2) = 7
      const items = createMockNodes(100);
      const list = new VirtualizedList(defaultConfig, items);

      expect(list.shouldVirtualize).toBe(true);
      expect(list.startIndex).toBe(0);
      expect(list.startIndex).toBeGreaterThanOrEqual(0);
      expect(list.endIndex).toBe(7);
      expect(list.endIndex).toBeLessThanOrEqual(items.length);
      expect(list.visibleItems).toHaveLength(7);
      expect(list.visibleItems[0].id).toBe('node-0');
      expect(list.visibleItems[6].id).toBe('node-6');
      expect(list.getVisibleNodeIds()).toEqual([
        'node-0',
        'node-1',
        'node-2',
        'node-3',
        'node-4',
        'node-5',
        'node-6',
      ]);
      expect(list.offsetY).toBe(0);
      expect(list.totalHeight).toBe(4000);
    });

    it('clamps negative scrollTop to non-negative startIndex and non-negative offsetY', () => {
      const items = createMockNodes(50);
      const list = new VirtualizedList(defaultConfig, items);

      list.updateScroll(-50);
      expect(list.startIndex).toBe(0);
      expect(list.startIndex).toBeGreaterThanOrEqual(0);
      expect(list.offsetY).toBe(0);
    });
  });

  describe('scrolled middle', () => {
    it('computes correct window indices when scrolled to middle', () => {
      // scrollTop = 400 => floor(400 / 40) = 10
      // visibleCount = ceil(200 / 40) = 5
      // overscanCount = 2
      // startIndex = max(0, 10 - 2) = 8
      // endIndex = min(100, 10 + 5 + 2) = 17
      const items = createMockNodes(100);
      const list = new VirtualizedList(defaultConfig, items);

      list.updateScroll(400);

      expect(list.startIndex).toBe(8);
      expect(list.endIndex).toBe(17);
      expect(list.startIndex).toBeGreaterThanOrEqual(0);
      expect(list.endIndex).toBeLessThanOrEqual(items.length);
      expect(list.visibleItems).toHaveLength(9);
      expect(list.visibleItems[0].id).toBe('node-8');
      expect(list.visibleItems[8].id).toBe('node-16');
      expect(list.getVisibleNodeIds()).toEqual([
        'node-8',
        'node-9',
        'node-10',
        'node-11',
        'node-12',
        'node-13',
        'node-14',
        'node-15',
        'node-16',
      ]);
      expect(list.offsetY).toBe(320); // 8 * 40
    });

    it('handles non-integral item offset scroll in the middle', () => {
      // scrollTop = 430 => floor(430 / 40) = 10
      // startIndex = max(0, 10 - 2) = 8
      // endIndex = min(100, 10 + 5 + 2) = 17
      const items = createMockNodes(100);
      const list = new VirtualizedList(defaultConfig, items);

      list.updateScroll(430);

      expect(list.startIndex).toBe(8);
      expect(list.endIndex).toBe(17);
      expect(list.offsetY).toBe(320);
    });
  });

  describe('end of list', () => {
    it('clamps endIndex to items.length without out-of-bounds indices', () => {
      // items = 50, itemHeight = 40, totalHeight = 2000
      // containerHeight = 200 => max scroll is 1800 (items.length * itemHeight - containerHeight)
      // scroll to bottom: 1800 => floor(1800 / 40) = 45
      // visibleCount = 5, overscanCount = 2
      // startIndex = max(0, 45 - 2) = 43
      // endIndex = min(50, 45 + 5 + 2 = 52) = 50
      const items = createMockNodes(50);
      const list = new VirtualizedList(defaultConfig, items);

      const maxScroll = items.length * defaultConfig.itemHeight - defaultConfig.containerHeight;
      list.updateScroll(maxScroll);

      expect(list.startIndex).toBe(43);
      expect(list.startIndex).toBeGreaterThanOrEqual(0);
      expect(list.endIndex).toBe(50);
      expect(list.endIndex).toBeLessThanOrEqual(items.length);
      expect(list.visibleItems).toHaveLength(7);
      expect(list.visibleItems[0].id).toBe('node-43');
      expect(list.visibleItems[6].id).toBe('node-49');
      expect(list.offsetY).toBe(43 * 40);
    });

    it('ensures endIndex never exceeds items.length when scrolled past the bottom', () => {
      const items = createMockNodes(50);
      const list = new VirtualizedList(defaultConfig, items);

      list.updateScroll(3000);

      expect(list.endIndex).toBe(50);
      expect(list.endIndex).toBeLessThanOrEqual(items.length);
      expect(list.startIndex).toBeGreaterThanOrEqual(0);
    });
  });

  describe('overscan behavior', () => {
    it('handles zero overscan count correctly', () => {
      const zeroOverscanConfig: VirtualizationConfig = {
        containerHeight: 200,
        itemHeight: 40,
        overscanCount: 0,
        threshold: 10,
      };
      const items = createMockNodes(50);
      const list = new VirtualizedList(zeroOverscanConfig, items);

      list.updateScroll(200); // index 5
      expect(list.startIndex).toBe(5);
      expect(list.endIndex).toBe(10); // 5 + 5 + 0
      expect(list.visibleItems).toHaveLength(5);
      expect(list.offsetY).toBe(200);
    });

    it('expands visible range symmetrically in middle according to overscanCount', () => {
      const largeOverscanConfig: VirtualizationConfig = {
        containerHeight: 200,
        itemHeight: 40,
        overscanCount: 5,
        threshold: 10,
      };
      const items = createMockNodes(100);
      const list = new VirtualizedList(largeOverscanConfig, items);

      list.updateScroll(400); // index 10
      // startIndex = max(0, 10 - 5) = 5
      // endIndex = min(100, 10 + 5 + 5) = 20
      expect(list.startIndex).toBe(5);
      expect(list.endIndex).toBe(20);
      expect(list.visibleItems).toHaveLength(15);
      expect(list.offsetY).toBe(200);
    });
  });

  describe('boundary and safety guarantees', () => {
    it('guarantees no negative indices and no out-of-bounds indices across scroll range', () => {
      const items = createMockNodes(30);
      const list = new VirtualizedList(defaultConfig, items);
      const maxScroll = items.length * defaultConfig.itemHeight - defaultConfig.containerHeight;

      // Test varying scroll positions within valid scrollable range [0, maxScroll]
      const scrollPositions = [0, 10, 39, 40, 41, 100, 300, 500, maxScroll];

      for (const st of scrollPositions) {
        list.updateScroll(st);
        expect(list.startIndex).toBeGreaterThanOrEqual(0);
        expect(list.startIndex).toBeLessThanOrEqual(list.endIndex);
        expect(list.endIndex).toBeLessThanOrEqual(items.length);
        expect(list.visibleItems.length).toBe(list.endIndex - list.startIndex);
        expect(list.offsetY).toBeGreaterThanOrEqual(0);
      }
    });

    it('updates range dynamically when updateItems is called', () => {
      const initialItems = createMockNodes(5);
      const list = new VirtualizedList(defaultConfig, initialItems);

      expect(list.shouldVirtualize).toBe(false);

      const expandedItems = createMockNodes(50);
      list.updateItems(expandedItems);

      expect(list.shouldVirtualize).toBe(true);
      expect(list.startIndex).toBe(0);
      expect(list.endIndex).toBe(7);
      expect(list.visibleItems).toHaveLength(7);
    });
  });
});
