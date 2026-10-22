import { describe, it, expect } from "vitest";
import { computeLayout } from "../lineage-renderer.worker";

describe("computeLayout", () => {
  it("returns an empty layout for an empty graph", () => {
    const result = computeLayout({ nodes: [], edges: [] });
    expect(result).toEqual({ nodes: [], edges: [], width: 0, height: 0 });
  });

  it("lays out a small graph in layers", () => {
    const result = computeLayout(
      {
        nodes: [
          { id: "a" },
          { id: "b" },
          { id: "c" },
        ],
        edges: [
          { from: "a", to: "b" },
          { from: "b", to: "c" },
        ],
      },
      { nodeWidth: 100, nodeHeight: 20, hGap: 10, vGap: 10 },
    );

    expect(result.nodes).toHaveLength(3);
    const by = Object.fromEntries(result.nodes.map((n) => [n.id, n]));
    expect(by).toHaveProperty("a");
    expect(by.a.layer).toBe(0);
    expect(by.b.layer).toBe(1);
    expect(by.c.layer).toBe(2);
    expect(by.a.y).toBe(0);
    expect(by.b.y).toBe(30);
    expect(by.c.y).toBe(60);
    expect(result.edges).toHaveLength(2);
    expect(result.width).toBeGreaterThan(0);
    expect(result.height).toBeGreaterThan(0);
  });

  it("places siblings on the same layer side-by-side", () => {
    const result = computeLayout(
      {
        nodes: [{ id: "root" }, { id: "l" }, { id: "r" }],
        edges: [
          { from: "root", to: "l" },
          { from: "root", to: "r" },
        ],
      },
      { nodeWidth: 100, nodeHeight: 20, hGap: 10, vGap: 10 },
    );
    const by = Object.fromEntries(result.nodes.map((n) => [n.id, n]));
    expect(by.root.layer).toBe(0);
    expect(by.l.layer).toBe(1);
    expect(by.r.layer).toBe(1);
    expect(by.l.x).toBe(0);
    expect(by.r.x).toBe(110);
  });

  it("ignores edges referencing missing nodes", () => {
    const result = computeLayout({
      nodes: [{ id: "a" }],
      edges: [{ from: "a", to: "missing" }],
    });
    expect(result.nodes).toHaveLength(1);
    expect(result.edges).toHaveLength(0);
  });
});
