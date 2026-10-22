import type { LineageNode, LinageEdge, LayoutNode, LayoutEdge, LayoutResult } from "../components/LineageGraph";

export interface LayoutInput {
  nodes: LineageNode[];
  edges: LineageEdge[];
}

export interface LayoutOptions {
  nodeWidth?: number;
  nodeHeight?: number;
  hGap?: number;
  vGap?: number;
}

const DEFAULT_OPTIONS: Required<LayoutOptions> = {
  nodeWidth: 160,
  nodeHeight: 40,
  hGap: 40,
  vGap: 20,
};

/**
 * Pure layout function. Computes a simple layered layout for a
 * directed graph using a topological-level assignment.
 */
export function computeLayout(
  input: LayoutInput,
  options: LayoutOptions = {},
): LayoutResult {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  const { nodes, edges } = input;

  if (nodes.length === 0) {
    return { nodes: [], edges: [], width: 0, height: 0 };
  }

  const indexById = new Map<string, number>();
  nodes.forEach((n, i) => indexById.set(n.id, i));

  // Build adjacency list and in-degree counts.
  const adjacency: number[][] = nodes.map(() => []);
  const inDegree = new Array(nodes.length).fill(0);
  for (const edge of edges) {
    const from = indexById.get(edge.from);
    const to = indexById.get(edge.to);
    if (from === undefined || to === undefined) continue;
    adjacency[from].push(to);
    inDegree[to] += 1;
  }

  // Kahn's algorithm to assign layers. Nodes in cycles fall back to layer 0.
  const layer = new Array<number>(nodes.length).fill(0);
  const queue: number[] = [];
  const remaining = inDegree.slice();
  for (let i = 0; i < nodes.length; i++) {
    if (remaining[i] === 0) queue.push(i);
  }
  const visited = new Array(nodes.length).fill(false);
  while (queue.length > 0) {
    const current = queue.shift()!;
    visited[current] = true;
    for (const next of adjacency[current]) {
      layer[next] = Math.max(layer[next], layer[current] + 1);
      remaining[next] -= 1;
      if (remaining[next] === 0) queue.push(next);
    }
  }

  // Nodes in cycles were never visited; put them on layer 0.
  for (let i = 0; i < nodes.length; i++) {
    if (!visited[i]) layer[i] = 0;
  }

  // Group nodes by layer and assign x/y coordinates.
  const layers = new Map<number, number[]>();
  for (let i = 0; i < nodes.length; i++) {
    const l = layer[i];
    if (!layers.has(l)) layers.set(l, []);
    layers.get(l)!.push(i);
  }

  const layoutNodes: LayoutNode[] = new Array(nodes.length);
  const layerKeys = Array.from(layers.keys()).sort((a, b) => a - b);
  let maxX = 0;
  let maxY = 0;
  for (const l of layerKeys) {
    const idxs = layers.get(l)!;
    const y = l * (opts.nodeHeight + opts.vGap);
    for (let j = 0; j < idxs.length; j++) {
      const idx = idxs[j];
      const x = j * (opts.nodeWidth + opts.hGap);
      layoutNodes[idx] = {
        id: nodes[idx].id,
        x,
        y,
        width: opts.nodeWidth,
        height: opts.nodeHeight,
        layer: l,
      };
      maxX = Math.max(maxX, x + opts.nodeWidth);
      maxY = Math.max(maxY, y + opts.nodeHeight);
    }
  }

  const layoutEdges: LayoutEdge[] = [];
  for (const edge of edges) {
    const from = indexById.get(edge.from);
    const to = indexById.get(edge.to);
    if (from === undefined || to === undefined) continue;
    const fromNode = layoutNodes[from];
    const toNode = layoutNodes[to];
    layoutEdges.push({
      id: edge.id ?? `${edge.from}->${edge.to}`,
      from: edge.from,
      to: edge.to,
      x1: fromNode.x + fromNode.width,
      y1: fromNode.y + fromNode.height / 2,
      x2: toNode.x,
      y2: toNode.y + toNode.height / 2,
    });
  }

  return { nodes: layoutNodes, edges: layoutEdges, width: maxX, height: maxY };
}

export interface LayoutRequestMessage {
  type: "layout";
  payload: LayoutInput;
  options?: LayoutOptions;
}

export interface LayoutResponseMessage {
  type: "layout-result";
  result: LayoutResult;
}

export interface LayoutErrorMessage {
  type: "layout-error";
  message: string;
}

const isWorkerContext = (): boolean =>
  typeof self !== "undefined" &&
  typeof (self as unknown as { postMessage?: unknown }).postMessage === "function" &&
  typeof (self as unknown as { addEventListener?: unknown }).addEventListener === "function";

if (isWorkerContext()) {
  self.addEventListener("message", (event: MessageEvent<LayoutRequestMessage>) => {
    const data = event.data;
    if (!data || data.type !== "layout") return;
    try {
      const result = computeLayout(data.payload, data.options);
      const response: LayoutResponseMessage = { type: "layout-result", result };
      self.postMessage(response);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const response: LayoutErrorMessage = { type: "layout-error", message };
      self.postMessage(response);
    }
  });
}
