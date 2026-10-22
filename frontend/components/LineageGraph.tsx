import { useEffect, useRef, useState } from "react";

export interface LineageNode {
  id: string;
  label?: string;
}

export interface LineageEdge {
  id?: string;
  from: string;
  to: string;
}

export interface LayoutNode {
  id: string;
  x: number;
  y: number;
  width: number;
  height: number;
  layer: number;
}

export interface LayoutEdge {
  id: string;
  from: string;
  to: string;
  x1: number;
  y1: number;
  x2: number;
  y2: number;
}

export interface LayoutResult {
  nodes: LayoutNode[];
  edges: LayoutEdge[];
  width: number;
  height: number;
}

export interface LineageGraphProps {
  nodes: LineageNode[];
  edges: LineageEdge[];
  workerFactory?: () => Worker;
}

type Status = "loading" | "rendered" | "error";

export default function LineageGraph({ nodes, edges, workerFactory }: LineageGraphProps) {
  const [status, setStatus] = useState<Status>("loading");
  const [layout, setLayout] = useState<LayoutResult | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const workerRef = useRef<Worker | null>(null);

  useEffect(() => {
    setStatus("loading");
    setLayout(null);
    setErrorMessage(null);

    if (nodes.length === 0) {
      setLayout({ nodes: [], edges: [], width: 0, height: 0 });
      setStatus("rendered");
      return undefined;
    }

    const factory =
      workerFactory ??
      (() =>
        new Worker(new URL("../workers/lineage-renderer.worker.ts", import.meta.url), {
          type: "module",
        }));

    let worker: Worker;
    try {
      worker = factory();
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : String(err));
      setStatus("error");
      return undefined;
    }
    workerRef.current = worker;

    const handleMessage = (event: MessageEvent) => {
      const data = event.data as
        | { type: "layout-result"; result: LayoutResult }
        | { type: "layout-error"; message: string }
        | undefined;
      if (!data) return;
      if (data.type === "layout-result") {
        setLayout(data.result);
        setStatus("rendered");
      } else if (data.type === "layout-error") {
        setErrorMessage(data.message);
        setStatus("error");
      }
    };

    const handleError = (event: ErrorEvent) => {
      setErrorMessage(event.message || "Worker error");
      setStatus("error");
    };

    worker.addEventListener("message", handleMessage);
    worker.addEventListener("error", handleError as EventListener);
    worker.postMessage({ type: "layout", payload: { nodes, edges } });

    return () => {
      worker.removeEventListener("message", handleMessage);
      worker.removeEventListener("error", handleError as EventListener);
      worker.terminate();
      if (workerRef.current === worker) workerRef.current = null;
    };
  }, [nodes, edges, workerFactory]);

  if (status === "loading") {
    return (
      <div data-testid="lineage-loading" role="status">
        Loading graph…
      </div>
    );
  }

  if (status === "error") {
    return (
      <div data-testid="lineage-error" role="alert">
        Error: {errorMessage ?? "Unknown error"}
      </div>
    );
  }

  const width = layout?.width ?? 0;
  const height = layout?.height ?? 0;

  return (
    <div data-testid="lineage-graph">
      <svg
        role="img"
        aria-label="Lineage graph"
        width={width || 1}
        height={height || 1}
        viewBox={`0 0 ${width || 1} ${height || 1}`}
      >
        {layout?.edges.map((edge) => (
          <line
            key={edge.id}
            data-testid={"lineage-edge"}
            x1={edge.x1}
            y1={edge.y1}
            x2={edge.x2}
            y2={edge.y2}
            stroke="#888"
            strokeWidth={1}
          />
        ))}
        {layout?.nodes.map((node) => {
          const label = nodes.find((n) => n.id === node.id)?.label ?? node.id;
          return (
            <g key={node.id} data-testid="lineage-node">
              <rect
                x={node.x}
                y={node.y}
                width={node.width}
                height={node.height}
                rx={4}
                fill="#fff"
                stroke="#333"
              />
              <text
                x={node.x + node.width / 2}
                y={node.y + node.height / 2}
                textAnchor="middle"
                dominantBaseline="middle"
                fontSize={12}
              >
                {label}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
