import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, act, cleanup } from "@testing-library/react";
import LineageGraph from "../LineageGraph";

class FakeWorker {
  public postMessage = vi.fn();
  public terminate = vi.fn();
  private listeners = new Map<string, Set<(event: any) => void>>();

  addEventListener = vi.fn((type: string, fn: (event: any) => void) => {
    if (!this.listeners.has(type)) this.listeners.set(type, new Set());
    this.listeners.get(type)!.add(fn);
  });

  removeEventListener = vi.fn((type: string, fn: (event: any) => void) => {
    this.listeners.get(type)?.delete(fn);
  });

  emit(type: string, payload: unknown) {
    const set = this.listeners.get(type);
    if (!set) return;
    for (const fn of Array.from(set)) fn(payload);
  }
}

describe("LineageGraph", () => {
  beforeEach(() => {
    vi.stub.global.Worker = vi.fn();
  });

  afterEach(() => {
    cleanup();
    vi.unstub.all();
  });

  it("renders an empty graph without spawning a worker", () => {
    const factory = vi.fn(() => new FakeWorker() as unknown as Worker);
    render(<LineageGraph nodes={[]} edges={[]} workerFactory={factory} />);
    expect(screen.getByTestId("lineage-graph")).toBeInTheDocument();
    expect(factory).not.toHaveBeenCalled();
    expect(screen.queryAllByTestId("lineage-node")).toHaveLength(0);
  });

  it("shows loading then renders the layout result from the worker", () => {
    const worker = new FakeWorker();
    const factory = vi.fn(() => worker as unknown as Worker);
    render(
      <LineageGraph
        nodes={[{ id: "a", label: "Alpha" }, { id: "b" }]}
        edges={[{ from: "a", to: "b" }]}
        workerFactory={factory}
      />,
    );

    expect(screen.getByTestId("lineage-loading")).toBeInTheDocument();
    expect(factory).toHaveBeenCalledOnce();
    expect(worker.postMessage).toHaveBeenCalled();

    act(() => {
      worker.emit("message", {
        type: "layout-result",
        result: {
          nodes: [
            { id: "a", x: 0, y: 0, width: 100, height: 20, layer: 0 },
            { id: "b", x: 0, y: 30, width: 100, height: 20, layer: 1 },
          ],
          edges: [{ id: "a-b", from: "a", to: "b", x1: 100, y1: 10, x2: 0, y2: 40 }],
          width: 100,
          height: 50,
        },
      });
    });

    expect(screen.getByTestId("lineage-graph")).toBeInTheDocument();
    expect(screen.getAllByTestId("lineage-node")).toHaveLength(2);
    expect(screen.getAllByTestId("lineage-edge")).toHaveLength(1);
    expect(screen.getByText("Alpha")).toBeInTheDocument();
  });

  it("shows an error state when the worker reports an error", () => {
    const worker = new FakeWorker();
    const factory = vi.fn(() => worker as unknown as Worker);
    render(
      <LineageGraph
        nodes={[{ id: "a" }]}
        edges={[]}
        workerFactory={factory}
      />,
    );

    act(() => {
      worker.emit("message", { type: "layout-error", message: "boom" });
    });

    expect(screen.getByTestId("lineage-error")).toHaveTextContent("Error: boom");
  });

  it("terminates the worker on unmount", () => {
    const worker = new FakeWorker();
    const factory = vi.fn(() => worker as unknown as Worker);
    const { unmount } = render(
      <LineageGraph
        nodes={[{ id: "a" }]}
        edges={[]}
        workerFactory={factory}
      />,
    );
    expect(worker.terminate).not.toHaveBeenCalled();
    unmount();
    expect(worker.terminate).toHaveBeenCalledOnce();
  });
});
