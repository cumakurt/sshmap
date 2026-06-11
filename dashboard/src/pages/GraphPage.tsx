import cytoscape, { type ElementDefinition } from "cytoscape";
import { useEffect, useRef, useState } from "react";
import { api, type GraphEdgeRecord } from "../api";

function cytoscapeNodeId(type: string, id: number): string {
  return `${type}:${id}`;
}

function toCytoscapeElements(edges: GraphEdgeRecord[]): ElementDefinition[] {
  const nodes = new Map<string, ElementDefinition>();

  for (const edge of edges) {
    nodes.set(cytoscapeNodeId(edge.from_type, edge.from_id), {
      data: {
        id: cytoscapeNodeId(edge.from_type, edge.from_id),
        label: edge.from_label,
        node_type: edge.from_type,
      },
    });
    nodes.set(cytoscapeNodeId(edge.to_type, edge.to_id), {
      data: {
        id: cytoscapeNodeId(edge.to_type, edge.to_id),
        label: edge.to_label,
        node_type: edge.to_type,
      },
    });
  }

  const edgeElements = edges.map((edge) => ({
    data: {
      id: `edge:${edge.id}`,
      source: cytoscapeNodeId(edge.from_type, edge.from_id),
      target: cytoscapeNodeId(edge.to_type, edge.to_id),
      label: edge.edge_type,
    },
  }));

  return [...nodes.values(), ...edgeElements];
}

export function GraphPage() {
  const [edges, setEdges] = useState<GraphEdgeRecord[]>([]);
  const [view, setView] = useState<"canvas" | "table">("canvas");
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    api<GraphEdgeRecord[]>("/api/graph").then(setEdges).catch(() => setEdges([]));
  }, []);

  useEffect(() => {
    if (view !== "canvas" || !containerRef.current) {
      return;
    }

    const cy = cytoscape({
      container: containerRef.current,
      elements: toCytoscapeElements(edges.slice(0, 500)),
      style: [
        {
          selector: "node",
          style: {
            "background-color": "#3b82f6",
            label: "data(label)",
            color: "#e7ecf3",
            "font-size": 10,
            "text-wrap": "wrap",
            "text-max-width": "120px",
          },
        },
        {
          selector: "edge",
          style: {
            width: 2,
            "line-color": "#64748b",
            "target-arrow-color": "#64748b",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            label: "data(label)",
            "font-size": 8,
            color: "#94a3b8",
          },
        },
      ],
      layout: { name: "cose", animate: false, fit: true, padding: 30 },
    });

    return () => {
      cy.destroy();
    };
  }, [edges, view]);

  return (
    <>
      <div className="graph-toolbar">
        <span className="muted">{edges.length} graph edges loaded.</span>
        <button type="button" onClick={() => setView("canvas")}>
          Canvas view
        </button>
        <button type="button" onClick={() => setView("table")}>
          Table view
        </button>
      </div>
      <div ref={containerRef} className={view === "canvas" ? "graph-cy" : "graph-cy hidden"} />
      {view === "table" ? (
        <table>
          <thead>
            <tr>
              <th>From</th>
              <th>Edge</th>
              <th>To</th>
              <th>Confidence</th>
            </tr>
          </thead>
          <tbody>
            {edges.slice(0, 200).map((edge) => (
              <tr key={edge.id}>
                <td>{edge.from_label}</td>
                <td>{edge.edge_type}</td>
                <td>{edge.to_label}</td>
                <td>{edge.confidence}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
    </>
  );
}
