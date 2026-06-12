use crate::models::{
    BlastRadiusRecord, GraphEdgeRecord, GraphNodeRecord, GraphPathRecord, GraphPathsRecord,
    KeyCompromiseBlastRadiusRecord,
};
use anyhow::{Result, bail};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Write;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum GraphExportFormat {
    Json,
    Dot,
    Cytoscape,
}

impl GraphExportFormat {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "dot" => Ok(Self::Dot),
            "cytoscape" => Ok(Self::Cytoscape),
            other => bail!("unsupported graph export format: {other}"),
        }
    }
}

pub fn render_graph_export(edges: &[GraphEdgeRecord], format: GraphExportFormat) -> Result<String> {
    match format {
        GraphExportFormat::Json => Ok(serde_json::to_string_pretty(edges)?),
        GraphExportFormat::Dot => Ok(render_dot(edges)),
        GraphExportFormat::Cytoscape => Ok(render_cytoscape(edges)?),
    }
}

pub fn edge_traversal_weight(edge: &GraphEdgeRecord) -> i64 {
    match edge.edge_type.as_str() {
        "USER_HAS_PASSWORDLESS_SUDO" => 1,
        "PUBLIC_KEY_CAN_LOGIN_TO_USER" => 2,
        "SSH_CA_GRANTS_USER_ACCESS" => 2,
        "USER_ON_HOST" | "HOST_HAS_USER" => 3,
        "PUBLIC_KEY_REUSED_ON_HOST" => 4,
        "USER_HAS_SUDO_RULE" | "SUDO_RULE_APPLIES_TO_HOST" => 5,
        "CLIENT_CONFIG_PROXY_JUMP" => 6,
        _ => edge.weight.max(1),
    }
}

pub fn find_weighted_path(
    edges: &[GraphEdgeRecord],
    from: GraphNodeRecord,
    to: GraphNodeRecord,
) -> GraphPathRecord {
    find_path_with_strategy(edges, from, to, PathStrategy::WeightedShortest)
}

pub fn find_all_paths(
    edges: &[GraphEdgeRecord],
    from: GraphNodeRecord,
    to: GraphNodeRecord,
    max_paths: usize,
) -> GraphPathsRecord {
    let start = NodeKey::from_node(&from);
    let goal = NodeKey::from_node(&to);
    let adjacency = build_adjacency(edges);
    let labels = build_label_map(edges, &from, &to);
    let mut paths = Vec::new();
    let mut current_path = Vec::<GraphEdgeRecord>::new();
    let mut visited = BTreeSet::from([start.clone()]);

    collect_paths(
        &adjacency,
        &labels,
        &start,
        &goal,
        &mut visited,
        &mut current_path,
        &mut paths,
        max_paths,
    );

    let path_records = paths
        .into_iter()
        .map(|path_edges| build_path_record(&from, &to, &labels, &path_edges))
        .collect::<Vec<_>>();

    GraphPathsRecord {
        from,
        to,
        truncated: path_records.len() >= max_paths,
        paths: path_records,
    }
}

pub fn compute_key_compromise_blast_radius(
    edges: &[GraphEdgeRecord],
    fingerprint: &str,
    entry_points: &[GraphNodeRecord],
) -> KeyCompromiseBlastRadiusRecord {
    let mut adjacency: BTreeMap<NodeKey, Vec<&GraphEdgeRecord>> = BTreeMap::new();
    let mut labels: BTreeMap<NodeKey, GraphNodeRecord> = BTreeMap::new();

    for edge in edges {
        let from_key = NodeKey::new(&edge.from_type, edge.from_id);
        let to_key = NodeKey::new(&edge.to_type, edge.to_id);
        labels.insert(
            from_key.clone(),
            GraphNodeRecord {
                node_type: edge.from_type.clone(),
                node_id: edge.from_id,
                label: edge.from_label.clone(),
            },
        );
        labels.insert(
            to_key.clone(),
            GraphNodeRecord {
                node_type: edge.to_type.clone(),
                node_id: edge.to_id,
                label: edge.to_label.clone(),
            },
        );
        adjacency.entry(from_key).or_default().push(edge);
    }

    let mut reachable_hosts = BTreeMap::<NodeKey, GraphNodeRecord>::new();
    let mut reachable_users = BTreeMap::<NodeKey, GraphNodeRecord>::new();
    let mut passwordless_sudo_hosts = BTreeMap::<NodeKey, GraphNodeRecord>::new();
    let mut total_path_weight = 0i64;

    for entry in entry_points {
        let start = NodeKey::from_node(entry);
        let mut queue = VecDeque::from([(start.clone(), 0i64)]);
        let mut best_weight = BTreeMap::from([(start.clone(), 0i64)]);

        while let Some((node, weight)) = queue.pop_front() {
            if let Some(record) = labels.get(&node) {
                match record.node_type.as_str() {
                    "HOST" => {
                        reachable_hosts.insert(node.clone(), record.clone());
                    }
                    "USER" => {
                        reachable_users.insert(node.clone(), record.clone());
                    }
                    _ => {}
                }
            }

            for edge in adjacency.get(&node).into_iter().flatten() {
                let next = NodeKey::new(&edge.to_type, edge.to_id);
                let next_weight = weight + edge_traversal_weight(edge);
                if best_weight
                    .get(&next)
                    .is_some_and(|existing| *existing <= next_weight)
                {
                    continue;
                }
                best_weight.insert(next.clone(), next_weight);
                total_path_weight = total_path_weight.max(next_weight);
                if edge.edge_type == "USER_HAS_PASSWORDLESS_SUDO"
                    && let Some(record) = labels.get(&next)
                    && record.node_type == "HOST"
                {
                    passwordless_sudo_hosts.insert(next.clone(), record.clone());
                }
                queue.push_back((next, next_weight));
            }
        }
    }

    let reachable_hosts_vec = reachable_hosts.into_values().collect::<Vec<_>>();
    KeyCompromiseBlastRadiusRecord {
        fingerprint: fingerprint.to_string(),
        entry_points: entry_points.to_vec(),
        host_count: reachable_hosts_vec.len(),
        reachable_hosts: reachable_hosts_vec,
        reachable_users: reachable_users.into_values().collect(),
        passwordless_sudo_hosts: passwordless_sudo_hosts.into_values().collect(),
        total_path_weight,
    }
}

enum PathStrategy {
    BreadthFirst,
    WeightedShortest,
}

pub fn find_path(
    edges: &[GraphEdgeRecord],
    from: GraphNodeRecord,
    to: GraphNodeRecord,
) -> GraphPathRecord {
    find_path_with_strategy(edges, from, to, PathStrategy::BreadthFirst)
}

fn find_path_with_strategy(
    edges: &[GraphEdgeRecord],
    from: GraphNodeRecord,
    to: GraphNodeRecord,
    strategy: PathStrategy,
) -> GraphPathRecord {
    let start = NodeKey::from_node(&from);
    let goal = NodeKey::from_node(&to);
    let adjacency = build_adjacency(edges);
    let labels = build_label_map(edges, &from, &to);

    let path_edges = match strategy {
        PathStrategy::BreadthFirst => bfs_path_edges(&adjacency, &start, &goal),
        PathStrategy::WeightedShortest => dijkstra_path_edges(&adjacency, &start, &goal),
    };

    if path_edges.is_empty() && start != goal {
        return GraphPathRecord {
            found: false,
            from,
            to,
            nodes: Vec::new(),
            edges: Vec::new(),
        };
    }

    build_path_record(&from, &to, &labels, &path_edges)
}

fn build_adjacency(edges: &[GraphEdgeRecord]) -> BTreeMap<NodeKey, Vec<&GraphEdgeRecord>> {
    let mut adjacency: BTreeMap<NodeKey, Vec<&GraphEdgeRecord>> = BTreeMap::new();
    for edge in edges {
        let from_key = NodeKey::new(&edge.from_type, edge.from_id);
        adjacency.entry(from_key).or_default().push(edge);
    }
    adjacency
}

fn build_label_map(
    edges: &[GraphEdgeRecord],
    from: &GraphNodeRecord,
    to: &GraphNodeRecord,
) -> BTreeMap<NodeKey, String> {
    let start = NodeKey::from_node(from);
    let goal = NodeKey::from_node(to);
    let mut labels: BTreeMap<NodeKey, String> = BTreeMap::new();
    labels.insert(start, from.label.clone());
    labels.insert(goal, to.label.clone());
    for edge in edges {
        let from_key = NodeKey::new(&edge.from_type, edge.from_id);
        let to_key = NodeKey::new(&edge.to_type, edge.to_id);
        labels.insert(from_key, edge.from_label.clone());
        labels.insert(to_key, edge.to_label.clone());
    }
    labels
}

fn bfs_path_edges(
    adjacency: &BTreeMap<NodeKey, Vec<&GraphEdgeRecord>>,
    start: &NodeKey,
    goal: &NodeKey,
) -> Vec<GraphEdgeRecord> {
    let mut queue = VecDeque::from([start.clone()]);
    let mut visited = BTreeSet::from([start.clone()]);
    let mut parent: BTreeMap<NodeKey, (NodeKey, i64)> = BTreeMap::new();

    while let Some(node) = queue.pop_front() {
        if node == *goal {
            break;
        }
        for edge in adjacency.get(&node).into_iter().flatten() {
            let next = NodeKey::new(&edge.to_type, edge.to_id);
            if visited.insert(next.clone()) {
                parent.insert(next.clone(), (node.clone(), edge.id));
                queue.push_back(next);
            }
        }
    }

    reconstruct_path_edges(adjacency, start, goal, &parent)
}

fn dijkstra_path_edges(
    adjacency: &BTreeMap<NodeKey, Vec<&GraphEdgeRecord>>,
    start: &NodeKey,
    goal: &NodeKey,
) -> Vec<GraphEdgeRecord> {
    let mut distances = BTreeMap::from([(start.clone(), 0i64)]);
    let mut parent: BTreeMap<NodeKey, (NodeKey, i64)> = BTreeMap::new();
    let mut queue = BTreeSet::from([(0i64, start.clone())]);

    while let Some((cost, node)) = queue.pop_first() {
        if node == *goal {
            break;
        }
        if distances.get(&node).is_some_and(|best| *best < cost) {
            continue;
        }
        for edge in adjacency.get(&node).into_iter().flatten() {
            let next = NodeKey::new(&edge.to_type, edge.to_id);
            let next_cost = cost + edge_traversal_weight(edge);
            if distances
                .get(&next)
                .is_some_and(|existing| *existing <= next_cost)
            {
                continue;
            }
            distances.insert(next.clone(), next_cost);
            parent.insert(next.clone(), (node.clone(), edge.id));
            queue.insert((next_cost, next));
        }
    }

    reconstruct_path_edges(adjacency, start, goal, &parent)
}

fn reconstruct_path_edges(
    adjacency: &BTreeMap<NodeKey, Vec<&GraphEdgeRecord>>,
    start: &NodeKey,
    goal: &NodeKey,
    parent: &BTreeMap<NodeKey, (NodeKey, i64)>,
) -> Vec<GraphEdgeRecord> {
    if !parent.contains_key(goal) && start != goal {
        return Vec::new();
    }

    let edge_by_id = adjacency
        .values()
        .flatten()
        .map(|edge| (edge.id, *edge))
        .collect::<BTreeMap<_, _>>();
    let mut path_edges = Vec::new();
    let mut current = goal.clone();
    while current != *start {
        let Some((previous, edge_id)) = parent.get(&current) else {
            break;
        };
        if let Some(edge) = edge_by_id.get(edge_id) {
            path_edges.push((*edge).clone());
        }
        current = previous.clone();
    }
    path_edges.reverse();
    path_edges
}

fn build_path_record(
    from: &GraphNodeRecord,
    to: &GraphNodeRecord,
    labels: &BTreeMap<NodeKey, String>,
    path_edges: &[GraphEdgeRecord],
) -> GraphPathRecord {
    let start = NodeKey::from_node(from);
    let mut path_nodes = Vec::new();
    path_nodes.push(node_record_from_key(&start, labels));
    for edge in path_edges {
        path_nodes.push(GraphNodeRecord {
            node_type: edge.to_type.clone(),
            node_id: edge.to_id,
            label: edge.to_label.clone(),
        });
    }

    GraphPathRecord {
        found: !path_edges.is_empty() || from.node_id == to.node_id,
        from: from.clone(),
        to: to.clone(),
        nodes: path_nodes,
        edges: path_edges.to_vec(),
    }
}

fn collect_paths(
    adjacency: &BTreeMap<NodeKey, Vec<&GraphEdgeRecord>>,
    labels: &BTreeMap<NodeKey, String>,
    current: &NodeKey,
    goal: &NodeKey,
    visited: &mut BTreeSet<NodeKey>,
    current_path: &mut Vec<GraphEdgeRecord>,
    paths: &mut Vec<Vec<GraphEdgeRecord>>,
    max_paths: usize,
) {
    if paths.len() >= max_paths {
        return;
    }
    if current == goal {
        paths.push(current_path.clone());
        return;
    }

    for edge in adjacency.get(current).into_iter().flatten() {
        let next = NodeKey::new(&edge.to_type, edge.to_id);
        if !visited.insert(next.clone()) {
            continue;
        }
        current_path.push((*edge).clone());
        collect_paths(
            adjacency,
            labels,
            &next,
            goal,
            visited,
            current_path,
            paths,
            max_paths,
        );
        current_path.pop();
        visited.remove(&next);
        if paths.len() >= max_paths {
            return;
        }
    }
}

pub fn format_path_text(path: &GraphPathRecord) -> String {
    let mut output = String::new();
    if !path.found {
        writeln!(
            output,
            "No path found from {}:{} to {}:{}.",
            path.from.node_type, path.from.label, path.to.node_type, path.to.label
        )
        .expect("writing to String cannot fail");
        return output;
    }

    writeln!(
        output,
        "Path found from {}:{} to {}:{}",
        path.from.node_type, path.from.label, path.to.node_type, path.to.label
    )
    .expect("writing to String cannot fail");

    for (index, node) in path.nodes.iter().enumerate() {
        writeln!(output, "{}. {} {}", index + 1, node.node_type, node.label)
            .expect("writing to String cannot fail");
        if let Some(edge) = path.edges.get(index) {
            writeln!(
                output,
                "   -> {} ({}, confidence {})",
                edge.edge_type,
                edge.evidence.as_deref().unwrap_or("-"),
                edge.confidence
            )
            .expect("writing to String cannot fail");
        }
    }

    output
}

pub fn compute_blast_radius(
    edges: &[GraphEdgeRecord],
    entry_points: &[GraphNodeRecord],
    username: &str,
) -> BlastRadiusRecord {
    let mut adjacency: BTreeMap<NodeKey, Vec<&GraphEdgeRecord>> = BTreeMap::new();
    let mut labels: BTreeMap<NodeKey, GraphNodeRecord> = BTreeMap::new();

    for edge in edges {
        let from_key = NodeKey::new(&edge.from_type, edge.from_id);
        let to_key = NodeKey::new(&edge.to_type, edge.to_id);
        labels.insert(
            from_key.clone(),
            GraphNodeRecord {
                node_type: edge.from_type.clone(),
                node_id: edge.from_id,
                label: edge.from_label.clone(),
            },
        );
        labels.insert(
            to_key.clone(),
            GraphNodeRecord {
                node_type: edge.to_type.clone(),
                node_id: edge.to_id,
                label: edge.to_label.clone(),
            },
        );
        adjacency.entry(from_key).or_default().push(edge);
    }

    let mut reachable_hosts = BTreeMap::<NodeKey, GraphNodeRecord>::new();
    let mut passwordless_sudo_hosts = BTreeMap::<NodeKey, GraphNodeRecord>::new();
    let mut reachable_public_keys = BTreeMap::<NodeKey, GraphNodeRecord>::new();
    let mut reachable_sudo_rules = BTreeMap::<NodeKey, GraphNodeRecord>::new();

    for entry in entry_points {
        let start = NodeKey::from_node(entry);
        let mut queue = VecDeque::from([start.clone()]);
        let mut visited = BTreeSet::from([start.clone()]);

        while let Some(node) = queue.pop_front() {
            if let Some(record) = labels.get(&node) {
                match record.node_type.as_str() {
                    "HOST" => {
                        reachable_hosts.insert(node.clone(), record.clone());
                    }
                    "PUBLIC_KEY" => {
                        reachable_public_keys.insert(node.clone(), record.clone());
                    }
                    "SUDO_RULE" => {
                        reachable_sudo_rules.insert(node.clone(), record.clone());
                    }
                    _ => {}
                }
            }

            for edge in adjacency.get(&node).into_iter().flatten() {
                let next = NodeKey::new(&edge.to_type, edge.to_id);
                if edge.edge_type == "USER_HAS_PASSWORDLESS_SUDO"
                    && let Some(record) = labels.get(&next)
                    && record.node_type == "HOST"
                {
                    passwordless_sudo_hosts.insert(next.clone(), record.clone());
                }
                if visited.insert(next.clone()) {
                    queue.push_back(next);
                }
            }
        }
    }

    let reachable_hosts_vec = reachable_hosts.into_values().collect::<Vec<_>>();
    let passwordless_sudo_hosts_vec = passwordless_sudo_hosts.into_values().collect::<Vec<_>>();

    BlastRadiusRecord {
        username: username.to_string(),
        entry_points: entry_points.to_vec(),
        reachable_hosts: reachable_hosts_vec.clone(),
        passwordless_sudo_hosts: passwordless_sudo_hosts_vec.clone(),
        reachable_public_keys: reachable_public_keys.into_values().collect(),
        reachable_sudo_rules: reachable_sudo_rules.into_values().collect(),
        host_count: reachable_hosts_vec.len(),
        passwordless_sudo_host_count: passwordless_sudo_hosts_vec.len(),
    }
}

pub fn format_blast_radius_text(record: &BlastRadiusRecord) -> String {
    let mut output = String::new();
    writeln!(
        output,
        "Blast radius for user {} across {} entry point(s)",
        record.username,
        record.entry_points.len()
    )
    .expect("writing to String cannot fail");
    writeln!(output, "Reachable hosts: {}", record.host_count)
        .expect("writing to String cannot fail");
    writeln!(
        output,
        "Passwordless sudo hosts: {}",
        record.passwordless_sudo_host_count
    )
    .expect("writing to String cannot fail");
    writeln!(
        output,
        "Reachable public keys: {}",
        record.reachable_public_keys.len()
    )
    .expect("writing to String cannot fail");
    writeln!(
        output,
        "Reachable sudo rules: {}",
        record.reachable_sudo_rules.len()
    )
    .expect("writing to String cannot fail");

    if !record.entry_points.is_empty() {
        writeln!(output, "\nEntry points:").expect("writing to String cannot fail");
        for entry in &record.entry_points {
            writeln!(output, "- {} {}", entry.node_type, entry.label)
                .expect("writing to String cannot fail");
        }
    }

    if !record.reachable_hosts.is_empty() {
        writeln!(output, "\nReachable hosts:").expect("writing to String cannot fail");
        for host in &record.reachable_hosts {
            writeln!(output, "- {}", host.label).expect("writing to String cannot fail");
        }
    }

    output
}

pub fn format_paths_text(record: &GraphPathsRecord) -> String {
    let mut output = String::new();
    writeln!(
        output,
        "Found {} path(s) from {}:{} to {}:{}",
        record.paths.len(),
        record.from.node_type,
        record.from.label,
        record.to.node_type,
        record.to.label
    )
    .expect("writing to String cannot fail");
    if record.truncated {
        writeln!(output, "Path list truncated at configured limit.")
            .expect("writing to String cannot fail");
    }
    for (index, path) in record.paths.iter().enumerate() {
        writeln!(output, "\nPath {}:", index + 1).expect("writing to String cannot fail");
        output.push_str(&format_path_text(path));
    }
    output
}

pub fn format_key_blast_radius_text(record: &KeyCompromiseBlastRadiusRecord) -> String {
    let mut output = String::new();
    writeln!(
        output,
        "Key compromise blast radius for {}",
        record.fingerprint
    )
    .expect("writing to String cannot fail");
    writeln!(output, "Reachable hosts: {}", record.host_count)
        .expect("writing to String cannot fail");
    writeln!(
        output,
        "Reachable users: {}",
        record.reachable_users.len()
    )
    .expect("writing to String cannot fail");
    writeln!(
        output,
        "Passwordless sudo hosts: {}",
        record.passwordless_sudo_hosts.len()
    )
    .expect("writing to String cannot fail");
    writeln!(output, "Max path weight: {}", record.total_path_weight)
        .expect("writing to String cannot fail");
    output
}

#[derive(Debug, Serialize)]
struct CytoscapeDocument {
    elements: CytoscapeElements,
}

#[derive(Debug, Serialize)]
struct CytoscapeElements {
    nodes: Vec<CytoscapeNode>,
    edges: Vec<CytoscapeEdge>,
}

#[derive(Debug, Serialize)]
struct CytoscapeNode {
    data: CytoscapeNodeData,
}

#[derive(Debug, Serialize)]
struct CytoscapeNodeData {
    id: String,
    label: String,
    node_type: String,
}

#[derive(Debug, Serialize)]
struct CytoscapeEdge {
    data: CytoscapeEdgeData,
}

#[derive(Debug, Serialize)]
struct CytoscapeEdgeData {
    id: String,
    source: String,
    target: String,
    label: String,
    confidence: String,
}

fn render_cytoscape(edges: &[GraphEdgeRecord]) -> Result<String> {
    let mut nodes = BTreeMap::<String, CytoscapeNodeData>::new();

    for edge in edges {
        nodes
            .entry(cytoscape_node_id(&edge.from_type, edge.from_id))
            .or_insert_with(|| CytoscapeNodeData {
                id: cytoscape_node_id(&edge.from_type, edge.from_id),
                label: edge.from_label.clone(),
                node_type: edge.from_type.clone(),
            });
        nodes
            .entry(cytoscape_node_id(&edge.to_type, edge.to_id))
            .or_insert_with(|| CytoscapeNodeData {
                id: cytoscape_node_id(&edge.to_type, edge.to_id),
                label: edge.to_label.clone(),
                node_type: edge.to_type.clone(),
            });
    }

    let document = CytoscapeDocument {
        elements: CytoscapeElements {
            nodes: nodes
                .into_values()
                .map(|data| CytoscapeNode { data })
                .collect(),
            edges: edges
                .iter()
                .map(|edge| CytoscapeEdge {
                    data: CytoscapeEdgeData {
                        id: format!("edge:{}", edge.id),
                        source: cytoscape_node_id(&edge.from_type, edge.from_id),
                        target: cytoscape_node_id(&edge.to_type, edge.to_id),
                        label: edge.edge_type.clone(),
                        confidence: edge.confidence.clone(),
                    },
                })
                .collect(),
        },
    };

    Ok(serde_json::to_string_pretty(&document)?)
}

fn cytoscape_node_id(node_type: &str, node_id: i64) -> String {
    format!("{node_type}:{node_id}")
}

fn render_dot(edges: &[GraphEdgeRecord]) -> String {
    let mut dot = String::from("digraph sshmap {\n  rankdir=LR;\n");
    for edge in edges {
        writeln!(
            dot,
            "  \"{}\" -> \"{}\" [label=\"{}\"];",
            dot_node_id(&edge.from_type, edge.from_id, &edge.from_label),
            dot_node_id(&edge.to_type, edge.to_id, &edge.to_label),
            escape_dot(&edge.edge_type)
        )
        .expect("writing to String cannot fail");
    }
    dot.push_str("}\n");
    dot
}

fn dot_node_id(node_type: &str, node_id: i64, label: &str) -> String {
    escape_dot(&format!("{node_type}:{node_id} {label}"))
}

fn escape_dot(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn node_record_from_key(key: &NodeKey, labels: &BTreeMap<NodeKey, String>) -> GraphNodeRecord {
    GraphNodeRecord {
        node_type: key.node_type.clone(),
        node_id: key.node_id,
        label: labels.get(key).cloned().unwrap_or_else(|| key.to_string()),
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct NodeKey {
    node_type: String,
    node_id: i64,
}

impl NodeKey {
    fn new(node_type: &str, node_id: i64) -> Self {
        Self {
            node_type: node_type.to_string(),
            node_id,
        }
    }

    fn from_node(node: &GraphNodeRecord) -> Self {
        Self::new(&node.node_type, node.node_id)
    }
}

impl std::fmt::Display for NodeKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}:{}", self.node_type, self.node_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_graph_export_formats() {
        assert_eq!(
            GraphExportFormat::parse("json").unwrap(),
            GraphExportFormat::Json
        );
        assert_eq!(
            GraphExportFormat::parse("DOT").unwrap(),
            GraphExportFormat::Dot
        );
        assert_eq!(
            GraphExportFormat::parse("cytoscape").unwrap(),
            GraphExportFormat::Cytoscape
        );
        assert!(GraphExportFormat::parse("xml").is_err());
    }

    #[test]
    fn renders_cytoscape_export() {
        let edges = vec![GraphEdgeRecord {
            id: 1,
            from_type: "user".to_string(),
            from_id: 1,
            from_label: "deploy".to_string(),
            to_type: "host".to_string(),
            to_id: 2,
            to_label: "web01".to_string(),
            edge_type: "USER_HOST".to_string(),
            weight: 1,
            confidence: "HIGH".to_string(),
            evidence: None,
        }];

        let rendered = render_graph_export(&edges, GraphExportFormat::Cytoscape).unwrap();
        assert!(rendered.contains("\"elements\""));
        assert!(rendered.contains("user:1"));
        assert!(rendered.contains("host:2"));
    }

    #[test]
    fn finds_directed_path() {
        let edges = vec![public_key_to_user_edge(1), user_to_host_edge(2)];
        let path = find_path(
            &edges,
            GraphNodeRecord {
                node_type: "PUBLIC_KEY".to_string(),
                node_id: 1,
                label: "key".to_string(),
            },
            GraphNodeRecord {
                node_type: "HOST".to_string(),
                node_id: 3,
                label: "web01".to_string(),
            },
        );

        assert!(path.found);
        assert_eq!(path.edges.len(), 2);
        assert_eq!(path.nodes.len(), 3);
    }

    #[test]
    fn renders_dot_graph() {
        let dot = render_dot(&[public_key_to_user_edge(1)]);

        assert!(dot.contains("digraph sshmap"));
        assert!(dot.contains("PUBLIC_KEY_CAN_LOGIN_TO_USER"));
    }

    #[test]
    fn computes_blast_radius_from_user_entry_points() {
        let edges = vec![public_key_to_user_edge(1), user_to_host_edge(2)];
        let entry_points = vec![GraphNodeRecord {
            node_type: "USER".to_string(),
            node_id: 2,
            label: "deploy@web01".to_string(),
        }];
        let blast_radius = compute_blast_radius(&edges, &entry_points, "deploy");

        assert_eq!(blast_radius.host_count, 1);
        assert_eq!(blast_radius.entry_points.len(), 1);
    }

    #[test]
    fn counts_passwordless_sudo_when_reached_by_alternate_path_first() {
        let mut edges = vec![
            GraphEdgeRecord {
                id: 1,
                from_type: "USER".to_string(),
                from_id: 2,
                from_label: "deploy@web01".to_string(),
                to_type: "HOST".to_string(),
                to_id: 3,
                to_label: "web01".to_string(),
                edge_type: "USER_ON_HOST".to_string(),
                weight: 1,
                confidence: "HIGH".to_string(),
                evidence: None,
            },
            GraphEdgeRecord {
                id: 2,
                from_type: "USER".to_string(),
                from_id: 2,
                from_label: "deploy@web01".to_string(),
                to_type: "HOST".to_string(),
                to_id: 3,
                to_label: "web01".to_string(),
                edge_type: "USER_HAS_PASSWORDLESS_SUDO".to_string(),
                weight: 1,
                confidence: "HIGH".to_string(),
                evidence: None,
            },
        ];
        let entry_points = vec![GraphNodeRecord {
            node_type: "USER".to_string(),
            node_id: 2,
            label: "deploy@web01".to_string(),
        }];
        let blast_radius = compute_blast_radius(&edges, &entry_points, "deploy");

        assert_eq!(blast_radius.passwordless_sudo_host_count, 1);
        edges.reverse();
        let blast_radius = compute_blast_radius(&edges, &entry_points, "deploy");
        assert_eq!(blast_radius.passwordless_sudo_host_count, 1);
    }

    fn public_key_to_user_edge(id: i64) -> GraphEdgeRecord {
        GraphEdgeRecord {
            id,
            from_type: "PUBLIC_KEY".to_string(),
            from_id: 1,
            from_label: "key".to_string(),
            to_type: "USER".to_string(),
            to_id: 2,
            to_label: "deploy@web01".to_string(),
            edge_type: "PUBLIC_KEY_CAN_LOGIN_TO_USER".to_string(),
            weight: 1,
            confidence: "HIGH".to_string(),
            evidence: None,
        }
    }

    fn user_to_host_edge(id: i64) -> GraphEdgeRecord {
        GraphEdgeRecord {
            id,
            from_type: "USER".to_string(),
            from_id: 2,
            from_label: "deploy@web01".to_string(),
            to_type: "HOST".to_string(),
            to_id: 3,
            to_label: "web01".to_string(),
            edge_type: "USER_ON_HOST".to_string(),
            weight: 1,
            confidence: "HIGH".to_string(),
            evidence: None,
        }
    }
}
