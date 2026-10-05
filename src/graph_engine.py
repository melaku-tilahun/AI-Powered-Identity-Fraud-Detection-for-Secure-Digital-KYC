from __future__ import annotations

from typing import Any, Dict, Tuple

import networkx as nx

from src.onboarding import OnboardingEvent


# ============================================================
# GRAPH CONSTRUCTION
# ============================================================

def build_onboarding_graph(
    onboarding: OnboardingEvent,
) -> nx.Graph:
    """
    Build an onboarding relationship graph.

    Node types:
        Identity
        Device
        Account
        Session
        Network

    The graph is intentionally implemented with NetworkX so the
    prototype does not require a separate graph database.
    """

    graph = nx.Graph()

    # --------------------------------------------------------
    # Core nodes
    # --------------------------------------------------------

    identity_node = onboarding.identity_id
    device_node = onboarding.device_id
    account_node = onboarding.account_id
    session_node = onboarding.session_id
    network_node = onboarding.network_id

    graph.add_node(
        identity_node,
        node_type="identity",
    )

    graph.add_node(
        device_node,
        node_type="device",
    )

    graph.add_node(
        account_node,
        node_type="account",
    )

    graph.add_node(
        session_node,
        node_type="session",
    )

    graph.add_node(
        network_node,
        node_type="network",
    )

    # --------------------------------------------------------
    # Core relationships
    # --------------------------------------------------------

    graph.add_edge(
        identity_node,
        account_node,
        relationship="owns_account",
    )

    graph.add_edge(
        identity_node,
        device_node,
        relationship="uses_device",
    )

    graph.add_edge(
        identity_node,
        session_node,
        relationship="initiates_session",
    )

    graph.add_edge(
        session_node,
        device_node,
        relationship="originates_from_device",
    )

    graph.add_edge(
        session_node,
        network_node,
        relationship="uses_network",
    )

    graph.add_edge(
        device_node,
        network_node,
        relationship="connected_to_network",
    )

    # --------------------------------------------------------
    # Coordinated-fraud relationships
    # --------------------------------------------------------

    metadata = onboarding.metadata or {}

    coordinated_identities = metadata.get(
        "coordinated_identities",
        [],
    )

    # The scenario metadata may store the identities directly
    # or inside a nested scenario object.
    if not coordinated_identities:

        coordinated_identities = metadata.get(
            "scenario_data",
            {},
        ).get(
            "coordinated_identities",
            [],
        )

    for coordinated_identity in coordinated_identities:

        if coordinated_identity == identity_node:
            continue

        graph.add_node(
            coordinated_identity,
            node_type="identity",
        )

        graph.add_edge(
            coordinated_identity,
            device_node,
            relationship="shares_device",
        )

        graph.add_edge(
            coordinated_identity,
            network_node,
            relationship="shares_network",
        )

    # --------------------------------------------------------
    # Synthetic account relationships
    # --------------------------------------------------------

    coordinated_accounts = metadata.get(
        "coordinated_accounts",
        [],
    )

    for coordinated_account in coordinated_accounts:

        graph.add_node(
            coordinated_account,
            node_type="account",
        )

        graph.add_edge(
            coordinated_account,
            device_node,
            relationship="associated_with_device",
        )

        graph.add_edge(
            coordinated_account,
            network_node,
            relationship="associated_with_network",
        )

    # --------------------------------------------------------
    # Add synthetic relationship evidence based on signal
    # values.
    #
    # This allows scenarios that don't explicitly provide all
    # identity IDs to still demonstrate graph coordination.
    # --------------------------------------------------------

    if onboarding.device_reuse_count >= 2:

        for index in range(
            max(0, onboarding.device_reuse_count - 1)
        ):

            synthetic_identity = (
                f"RELATED-ID-{index + 1:03d}"
            )

            # Don't duplicate the current identity.
            if synthetic_identity == identity_node:
                continue

            graph.add_node(
                synthetic_identity,
                node_type="identity",
            )

            graph.add_edge(
                synthetic_identity,
                device_node,
                relationship="shares_device",
            )

    if onboarding.network_identity_count >= 2:

        for index in range(
            max(0, onboarding.network_identity_count - 1)
        ):

            synthetic_identity = (
                f"NETWORK-ID-{index + 1:03d}"
            )

            if synthetic_identity == identity_node:
                continue

            graph.add_node(
                synthetic_identity,
                node_type="identity",
            )

            graph.add_edge(
                synthetic_identity,
                network_node,
                relationship="shares_network",
            )

    return graph


# ============================================================
# GRAPH ANALYSIS
# ============================================================

def analyze_graph(
    graph: nx.Graph,
    identity_id: str,
    device_id: str,
    network_id: str,
) -> Dict[str, Any]:
    """
    Analyze the onboarding graph and return graph-derived
    fraud-risk signals.
    """

    if graph is None:
        return {
            "score": 0.0,
            "suspicious_relationships": 0,
            "identity_connections": 0,
            "device_connections": 0,
            "network_connections": 0,
            "centrality": 0.0,
            "signals": [],
        }

    # --------------------------------------------------------
    # Node degrees
    # --------------------------------------------------------

    identity_degree = (
        graph.degree(identity_id)
        if identity_id in graph
        else 0
    )

    device_degree = (
        graph.degree(device_id)
        if device_id in graph
        else 0
    )

    network_degree = (
        graph.degree(network_id)
        if network_id in graph
        else 0
    )

    # --------------------------------------------------------
    # Count identity relationships around the device
    # --------------------------------------------------------

    device_identity_count = 0

    if device_id in graph:

        for neighbor in graph.neighbors(
            device_id
        ):

            node_data = graph.nodes[neighbor]

            if node_data.get("node_type") == "identity":
                device_identity_count += 1

    # --------------------------------------------------------
    # Count identities around network
    # --------------------------------------------------------

    network_identity_count = 0

    if network_id in graph:

        for neighbor in graph.neighbors(
            network_id
        ):

            node_data = graph.nodes[neighbor]

            if node_data.get("node_type") == "identity":
                network_identity_count += 1

    # --------------------------------------------------------
    # Suspicious relationships
    # --------------------------------------------------------

    suspicious_relationships = 0
    signals = []

    if device_identity_count >= 3:

        suspicious_relationships += (
            device_identity_count - 1
        )

        signals.append(
            f"{device_identity_count} identities "
            f"are connected to the same device"
        )

    if network_identity_count >= 3:

        suspicious_relationships += (
            network_identity_count - 1
        )

        signals.append(
            f"{network_identity_count} identities "
            f"are connected to the same network"
        )

    # --------------------------------------------------------
    # Device centrality
    # --------------------------------------------------------

    try:

        centrality = nx.degree_centrality(
            graph
        ).get(
            device_id,
            0.0,
        )

    except Exception:
        centrality = 0.0

    # --------------------------------------------------------
    # Graph risk score
    # --------------------------------------------------------

    score = 0.0

    # Shared device
    if device_identity_count >= 2:

        score += min(
            40.0,
            device_identity_count * 8.0,
        )

    # Shared network
    if network_identity_count >= 2:

        score += min(
            25.0,
            network_identity_count * 5.0,
        )

    # High-degree device
    if device_degree >= 4:

        score += 15.0

    # High-degree network
    if network_degree >= 5:

        score += 10.0

    # High centrality
    if centrality >= 0.30:

        score += 10.0

    score = min(
        100.0,
        score,
    )

    # --------------------------------------------------------
    # Add explicit graph signals
    # --------------------------------------------------------

    if device_degree >= 4:

        signals.append(
            "Device has unusually high graph connectivity"
        )

    if network_degree >= 5:

        signals.append(
            "Network node has unusually high connectivity"
        )

    if centrality >= 0.30:

        signals.append(
            "Device has high graph centrality"
        )

    return {
        "score": round(score, 2),

        "suspicious_relationships": (
            suspicious_relationships
        ),

        "identity_connections": (
            identity_degree
        ),

        "device_connections": (
            device_degree
        ),

        "network_connections": (
            network_degree
        ),

        "device_identity_count": (
            device_identity_count
        ),

        "network_identity_count": (
            network_identity_count
        ),

        "centrality": round(
            centrality,
            4,
        ),

        "signals": signals,
    }


# ============================================================
# GRAPH SUMMARY
# ============================================================

def graph_summary(
    graph: nx.Graph,
) -> Dict[str, Any]:
    """
    Return useful statistics for the dashboard.
    """

    if graph is None:

        return {
            "nodes": 0,
            "edges": 0,
            "identities": 0,
            "devices": 0,
            "accounts": 0,
            "sessions": 0,
            "networks": 0,
        }

    node_counts = {
        "identity": 0,
        "device": 0,
        "account": 0,
        "session": 0,
        "network": 0,
    }

    for _, data in graph.nodes(
        data=True
    ):

        node_type = data.get(
            "node_type"
        )

        if node_type in node_counts:

            node_counts[node_type] += 1

    return {
        "nodes": graph.number_of_nodes(),
        "edges": graph.number_of_edges(),

        "identities": node_counts["identity"],
        "devices": node_counts["device"],
        "accounts": node_counts["account"],
        "sessions": node_counts["session"],
        "networks": node_counts["network"],
    }


# ============================================================
# EDGE EXPORT
# ============================================================

def get_graph_edges(
    graph: nx.Graph,
):
    """
    Return graph edges in dashboard-friendly format.
    """

    edges = []

    if graph is None:
        return edges

    for source, target, data in graph.edges(
        data=True
    ):

        edges.append(
            {
                "source": source,
                "target": target,
                "relationship": data.get(
                    "relationship",
                    "connected",
                ),
            }
        )

    return edges


# ============================================================
# RISK HELPERS
# ============================================================

def calculate_graph_risk(
    graph: nx.Graph,
    identity_id: str,
    device_id: str,
    network_id: str,
) -> float:
    """
    Convenience function returning only the graph-risk score.
    """

    result = analyze_graph(
        graph,
        identity_id,
        device_id,
        network_id,
    )

    return float(
        result["score"]
    )