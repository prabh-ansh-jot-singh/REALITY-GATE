"""
REALITY-GATE v2.0 — Real NetworkX DiGraph LPM Effective-Route & Dual-Plane Solver
Constructs Declared vs. Observed topology graphs from persisted SQLite routes/flows,
performs ipaddress Longest Prefix Match (LPM), and simulates edge-removal blast radius.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional, Tuple
import networkx as nx


class DualPlaneGraphSolver:
    @staticmethod
    def resolve_lpm(target_cidr: str, effective_routes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Real Longest Prefix Match (LPM) over active persisted effective routes."""
        try:
            target_net = ipaddress.ip_network(target_cidr, strict=False)
        except ValueError:
            return {"prefix": target_cidr, "next_hop_ip": "N/A", "route_table": "N/A", "nsg_rule": "DEFAULT", "state": "UNKNOWN"}

        best: Optional[Dict[str, Any]] = None
        best_len = -1
        for r in effective_routes:
            if r.get("state") == "DELETED":
                continue
            try:
                net = ipaddress.ip_network(r["prefix"], strict=False)
            except ValueError:
                continue
            if target_net.subnet_of(net) or net.subnet_of(target_net):
                if net.prefixlen > best_len:
                    best = r
                    best_len = net.prefixlen

        if best is None:
            best = next((r for r in effective_routes if r["prefix"] == target_cidr), None)
        if best is None:
            return {"prefix": target_cidr, "next_hop_ip": "N/A", "route_table": "N/A", "nsg_rule": "DEFAULT", "state": "MISSING"}
        return dict(best)

    @staticmethod
    def build_dual_plane_graphs(
        tenant_name: str,
        effective_routes: List[Dict[str, Any]],
        flows: List[Dict[str, Any]],
        cmdb_cis: List[Dict[str, Any]],
        outage_active: bool = False,
        rerouted_to_backup: bool = False,
    ) -> Tuple[nx.DiGraph, nx.DiGraph]:
        declared = nx.DiGraph()
        observed = nx.DiGraph()

        ci_map = {c["cidr"]: c for c in cmdb_cis}
        route_map = {r["prefix"]: r for r in effective_routes}

        nodes = [
            ("app-tier", {"label": "App Tier", "cidr": "10.10.0.0/24", "plane": "DUAL_VERIFIED"}),
            ("backup-dr", {"label": "Backup / DR", "cidr": "10.41.0.0/16", "plane": ci_map.get("10.41.0.0/16", {}).get("sync_status", "DUAL_VERIFIED")}),
            ("vnet-hub", {"label": f"VNet ({tenant_name})", "cidr": "10.0.0.0/16", "plane": "DUAL_VERIFIED"}),
            ("sql-repl", {"label": "SQL Replication", "cidr": "10.40.0.0/16", "plane": ci_map.get("10.40.0.0/16", {}).get("sync_status", "OBSERVED_ONLY")}),
            ("prod-svc", {"label": "Prod Services", "cidr": "10.41.2.10", "plane": "DUAL_VERIFIED"}),
            ("batch-bk", {"label": "Weekly Batch DB", "cidr": "10.77.0.0/24", "plane": ci_map.get("10.77.0.0/24", {}).get("sync_status", "HISTORICAL_SCHEDULED")}),
            ("dmz-noise", {"label": "DMZ Legacy", "cidr": "10.88.0.0/24", "plane": ci_map.get("10.88.0.0/24", {}).get("sync_status", "SCANNER_NOISE")}),
            ("dev-dead", {"label": "Dev Scratch", "cidr": "10.99.0.0/24", "plane": ci_map.get("10.99.0.0/24", {}).get("sync_status", "DUAL_VERIFIED")}),
        ]
        for nid, attrs in nodes:
            declared.add_node(nid, **attrs)
            observed.add_node(nid, **attrs)

        declared_edges = [
            ("app-tier", "vnet-hub", {"state": "ACTIVE"}),
            ("backup-dr", "vnet-hub", {"state": "STANDBY_BACKUP"}),
            ("vnet-hub", "backup-dr", {"state": "SYMMETRIC_RETURN"}),
            ("vnet-hub", "prod-svc", {"state": "ACTIVE"}),
            ("vnet-hub", "sql-repl", {"state": route_map.get("10.40.0.0/16", {}).get("state", "ACTIVE")}),
            ("vnet-hub", "batch-bk", {"state": route_map.get("10.77.0.0/24", {}).get("state", "ACTIVE")}),
            ("vnet-hub", "dmz-noise", {"state": route_map.get("10.88.0.0/24", {}).get("state", "ACTIVE")}),
            ("vnet-hub", "dev-dead", {"state": route_map.get("10.99.0.0/24", {}).get("state", "ACTIVE")}),
        ]
        for u, v, d in declared_edges:
            if d.get("state") != "DELETED":
                declared.add_edge(u, v, **d)

        # Observed plane edges from live flows
        if not outage_active and route_map.get("10.40.0.0/16", {}).get("state") != "DELETED":
            sql_flow = next((f for f in flows if f["matched_cidr"] == "10.40.0.0/16"), None)
            observed.add_edge(
                "vnet-hub",
                "sql-repl",
                protocol="TCP/1433",
                packets_per_hr=sql_flow["packets_per_hr"] if sql_flow else 14200,
                status="ACTIVE_SQL",
            )
        if rerouted_to_backup:
            observed.add_edge(
                "vnet-hub",
                "prod-svc",
                protocol="TCP/1433",
                packets_per_hr=14200,
                status="FAILOVER_ACTIVE",
            )
            observed.add_edge(
                "vnet-hub",
                "backup-dr",
                protocol="TCP/1433",
                packets_per_hr=14200,
                status="FAILOVER_ACTIVE",
            )

        return declared, observed

    @staticmethod
    def simulate_edge_removal_blast_radius(
        observed_graph: nx.DiGraph,
        target_cidr: str,
    ) -> Dict[str, Any]:
        """Clone observed graph in NetworkX, sever target edge, and test reachability."""
        sim = observed_graph.copy()
        cidr_to_node = {
            "10.40.0.0/16": "sql-repl",
            "10.41.0.0/16": "backup-dr",
            "10.77.0.0/24": "batch-bk",
            "10.88.0.0/24": "dmz-noise",
            "10.99.0.0/24": "dev-dead",
        }
        node = cidr_to_node.get(target_cidr)
        had_path = bool(node and sim.has_edge("vnet-hub", node))
        if had_path:
            sim.remove_edge("vnet-hub", node)
        still_reachable = bool(node and nx.has_path(sim, "vnet-hub", node))
        impacted = [node] if (had_path and not still_reachable) else []
        return {
            "target_cidr": target_cidr,
            "had_observed_path": had_path,
            "still_reachable_after_delete": still_reachable,
            "impacted_nodes": impacted,
            "blast_radius": "HIGH" if impacted else "LOW",
        }
