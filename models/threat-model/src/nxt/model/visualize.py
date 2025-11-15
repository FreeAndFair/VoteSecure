#!/usr/bin/env python3
"""
Interactive Pyvis visualization for the SecureVote threat model.

Generates an interactive HTML file that can be opened in a browser
to explore the threat model graph.
"""

import argparse
from pathlib import Path

from pyvis.network import Network

from nxt.model import model as threat_model
from nxt.schema.types import EdgeType


# Color scheme for node types
NODE_COLORS = {
    "property": "#4CAF50",    # Green - security properties
    "attack": "#F44336",      # Red - attacks
    "pattern": "#FF9800",     # Orange - attack patterns
    "mitigation": "#2196F3",  # Blue - mitigations
    "context": "#9C27B0",     # Purple - contexts
}

# Node shapes
NODE_SHAPES = {
    "property": "diamond",
    "attack": "triangle",
    "pattern": "triangleDown",
    "mitigation": "square",
    "context": "dot",
}

# Edge colors by type
EDGE_COLORS = {
    EdgeType.REFINES: "#666666",      # Gray
    EdgeType.TARGETS: "#F44336",       # Red
    EdgeType.ACHIEVES: "#FF5722",      # Deep Orange
    EdgeType.REQUIRES: "#795548",      # Brown
    EdgeType.VARIANT_OF: "#607D8B",    # Blue Gray
    EdgeType.MITIGATES: "#2196F3",     # Blue
    EdgeType.OCCURS_IN: "#9C27B0",     # Purple
}


def _compute_attack_mitigations(model) -> dict[str, list[dict]]:
    """
    Precompute mitigation lines for each attack.

    Returns a dict mapping attack node IDs to lists of mitigation dicts.
    Each dict contains:
    - line: The attack line string (e.g., "Ineligible ballots > Compromised device (EAS) → Escalation of privilege → Cybersecurity---Escalation")
    - rationale: The rationale for this mitigation application
    - style: 'direct', 'inherited', or 'oos'

    For each attack, we collect:
    1. Direct mitigations on that attack
    2. Pattern mitigations (via variant_of hierarchy)
    3. Mitigations from child attacks (attacks that achieve this one)
    """
    attack_mitigations = {}

    for attack in model.attacks:
        node_id = attack.id
        mitigations = []

        # Recursively collect mitigations from this attack and its children
        _collect_attack_mits(model, attack, [], mitigations)

        attack_mitigations[node_id] = mitigations

    return attack_mitigations


def _get_attack_display(attack) -> str:
    """Get attack name with context for display."""
    if attack.occurs_in:
        contexts = ", ".join(c.id for c in attack.occurs_in)
        return f"{attack.name} ({contexts})"
    return attack.name


def _collect_attack_mits(model, attack, lineage: list[str], mitigations: list[dict]) -> None:
    """
    Recursively collect mitigations from an attack and its children.

    Args:
        model: The threat model
        attack: Current attack being processed
        lineage: Path from root to current attack (display names)
        mitigations: Accumulator list for mitigation dicts
    """
    # Build current lineage
    current_name = _get_attack_display(attack)
    current_lineage = lineage + [current_name]

    # Direct mitigations on this attack
    for ma in attack.mitigations:
        attack_line = " > ".join(current_lineage + [ma.mitigation.name])
        rationale = ma.rationale or ""
        if ma.mitigation.id == "OOS":
            mitigations.append({
                "line": f"⚠️ {attack_line}",
                "rationale": rationale,
                "style": "oos"
            })
        else:
            mitigations.append({
                "line": f"✓ {attack_line}",
                "rationale": rationale,
                "style": "direct"
            })

    # Pattern mitigations (from variant_of hierarchy)
    if attack.variant_of:
        pattern_mits = _collect_pattern_mits(model, attack.variant_of, [])
        for mit_name, pattern_path, is_oos, rationale in pattern_mits:
            # Build attack line: lineage > attack → pattern_path → mitigation
            attack_part = " > ".join(current_lineage)
            if pattern_path:
                pattern_str = " → ".join(pattern_path)
                attack_line = f"{attack_part} → {pattern_str} → {mit_name}"
            else:
                attack_line = f"{attack_part} → {mit_name}"

            if is_oos:
                mitigations.append({
                    "line": f"⚠️ {attack_line}",
                    "rationale": rationale,
                    "style": "oos"
                })
            else:
                mitigations.append({
                    "line": f"○ {attack_line}",
                    "rationale": rationale,
                    "style": "inherited"
                })

    # Recurse into children (attacks that achieve this one)
    children = [a for a in model.attacks if attack in a.achieves]
    for child in children:
        _collect_attack_mits(model, child, current_lineage, mitigations)


def _collect_pattern_mits(model, pattern, pattern_path: list[str]) -> list[tuple[str, list[str], bool, str]]:
    """
    Collect mitigations from a pattern and its refinements.
    Returns list of (mitigation_name, pattern_path, is_oos, rationale) tuples.

    Args:
        model: The threat model
        pattern: The pattern to collect mitigations from
        pattern_path: The path of pattern names leading to this pattern
    """
    result = []

    # Mitigations on this pattern
    for ma in pattern.mitigations:
        is_oos = ma.mitigation.id == "OOS"
        rationale = ma.rationale or ""
        result.append((ma.mitigation.name, pattern_path.copy(), is_oos, rationale))

    # Recurse into patterns that refine this one
    for child_pattern in model.patterns:
        if child_pattern.refines == pattern:
            child_path = pattern_path + [child_pattern.name]
            result.extend(_collect_pattern_mits(model, child_pattern, child_path))

    return result


def _inject_focus_mode_js(
    html_path: str,
    G,
    attack_mitigations: dict[str, list[dict]],
) -> None:
    """
    Inject custom JavaScript for directional transitive reachability.

    When a node is clicked:
    - Follow outgoing edges transitively (forward reachability)
    - Follow incoming edges transitively (backward reachability)
    - But never reverse direction mid-traversal
    - Highlight reachable nodes, gray out unreachable ones
    """
    import json

    # Build adjacency lists for JavaScript
    out_edges = {}  # node -> list of successor nodes
    in_edges = {}   # node -> list of predecessor nodes

    for node in G.nodes():
        out_edges[node] = list(G.successors(node))
        in_edges[node] = list(G.predecessors(node))

    # Store original node colors
    node_colors = {}
    for node_id, data in G.nodes(data=True):
        node_type = data.get("node_type", "unknown")
        node_colors[node_id] = NODE_COLORS.get(node_type, "#888888")

    # Build node labels and descriptions for search and display
    node_labels = {}
    node_descriptions = {}
    for node_id, data in G.nodes(data=True):
        node_obj = data.get("node")
        node_type = data.get("node_type", "unknown")
        if node_type == "property":
            node_labels[node_id] = node_obj.id
            node_descriptions[node_id] = node_obj.description or ""
        elif node_type == "attack":
            node_labels[node_id] = node_obj.name
            node_descriptions[node_id] = node_obj.description or ""
        elif node_type == "pattern":
            node_labels[node_id] = node_obj.name
            node_descriptions[node_id] = node_obj.description or ""
        elif node_type == "mitigation":
            node_labels[node_id] = node_obj.name
            node_descriptions[node_id] = node_obj.description or ""
        elif node_type == "context":
            node_labels[node_id] = f"{node_obj.id}: {node_obj.name}"
            node_descriptions[node_id] = node_obj.name or ""
        else:
            node_labels[node_id] = str(node_id)
            node_descriptions[node_id] = ""

    js_code = f'''
<style>
html, body {{
    margin: 0;
    padding: 0;
    height: 100%;
    overflow: hidden;
}}
#mainContainer {{
    display: flex;
    height: 100vh;
    width: 100vw;
}}
#sidePanel {{
    width: 280px;
    min-width: 280px;
    height: 100%;
    background: #f8f9fa;
    border-right: 1px solid #dee2e6;
    box-shadow: 2px 0 10px rgba(0,0,0,0.1);
    z-index: 1000;
    font-family: Arial, sans-serif;
    font-size: 13px;
    display: flex;
    flex-direction: column;
    box-sizing: border-box;
}}
#sidePanel h3 {{
    margin: 0;
    padding: 15px;
    background: #343a40;
    color: white;
    font-size: 16px;
}}
#sidePanel .section {{
    padding: 15px;
    border-bottom: 1px solid #dee2e6;
}}
#sidePanel .section-title {{
    font-weight: bold;
    margin-bottom: 10px;
    color: #495057;
}}
#searchInput {{
    width: 100%;
    padding: 8px 10px;
    border: 1px solid #ced4da;
    border-radius: 4px;
    font-size: 13px;
    box-sizing: border-box;
}}
#searchInput:focus {{
    outline: none;
    border-color: #80bdff;
    box-shadow: 0 0 0 2px rgba(0,123,255,0.25);
}}
#searchResults {{
    max-height: 200px;
    overflow-y: auto;
    margin-top: 8px;
    border: 1px solid #dee2e6;
    border-radius: 4px;
    background: white;
    display: none;
}}
#searchResults.active {{
    display: block;
}}
.search-item {{
    padding: 8px 10px;
    cursor: pointer;
    border-bottom: 1px solid #eee;
}}
.search-item:last-child {{
    border-bottom: none;
}}
.search-item:hover {{
    background: #e9ecef;
}}
.search-item .node-type {{
    font-size: 10px;
    color: #6c757d;
    text-transform: uppercase;
}}
#sidePanel label {{
    display: flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
}}
#sidePanel input[type="checkbox"] {{
    width: 16px;
    height: 16px;
}}
#focusStatus {{
    padding: 15px;
    background: #e9ecef;
    color: #495057;
}}
#focusStatus.active {{
    background: #d4edda;
    color: #155724;
}}
#nodeDetails {{
    flex: 1;
    padding: 15px;
    overflow-y: auto;
    border-top: 1px solid #dee2e6;
    display: none;
}}
#nodeDetails.active {{
    display: block;
}}
#nodeDetails .node-header {{
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 8px;
}}
#nodeDetails .node-title {{
    font-weight: bold;
    font-size: 14px;
    margin-bottom: 5px;
    color: #212529;
    flex: 1;
}}
#nodeDetails #copyLinkBtn {{
    background: #e9ecef;
    border: none;
    border-radius: 4px;
    padding: 4px 8px;
    cursor: pointer;
    font-size: 14px;
    transition: background 0.2s;
}}
#nodeDetails #copyLinkBtn:hover {{
    background: #dee2e6;
}}
#nodeDetails #copyLinkBtn.copied {{
    background: #28a745;
    color: white;
}}
#nodeDetails .node-type-badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 10px;
    text-transform: uppercase;
    margin-bottom: 10px;
    color: white;
}}
#nodeDetails .node-type-badge.property {{ background: #4CAF50; }}
#nodeDetails .node-type-badge.attack {{ background: #F44336; }}
#nodeDetails .node-type-badge.pattern {{ background: #FF9800; }}
#nodeDetails .node-type-badge.mitigation {{ background: #2196F3; }}
#nodeDetails .node-type-badge.context {{ background: #9C27B0; }}
#nodeDetails .node-description {{
    font-size: 12px;
    line-height: 1.5;
    color: #495057;
}}
#nodeDetails .node-id {{
    font-family: monospace;
    font-size: 10px;
    color: #6c757d;
    background: #e9ecef;
    padding: 2px 6px;
    border-radius: 3px;
    display: inline-block;
    margin-bottom: 8px;
}}
#nodeMitigations {{
    margin-top: 12px;
    display: none;
}}
#nodeMitigations.active {{
    display: block;
}}
#nodeMitigations .mitigations-title {{
    font-weight: bold;
    font-size: 12px;
    color: #495057;
    margin-bottom: 6px;
    border-top: 1px solid #dee2e6;
    padding-top: 10px;
}}
#nodeMitigations ul {{
    margin: 0;
    padding-left: 0;
    list-style: none;
    font-size: 11px;
    line-height: 1.5;
}}
#nodeMitigations li {{
    color: #495057;
    margin-bottom: 8px;
    padding-left: 4px;
    border-left: 2px solid #28a745;
}}
#nodeMitigations li.inherited {{
    color: #6c757d;
    border-left-color: #6c757d;
}}
#nodeMitigations li.oos {{
    color: #856404;
    border-left-color: #ffc107;
}}
#nodeMitigations .attack-line {{
    font-weight: 500;
    cursor: default;
}}
#nodeMitigations li {{
    position: relative;
}}
#nodeMitigations .info-icon {{
    display: inline-block;
    width: 14px;
    height: 14px;
    line-height: 14px;
    text-align: center;
    font-size: 10px;
    color: #6c757d;
    background: #e9ecef;
    border-radius: 50%;
    margin-left: 6px;
    cursor: help;
    vertical-align: middle;
}}
#nodeMitigations .info-icon:hover {{
    background: #dee2e6;
    color: #495057;
}}
#nodeMitigations .tooltip {{
    visibility: hidden;
    opacity: 0;
    position: fixed;
    background: #2d3436;
    color: #fff;
    padding: 12px 14px;
    border-radius: 6px;
    font-size: 13px;
    font-style: normal;
    font-weight: normal;
    line-height: 1.5;
    max-width: 400px;
    z-index: 1000;
    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    transition: opacity 0.2s, visibility 0.2s;
    pointer-events: none;
}}
#nodeMitigations .tooltip::before {{
    content: '';
    position: absolute;
    top: -6px;
    left: 20px;
    border-width: 0 6px 6px 6px;
    border-style: solid;
    border-color: transparent transparent #2d3436 transparent;
}}
#nodeMitigations .info-icon:hover + .tooltip {{
    visibility: visible;
    opacity: 1;
}}
.hint {{
    color: #6c757d;
    font-size: 11px;
    margin-top: 8px;
}}
#graphContainer {{
    flex: 1;
    height: 100%;
    position: relative;
}}
/* Custom HTML tooltip for nodes/edges */
#customTooltip {{
    position: fixed;
    background: #2d3436;
    color: #fff;
    padding: 10px 14px;
    border-radius: 6px;
    font-size: 13px;
    font-family: Arial, sans-serif;
    line-height: 1.5;
    max-width: 400px;
    z-index: 2000;
    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    pointer-events: none;
    display: none;
}}
#customTooltip.visible {{
    display: block;
}}
#customTooltip b {{
    color: #74b9ff;
}}
/* Physics config panel */
#physicsConfig {{
    position: fixed;
    bottom: 10px;
    left: 10px;
    background: #f8f9fa;
    border: 1px solid #dee2e6;
    border-radius: 6px;
    font-family: Arial, sans-serif;
    font-size: 12px;
    z-index: 1500;
    box-shadow: 0 2px 8px rgba(0,0,0,0.15);
    max-width: 280px;
}}
#physicsConfig summary {{
    padding: 8px 12px;
    cursor: pointer;
    user-select: none;
    font-weight: bold;
    color: #495057;
    background: #e9ecef;
    border-radius: 6px;
}}
#physicsConfig[open] summary {{
    border-radius: 6px 6px 0 0;
    border-bottom: 1px solid #dee2e6;
}}
#physicsConfig summary:hover {{
    background: #dee2e6;
}}
#physicsConfig .config-content {{
    padding: 12px;
}}
#physicsConfig .config-row {{
    margin-bottom: 10px;
}}
#physicsConfig .config-row:last-child {{
    margin-bottom: 0;
}}
#physicsConfig label {{
    display: block;
    margin-bottom: 4px;
    color: #495057;
}}
#physicsConfig label span {{
    float: right;
    font-family: monospace;
    color: #6c757d;
}}
#physicsConfig input[type="range"] {{
    width: 100%;
    margin: 0;
}}
#physicsConfig .config-buttons {{
    margin-top: 12px;
    padding-top: 10px;
    border-top: 1px solid #dee2e6;
    display: flex;
    gap: 8px;
}}
#physicsConfig button {{
    flex: 1;
    padding: 6px 10px;
    border: 1px solid #ced4da;
    border-radius: 4px;
    background: #fff;
    cursor: pointer;
    font-size: 11px;
}}
#physicsConfig button:hover {{
    background: #e9ecef;
}}
#physicsConfig button.primary {{
    background: #007bff;
    border-color: #007bff;
    color: white;
}}
#physicsConfig button.primary:hover {{
    background: #0056b3;
}}
</style>
<script type="text/javascript">
document.addEventListener('DOMContentLoaded', function() {{
    // Wrap existing content in flex container
    var mynetwork = document.getElementById('mynetwork');

    // Create main container
    var mainContainer = document.createElement('div');
    mainContainer.id = 'mainContainer';

    // Create side panel
    var sidePanel = document.createElement('div');
    sidePanel.id = 'sidePanel';
    sidePanel.innerHTML = `
        <h3>Threat Model Explorer</h3>
        <div class="section">
            <div class="section-title">Search Nodes</div>
            <input type="text" id="searchInput" placeholder="Type to search...">
            <div id="searchResults"></div>
        </div>
        <div id="focusStatus">Shift+Click to toggle hide mode</div>
        <div id="nodeDetails">
            <div class="node-header">
                <div class="node-title" id="nodeTitle"></div>
                <button id="copyLinkBtn" title="Copy link to this node">🔗</button>
            </div>
            <div class="node-id" id="nodeId"></div>
            <span class="node-type-badge" id="nodeTypeBadge"></span>
            <div class="node-description" id="nodeDescription"></div>
            <div id="nodeMitigations">
                <div class="mitigations-title">Attack Lines</div>
                <ul id="mitigationsList"></ul>
            </div>
        </div>
    `;

    // Create graph container
    var graphContainer = document.createElement('div');
    graphContainer.id = 'graphContainer';

    // Reparent mynetwork
    mynetwork.parentNode.insertBefore(mainContainer, mynetwork);
    mainContainer.appendChild(sidePanel);
    mainContainer.appendChild(graphContainer);
    graphContainer.appendChild(mynetwork);

    // Make mynetwork fill the graph container
    mynetwork.style.width = '100%';
    mynetwork.style.height = '100%';

    // Create custom tooltip element for HTML rendering
    var customTooltip = document.createElement('div');
    customTooltip.id = 'customTooltip';
    document.body.appendChild(customTooltip);

    // Create physics config panel
    var physicsConfig = document.createElement('details');
    physicsConfig.id = 'physicsConfig';
    physicsConfig.innerHTML = `
        <summary>⚙️ Physics Settings</summary>
        <div class="config-content">
            <div class="config-row">
                <label>Repulsion <span id="gravityValue">-8000</span></label>
                <input type="range" id="gravitySlider" min="-50000" max="-1000" step="500" value="-8000">
            </div>
            <div class="config-row">
                <label>Central Gravity <span id="centralGravityValue">0.5</span></label>
                <input type="range" id="centralGravitySlider" min="0" max="5" step="0.1" value="0.5">
            </div>
            <div class="config-row">
                <label>Spring Length <span id="springLengthValue">300</span></label>
                <input type="range" id="springLengthSlider" min="50" max="1000" step="25" value="300">
            </div>
            <div class="config-row">
                <label>Spring Strength <span id="springStrengthValue">0.03</span></label>
                <input type="range" id="springStrengthSlider" min="0.01" max="0.2" step="0.01" value="0.03">
            </div>
            <div class="config-row">
                <label>Damping <span id="dampingValue">0.09</span></label>
                <input type="range" id="dampingSlider" min="0.01" max="0.5" step="0.01" value="0.09">
            </div>
            <div class="config-buttons">
                <button id="resetPhysicsBtn">Reset</button>
                <button id="togglePhysicsBtn" class="primary">Freeze</button>
            </div>
        </div>
    `;
    document.body.appendChild(physicsConfig);
}});
</script>
<script type="text/javascript">
(function() {{
    // Helper function to escape HTML special characters
    function escapeHtml(text) {{
        var div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }}

    // Adjacency data
    var outEdges = {json.dumps(out_edges)};
    var inEdges = {json.dumps(in_edges)};
    var originalColors = {json.dumps(node_colors)};
    var nodeLabels = {json.dumps(node_labels)};
    var nodeDescriptions = {json.dumps(node_descriptions)};
    var attackMitigations = {json.dumps(attack_mitigations)};

    // Build node type lookup
    var nodeTypes = {json.dumps({nid: data.get("node_type", "unknown") for nid, data in G.nodes(data=True)})};

    // Wait for network to be ready
    function waitForNetwork() {{
        if (typeof network === 'undefined') {{
            setTimeout(waitForNetwork, 100);
            return;
        }}
        // Wait a bit more for DOM restructuring
        setTimeout(function() {{
            setupFocusMode();
            setupSearch();
            setupCustomTooltips();
            setupPhysicsConfig();
            // Enable hover events and disable default Vis.js tooltips (we use custom HTML tooltips)
            network.setOptions({{
                interaction: {{
                    hover: true,  // Required for hoverNode/hoverEdge events
                    tooltipDelay: 999999999  // Effectively disable default tooltips
                }}
            }});

            // Disable physics after initial stabilization to stop constant movement
            network.once('stabilizationIterationsDone', function() {{
                network.setOptions({{ physics: {{ enabled: false }} }});
                // Update the toggle button state
                var toggleBtn = document.getElementById('togglePhysicsBtn');
                if (toggleBtn) {{
                    toggleBtn.textContent = 'Unfreeze';
                    toggleBtn.classList.remove('primary');
                }}
            }});

            // Resize network to fit new container
            network.redraw();
            network.fit();
            // Check for URL parameters
            handleUrlParameters();
        }}, 200);
    }}

    // Handle URL parameters to focus on specific nodes
    function handleUrlParameters() {{
        var params = new URLSearchParams(window.location.search);
        var nodeId = params.get('node');
        var hideMode = params.get('hide') === 'true';

        if (nodeId && nodeLabels[nodeId]) {{
            // Update hide mode if specified
            if (hideMode) {{
                hideUnreachableMode = true;
            }}

            // Focus on the node with animation
            network.focus(nodeId, {{
                scale: 1.2,
                animation: {{
                    duration: 800,
                    easingFunction: 'easeInOutQuad'
                }}
            }});

            // Apply focus behavior
            setTimeout(function() {{
                applyFocus(nodeId, hideUnreachableMode);
            }}, 100);
        }}
    }}

    function setupSearch() {{
        var searchInput = document.getElementById('searchInput');
        var searchResults = document.getElementById('searchResults');

        // Build searchable list
        var nodeList = [];
        for (var nodeId in nodeLabels) {{
            nodeList.push({{
                id: nodeId,
                label: nodeLabels[nodeId],
                type: nodeTypes[nodeId]
            }});
        }}

        searchInput.addEventListener('input', function() {{
            var query = this.value.toLowerCase().trim();
            if (query.length < 2) {{
                searchResults.classList.remove('active');
                searchResults.innerHTML = '';
                return;
            }}

            var matches = nodeList.filter(function(node) {{
                return node.label.toLowerCase().includes(query);
            }}).slice(0, 20);

            if (matches.length === 0) {{
                searchResults.innerHTML = '<div class="search-item">No matches found</div>';
            }} else {{
                searchResults.innerHTML = matches.map(function(node) {{
                    return '<div class="search-item" data-id="' + node.id + '">' +
                           '<div>' + node.label + '</div>' +
                           '<div class="node-type">' + node.type + '</div></div>';
                }}).join('');
            }}
            searchResults.classList.add('active');
        }});

        searchResults.addEventListener('click', function(e) {{
            var item = e.target.closest('.search-item');
            if (item && item.dataset.id) {{
                var nodeId = item.dataset.id;
                network.selectNodes([nodeId]);
                network.focus(nodeId, {{
                    scale: 1.5,
                    animation: {{
                        duration: 500,
                        easingFunction: 'easeInOutQuad'
                    }}
                }});

                // Trigger the focus behavior
                applyFocus(nodeId, hideUnreachableMode);

                searchInput.value = '';
                searchResults.classList.remove('active');
                searchResults.innerHTML = '';
            }}
        }});

        // Close results when clicking outside
        document.addEventListener('click', function(e) {{
            if (!searchInput.contains(e.target) && !searchResults.contains(e.target)) {{
                searchResults.classList.remove('active');
            }}
        }});
    }}

    function setupCustomTooltips() {{
        var tooltip = document.getElementById('customTooltip');
        var allNodes = network.body.data.nodes;
        var allEdges = network.body.data.edges;

        // Build title lookup from nodes dataset
        var nodeTitles = {{}};
        allNodes.forEach(function(node) {{
            nodeTitles[node.id] = node.title || '';
        }});

        // Build title lookup from edges dataset
        var edgeTitles = {{}};
        allEdges.forEach(function(edge) {{
            edgeTitles[edge.id] = edge.title || '';
        }});

        function showTooltip(htmlContent, x, y) {{
            tooltip.innerHTML = htmlContent;
            tooltip.classList.add('visible');
            // Position tooltip near cursor, but avoid edge of screen
            var tooltipWidth = tooltip.offsetWidth;
            var tooltipHeight = tooltip.offsetHeight;
            var left = x + 15;
            var top = y + 15;
            // Adjust if would overflow right
            if (left + tooltipWidth > window.innerWidth - 10) {{
                left = x - tooltipWidth - 10;
            }}
            // Adjust if would overflow bottom
            if (top + tooltipHeight > window.innerHeight - 10) {{
                top = y - tooltipHeight - 10;
            }}
            tooltip.style.left = left + 'px';
            tooltip.style.top = top + 'px';
        }}

        function hideTooltip() {{
            tooltip.classList.remove('visible');
        }}

        // Track mouse position for tooltip positioning
        var mouseX = 0, mouseY = 0;
        document.addEventListener('mousemove', function(e) {{
            mouseX = e.clientX;
            mouseY = e.clientY;
        }});

        network.on('hoverNode', function(params) {{
            var nodeId = params.node;
            var title = nodeTitles[nodeId];
            if (title) {{
                showTooltip(title, mouseX, mouseY);
            }}
        }});

        network.on('blurNode', function(params) {{
            hideTooltip();
        }});

        network.on('hoverEdge', function(params) {{
            var edgeId = params.edge;
            var title = edgeTitles[edgeId];
            if (title) {{
                showTooltip(title, mouseX, mouseY);
            }}
        }});

        network.on('blurEdge', function(params) {{
            hideTooltip();
        }});
    }}

    // Default physics values
    var defaultPhysics = {{
        gravity: -8000,
        centralGravity: 0.5,
        springLength: 300,
        springStrength: 0.03,
        damping: 0.09
    }};

    function setupPhysicsConfig() {{
        var gravitySlider = document.getElementById('gravitySlider');
        var centralGravitySlider = document.getElementById('centralGravitySlider');
        var springLengthSlider = document.getElementById('springLengthSlider');
        var springStrengthSlider = document.getElementById('springStrengthSlider');
        var dampingSlider = document.getElementById('dampingSlider');

        var gravityValue = document.getElementById('gravityValue');
        var centralGravityValue = document.getElementById('centralGravityValue');
        var springLengthValue = document.getElementById('springLengthValue');
        var springStrengthValue = document.getElementById('springStrengthValue');
        var dampingValue = document.getElementById('dampingValue');

        var resetBtn = document.getElementById('resetPhysicsBtn');
        var togglePhysicsBtn = document.getElementById('togglePhysicsBtn');
        var physicsEnabled = false;  // Starts disabled after initial stabilization

        function updatePhysics() {{
            physicsEnabled = true;
            togglePhysicsBtn.textContent = 'Freeze';
            togglePhysicsBtn.classList.add('primary');
            network.setOptions({{
                physics: {{
                    enabled: true,
                    barnesHut: {{
                        gravitationalConstant: parseFloat(gravitySlider.value),
                        centralGravity: parseFloat(centralGravitySlider.value),
                        springLength: parseFloat(springLengthSlider.value),
                        springConstant: parseFloat(springStrengthSlider.value),
                        damping: parseFloat(dampingSlider.value)
                    }}
                }}
            }});
        }}

        function updateDisplay() {{
            gravityValue.textContent = gravitySlider.value;
            centralGravityValue.textContent = centralGravitySlider.value;
            springLengthValue.textContent = springLengthSlider.value;
            springStrengthValue.textContent = springStrengthSlider.value;
            dampingValue.textContent = dampingSlider.value;
        }}

        // Add event listeners to all sliders
        [gravitySlider, centralGravitySlider, springLengthSlider, springStrengthSlider, dampingSlider].forEach(function(slider) {{
            slider.addEventListener('input', function() {{
                updateDisplay();
                updatePhysics();
            }});
        }});

        // Reset button
        resetBtn.addEventListener('click', function() {{
            gravitySlider.value = defaultPhysics.gravity;
            centralGravitySlider.value = defaultPhysics.centralGravity;
            springLengthSlider.value = defaultPhysics.springLength;
            springStrengthSlider.value = defaultPhysics.springStrength;
            dampingSlider.value = defaultPhysics.damping;
            updateDisplay();
            updatePhysics();
        }});

        // Toggle physics on/off
        togglePhysicsBtn.addEventListener('click', function() {{
            physicsEnabled = !physicsEnabled;
            network.setOptions({{ physics: {{ enabled: physicsEnabled }} }});
            if (physicsEnabled) {{
                togglePhysicsBtn.textContent = 'Freeze';
                togglePhysicsBtn.classList.add('primary');
            }} else {{
                togglePhysicsBtn.textContent = 'Unfreeze';
                togglePhysicsBtn.classList.remove('primary');
            }}
        }});
    }}

    var applyFocus; // Will be set by setupFocusMode

    var hideUnreachableMode = false; // Track hide mode state

    function setupFocusMode() {{
        var allNodes = network.body.data.nodes;
        var allEdges = network.body.data.edges;
        var statusDiv = document.getElementById('focusStatus');
        var nodeDetails = document.getElementById('nodeDetails');
        var nodeTitle = document.getElementById('nodeTitle');
        var nodeIdElem = document.getElementById('nodeId');
        var nodeTypeBadge = document.getElementById('nodeTypeBadge');
        var nodeDescription = document.getElementById('nodeDescription');
        var nodeMitigations = document.getElementById('nodeMitigations');
        var mitigationsList = document.getElementById('mitigationsList');
        var copyLinkBtn = document.getElementById('copyLinkBtn');

        // Copy link button handler
        copyLinkBtn.addEventListener('click', function() {{
            if (currentFocusNode) {{
                var url = window.location.origin + window.location.pathname + '?node=' + encodeURIComponent(currentFocusNode);
                if (hideUnreachableMode) {{
                    url += '&hide=true';
                }}
                navigator.clipboard.writeText(url).then(function() {{
                    copyLinkBtn.textContent = '✓';
                    copyLinkBtn.classList.add('copied');
                    setTimeout(function() {{
                        copyLinkBtn.textContent = '🔗';
                        copyLinkBtn.classList.remove('copied');
                    }}, 1500);
                }});
            }}
        }});

        // Update URL when focusing on a node (without reloading)
        function updateUrl(nodeId) {{
            var url = window.location.pathname;
            if (nodeId) {{
                url += '?node=' + encodeURIComponent(nodeId);
                if (hideUnreachableMode) {{
                    url += '&hide=true';
                }}
            }}
            window.history.replaceState(null, '', url);
        }}

        // Store original node data
        var originalNodeData = {{}};
        allNodes.forEach(function(node) {{
            originalNodeData[node.id] = {{
                color: node.color,
                label: node.label,
                font: node.font || {{}},
                hidden: false
            }};
        }});

        // Store original edge data
        var originalEdgeData = {{}};
        allEdges.forEach(function(edge) {{
            originalEdgeData[edge.id] = {{
                color: edge.color,
                hidden: false
            }};
        }});

        var currentFocusNode = null;

        function showNodeDetails(nodeId) {{
            var label = nodeLabels[nodeId] || nodeId;
            var type = nodeTypes[nodeId] || 'unknown';
            var desc = nodeDescriptions[nodeId] || '';

            nodeTitle.textContent = label;
            nodeIdElem.textContent = nodeId;
            nodeTypeBadge.textContent = type;
            nodeTypeBadge.className = 'node-type-badge ' + type;
            nodeDescription.textContent = desc;
            nodeDetails.classList.add('active');

            // Show mitigations for attacks
            if (type === 'attack' && attackMitigations[nodeId]) {{
                var mits = attackMitigations[nodeId];
                if (mits.length > 0) {{
                    mitigationsList.innerHTML = mits.map(function(mit) {{
                        var tooltip = mit.rationale ? '<span class="info-icon">i</span><span class="tooltip">' + escapeHtml(mit.rationale) + '</span>' : '';
                        return '<li class="' + mit.style + '"><div class="attack-line">' + mit.line + tooltip + '</div></li>';
                    }}).join('');

                    // Position tooltips near their icons
                    setTimeout(function() {{
                        var icons = mitigationsList.querySelectorAll('.info-icon');
                        icons.forEach(function(icon) {{
                            var tooltip = icon.nextElementSibling;
                            if (tooltip) {{
                                icon.addEventListener('mouseenter', function(e) {{
                                    var rect = icon.getBoundingClientRect();
                                    tooltip.style.left = Math.max(10, rect.left - 20) + 'px';
                                    tooltip.style.top = (rect.bottom + 8) + 'px';
                                    // Ensure tooltip doesn't go off-screen right
                                    var tooltipRect = tooltip.getBoundingClientRect();
                                    if (tooltipRect.right > window.innerWidth - 10) {{
                                        tooltip.style.left = (window.innerWidth - tooltipRect.width - 10) + 'px';
                                    }}
                                }});
                            }}
                        }});
                    }}, 0);

                    nodeMitigations.classList.add('active');
                }} else {{
                    mitigationsList.innerHTML = '<li>No mitigations</li>';
                    nodeMitigations.classList.add('active');
                }}
            }} else {{
                nodeMitigations.classList.remove('active');
            }}
        }}

        function hideNodeDetails() {{
            nodeDetails.classList.remove('active');
            nodeMitigations.classList.remove('active');
        }}

        // Compute forward reachable nodes (following out-edges)
        function forwardReachable(startNode) {{
            var visited = new Set();
            var queue = [startNode];
            while (queue.length > 0) {{
                var node = queue.shift();
                if (visited.has(node)) continue;
                visited.add(node);
                var successors = outEdges[node] || [];
                for (var i = 0; i < successors.length; i++) {{
                    if (!visited.has(successors[i])) {{
                        queue.push(successors[i]);
                    }}
                }}
            }}
            return visited;
        }}

        // Compute backward reachable nodes (following in-edges)
        function backwardReachable(startNode) {{
            var visited = new Set();
            var queue = [startNode];
            while (queue.length > 0) {{
                var node = queue.shift();
                if (visited.has(node)) continue;
                visited.add(node);
                var predecessors = inEdges[node] || [];
                for (var i = 0; i < predecessors.length; i++) {{
                    if (!visited.has(predecessors[i])) {{
                        queue.push(predecessors[i]);
                    }}
                }}
            }}
            return visited;
        }}

        function resetGraph() {{
            currentFocusNode = null;
            statusDiv.textContent = 'Click a node to focus';
            statusDiv.classList.remove('active');
            hideNodeDetails();
            updateUrl(null);  // Clear URL parameter

            var updates = [];
            allNodes.forEach(function(node) {{
                var orig = originalNodeData[node.id];
                updates.push({{
                    id: node.id,
                    color: orig.color,
                    label: orig.label,
                    font: {{ color: '#000000' }},
                    hidden: false
                }});
            }});
            allNodes.update(updates);

            var edgeUpdates = [];
            allEdges.forEach(function(edge) {{
                edgeUpdates.push({{
                    id: edge.id,
                    color: originalEdgeData[edge.id].color,
                    hidden: false
                }});
            }});
            allEdges.update(edgeUpdates);
        }}

        applyFocus = function(selectedNode, hideMode) {{
            currentFocusNode = selectedNode;
            showNodeDetails(selectedNode);
            updateUrl(selectedNode);  // Update URL with current node

            // Compute reachable nodes in both directions
            var forwardSet = forwardReachable(selectedNode);
            var backwardSet = backwardReachable(selectedNode);
            var reachableSet = new Set([...forwardSet, ...backwardSet]);

            var reachableCount = reachableSet.size;
            var totalCount = Object.keys(originalNodeData).length;
            statusDiv.textContent = 'Focused: ' + reachableCount + ' of ' + totalCount + ' nodes';
            statusDiv.classList.add('active');

            // Update node appearance
            var updates = [];
            allNodes.forEach(function(node) {{
                var orig = originalNodeData[node.id];
                if (node.id === selectedNode) {{
                    updates.push({{
                        id: node.id,
                        color: orig.color,
                        label: orig.label,
                        font: {{ color: '#000000', bold: true }},
                        hidden: false
                    }});
                }} else if (reachableSet.has(node.id)) {{
                    updates.push({{
                        id: node.id,
                        color: orig.color,
                        label: orig.label,
                        font: {{ color: '#000000' }},
                        hidden: false
                    }});
                }} else {{
                    if (hideMode) {{
                        updates.push({{
                            id: node.id,
                            hidden: true
                        }});
                    }} else {{
                        updates.push({{
                            id: node.id,
                            color: '#e0e0e0',
                            label: '',
                            font: {{ color: '#e0e0e0' }},
                            hidden: false
                        }});
                    }}
                }}
            }});
            allNodes.update(updates);

            // Update edge appearance
            var edgeUpdates = [];
            allEdges.forEach(function(edge) {{
                var fromReachable = reachableSet.has(edge.from);
                var toReachable = reachableSet.has(edge.to);
                if (fromReachable && toReachable) {{
                    edgeUpdates.push({{
                        id: edge.id,
                        color: originalEdgeData[edge.id].color,
                        hidden: false
                    }});
                }} else {{
                    if (hideMode) {{
                        edgeUpdates.push({{
                            id: edge.id,
                            hidden: true
                        }});
                    }} else {{
                        edgeUpdates.push({{
                            id: edge.id,
                            color: '#e0e0e0',
                            hidden: false
                        }});
                    }}
                }}
            }});
            allEdges.update(edgeUpdates);

            // If hiding nodes, fit view to visible nodes
            if (hideMode) {{
                network.fit({{
                    animation: {{
                        duration: 500,
                        easingFunction: 'easeInOutQuad'
                    }}
                }});
            }}
        }}



        // Handle node click
        network.on("click", function(params) {{
            if (params.nodes.length === 0) {{
                resetGraph();
                return;
            }}

            var selectedNode = params.nodes[0];

            // Shift+Click toggles hide mode
            if (params.event.srcEvent.shiftKey) {{
                hideUnreachableMode = !hideUnreachableMode;
            }}

            applyFocus(selectedNode, hideUnreachableMode);
        }});
    }}

    waitForNetwork();
}})();
</script>
'''

    # Read the HTML file and inject the script before </body>
    with open(html_path, 'r', encoding='utf-8') as f:
        html_content = f.read()

    html_content = html_content.replace('</body>', js_code + '</body>')

    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html_content)


def create_visualization(
    output_path: str = "threat-model.html",
    height: str = "900px",
    width: str = "100%",
) -> None:
    """
    Create an interactive Pyvis visualization of the threat model.
    """
    # Build the model graph
    G = threat_model.graph

    # Create Pyvis network
    net = Network(
        height=height,
        width=width,
        directed=True,
        bgcolor="#ffffff",
        font_color=False,
        select_menu=False,
        filter_menu=False,
    )

    # Configure physics for better layout - spread nodes apart more
    net.barnes_hut(
        gravity=-8000,        # Stronger repulsion between nodes
        central_gravity=0.5,  # Moderate pull toward center (keeps isolated nodes from drifting)
        spring_length=300,    # Longer edges for more spacing
        spring_strength=0.03, # Weaker springs allow more spreading
        damping=0.09,
    )

    # Add nodes
    for node_id, data in G.nodes(data=True):
        node_type = data.get("node_type", "unknown")
        node_obj = data.get("node")

        # Build label and title (hover text)
        def truncate(text: str, max_len: int) -> str:
            """Truncate text and add ellipsis only if actually truncated."""
            if len(text) > max_len:
                return text[:max_len] + "..."
            return text

        if node_type == "property":
            label = node_obj.id
            title = f"<b>{node_obj.id}</b><br><br>{truncate(node_obj.description, 200)}"
        elif node_type == "attack":
            label = truncate(node_obj.name, 30)
            contexts = ", ".join(c.id for c in node_obj.occurs_in) if node_obj.occurs_in else "N/A"
            title = f"<b>{node_obj.name}</b><br><br>ID: {node_obj.id}<br>Contexts: {contexts}"
            if node_obj.description:
                title += f"<br><br>{truncate(node_obj.description, 300)}"
        elif node_type == "pattern":
            label = truncate(node_obj.name, 30)
            title = f"<b>Pattern: {node_obj.name}</b><br><br>ID: {node_obj.id}"
            if node_obj.description:
                title += f"<br><br>{truncate(node_obj.description, 300)}"
        elif node_type == "mitigation":
            label = truncate(node_obj.name, 25)
            title = f"<b>Mitigation: {node_obj.name}</b><br><br>ID: {node_obj.id}"
            if node_obj.description:
                title += f"<br><br>{truncate(node_obj.description, 300)}"
        elif node_type == "context":
            label = node_obj.id
            title = f"<b>Context: {node_obj.id}</b><br><br>{node_obj.name}"
        else:
            label = str(node_id)
            title = str(node_id)

        net.add_node(
            node_id,
            label=label,
            title=title,
            color=NODE_COLORS.get(node_type, "#888888"),
            shape=NODE_SHAPES.get(node_type, "dot"),
            size=25 if node_type in ("property", "attack") else 20,
            group=node_type,
        )

    # Add edges
    for source, target, data in G.edges(data=True):
        edge_type = data.get("edge_type", EdgeType.REFINES)

        # Build edge title (hover text)
        title = edge_type.value
        if "rationale" in data and data["rationale"]:
            rationale = data["rationale"]
            if len(rationale) > 200:
                rationale = rationale[:200] + "..."
            title += f"<br><br>{rationale}"

        net.add_edge(
            source,
            target,
            title=title,
            color=EDGE_COLORS.get(edge_type, "#888888"),
            arrows="to",
            smooth={"type": "curvedCW", "roundness": 0.1},
        )

    # Generate HTML
    net.write_html(output_path)

    # Precompute attack mitigations for the side panel
    attack_mitigations = _compute_attack_mitigations(threat_model)

    # Add custom JavaScript for directional transitive reachability
    _inject_focus_mode_js(output_path, G, attack_mitigations)

    print(f"Visualization saved to: {output_path}")
    print(f"  Nodes: {G.number_of_nodes()}")
    print(f"  Open in a browser to explore the threat model interactively.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate interactive threat model visualizations"
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="threat_model.html",
        help="Output HTML file path",
    )

    args = parser.parse_args()
    create_visualization(output_path=args.output)


if __name__ == "__main__":
    main()
