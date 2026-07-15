(() => {
  "use strict";

  const canvas = document.getElementById("contract-canvas");
  const ctx = canvas.getContext("2d");
  const detail = document.getElementById("detail-panel");
  const empty = document.getElementById("empty-state");
  const dot = document.getElementById("connection-dot");
  const connectionLabel = document.getElementById("connection-label");
  const counts = document.getElementById("graph-counts");

  const NODE_W = 224;
  const CONTRACT_H = 86;
  const TERMINAL_H = 74;
  const COLUMN_GAP = 112;
  const ROW_GAP = 40;

  let browserState = { connected: false, snapshot: null };
  let graph = { nodes: [], edges: [], byId: new Map() };
  const positions = new Map();
  const pinned = new Set();
  let selectedId = null;
  let firstLayout = true;
  let viewport = { x: 64, y: 64, scale: 1 };
  let interaction = null;
  let moved = false;

  function nodeIdForInstance(index) { return `instance:${index}`; }
  function nodeIdForTerminal(outpoint) { return `terminal:${outpoint}`; }

  function deriveGraph(snapshot) {
    const nodes = [];
    const edges = [];
    const byId = new Map();
    if (!snapshot) return { nodes, edges, byId };

    for (const instance of snapshot.instances || []) {
      const node = {
        id: nodeIdForInstance(instance.index),
        kind: "contract",
        data: instance,
        width: NODE_W,
        height: CONTRACT_H,
      };
      nodes.push(node);
      byId.set(node.id, node);
    }
    for (const utxo of snapshot.terminal_utxos || []) {
      const node = {
        id: nodeIdForTerminal(utxo.outpoint),
        kind: "terminal",
        data: utxo,
        width: NODE_W,
        height: TERMINAL_H,
      };
      nodes.push(node);
      byId.set(node.id, node);
    }

    for (const instance of snapshot.instances || []) {
      const from = nodeIdForInstance(instance.index);
      for (const child of instance.child_indices || []) {
        const to = nodeIdForInstance(child);
        if (byId.has(to)) edges.push({ from, to, label: instance.spending_clause || "spend" });
      }
      for (const outpoint of instance.terminal_outpoints || []) {
        const to = nodeIdForTerminal(outpoint);
        if (byId.has(to)) edges.push({ from, to, label: instance.spending_clause || "spend" });
      }
    }
    return { nodes, edges, byId };
  }

  function layoutGraph(reset = false) {
    if (reset) {
      positions.clear();
      pinned.clear();
    }
    const incoming = new Map(graph.nodes.map(node => [node.id, []]));
    const outgoing = new Map(graph.nodes.map(node => [node.id, []]));
    for (const edge of graph.edges) {
      incoming.get(edge.to)?.push(edge.from);
      outgoing.get(edge.from)?.push(edge.to);
    }

    const depth = new Map(graph.nodes.map(node => [node.id, 0]));
    for (let pass = 0; pass < graph.nodes.length; pass += 1) {
      let changed = false;
      for (const edge of graph.edges) {
        const next = Math.min(graph.nodes.length, (depth.get(edge.from) || 0) + 1);
        if (next > (depth.get(edge.to) || 0)) {
          depth.set(edge.to, next);
          changed = true;
        }
      }
      if (!changed) break;
    }

    const columns = new Map();
    for (const node of graph.nodes) {
      const d = depth.get(node.id) || 0;
      if (!columns.has(d)) columns.set(d, []);
      columns.get(d).push(node);
    }

    for (const [d, column] of [...columns.entries()].sort((a, b) => a[0] - b[0])) {
      column.sort((a, b) => {
        const ap = incoming.get(a.id) || [];
        const bp = incoming.get(b.id) || [];
        const ay = ap.length ? average(ap.map(id => positions.get(id)?.y ?? 0)) : 0;
        const by = bp.length ? average(bp.map(id => positions.get(id)?.y ?? 0)) : 0;
        return ay - by || a.id.localeCompare(b.id);
      });
      let y = 40;
      for (const node of column) {
        if (!positions.has(node.id) || reset) {
          positions.set(node.id, { x: 40 + d * (NODE_W + COLUMN_GAP), y });
        }
        if (!pinned.has(node.id)) {
          const pos = positions.get(node.id);
          pos.x = 40 + d * (NODE_W + COLUMN_GAP);
          pos.y = y;
        }
        y += node.height + ROW_GAP;
      }
    }
  }

  function average(values) {
    return values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : 0;
  }

  function applyBrowserState(next) {
    browserState = next || { connected: false, snapshot: null };
    const previousIds = new Set(graph.nodes.map(node => node.id));
    graph = deriveGraph(browserState.snapshot);
    layoutGraph(false);
    const hasNewNodes = graph.nodes.some(node => !previousIds.has(node.id));

    if (selectedId && !graph.byId.has(selectedId)) selectedId = null;
    updateStatus();
    updateDetail();
    empty.classList.toggle("hidden", graph.nodes.length > 0);
    if (firstLayout && graph.nodes.length) {
      firstLayout = false;
      requestAnimationFrame(fitGraph);
    } else if (hasNewNodes) {
      draw();
    }
  }

  function updateStatus() {
    dot.classList.toggle("connected", browserState.connected);
    connectionLabel.textContent = browserState.connected ? "Manager connected" : "Manager disconnected";
    const snapshot = browserState.snapshot;
    counts.textContent = `${snapshot?.instances?.length || 0} contracts · ${snapshot?.terminal_utxos?.length || 0} terminal UTXOs`;
  }

  function resizeCanvas() {
    const rect = canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    const width = Math.max(1, Math.round(rect.width * dpr));
    const height = Math.max(1, Math.round(rect.height * dpr));
    if (canvas.width !== width || canvas.height !== height) {
      canvas.width = width;
      canvas.height = height;
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    draw();
  }

  function worldToScreen(point) {
    return { x: point.x * viewport.scale + viewport.x, y: point.y * viewport.scale + viewport.y };
  }

  function screenToWorld(point) {
    return { x: (point.x - viewport.x) / viewport.scale, y: (point.y - viewport.y) / viewport.scale };
  }

  function draw() {
    const rect = canvas.getBoundingClientRect();
    ctx.clearRect(0, 0, rect.width, rect.height);
    drawGrid(rect.width, rect.height);
    for (const edge of graph.edges) drawEdge(edge);
    for (const node of graph.nodes) drawNode(node);
  }

  function drawGrid(width, height) {
    const spacing = 28 * viewport.scale;
    if (spacing < 10) return;
    ctx.fillStyle = "#27313d55";
    const startX = ((viewport.x % spacing) + spacing) % spacing;
    const startY = ((viewport.y % spacing) + spacing) % spacing;
    for (let x = startX; x < width; x += spacing) {
      for (let y = startY; y < height; y += spacing) {
        ctx.beginPath(); ctx.arc(x, y, 1, 0, Math.PI * 2); ctx.fill();
      }
    }
  }

  function drawEdge(edge) {
    const fromNode = graph.byId.get(edge.from);
    const toNode = graph.byId.get(edge.to);
    const fromPos = positions.get(edge.from);
    const toPos = positions.get(edge.to);
    if (!fromNode || !toNode || !fromPos || !toPos) return;

    const start = worldToScreen({ x: fromPos.x + fromNode.width, y: fromPos.y + fromNode.height / 2 });
    const end = worldToScreen({ x: toPos.x, y: toPos.y + toNode.height / 2 });
    const bend = Math.max(30, (end.x - start.x) * .48);
    ctx.beginPath();
    ctx.moveTo(start.x, start.y);
    ctx.bezierCurveTo(start.x + bend, start.y, end.x - bend, end.y, end.x, end.y);
    ctx.strokeStyle = "#617083";
    ctx.lineWidth = Math.max(1, 1.4 * viewport.scale);
    ctx.stroke();

    const arrow = Math.max(5, 7 * viewport.scale);
    ctx.beginPath();
    ctx.moveTo(end.x, end.y);
    ctx.lineTo(end.x - arrow, end.y - arrow * .62);
    ctx.lineTo(end.x - arrow, end.y + arrow * .62);
    ctx.closePath();
    ctx.fillStyle = "#77879a";
    ctx.fill();

    if (viewport.scale > .52 && edge.label) {
      const mid = { x: (start.x + end.x) / 2, y: (start.y + end.y) / 2 - 7 };
      ctx.font = `${Math.max(9, 10 * viewport.scale)}px ui-monospace, monospace`;
      const label = truncate(edge.label, 20);
      const width = ctx.measureText(label).width + 10;
      ctx.fillStyle = "#0c1118dd";
      roundRect(mid.x - width / 2, mid.y - 9, width, 17, 4); ctx.fill();
      ctx.fillStyle = "#8e9baa";
      ctx.textAlign = "center"; ctx.textBaseline = "middle";
      ctx.fillText(label, mid.x, mid.y);
    }
  }

  function drawNode(node) {
    const pos = positions.get(node.id);
    if (!pos) return;
    const screen = worldToScreen(pos);
    const width = node.width * viewport.scale;
    const height = node.height * viewport.scale;
    if (screen.x + width < -20 || screen.y + height < -20 || screen.x > canvas.clientWidth + 20 || screen.y > canvas.clientHeight + 20) return;

    const selected = node.id === selectedId;
    const status = node.kind === "terminal" ? "terminal" : node.data.status.toLowerCase();
    const palette = status === "funded"
      ? { border: "#54c98b", accent: "#69db9f", fill: "#12231d" }
      : status === "terminal"
        ? { border: "#d49d4b", accent: "#f1b65c", fill: "#261e13" }
        : { border: "#536273", accent: "#8391a1", fill: "#151b23" };

    ctx.shadowColor = selected ? "#59d7d077" : "#0007";
    ctx.shadowBlur = selected ? 18 : 10;
    ctx.fillStyle = palette.fill;
    ctx.strokeStyle = selected ? "#59d7d0" : palette.border;
    ctx.lineWidth = selected ? 2.2 : 1.2;
    roundRect(screen.x, screen.y, width, height, Math.max(7, 10 * viewport.scale));
    ctx.fill(); ctx.stroke();
    ctx.shadowBlur = 0;

    const barWidth = Math.max(3, 4 * viewport.scale);
    ctx.fillStyle = palette.accent;
    roundRect(screen.x, screen.y, barWidth, height, Math.max(5, 8 * viewport.scale)); ctx.fill();

    if (viewport.scale < .35) return;
    const pad = 16 * viewport.scale;
    ctx.textAlign = "left"; ctx.textBaseline = "top";
    ctx.fillStyle = "#e6edf5";
    ctx.font = `600 ${Math.max(9, 13 * viewport.scale)}px system-ui, sans-serif`;
    const title = node.kind === "terminal" ? "Terminal UTXO" : node.data.contract_name;
    ctx.fillText(truncate(title, 24), screen.x + pad, screen.y + 13 * viewport.scale);
    ctx.fillStyle = palette.accent;
    ctx.font = `600 ${Math.max(7, 9 * viewport.scale)}px system-ui, sans-serif`;
    ctx.fillText(status.toUpperCase(), screen.x + pad, screen.y + 35 * viewport.scale);
    ctx.fillStyle = "#8f9baa";
    ctx.font = `${Math.max(7, 9.5 * viewport.scale)}px ui-monospace, monospace`;
    const outpoint = node.kind === "terminal" ? node.data.outpoint : (node.data.outpoint || `instance #${node.data.index}`);
    ctx.fillText(truncateMiddle(outpoint, 29), screen.x + pad, screen.y + 55 * viewport.scale);
    const amount = node.kind === "terminal" ? node.data.amount_sat : node.data.funding_amount_sat;
    if (amount != null) {
      ctx.textAlign = "right";
      ctx.fillStyle = "#b5c0cd";
      ctx.fillText(`${formatNumber(amount)} sat`, screen.x + width - 12 * viewport.scale, screen.y + 35 * viewport.scale);
    }
  }

  function roundRect(x, y, width, height, radius) {
    const r = Math.min(radius, width / 2, height / 2);
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.arcTo(x + width, y, x + width, y + height, r);
    ctx.arcTo(x + width, y + height, x, y + height, r);
    ctx.arcTo(x, y + height, x, y, r);
    ctx.arcTo(x, y, x + width, y, r);
    ctx.closePath();
  }

  function hitNode(screenPoint) {
    const world = screenToWorld(screenPoint);
    for (let i = graph.nodes.length - 1; i >= 0; i -= 1) {
      const node = graph.nodes[i];
      const pos = positions.get(node.id);
      if (pos && world.x >= pos.x && world.x <= pos.x + node.width && world.y >= pos.y && world.y <= pos.y + node.height) return node;
    }
    return null;
  }

  function fitGraph() {
    if (!graph.nodes.length) return;
    const bounds = graphBounds();
    const width = canvas.clientWidth;
    const height = canvas.clientHeight;
    const padding = 70;
    viewport.scale = Math.max(.2, Math.min(1.35, (width - padding * 2) / bounds.width, (height - padding * 2) / bounds.height));
    viewport.x = (width - bounds.width * viewport.scale) / 2 - bounds.x * viewport.scale;
    viewport.y = (height - bounds.height * viewport.scale) / 2 - bounds.y * viewport.scale;
    draw();
  }

  function graphBounds() {
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const node of graph.nodes) {
      const pos = positions.get(node.id);
      if (!pos) continue;
      minX = Math.min(minX, pos.x); minY = Math.min(minY, pos.y);
      maxX = Math.max(maxX, pos.x + node.width); maxY = Math.max(maxY, pos.y + node.height);
    }
    return { x: minX, y: minY, width: Math.max(1, maxX - minX), height: Math.max(1, maxY - minY) };
  }

  function pointerPoint(event) {
    const rect = canvas.getBoundingClientRect();
    return { x: event.clientX - rect.left, y: event.clientY - rect.top };
  }

  canvas.addEventListener("pointerdown", event => {
    const point = pointerPoint(event);
    const node = hitNode(point);
    moved = false;
    canvas.setPointerCapture(event.pointerId);
    canvas.classList.add("dragging");
    if (node) {
      const world = screenToWorld(point);
      const pos = positions.get(node.id);
      interaction = { kind: "node", id: node.id, dx: world.x - pos.x, dy: world.y - pos.y, start: point };
      selectedId = node.id;
      updateDetail();
    } else {
      interaction = { kind: "pan", start: point, x: viewport.x, y: viewport.y };
    }
    draw();
  });

  canvas.addEventListener("pointermove", event => {
    if (!interaction) return;
    const point = pointerPoint(event);
    if (Math.hypot(point.x - interaction.start.x, point.y - interaction.start.y) > 3) moved = true;
    if (interaction.kind === "pan") {
      viewport.x = interaction.x + point.x - interaction.start.x;
      viewport.y = interaction.y + point.y - interaction.start.y;
    } else {
      const world = screenToWorld(point);
      positions.set(interaction.id, { x: world.x - interaction.dx, y: world.y - interaction.dy });
      if (moved) pinned.add(interaction.id);
    }
    draw();
  });

  function endPointer(event) {
    if (!interaction) return;
    if (interaction.kind === "pan" && !moved) {
      selectedId = null;
      updateDetail();
    }
    interaction = null;
    canvas.classList.remove("dragging");
    if (canvas.hasPointerCapture(event.pointerId)) canvas.releasePointerCapture(event.pointerId);
    draw();
  }
  canvas.addEventListener("pointerup", endPointer);
  canvas.addEventListener("pointercancel", endPointer);

  canvas.addEventListener("wheel", event => {
    event.preventDefault();
    const point = pointerPoint(event);
    const before = screenToWorld(point);
    const factor = Math.exp(-event.deltaY * .0012);
    viewport.scale = Math.max(.18, Math.min(2.4, viewport.scale * factor));
    viewport.x = point.x - before.x * viewport.scale;
    viewport.y = point.y - before.y * viewport.scale;
    draw();
  }, { passive: false });

  document.getElementById("fit-button").addEventListener("click", fitGraph);
  document.getElementById("reset-button").addEventListener("click", () => {
    layoutGraph(true);
    fitGraph();
  });

  function updateDetail() {
    const node = selectedId ? graph.byId.get(selectedId) : null;
    if (!node) {
      detail.innerHTML = `<div class="detail-empty"><span class="detail-icon">↖</span><strong>Select a node</strong><p>Click a contract instance or terminal UTXO to inspect it.</p></div>`;
      return;
    }
    detail.innerHTML = node.kind === "contract" ? contractDetail(node.data) : terminalDetail(node.data);
  }

  function contractDetail(instance) {
    const funding = findTransaction(instance.funding_txid);
    const spending = findTransaction(instance.spending_txid);
    const args = instance.named_spending_args?.length
      ? instance.named_spending_args.map(arg => `<div class="arg"><span class="field-label">${esc(arg.name)} · ${esc(arg.kind)}</span>${arg.signer_pubkey ? field("Signer pubkey", arg.signer_pubkey, true) : ""}<pre>${arg.values_hex.map((value, index) => `[${index}] ${value || "<empty>"}`).join("\n")}</pre></div>`).join("")
      : instance.spending_args?.length
        ? `<pre>${instance.spending_args.map((value, index) => `[${index}] ${value || "<empty>"}`).join("\n")}</pre>`
        : `<span class="field-value">—</span>`;

    return `<div class="detail-head"><div class="eyebrow">Contract instance #${instance.index}</div><h2>${esc(instance.contract_name)}</h2><span class="badge ${instance.status.toLowerCase()}">${esc(instance.status)}</span></div>
      <div class="detail-body">
        <section class="detail-section"><h3>UTXO</h3>
          ${field("Outpoint", instance.outpoint || "—", true)}
          ${field("Amount", instance.funding_amount_sat == null ? "—" : `${formatNumber(instance.funding_amount_sat)} sat`)}
          ${field("Address", instance.address || "—", true)}
        </section>
        <section class="detail-section"><h3>Contract data</h3>
          ${debugValue("Parameters", instance.params_debug || "Unavailable")}
          <details><summary>Raw parameter encoding · ${Math.floor((instance.params_hex || "").length / 2)} bytes</summary><pre>${esc(instance.params_hex || "<empty>")}</pre></details>
          ${debugValue("Logical state", instance.state_debug || "Stateless")}
          <details><summary>Committed state · ${Math.floor((instance.data_hex || "").length / 2)} bytes</summary><pre>${esc(instance.data_hex || "<empty>")}</pre></details>
        </section>
        <section class="detail-section"><h3>Spend</h3>
          ${field("Clause", instance.spending_clause || "Not spent")}
          ${field("Input index", instance.spending_vin == null ? "—" : String(instance.spending_vin))}
          <div class="field"><span class="field-label">Witness arguments</span>${args}</div>
        </section>
        ${transactionSection("Funding transaction", funding)}
        ${transactionSection("Spending transaction", spending)}
      </div>`;
  }

  function terminalDetail(utxo) {
    const creating = findTransaction(utxo.txid);
    return `<div class="detail-head"><div class="eyebrow">Graph leaf</div><h2>Terminal UTXO</h2><span class="badge terminal">Terminal</span></div>
      <div class="detail-body">
        <section class="detail-section"><h3>Output</h3>
          ${field("Outpoint", utxo.outpoint, true)}
          ${field("Amount", `${formatNumber(utxo.amount_sat)} sat`)}
          ${field("Address", utxo.address || "Non-address script", true)}
          <details><summary>scriptPubKey</summary><pre>${esc(utxo.script_pubkey_hex || "<empty>")}</pre></details>
        </section>
        <section class="detail-section"><div class="notice">Terminal outputs are graph leaves. The inspector does not monitor them for later external spends.</div></section>
        ${transactionSection("Creating transaction", creating)}
      </div>`;
  }

  function transactionSection(title, tx) {
    if (!tx) return `<section class="detail-section"><h3>${esc(title)}</h3><span class="field-value">Unavailable</span></section>`;
    const inputs = tx.inputs.map((input, index) => `<details><summary>Input ${index} · ${esc(truncateMiddle(input.previous_output, 30))}</summary>${field("Previous output", input.previous_output, true)}${field("Sequence", String(input.sequence))}<span class="field-label">scriptSig</span><pre>${esc(input.script_sig_hex || "<empty>")}</pre><span class="field-label">Witness</span><pre>${input.witness.map((value, i) => `[${i}] ${esc(value || "<empty>")}`).join("\n") || "<empty>"}</pre></details>`).join("");
    const outputs = tx.outputs.map(output => `<details><summary>Output ${output.vout} · ${formatNumber(output.amount_sat)} sat</summary>${field("Address", output.address || "Non-address script", true)}<span class="field-label">scriptPubKey</span><pre>${esc(output.script_pubkey_hex || "<empty>")}</pre></details>`).join("");
    return `<section class="detail-section"><h3>${esc(title)}</h3>
      ${field("Txid", tx.txid, true)}
      <div class="tx-summary"><div class="metric"><b>${tx.vsize}</b><span>vbytes</span></div><div class="metric"><b>${tx.inputs.length}</b><span>inputs</span></div><div class="metric"><b>${tx.outputs.length}</b><span>outputs</span></div></div>
      ${field("Version / lock time", `${tx.version} / ${tx.lock_time}`)}
      ${inputs}${outputs}
      <details><summary>Raw transaction · ${Math.floor(tx.raw_hex.length / 2)} bytes</summary><pre>${esc(tx.raw_hex)}</pre></details>
    </section>`;
  }

  function findTransaction(txid) {
    if (!txid) return null;
    return browserState.snapshot?.transactions?.find(tx => tx.txid === txid) || null;
  }

  function field(label, value, mono = false) {
    return `<div class="field"><span class="field-label">${esc(label)}</span><span class="field-value${mono ? " mono" : ""}">${esc(value)}</span></div>`;
  }

  function debugValue(label, value) {
    return `<div class="field"><span class="field-label">${esc(label)}</span><pre>${esc(value)}</pre></div>`;
  }

  function esc(value) {
    return String(value).replace(/[&<>"']/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
  }
  function truncate(value, length) { return value.length <= length ? value : `${value.slice(0, length - 1)}…`; }
  function truncateMiddle(value, length) {
    if (!value || value.length <= length) return value || "";
    const half = Math.floor((length - 1) / 2);
    return `${value.slice(0, half)}…${value.slice(-half)}`;
  }
  function formatNumber(value) { return Number(value).toLocaleString("en-US"); }

  async function connect() {
    try {
      const response = await fetch("/api/state", { cache: "no-store" });
      if (response.ok) applyBrowserState(await response.json());
    } catch (_) {
      connectionLabel.textContent = "Browser bridge unavailable";
    }

    const events = new EventSource("/api/events");
    events.addEventListener("state", event => {
      try { applyBrowserState(JSON.parse(event.data)); } catch (error) { console.error("invalid inspector state", error); }
    });
    events.onerror = () => {
      dot.classList.remove("connected");
      connectionLabel.textContent = "Browser bridge reconnecting";
    };
  }

  new ResizeObserver(resizeCanvas).observe(canvas);
  window.addEventListener("resize", resizeCanvas);
  connect();
})();
