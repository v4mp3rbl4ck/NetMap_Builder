import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import ReactFlow, {
  Background,
  BaseEdge,
  Controls,
  EdgeLabelRenderer,
  MiniMap,
  MarkerType,
  Handle,
  Position,
  applyEdgeChanges,
  applyNodeChanges,
  getSmoothStepPath,
  getNodesBounds,
  getViewportForBounds,
  ReactFlowProvider,
  useReactFlow,
} from 'reactflow';
import 'reactflow/dist/style.css';
import * as htmlToImage from 'html-to-image';
import dagre from 'dagre';
import { jsPDF } from 'jspdf';
import {
  ChevronLeft,
  ChevronRight,
  Database,
  Download,
  FileInput,
  Filter,
  Globe,
  Maximize2,
  Minimize2,
  Layers,
  Link2,
  Lock,
  Monitor,
  Network,
  Plus,
  RefreshCw,
  Save,
  Search,
  Server,
  Shield,
  Trash2,
  Upload,
  Users,
  X,
  Zap,
} from 'lucide-react';
import './styles.css';

const API = '/api';
const VERSION = 'v.1.5.1';
const DEVICE_TYPES = ['firewall', 'router', 'switch', 'server', 'endpoint', 'printer', 'access_point', 'camera', 'nas', 'ups', 'cloud', 'internet', 'network', 'unknown'];
const ICONS = ['auto', 'firewall', 'router', 'switch', 'server', 'endpoint', 'printer', 'access_point', 'camera', 'nas', 'ups', 'cloud', 'internet', 'database', 'wifi', 'unknown'];
const STATUSES = ['UP', 'DOWN', 'WARNING', 'UNKNOWN', 'DEGRADED'];
const LINK_TYPES = ['physical_link', 'l2_link', 'l3_link', 'firewall_link', 'vpn_link', 'wireless_link', 'service_dependency', 'uplink', 'backup_link', 'internet_link'];
const ENTITY_TYPES = ['device', 'segment', 'service'];
const USER_ROLES = ['admin', 'editor', 'viewer', 'auditor'];
const EXPORT_BACKGROUND = '#f4f8fa';
const EXPORT_PADDING = 220;
const EXPORT_MIN_WIDTH = 1400;
const EXPORT_MIN_HEIGHT = 900;

function scriptJson(value) {
  return JSON.stringify(value).replace(/</g, '\\u003c');
}

function getUser() {
  try { return JSON.parse(localStorage.getItem('netmap-user') || 'null'); } catch { return null; }
}

function request(path, options = {}) {
  const cfg = { ...options };
  const user = getUser();
  const headers = { ...(cfg.headers || {}) };
  if (user?.token) {
    headers.Authorization = `Bearer ${user.token}`;
  }
  if (cfg.body && !(cfg.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
    cfg.body = JSON.stringify(cfg.body);
  }
  cfg.headers = headers;
  cfg.credentials = cfg.credentials || 'same-origin';
  return fetch(`${API}${path}`, cfg).then(async (res) => {
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      if (res.status === 401 && path !== '/auth/login') localStorage.removeItem('netmap-user');
      const detail = data.detail || data.message || `HTTP ${res.status}`;
      const message = typeof detail === 'string' ? detail : (detail.message || JSON.stringify(detail));
      throw new Error(message);
    }
    return data;
  });
}

function iconFor(icon, type) {
  const key = icon && icon !== 'auto' ? icon : type;
  if (key === 'firewall') return '🧱';
  if (key === 'router') return '🔀';
  if (key === 'switch') return '▦';
  if (key === 'server') return '🖥️';
  if (key === 'endpoint') return '💻';
  if (key === 'printer') return '🖨️';
  if (key === 'access_point' || key === 'wifi') return '📡';
  if (key === 'cloud') return '☁️';
  if (key === 'internet') return '🌐';
  if (key === 'database') return '🗄️';
  if (key === 'camera') return '📷';
  if (key === 'nas') return '▣';
  if (key === 'ups') return '🔋';
  return '❔';
}

function statusColor(status) {
  if (status === 'UP') return '#22c55e';
  if (status === 'DOWN') return '#ef4444';
  if (status === 'WARNING') return '#eab308';
  if (status === 'DEGRADED') return '#a855f7';
  return '#94a3b8';
}

function isInternetDevice(device = {}) {
  const text = [device.hostname, device.device_type, device.icon, device.role].join(' ').toLowerCase();
  return text.includes('internet') || device.device_type === 'internet' || device.icon === 'internet';
}

function parallelOffset(index = 0, count = 1) {
  if (count <= 1) return 0;
  const center = (count - 1) / 2;
  const step = count > 3 ? 22 : 28;
  return (index - center) * step;
}

function pointFromHandle(x, y, position, distance = 28) {
  if (position === Position.Top) return { x, y: y - distance };
  if (position === Position.Bottom) return { x, y: y + distance };
  if (position === Position.Left) return { x: x - distance, y };
  if (position === Position.Right) return { x: x + distance, y };
  return { x, y };
}

const HANDLE_SIDE_POSITION = {
  top: Position.Top,
  bottom: Position.Bottom,
  left: Position.Left,
  right: Position.Right,
};
const HIDDEN_HANDLE_STYLE = { opacity: 0, pointerEvents: 'none' };

function handleStyle(side, percent = 50) {
  const base = { opacity: 1 };
  if (side === 'top' || side === 'bottom') return { ...base, left: `${percent}%`, transform: 'translateX(-50%)' };
  return { ...base, top: `${percent}%`, transform: 'translateY(-50%)' };
}

function handleVector(position) {
  if (position === Position.Top) return { x: 0, y: -1 };
  if (position === Position.Bottom) return { x: 0, y: 1 };
  if (position === Position.Left) return { x: -1, y: 0 };
  if (position === Position.Right) return { x: 1, y: 0 };
  return { x: 0, y: 1 };
}

function bezierPoint(p0, p1, p2, p3, t) {
  const mt = 1 - t;
  return {
    x: mt ** 3 * p0.x + 3 * mt ** 2 * t * p1.x + 3 * mt * t ** 2 * p2.x + t ** 3 * p3.x,
    y: mt ** 3 * p0.y + 3 * mt ** 2 * t * p1.y + 3 * mt * t ** 2 * p2.y + t ** 3 * p3.y,
  };
}

function parallelCablePath(sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, offset = 0) {
  const dx = targetX - sourceX;
  const dy = targetY - sourceY;
  const distance = Math.max(1, Math.sqrt(dx * dx + dy * dy));
  const nx = -dy / distance;
  const ny = dx / distance;
  const sourceVector = handleVector(sourcePosition);
  const targetVector = handleVector(targetPosition);
  const curve = Math.min(180, Math.max(70, distance * 0.38));
  const p0 = { x: sourceX, y: sourceY };
  const p3 = { x: targetX, y: targetY };
  const p1 = { x: sourceX + sourceVector.x * curve + nx * offset, y: sourceY + sourceVector.y * curve + ny * offset };
  const p2 = { x: targetX + targetVector.x * curve + nx * offset, y: targetY + targetVector.y * curve + ny * offset };
  return {
    path: `M ${p0.x},${p0.y} C ${p1.x},${p1.y} ${p2.x},${p2.y} ${p3.x},${p3.y}`,
    sourceLane: bezierPoint(p0, p1, p2, p3, 0.18),
    targetLane: bezierPoint(p0, p1, p2, p3, 0.88),
    labelLane: bezierPoint(p0, p1, p2, p3, 0.72),
  };
}

function DeviceNode({ data, selected }) {
  const visualHandles = data.visual_handles || [];
  const hideDefaultHandles = visualHandles.length > 0;
  return (
    <div className={`device-node ${selected ? 'selected' : ''} ${data.impact ? 'impact' : ''} status-${data.status || 'UNKNOWN'}`}>
      <Handle id="target-top" type="target" position={Position.Top} style={hideDefaultHandles ? HIDDEN_HANDLE_STYLE : undefined} />
      <Handle id="target-bottom" type="target" position={Position.Bottom} style={HIDDEN_HANDLE_STYLE} />
      <Handle id="target-left" type="target" position={Position.Left} style={HIDDEN_HANDLE_STYLE} />
      <Handle id="target-right" type="target" position={Position.Right} style={HIDDEN_HANDLE_STYLE} />
      <Handle id="source-top" type="source" position={Position.Top} style={HIDDEN_HANDLE_STYLE} />
      <Handle id="source-bottom" type="source" position={Position.Bottom} style={hideDefaultHandles ? HIDDEN_HANDLE_STYLE : undefined} />
      <Handle id="source-left" type="source" position={Position.Left} style={HIDDEN_HANDLE_STYLE} />
      <Handle id="source-right" type="source" position={Position.Right} style={HIDDEN_HANDLE_STYLE} />
      {visualHandles.map((handle) => (
        <Handle
          key={handle.id}
          id={handle.id}
          type={handle.type}
          position={HANDLE_SIDE_POSITION[handle.side] || Position.Bottom}
          className="visual-handle"
          style={handleStyle(handle.side, handle.percent)}
        />
      ))}
      <div className="device-icon">{iconFor(data.icon, data.device_type)}</div>
      <div className="device-title">{data.hostname}</div>
      <div className="device-ip">{data.management_ip || 'sin IP'}</div>
      <div className="device-meta"><span>{data.device_type}</span><span>{data.status}</span></div>
      {data.is_perimeter ? <div className="tag tag-red">Perimetral</div> : null}
      {data.is_main ? <div className="tag tag-blue">Principal</div> : null}
    </div>
  );
}

function SegmentNode({ data, selected }) {
  return (
    <div className={`segment-node ${selected ? 'selected' : ''}`} style={{ borderColor: data.color || '#38bdf8' }}>
      <Handle type="target" position={Position.Top} />
      <Handle type="source" position={Position.Bottom} />
      <div className="segment-title">{data.collapsed ? '▸' : '▾'} {data.name}</div>
      <div className="segment-meta">{data.vlan ? `VLAN ${data.vlan}` : 'sin VLAN'} · {data.count || 0} hosts</div>
      <div className="segment-meta">{data.cidr || 'sin CIDR'}</div>
    </div>
  );
}

function ServiceNode({ data, selected }) {
  return (
    <div className={`service-node ${selected ? 'selected' : ''} ${data.impact ? 'impact' : ''}`}>
      <Handle type="target" position={Position.Top} />
      <Handle type="source" position={Position.Bottom} />
      <div className="device-icon">⚙️</div>
      <div className="device-title">{data.name}</div>
      <div className="device-ip">{data.service_type || 'servicio'}</div>
      <div className="device-meta"><span>{data.criticality}</span><span>{data.status}</span></div>
    </div>
  );
}

const nodeTypes = { device: DeviceNode, segment: SegmentNode, service: ServiceNode };

function NearTargetEdge({ sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, markerEnd, style, label, className, data }) {
  const offset = data?.parallel_offset || 0;
  const isParallel = data?.entity_type === 'link' && data?.parallel_count > 1;
  const cable = isParallel ? parallelCablePath(sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, offset) : null;
  const [smoothPath] = getSmoothStepPath({ sourceX, sourceY, sourcePosition, targetX, targetY, targetPosition, borderRadius: 16 });
  const edgePath = cable?.path || smoothPath;
  const showEndpointLabels = data?.entity_type === 'link' && (data?.source_interface || data?.target_interface || data?.parallel_count > 1);
  const sourceLabel = data?.source_interface || (data?.parallel_count > 1 ? `link ${Number(data?.parallel_index || 0) + 1}` : '');
  const targetLabel = data?.target_interface || (data?.parallel_count > 1 ? `link ${Number(data?.parallel_index || 0) + 1}` : '');
  const sourcePoint = cable?.sourceLane || pointFromHandle(sourceX, sourceY, sourcePosition, 22);
  const targetPoint = cable?.targetLane || pointFromHandle(targetX, targetY, targetPosition, 18);
  const labelPoint = cable?.labelLane || pointFromHandle(targetX, targetY, targetPosition, showEndpointLabels && targetLabel ? 36 : 24);
  return (
    <>
      <BaseEdge path={edgePath} markerEnd={markerEnd} style={style} className={className} />
      {(label || showEndpointLabels) ? (
        <EdgeLabelRenderer>
          {showEndpointLabels && sourceLabel ? (
            <div className="edge-port-label edge-port-source" style={{ transform: `translate(-50%, -50%) translate(${sourcePoint.x}px, ${sourcePoint.y}px)` }}>
              {sourceLabel}
            </div>
          ) : null}
          {label ? (
            <div
              className={`edge-near-label ${data?.entity_type === 'dependency' ? 'dependency-label' : ''} ${data?.parallel_count > 1 ? 'parallel-label' : ''}`}
              style={{ transform: `translate(-50%, -50%) translate(${labelPoint.x}px, ${labelPoint.y}px)` }}
            >
              {label}
            </div>
          ) : null}
          {showEndpointLabels && targetLabel ? (
            <div className="edge-port-label edge-port-target" style={{ transform: `translate(-50%, -50%) translate(${targetPoint.x}px, ${targetPoint.y}px)` }}>
              {targetLabel}
            </div>
          ) : null}
        </EdgeLabelRenderer>
      ) : null}
    </>
  );
}

const edgeTypes = { nearTarget: NearTargetEdge };

function layoutTier(node) {
  if (isInternetDevice(node.data)) return 0;
  const tier = Number(node.data?.tier);
  return Number.isFinite(tier) ? tier : inferVisualTier(node.data?.device_type, node.data?.role);
}

function inferVisualTier(deviceType = '', role = '') {
  const dtype = String(deviceType || '').toLowerCase();
  const r = String(role || '').toLowerCase();
  if (dtype.includes('internet') || dtype.includes('cloud')) return 0;
  if (dtype.includes('firewall') || r.includes('perimeter')) return 1;
  if (dtype.includes('router')) return 2;
  if (r.includes('core')) return 3;
  if (dtype.includes('switch') && r.includes('access')) return 5;
  if (dtype.includes('switch')) return 4;
  return 6;
}

function hierarchyLayoutEdges(nodes, edges) {
  const nodeById = new Map(nodes.map((n) => [n.id, n]));
  const edgeMap = new Map();
  const push = (source, target, virtual = false) => {
    if (!source || !target || source === target || !nodeById.has(source) || !nodeById.has(target)) return;
    const key = `${source}->${target}`;
    if (!edgeMap.has(key)) edgeMap.set(key, { source, target, virtual });
  };

  (edges || []).forEach((edge) => {
    const source = nodeById.get(edge.source);
    const target = nodeById.get(edge.target);
    if (!source || !target) return;
    const sourceTier = layoutTier(source);
    const targetTier = layoutTier(target);
    if (sourceTier > targetTier) push(edge.target, edge.source);
    else push(edge.source, edge.target);
  });

  nodes.forEach((node) => {
    const parentId = node.data?.parent_device_id;
    if (parentId && nodeById.has(parentId)) push(parentId, node.id, true);
  });

  const internetNodes = nodes.filter((n) => isInternetDevice(n.data));
  if (internetNodes.length) {
    const root = internetNodes[0];
    internetNodes.slice(1).forEach((n) => push(root.id, n.id, true));
    const incoming = new Set([...edgeMap.values()].map((edge) => edge.target));
    nodes.forEach((node) => {
      if (node.id !== root.id && !isInternetDevice(node.data) && !incoming.has(node.id)) {
        push(root.id, node.id, true);
      }
    });
  }

  return [...edgeMap.values()];
}

function getLayoutedElements(nodes, edges, direction = 'TB') {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: direction, ranksep: 132, nodesep: 86, edgesep: 34, ranker: 'network-simplex' });
  nodes.forEach((n) => g.setNode(n.id, { width: n.type === 'segment' ? 300 : 190, height: n.type === 'segment' ? 130 : 120 }));
  hierarchyLayoutEdges(nodes, edges).forEach((e) => g.setEdge(e.source, e.target, { weight: e.virtual ? 2 : 4 }));
  dagre.layout(g);
  return nodes.map((n) => {
    const pos = g.node(n.id);
    return { ...n, position: { x: pos.x - 95, y: pos.y - 60 } };
  });
}

function layoutByMode(nodes, edges, mode, state) {
  if (mode === 'segment') {
    const segIndex = new Map((state.segments || []).map((s, idx) => [s.id, idx]));
    return nodes.map((n, idx) => {
      const seg = n.data?.segment_id || n.id?.replace('segment-', '');
      const col = segIndex.get(seg) ?? 0;
      const row = n.type === 'segment' ? 0 : idx % 8;
      return { ...n, position: { x: col * 420 + 80, y: n.type === 'segment' ? 60 : 220 + row * 150 } };
    });
  }
  if (mode === 'cidr') {
    const segmentsById = new Map((state.segments || []).map((s) => [s.id, s]));
    const groupKeys = [...new Set(nodes.map((n) => {
      const sid = n.type === 'segment' ? n.id?.replace('segment-', '') : n.data?.segment_id;
      const seg = segmentsById.get(sid);
      return seg?.cidr || (seg?.vlan ? `VLAN-${seg.vlan}` : 'Sin-CIDR');
    }))].sort();
    const groupIndex = new Map(groupKeys.map((k, idx) => [k, idx]));
    return nodes.map((n, idx) => {
      const sid = n.type === 'segment' ? n.id?.replace('segment-', '') : n.data?.segment_id;
      const seg = segmentsById.get(sid);
      const key = seg?.cidr || (seg?.vlan ? `VLAN-${seg.vlan}` : 'Sin-CIDR');
      const col = groupIndex.get(key) ?? 0;
      const row = n.type === 'segment' ? 0 : idx % 8;
      return { ...n, position: { x: col * 430 + 80, y: n.type === 'segment' ? 60 : 220 + row * 142 } };
    });
  }
  if (mode === 'type') {
    const order = DEVICE_TYPES;
    return nodes.map((n, idx) => {
      const col = Math.max(0, order.indexOf(n.data?.device_type || 'unknown'));
      return { ...n, position: { x: col * 260 + 80, y: 80 + (idx % 10) * 150 } };
    });
  }
  if (mode === 'status') {
    return nodes.map((n, idx) => {
      const col = Math.max(0, STATUSES.indexOf(n.data?.status || 'UNKNOWN'));
      return { ...n, position: { x: col * 300 + 80, y: 100 + (idx % 10) * 150 } };
    });
  }
  if (mode === 'sede') return getLayoutedElements(nodes, edges, 'LR');
  return getLayoutedElements(nodes, edges, 'TB');
}

function hasSavedPosition(item) {
  return Number.isFinite(item?.x_position) && Number.isFinite(item?.y_position);
}

function segmentIdFromNodeId(nodeId) {
  return String(nodeId || '').replace(/^segment-/, '');
}

function spreadSegmentGroups(nodes, segments) {
  const nodesBySegment = new Map();
  nodes.forEach((n) => {
    const sid = n.data?.segment_id || 'none';
    if (!nodesBySegment.has(sid)) nodesBySegment.set(sid, []);
    nodesBySegment.get(sid).push(n);
  });

  const offsets = new Map();
  const segmentSlots = new Map();
  let cursorX = 80;
  let cursorY = 60;
  let rowHeight = 0;
  const maxRowWidth = 1700;
  const gapX = 120;
  const gapY = 110;

  segments.forEach((s, idx) => {
    const list = nodesBySegment.get(s.id) || [];
    const minX = list.length ? Math.min(...list.map((n) => n.position.x)) : 0;
    const minY = list.length ? Math.min(...list.map((n) => n.position.y)) : 0;
    const maxX = list.length ? Math.max(...list.map((n) => n.position.x)) : 220;
    const maxY = list.length ? Math.max(...list.map((n) => n.position.y)) : 120;
    const width = Math.max(320, maxX - minX + 310);
    const height = Math.max(170, maxY - minY + 220);

    if (idx > 0 && cursorX + width > maxRowWidth) {
      cursorX = 80;
      cursorY += rowHeight + gapY;
      rowHeight = 0;
    }

    const sourceX = minX - 70;
    const sourceY = minY - 90;
    segmentSlots.set(s.id, { x: cursorX, y: cursorY });
    offsets.set(s.id, { dx: cursorX - sourceX, dy: cursorY - sourceY });
    cursorX += width + gapX;
    rowHeight = Math.max(rowHeight, height);
  });

  return {
    nodes: nodes.map((n) => {
      const offset = offsets.get(n.data?.segment_id);
      if (!offset) return n;
      return { ...n, position: { x: n.position.x + offset.dx, y: n.position.y + offset.dy } };
    }),
    segmentSlots,
  };
}

function nodeBounds(node) {
  const width = Number(node?.style?.width) || (node?.type === 'segment' ? 300 : 190);
  const height = Number(node?.style?.height) || (node?.type === 'segment' ? 130 : 120);
  return { width, height };
}

function nodeCenter(node) {
  const { width, height } = nodeBounds(node);
  return { x: node.position.x + width / 2, y: node.position.y + height / 2 };
}

function linkHandleProps(sourceNode, targetNode) {
  if (!sourceNode || !targetNode || sourceNode.type !== 'device' || targetNode.type !== 'device') return {};
  const source = nodeCenter(sourceNode);
  const target = nodeCenter(targetNode);
  const dx = target.x - source.x;
  const dy = target.y - source.y;
  if (Math.abs(dy) >= 85 || Math.abs(dy) >= Math.abs(dx) * 0.35) {
    return dy >= 0
      ? { sourceHandle: 'source-bottom', targetHandle: 'target-top' }
      : { sourceHandle: 'source-top', targetHandle: 'target-bottom' };
  }
  if (Math.abs(dx) >= Math.abs(dy)) {
    return dx >= 0
      ? { sourceHandle: 'source-right', targetHandle: 'target-left' }
      : { sourceHandle: 'source-left', targetHandle: 'target-right' };
  }
  return dy >= 0
    ? { sourceHandle: 'source-bottom', targetHandle: 'target-top' }
    : { sourceHandle: 'source-top', targetHandle: 'target-bottom' };
}

function linkSides(sourceNode, targetNode) {
  const props = linkHandleProps(sourceNode, targetNode);
  return {
    sourceSide: String(props.sourceHandle || 'source-bottom').replace('source-', ''),
    targetSide: String(props.targetHandle || 'target-top').replace('target-', ''),
  };
}

function lanePercent(index, count) {
  if (count <= 1) return 50;
  const spread = Math.min(76, 18 + count * 14);
  const start = (100 - spread) / 2;
  return start + (spread * index) / (count - 1);
}

function buildDynamicHandles(mappedLinks, nodeById) {
  const requestsBySide = new Map();
  const assignments = new Map();
  const handlesByNode = new Map();
  const addRequest = (request) => {
    const key = `${request.nodeId}:${request.side}`;
    if (!requestsBySide.has(key)) requestsBySide.set(key, []);
    requestsBySide.get(key).push(request);
  };

  mappedLinks.forEach((link) => {
    const sourceNode = nodeById.get(link._source);
    const targetNode = nodeById.get(link._target);
    if (!sourceNode || !targetNode || sourceNode.type !== 'device' || targetNode.type !== 'device') return;
    const sides = linkSides(sourceNode, targetNode);
    addRequest({ edgeId: link.id, type: 'source', nodeId: link._source, side: sides.sourceSide, otherNodeId: link._target });
    addRequest({ edgeId: link.id, type: 'target', nodeId: link._target, side: sides.targetSide, otherNodeId: link._source });
  });

  requestsBySide.forEach((requests) => {
    const side = requests[0]?.side || 'bottom';
    const axis = side === 'top' || side === 'bottom' ? 'x' : 'y';
    const sorted = requests
      .slice()
      .sort((a, b) => {
        const ac = nodeCenter(nodeById.get(a.otherNodeId) || nodeById.get(a.nodeId))[axis];
        const bc = nodeCenter(nodeById.get(b.otherNodeId) || nodeById.get(b.nodeId))[axis];
        return ac - bc || a.edgeId.localeCompare(b.edgeId);
      });
    sorted.forEach((request, index) => {
      const percent = lanePercent(index, sorted.length);
      const handle = {
        id: `${request.type}-${request.side}-${request.edgeId}`,
        type: request.type,
        side: request.side,
        percent,
      };
      assignments.set(`${request.edgeId}:${request.type}`, handle.id);
      if (!handlesByNode.has(request.nodeId)) handlesByNode.set(request.nodeId, []);
      handlesByNode.get(request.nodeId).push(handle);
    });
  });

  return { assignments, handlesByNode };
}

function buildFlow(state, impactIds = new Set(), showServices = true, showSegments = true, impactEdgeIds = new Set()) {
  const segments = state.segments || [];
  const devices = state.devices || [];
  const links = state.links || [];
  const services = state.services || [];
  const dependencies = state.dependencies || [];

  const deviceNodes = devices.map((d, i) => ({
    id: d.id,
    type: 'device',
    position: { x: Number.isFinite(d.x_position) ? d.x_position : (d.tier || 6) * 40 + (i % 4) * 240, y: Number.isFinite(d.y_position) ? d.y_position : (d.tier || 6) * 150 },
    data: { ...d, entity_type: 'device', impact: impactIds.has(d.id) },
    zIndex: 30,
  }));

  const hasPositions = devices.some(hasSavedPosition);
  let laidDevices = hasPositions ? deviceNodes : getLayoutedElements(deviceNodes, links.map((l) => ({ id: l.id, source: l.source_device_id, target: l.target_device_id })));
  let segmentSlots = new Map();
  if (!hasPositions && !segments.some(hasSavedPosition)) {
    const packed = spreadSegmentGroups(laidDevices, segments);
    laidDevices = packed.nodes;
    segmentSlots = packed.segmentSlots;
  }

  const devicesBySegment = new Map();
  laidDevices.forEach((n) => {
    const sid = n.data.segment_id || 'none';
    if (!devicesBySegment.has(sid)) devicesBySegment.set(sid, []);
    devicesBySegment.get(sid).push(n);
  });

  const collapsedMap = new Map();
  const groupNodes = segments.map((s, idx) => {
    const groupId = `segment-${s.id}`;
    const list = devicesBySegment.get(s.id) || [];
    list.forEach((n) => { if (showSegments && s.collapsed) collapsedMap.set(n.id, groupId); });
    const minX = list.length ? Math.min(...list.map((n) => n.position.x)) : idx * 360 + 60;
    const minY = list.length ? Math.min(...list.map((n) => n.position.y)) : 60;
    const maxX = list.length ? Math.max(...list.map((n) => n.position.x)) : minX + 220;
    const maxY = list.length ? Math.max(...list.map((n) => n.position.y)) : minY + 120;
    const collapsed = !!s.collapsed;
    const segmentPosition = list.length
      ? { x: minX - 70, y: minY - 90 }
      : { x: s.x_position ?? segmentSlots.get(s.id)?.x ?? minX - 70, y: s.y_position ?? segmentSlots.get(s.id)?.y ?? minY - 90 };
    return {
      id: groupId,
      type: 'segment',
      position: segmentPosition,
      style: { width: collapsed ? 250 : Math.max(270, maxX - minX + 310), height: collapsed ? 130 : Math.max(150, maxY - minY + 220), zIndex: -10 },
      data: { ...s, entity_type: 'segment', count: list.length, impact: impactIds.has(s.id) },
      draggable: true,
      selectable: true,
      zIndex: -10,
    };
  });

  let visibleDeviceNodes = laidDevices.filter((n) => !collapsedMap.has(n.id));
  const serviceNodes = showServices ? services.map((s, idx) => ({
    id: `service-${s.id}`,
    type: 'service',
    position: { x: 1050 + (idx % 3) * 240, y: 120 + Math.floor(idx / 3) * 150 },
    data: { ...s, entity_type: 'service', impact: impactIds.has(s.id) },
    zIndex: 30,
  })) : [];
  let flowNodeById = new Map([...groupNodes, ...visibleDeviceNodes, ...serviceNodes].map((n) => [n.id, n]));
  const mappedLinks = links.map((l) => ({
    ...l,
    _source: collapsedMap.get(l.source_device_id) || l.source_device_id,
    _target: collapsedMap.get(l.target_device_id) || l.target_device_id,
  })).filter((l) => l._source !== l._target);
  const dynamicHandles = buildDynamicHandles(mappedLinks, flowNodeById);
  visibleDeviceNodes = visibleDeviceNodes.map((node) => ({
    ...node,
    data: { ...node.data, visual_handles: dynamicHandles.handlesByNode.get(node.id) || [] },
  }));
  flowNodeById = new Map([...groupNodes, ...visibleDeviceNodes, ...serviceNodes].map((n) => [n.id, n]));

  const entityNodeId = (type, id) => {
    if (type === 'device') return collapsedMap.get(id) || id;
    if (type === 'segment') return `segment-${id}`;
    if (type === 'service') return `service-${id}`;
    return id;
  };

  const edgeMap = new Map();
  function pushEdge(e) { if (e.source !== e.target && !edgeMap.has(e.id)) edgeMap.set(e.id, e); }
  const linkGroups = new Map();
  mappedLinks.forEach((l) => {
    const src = l._source;
    const tgt = l._target;
    const groupKey = [src, tgt].sort().join('::');
    if (!linkGroups.has(groupKey)) linkGroups.set(groupKey, []);
    linkGroups.get(groupKey).push(l);
  });
  linkGroups.forEach((group) => {
    const count = group.length;
    group
      .slice()
      .sort((a, b) => [a.source_interface, a.target_interface, a.id].join('|').localeCompare([b.source_interface, b.target_interface, b.id].join('|')))
      .forEach((link, index) => {
        const groupName = link.link_group || link.metadata?.link_group || '';
        const role = link.link_role || link.metadata?.link_role || '';
        const baseHandles = linkHandleProps(flowNodeById.get(link._source), flowNodeById.get(link._target));
        const labelParts = [
          link.label || link.link_type || 'link',
          groupName,
          role,
          count > 1 ? `${index + 1}/${count}` : '',
        ].filter(Boolean);
        pushEdge({
          id: link.id,
          source: link._source,
          target: link._target,
          ...baseHandles,
          sourceHandle: dynamicHandles.assignments.get(`${link.id}:source`) || baseHandles.sourceHandle,
          targetHandle: dynamicHandles.assignments.get(`${link.id}:target`) || baseHandles.targetHandle,
          label: labelParts.join(' · '),
          type: 'nearTarget',
          markerEnd: { type: MarkerType.ArrowClosed },
          data: {
            ...link,
            entity_type: 'link',
            parallel_links: group,
            parallel_count: count,
            parallel_index: index,
            parallel_offset: parallelOffset(index, count),
          },
          className: `${impactEdgeIds.has(link.id) ? 'impact-link-edge ' : ''}${count > 1 ? 'multi-link-edge ' : ''}${role ? `link-role-${role} ` : ''}edge-${link.status || 'UNKNOWN'}`,
          style: { strokeWidth: count > 1 ? 3 : 2.2 },
          zIndex: 20,
        });
      });
  });
  dependencies.forEach((d) => pushEdge({ id: d.id, source: entityNodeId(d.target_type, d.target_id), target: entityNodeId(d.source_type, d.source_id), label: d.dependency_type, type: 'nearTarget', markerEnd: { type: MarkerType.ArrowClosed }, data: { ...d, entity_type: 'dependency' }, className: `${impactEdgeIds.has(d.id) ? 'impact-link-edge ' : ''}dependency-edge criticality-${d.criticality}`, zIndex: 20 }));

  return { nodes: [...(showSegments ? groupNodes : []), ...visibleDeviceNodes, ...serviceNodes], edges: [...edgeMap.values()] };
}

function downloadBlob(content, filename, type = 'application/octet-stream') {
  const blob = content instanceof Blob ? content : new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function csvEscape(value) {
  const s = String(value ?? '');
  return /[",\n;]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function LoginScreen({ onLogin }) {
  const [credentials, setCredentials] = useState({ username: '', password: '' });
  const [error, setError] = useState('');
  async function submit(e) {
    e.preventDefault();
    try {
      const data = await request('/auth/login', { method: 'POST', body: credentials });
      const session = { ...data.user, token: data.token, expires_at: Date.now() + (Number(data.expires_in || 0) * 1000) };
      localStorage.setItem('netmap-user', JSON.stringify(session));
      onLogin(session);
    } catch (err) { setError(err.message); }
  }
  return <div className="login-page"><form onSubmit={submit} className="login-card"><Network size={42}/><h1>NetMap Builder</h1><p>v.1.5.1 · Portal enterprise</p><input value={credentials.username} onChange={e=>setCredentials({...credentials, username:e.target.value})} placeholder="usuario" autoComplete="username"/><input type="password" value={credentials.password} onChange={e=>setCredentials({...credentials, password:e.target.value})} placeholder="contraseña" autoComplete="current-password"/><button className="primary"><Lock size={16}/> Entrar</button>{error ? <div className="error-box">{error}</div> : null}<small>Acceso protegido. Usa las credenciales asignadas por el administrador.</small><div className="login-author">Creado por <a href="https://www.linkedin.com/in/v4mp3rbl4ck/" target="_blank" rel="noopener noreferrer">@v4mp3rbl4ck</a></div></form></div>
}

function AppShell() {
  const flowWrapper = useRef(null);
  const segmentDragRef = useRef(null);
  const { fitView } = useReactFlow();
  const [user, setUser] = useState(getUser());
  const canEdit = user?.role === 'admin' || user?.role === 'editor';
  const canExport = user?.role === 'admin' || user?.role === 'editor';
  const [state, setState] = useState({ devices: [], interfaces: [], links: [], segments: [], services: [], dependencies: [], audit: [], versions: [], users: [] });
  const [nodes, setNodes] = useState([]);
  const [edges, setEdges] = useState([]);
  const [selected, setSelected] = useState(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState(null);
  const [activeTab, setActiveTab] = useState('mapa');
  const [mapFullscreen, setMapFullscreen] = useState(false);
  const [message, setMessage] = useState('Inicializando...');
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState({ type: '', segment: '', status: '', vlan: '', ip: '', cidr: '' });
  const [impact, setImpact] = useState(null);
  const [selectedIds, setSelectedIds] = useState([]);
  const [bulk, setBulk] = useState({ segment_name: '', status: '', icon: '', device_type: '', parent_device_id: '', vlan: '' });
  const [bulkRelation, setBulkRelation] = useState({ target_device_id: '', link_type: 'uplink', status: 'UP', label: 'dependen del principal', direction: 'target_to_selected', set_parent: true });
  const [contextMenu, setContextMenu] = useState(null);
  const [layoutMode, setLayoutMode] = useState('jerarquia');
  const [showServices, setShowServices] = useState(true);
  const [showSegments, setShowSegments] = useState(true);
  const [versionForm, setVersionForm] = useState({ name: 'Mapa Principal', version: VERSION });
  const [compare, setCompare] = useState({ a: '', b: '', result: null });
  const [rightPanelOpen, setRightPanelOpen] = useState(false);
  const [leftCollapsed, setLeftCollapsed] = useState(false);
  const [form, setForm] = useState({ hostname: '', management_ip: '', device_type: 'endpoint', icon: 'auto', status: 'UP', segment_name: 'Usuarios', vlan: 50, role: 'host', tier: 6, parent_device_id: '' });
  const [linkForm, setLinkForm] = useState({ source_device_id: '', target_device_id: '', link_type: 'physical_link', status: 'UP', label: '', source_interface: '', target_interface: '', link_group: '', link_role: '' });
  const [depForm, setDepForm] = useState({ source_type: 'service', source_id: '', target_type: 'device', target_id: '', dependency_type: 'depends_on', criticality: 'medium' });
  const [svcForm, setSvcForm] = useState({ name: '', service_type: 'web', criticality: 'medium', status: 'UP', owner: '', description: '' });
  const [userForm, setUserForm] = useState({ username: '', password: '', role: 'viewer', display_name: '', is_active: true });

  const impactIds = useMemo(() => {
    const ids = new Set();
    if (!impact) return ids;
    ids.add(impact.root_cause?.id);
    impact.affected_devices?.forEach((d) => ids.add(d.id));
    impact.affected_services?.forEach((s) => ids.add(s.id));
    impact.affected_segments?.forEach((s) => ids.add(s.id));
    return ids;
  }, [impact]);
  const impactEdgeIds = useMemo(() => new Set((impact?.impact_edges || []).map((e) => e.edge_id).filter(Boolean)), [impact]);

  const selectedDevice = selected?.type === 'device' ? state.devices?.find((d) => d.id === selected.id) : null;
  const selectedSegment = selected?.type === 'segment' ? state.segments?.find((s) => s.id === selected.id) : null;
  const selectedService = selected?.type === 'service' ? state.services?.find((s) => s.id === selected.id) : null;
  const selectedEdge = useMemo(() => state.links?.find((l) => l.id === selectedEdgeId), [state.links, selectedEdgeId]);
  const selectedDep = useMemo(() => state.dependencies?.find((d) => d.id === selectedEdgeId), [state.dependencies, selectedEdgeId]);

  const loadState = useCallback(async () => {
    try {
      const data = await request('/state');
      setState(data);
      const flow = buildFlow(data, impactIds, showServices, showSegments, impactEdgeIds);
      setNodes(flow.nodes);
      setEdges(flow.edges);
      setMessage(`Conectado a PostgreSQL. ${data.devices.length} dispositivos, ${data.links.length} enlaces, ${data.dependencies.length} dependencias.`);
      setTimeout(() => fitView({ padding: 0.2, duration: 400 }), 150);
    } catch (err) { setMessage(`Error cargando API: ${err.message}`); }
  }, [fitView, impactIds, impactEdgeIds, showServices, showSegments]);

  useEffect(() => { if (user) loadState(); }, [user]);
  useEffect(() => { const flow = buildFlow(state, impactIds, showServices, showSegments, impactEdgeIds); setNodes(flow.nodes); setEdges(flow.edges); }, [state, impactIds, impactEdgeIds, showServices, showSegments]);
  useEffect(() => { if (selected || selectedEdgeId) setRightPanelOpen(true); }, [selected, selectedEdgeId]);

  const enterMapFullscreen = useCallback(() => {
    setActiveTab('mapa');
    setMapFullscreen(true);
    setTimeout(() => fitView({ padding: 0.08, duration: 350 }), 120);
  }, [fitView]);

  const exitMapFullscreen = useCallback(() => {
    setMapFullscreen(false);
    setTimeout(() => fitView({ padding: 0.18, duration: 250 }), 120);
  }, [fitView]);

  useEffect(() => {
    const onKey = (event) => {
      if (event.key === 'Escape' && mapFullscreen) exitMapFullscreen();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [mapFullscreen, exitMapFullscreen]);

  const handleFlowClickCapture = useCallback((event) => {
    const controlButton = event.target?.closest?.('button');
    if (!controlButton) return;
    const hint = `${controlButton.getAttribute('aria-label') || ''} ${controlButton.getAttribute('title') || ''} ${controlButton.className || ''}`.toLowerCase();
    if (hint.includes('fit') || hint.includes('view')) {
      enterMapFullscreen();
    }
  }, [enterMapFullscreen]);

  const onNodesChange = useCallback((changes) => setNodes((nds) => applyNodeChanges(changes, nds)), []);
  const onEdgesChange = useCallback((changes) => setEdges((eds) => applyEdgeChanges(changes, eds)), []);

  const logout = useCallback(async () => {
    try { await request('/auth/logout', { method: 'POST' }); } catch {}
    localStorage.removeItem('netmap-user');
    setUser(null);
  }, []);

  const onNodeDragStart = useCallback((_, node) => {
    const entityType = node.data?.entity_type || node.type;
    if (entityType !== 'segment') {
      segmentDragRef.current = null;
      return;
    }
    const segmentId = segmentIdFromNodeId(node.id);
    const childPositions = new Map(
      nodes
        .filter((n) => (n.data?.entity_type || n.type) === 'device' && n.data?.segment_id === segmentId)
        .map((n) => [n.id, { ...n.position }])
    );
    segmentDragRef.current = { nodeId: node.id, segmentId, start: { ...node.position }, childPositions };
  }, [nodes]);

  const onNodeDrag = useCallback((_, node) => {
    const drag = segmentDragRef.current;
    if (!drag || drag.nodeId !== node.id) return;
    const dx = node.position.x - drag.start.x;
    const dy = node.position.y - drag.start.y;
    setNodes((current) => current.map((n) => {
      const start = drag.childPositions.get(n.id);
      return start ? { ...n, position: { x: start.x + dx, y: start.y + dy } } : n;
    }));
  }, []);

  const savePosition = useCallback(async (_, node) => {
    if (!canEdit) return;
    const position = { x_position: node.position.x, y_position: node.position.y };
    const entityType = node.data?.entity_type || node.type;
    try {
      if (entityType === 'device') {
        await request(`/devices/${node.id}/position`, { method: 'PATCH', body: position });
        setState((current) => ({ ...current, devices: current.devices.map((d) => d.id === node.id ? { ...d, ...position } : d) }));
        return;
      }
      if (entityType === 'segment') {
        const segmentId = segmentIdFromNodeId(node.id);
        const drag = segmentDragRef.current;
        const movedDevices = drag?.segmentId === segmentId
          ? [...drag.childPositions.entries()].map(([id, start]) => ({
            id,
            x_position: start.x + node.position.x - drag.start.x,
            y_position: start.y + node.position.y - drag.start.y,
          }))
          : [];
        await request(`/segments/${segmentId}/position`, { method: 'PATCH', body: position });
        await Promise.all(movedDevices.map((d) => request(`/devices/${d.id}/position`, { method: 'PATCH', body: { x_position: d.x_position, y_position: d.y_position } })));
        const movedById = new Map(movedDevices.map((d) => [d.id, d]));
        setState((current) => ({
          ...current,
          segments: current.segments.map((s) => s.id === segmentId ? { ...s, ...position } : s),
          devices: current.devices.map((d) => movedById.has(d.id) ? { ...d, ...movedById.get(d.id) } : d),
        }));
        segmentDragRef.current = null;
      }
    } catch (err) {
      if (entityType === 'segment') segmentDragRef.current = null;
      setMessage(`No se pudo guardar posición: ${err.message}`);
    }
  }, [canEdit]);

  const onConnect = useCallback(async (params) => {
    if (!canEdit) return setMessage('Tu rol no permite crear relaciones.');
    try {
      await request('/links', { method: 'POST', body: { source_device_id: params.source, target_device_id: params.target, link_type: 'physical_link', status: 'UP', label: 'manual', discovery_method: 'reactflow' } });
      await loadState();
      setMessage('Relación creada desde el diagrama.');
    } catch (err) { setMessage(`Error creando relación: ${err.message}`); }
  }, [loadState, canEdit]);

  async function addDevice(e) {
    e.preventDefault();
    if (!canEdit) return;
    try {
      const payload = { ...form, vlan: form.vlan === '' ? null : Number(form.vlan), tier: Number(form.tier || 6), parent_device_id: form.parent_device_id || null };
      await request('/devices', { method: 'POST', body: payload });
      setForm({ hostname: '', management_ip: '', device_type: 'endpoint', icon: 'auto', status: 'UP', segment_name: 'Usuarios', vlan: 50, role: 'host', tier: 6, parent_device_id: '' });
      await loadState();
      setMessage('Dispositivo añadido y guardado en PostgreSQL.');
    } catch (err) { setMessage(`Error añadiendo dispositivo: ${err.message}`); }
  }

  async function updateDevicePatch(id, patch, silent = false) {
    if (!canEdit) return setMessage('Tu rol no permite editar.');
    try {
      await request(`/devices/${id}`, { method: 'PATCH', body: patch });
      await loadState();
      setSelected({ type: 'device', id });
      if (!silent) setMessage('Propiedades guardadas con autoguardado.');
    } catch (err) { setMessage(`Error guardando propiedades: ${err.message}`); }
  }

  async function duplicateDevice(id) {
    if (!canEdit) return;
    try { await request(`/devices/${id}/duplicate`, { method: 'POST' }); await loadState(); setMessage('Dispositivo duplicado.'); }
    catch (err) { setMessage(`Error duplicando: ${err.message}`); }
  }

  async function deleteDevice(id) {
    if (!canEdit) return;
    if (!id || !confirm('¿Eliminar este dispositivo y sus relaciones?')) return;
    try { await request(`/devices/${id}`, { method: 'DELETE' }); setSelected(null); setImpact(null); await loadState(); setMessage('Dispositivo eliminado.'); }
    catch (err) { setMessage(`Error eliminando: ${err.message}`); }
  }

  async function bulkUpdate() {
    if (!canEdit || !selectedIds.length) return;
    const patch = {};
    Object.entries(bulk).forEach(([k, v]) => { if (v !== '') patch[k] = k === 'vlan' ? Number(v) : v; });
    try { const data = await request('/devices/bulk', { method: 'POST', body: { ids: selectedIds, patch } }); setState(data.state); setMessage(`Edición masiva aplicada: ${data.updated} dispositivos.`); }
    catch (err) { setMessage(`Error edición masiva: ${err.message}`); }
  }

  async function bulkDelete() {
    if (!canEdit || !selectedIds.length) return;
    if (!confirm(`Eliminar ${selectedIds.length} dispositivos seleccionados?`)) return;
    try { const data = await request('/devices/bulk-delete', { method: 'POST', body: selectedIds }); setSelectedIds([]); setState(data.state); setMessage(`Eliminados: ${data.deleted}`); }
    catch (err) { setMessage(`Error eliminando en bloque: ${err.message}`); }
  }

  async function bulkRelate(customTargetId = null) {
    if (!canEdit || !selectedIds.length) return;
    const targetId = customTargetId || bulkRelation.target_device_id;
    if (!targetId) return setMessage('Selecciona el router/switch/equipo principal para crear la relación masiva.');
    const ids = selectedIds.filter((id) => id !== targetId);
    if (!ids.length) return setMessage('La selección solo contiene el equipo principal. Selecciona también los equipos dependientes.');
    try {
      const data = await request('/devices/bulk-relate', {
        method: 'POST',
        body: { ...bulkRelation, target_device_id: targetId, ids },
      });
      setState(data.state);
      setSelectedIds(ids);
      setMessage(`Relación masiva aplicada: ${data.created} enlaces creados, ${data.skipped} omitidos, ${data.parent_updates} parent actualizados.`);
    } catch (err) { setMessage(`Error relación masiva: ${err.message}`); }
  }

  async function addLink(e) {
    e.preventDefault();
    if (!canEdit) return;
    try { await request('/links', { method: 'POST', body: linkForm }); setLinkForm({ source_device_id: '', target_device_id: '', link_type: 'physical_link', status: 'UP', label: '', source_interface: '', target_interface: '', link_group: '', link_role: '' }); await loadState(); setMessage('Relación gráfica creada.'); }
    catch (err) { setMessage(`Error creando relación: ${err.message}`); }
  }

  async function updateLink(id, payload) {
    if (!canEdit) return;
    try { await request(`/links/${id}`, { method: 'PATCH', body: payload }); await loadState(); setSelectedEdgeId(id); setMessage('Relación actualizada.'); }
    catch (err) { setMessage(`Error actualizando relación: ${err.message}`); }
  }

  async function deleteLink(id) {
    if (!canEdit) return;
    if (!confirm('¿Eliminar esta relación?')) return;
    try { await request(`/links/${id}`, { method: 'DELETE' }); setSelectedEdgeId(null); await loadState(); setMessage('Relación eliminada.'); }
    catch (err) { setMessage(`Error eliminando relación: ${err.message}`); }
  }

  async function addService(e) {
    e.preventDefault();
    if (!canEdit) return;
    try { await request('/services', { method: 'POST', body: svcForm }); setSvcForm({ name: '', service_type: 'web', criticality: 'medium', status: 'UP', owner: '', description: '' }); await loadState(); setMessage('Servicio guardado.'); }
    catch (err) { setMessage(`Error servicio: ${err.message}`); }
  }

  async function addDependency(e) {
    e.preventDefault();
    if (!canEdit) return;
    try { await request('/dependencies', { method: 'POST', body: depForm }); setDepForm({ source_type: 'service', source_id: '', target_type: 'device', target_id: '', dependency_type: 'depends_on', criticality: 'medium' }); await loadState(); setMessage('Dependencia / relación de segmento creada.'); }
    catch (err) { setMessage(`Error dependencia: ${err.message}`); }
  }

  async function deleteDependency(id) {
    if (!canEdit) return;
    try { await request(`/dependencies/${id}`, { method: 'DELETE' }); setSelectedEdgeId(null); await loadState(); setMessage('Dependencia eliminada.'); }
    catch (err) { setMessage(`Error eliminando dependencia: ${err.message}`); }
  }

  async function runImpact(id) {
    if (!id) return;
    try { const data = await request(`/impact/${id}`); setImpact(data); setActiveTab('impacto'); setMessage(data.summary); }
    catch (err) { setMessage(`Error impacto: ${err.message}`); }
  }

  async function resetAll() {
    if (!canEdit) return;
    if (!confirm('Esto eliminará toda la data guardada en PostgreSQL. ¿Continuar?')) return;
    try { const data = await request('/reset', { method: 'POST' }); setState(data); setSelected(null); setImpact(null); await loadState(); setMessage('Data eliminada correctamente.'); }
    catch (err) { setMessage(`Error limpiando DB: ${err.message}`); }
  }

  async function seedDemo() {
    if (!canEdit) return;
    try { await request('/seed-demo', { method: 'POST' }); await loadState(); setMessage('Demo recargada.'); }
    catch (err) { setMessage(`Error demo: ${err.message}`); }
  }

  async function importFile(kind, file) {
    if (!file || !canEdit) return;
    const fd = new FormData(); fd.append('file', file);
    try { const data = await request(`/import/${kind}`, { method: 'POST', body: fd }); setState(data.state || await request('/state')); await loadState(); setMessage(`Importación ${kind}: ${data.created || 0} creados, ${data.updated || 0} actualizados. Errores: ${(data.errors || []).length}`); }
    catch (err) { setMessage(`Error importando ${kind}: ${err.message}`); }
  }

  function autoLayout() {
    const deviceNodes = nodes.filter((n) => n.type === 'device');
    const nextDevices = layoutByMode(deviceNodes, edges, layoutMode, state);
    const pos = new Map(nextDevices.map((n) => [n.id, n.position]));
    setNodes((nds) => nds.map((n) => pos.has(n.id) ? { ...n, position: pos.get(n.id) } : n));
    setState((current) => ({
      ...current,
      devices: current.devices.map((d) => pos.has(d.id) ? { ...d, x_position: pos.get(d.id).x, y_position: pos.get(d.id).y } : d),
    }));
    nextDevices.forEach((n) => request(`/devices/${n.id}/position`, { method: 'PATCH', body: { x_position: n.position.x, y_position: n.position.y } }).catch(() => {}));
    setTimeout(() => fitView({ padding: 0.2, duration: 400 }), 100);
    setMessage(`Layout automático aplicado: ${layoutMode}.`);
  }

  function getExportGeometry(exportNodes = nodes) {
    const bounds = getNodesBounds(exportNodes);
    const imageWidth = Math.ceil(Math.max(EXPORT_MIN_WIDTH, bounds.width + EXPORT_PADDING * 2));
    const imageHeight = Math.ceil(Math.max(EXPORT_MIN_HEIGHT, bounds.height + EXPORT_PADDING * 2));
    const viewport = getViewportForBounds(bounds, imageWidth, imageHeight, 0.05, 2, 0.08);
    return { bounds, imageWidth, imageHeight, viewport };
  }

  async function renderMapExportImage(pixelRatio = 2) {
    const viewportElement = document.querySelector('.react-flow__viewport');
    const exportNodes = nodes.filter((n) => !n.hidden);
    if (!viewportElement || !exportNodes.length) throw new Error('No hay mapa visible para exportar.');
    const geometry = getExportGeometry(exportNodes);
    const dataUrl = await htmlToImage.toPng(viewportElement, {
      backgroundColor: EXPORT_BACKGROUND,
      width: geometry.imageWidth,
      height: geometry.imageHeight,
      pixelRatio,
      cacheBust: true,
      style: {
        width: `${geometry.imageWidth}px`,
        height: `${geometry.imageHeight}px`,
        transform: `translate(${geometry.viewport.x}px, ${geometry.viewport.y}px) scale(${geometry.viewport.zoom})`,
      },
    });
    return { dataUrl, ...geometry };
  }

  async function exportPNG() {
    if (!canExport) return setMessage('Tu rol no permite exportar información.');
    try {
      const { dataUrl, imageWidth, imageHeight } = await renderMapExportImage(2);
      const res = await fetch(dataUrl); downloadBlob(await res.blob(), `netmap-builder-diagrama-${VERSION}.png`, 'image/png');
      setMessage(`PNG exportado completo con fondo claro (${imageWidth}x${imageHeight}px).`);
    } catch (err) { setMessage(`Error exportando PNG: ${err.message}`); }
  }

  function exportJSON() {
    if (!canExport) return setMessage('Tu rol no permite exportar información.');
    downloadBlob(JSON.stringify(state, null, 2), `netmap-builder-backup-${VERSION}.json`, 'application/json'); setMessage('JSON exportado.');
  }

  async function exportInventory() {
    if (!canExport) return setMessage('Tu rol no permite exportar información.');
    try { const data = await request('/export/inventory.csv'); downloadBlob(data.content, data.filename, 'text/csv'); setMessage('Inventario CSV exportado.'); }
    catch (err) { setMessage(`Error exportando inventario: ${err.message}`); }
  }

  function downloadDeviceTemplate() {
    const rows = [
      ['hostname','ip','type','role','tier','segment','cidr','vlan','is_main','is_perimeter','parent','status','icon','vendor','model','serial_number'],
      ['FW-EDGE-01','10.0.0.1','firewall','perimeter','1','WAN','10.0.0.0/30','','true','true','','UP','firewall','Fortinet','FG-100F',''],
      ['SW-CORE-01','192.168.1.2','switch','core','3','Core','192.168.1.0/24','1','true','false','FW-EDGE-01','UP','switch','Cisco','C9300',''],
      ['PC-001','192.168.50.20','endpoint','host','6','Usuarios','192.168.50.0/24','50','false','false','SW-CORE-01','UP','endpoint','','',''],
    ];
    const csv = rows.map((r) => r.map(csvEscape).join(',')).join('\n');
    downloadBlob(csv, `template-devices-${VERSION}.csv`, 'text/csv');
    setMessage('Template devices.csv descargado. Puedes editarlo y cargarlo masivamente desde Importar.');
  }

  function downloadInterfaceTemplate() {
    const rows = [
      ['device','interface','ip','mac','vlan','status','speed','zone','description'],
      ['SW-ACCESS-01','Gi1/0/49','','00:11:22:33:44:49','50','UP','1Gbps','Usuarios','Uplink 1 hacia core'],
      ['SW-ACCESS-01','Gi1/0/50','','00:11:22:33:44:50','50','UP','1Gbps','Usuarios','Uplink 2 hacia core'],
      ['SW-CORE-01','Gi1/0/1','','00:11:22:AA:BB:01','50','UP','1Gbps','Core','Hacia SW-ACCESS-01 Gi1/0/49'],
      ['SW-CORE-01','Gi1/0/2','','00:11:22:AA:BB:02','50','UP','1Gbps','Core','Hacia SW-ACCESS-01 Gi1/0/50'],
    ];
    const csv = rows.map((r) => r.map(csvEscape).join(',')).join('\n');
    downloadBlob(csv, `template-interfaces-${VERSION}.csv`, 'text/csv');
    setMessage('Template interfaces.csv descargado para puertos/NICs.');
  }

  function downloadLinksTemplate() {
    const rows = [
      ['source_device','source_interface','target_device','target_interface','link_type','status','label','link_group','link_role','discovery_method','notes'],
      ['SW-ACCESS-01','Gi1/0/49','SW-CORE-01','Gi1/0/1','physical_link','UP','Uplink 1','LAG-01','primary','manual','Primer enlace del port-channel'],
      ['SW-ACCESS-01','Gi1/0/50','SW-CORE-01','Gi1/0/2','physical_link','UP','Uplink 2','LAG-01','primary','manual','Segundo enlace del port-channel'],
      ['SRV-APP-01','eth1','SW-SERVER-01','Gi1/0/11','backup_link','UP','NIC backup','','backup','manual','Interfaz redundante'],
    ];
    const csv = rows.map((r) => r.map(csvEscape).join(',')).join('\n');
    downloadBlob(csv, `template-links-${VERSION}.csv`, 'text/csv');
    setMessage('Template links.csv descargado con link_group y link_role.');
  }

  function exportHTML() {
    if (!canExport) return setMessage('Tu rol no permite exportar información.');
    const exportNodes = nodes.filter((n) => !n.hidden);
    if (!exportNodes.length) return setMessage('No hay mapa visible para exportar.');
    const geometry = getExportGeometry(exportNodes);
    const flow = {
      nodes: exportNodes,
      edges,
      state,
      version: VERSION,
      exported_at: new Date().toISOString(),
      exported_label: new Date().toLocaleString(),
      geometry: {
        bounds: geometry.bounds,
        imageWidth: geometry.imageWidth,
        imageHeight: geometry.imageHeight,
      },
    };
    const html = `<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NetMap Builder Export ${VERSION}</title>
  <style>
    :root{--bg:${EXPORT_BACKGROUND};--card:#fff;--line:#d6e3e8;--text:#0d0d0d;--muted:#5f6f79;--orange:#ff8201;--blue:#0085ff;--green:#22c55e;--red:#ef4444;--yellow:#eab308;--purple:#7c3aed}
    *{box-sizing:border-box}
    body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,Segoe UI,Arial,sans-serif;overflow:hidden}
    .toolbar{position:fixed;z-index:20;top:12px;left:12px;right:12px;min-height:48px;background:rgba(255,250,244,.96);border:1px solid rgba(255,130,1,.28);border-radius:13px;padding:8px 10px;display:flex;gap:8px;align-items:center;box-shadow:0 14px 34px rgba(13,13,13,.12)}
    .toolbar b{white-space:nowrap}.toolbar span{color:var(--muted);font-size:12px}.toolbar button{border:1px solid #cfdce1;background:#fff;color:var(--text);border-radius:9px;padding:7px 9px;cursor:pointer;font-weight:800}.toolbar button:hover{border-color:var(--orange);background:#fff7ed}
    .wrap{position:relative;width:100vw;height:100vh;overflow:hidden;background:radial-gradient(circle at 50% 0%,rgba(255,130,1,.13),transparent 34%),radial-gradient(#c9d7dc 1px,transparent 1px),var(--bg);background-size:auto,18px 18px,auto}
    .canvas{position:absolute;left:0;top:0;transform-origin:0 0;overflow:visible}
    .edges{position:absolute;left:0;top:0;width:1px;height:1px;overflow:visible;z-index:4;pointer-events:none}
    .edge-line{fill:none;stroke:var(--green);stroke-width:2.5;stroke-linecap:round;stroke-linejoin:round}
    .edge-line.multi-link-edge{stroke:var(--orange);stroke-width:3.4}.edge-line.impact-link-edge{stroke:#0d0d0d;stroke-width:4.4}.edge-line.dependency-edge{stroke:var(--purple);stroke-dasharray:8 6}
    .edge-label{position:absolute;z-index:6;transform:translate(-50%,-50%);background:rgba(255,255,255,.95);border:1px solid rgba(255,130,1,.28);border-radius:6px;padding:2px 5px;font-size:10.5px;font-weight:900;white-space:nowrap;box-shadow:0 5px 12px rgba(13,13,13,.10);pointer-events:none}
    .segment{position:absolute;z-index:1;border:2px dashed rgba(255,130,1,.46);background:rgba(255,240,221,.30);border-radius:16px;padding:9px;color:#0d0d0d}
    .segment b{display:block;font-size:13px}.segment small{display:block;margin-top:4px;color:#475569;font-size:11px}
    .node{position:absolute;z-index:8;width:190px;min-height:102px;border:2px solid #cbd8dd;border-radius:14px;background:linear-gradient(180deg,#fff,#f9fcfd);box-shadow:0 10px 22px rgba(13,13,13,.10);padding:9px;text-align:center;cursor:pointer}
    .node.service{border-style:dashed}.node.impact{box-shadow:0 0 0 5px rgba(234,179,8,.20),0 10px 22px rgba(13,13,13,.10)}
    .node .icon{font-size:25px;line-height:1}.node b{display:block;margin-top:5px;font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.node small{display:block;color:#647582;font-size:11px;margin-top:2px}.meta{display:flex;justify-content:space-between;gap:8px;margin-top:7px;color:#647582;font-size:10.5px}
    .tag{display:inline-block;margin:6px 2px 0;padding:2px 6px;border-radius:99px;font-size:10px}.tag-red{background:#fff1f2;color:#be123c}.tag-blue{background:#edf6ff;color:#006fd6}
    .status-UP{border-color:rgba(34,197,94,.70)}.status-DOWN{border-color:rgba(239,68,68,.86)}.status-WARNING{border-color:rgba(234,179,8,.86)}.status-DEGRADED{border-color:rgba(168,85,247,.86)}
    .panel{position:fixed;right:12px;bottom:12px;z-index:18;width:min(360px,calc(100vw - 24px));max-height:34vh;overflow:auto;background:#fff;border:1px solid var(--line);border-radius:13px;padding:10px;white-space:pre-wrap;color:#334155;box-shadow:0 14px 34px rgba(13,13,13,.12);font-size:12px}
  </style>
</head>
<body>
  <div class="toolbar">
    <b>NetMap Builder ${VERSION}</b>
    <button onclick="fit()">Ajustar</button>
    <button onclick="zoom(1.15)">+</button>
    <button onclick="zoom(0.85)">-</button>
    <span>Exportado: ${flow.exported_label}</span>
  </div>
  <div id="wrap" class="wrap"><div id="canvas" class="canvas"></div></div>
  <div id="panel" class="panel">Click en un equipo para ver propiedades.</div>
  <script>
    const data=${scriptJson(flow)};
    const wrap=document.getElementById("wrap");
    const canvas=document.getElementById("canvas");
    const panel=document.getElementById("panel");
    let x=0,y=0,z=1,drag=false,lx=0,ly=0;
    const svgns="http://www.w3.org/2000/svg";
    function esc(v){return String(v==null?"":v).replace(/[&<>"']/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;","'":"&#39;"}[c]})}
    function icon(k,t){k=k&&k!=="auto"?k:t;return {firewall:"🧱",router:"🔀",switch:"▦",server:"🖥️",endpoint:"💻",printer:"🖨️",access_point:"📡",cloud:"☁️",internet:"🌐",database:"🗄️",camera:"📷",nas:"▣",ups:"🔋"}[k]||"❔"}
    function dims(n){var s=n.style||{};if(n.type==="segment")return {w:Number(s.width)||300,h:Number(s.height)||140};return {w:Number(s.width)||190,h:Number(s.height)||112}}
    function sideFromHandle(id,fallback){id=String(id||fallback||"bottom").toLowerCase();if(id.indexOf("left")>=0)return "left";if(id.indexOf("right")>=0)return "right";if(id.indexOf("top")>=0)return "top";return "bottom"}
    function percentFor(n,id){var list=(n.data&&n.data.visual_handles)||[];for(var i=0;i<list.length;i++){if(list[i].id===id)return Number(list[i].percent)||50}return 50}
    function handlePoint(n,id,fallback){var d=dims(n),side=sideFromHandle(id,fallback),p=percentFor(n,id),px=n.position.x,py=n.position.y;if(side==="top")return {x:px+d.w*p/100,y:py,side:side};if(side==="bottom")return {x:px+d.w*p/100,y:py+d.h,side:side};if(side==="left")return {x:px,y:py+d.h*p/100,side:side};return {x:px+d.w,y:py+d.h*p/100,side:side}}
    function vec(side){if(side==="top")return {x:0,y:-1};if(side==="bottom")return {x:0,y:1};if(side==="left")return {x:-1,y:0};return {x:1,y:0}}
    function point(p0,p1,p2,p3,t){var m=1-t;return {x:m*m*m*p0.x+3*m*m*t*p1.x+3*m*t*t*p2.x+t*t*t*p3.x,y:m*m*m*p0.y+3*m*m*t*p1.y+3*m*t*t*p2.y+t*t*t*p3.y}}
    function curve(sp,tp,offset){var dx=tp.x-sp.x,dy=tp.y-sp.y,dist=Math.max(1,Math.sqrt(dx*dx+dy*dy)),nx=-dy/dist,ny=dx/dist,sv=vec(sp.side),tv=vec(tp.side),c=Math.min(180,Math.max(70,dist*.38)),p0={x:sp.x,y:sp.y},p3={x:tp.x,y:tp.y},p1={x:sp.x+sv.x*c+nx*offset,y:sp.y+sv.y*c+ny*offset},p2={x:tp.x+tv.x*c+nx*offset,y:tp.y+tv.y*c+ny*offset};return {d:"M "+p0.x+","+p0.y+" C "+p1.x+","+p1.y+" "+p2.x+","+p2.y+" "+p3.x+","+p3.y,label:point(p0,p1,p2,p3,.72)}}
    function edgeColor(e){var c=e.className||"";if(c.indexOf("impact-link-edge")>=0)return "#0d0d0d";if(c.indexOf("dependency-edge")>=0)return "#7c3aed";if(c.indexOf("edge-DOWN")>=0)return "#ef4444";if(c.indexOf("edge-WARNING")>=0)return "#eab308";if(c.indexOf("edge-DEGRADED")>=0)return "#a855f7";if(c.indexOf("edge-UNKNOWN")>=0)return "#94a3b8";if(c.indexOf("multi-link-edge")>=0)return "#ff8201";return "#22c55e"}
    function render(){canvas.style.transform="translate("+x+"px,"+y+"px) scale("+z+")"}
    function zoom(f){z=Math.max(.05,Math.min(3,z*f));render()}
    function fit(){var b=data.geometry.bounds,pad=84,zw=(wrap.clientWidth-pad*2)/Math.max(1,b.width),zh=(wrap.clientHeight-pad*2)/Math.max(1,b.height);z=Math.max(.05,Math.min(1.5,Math.min(zw,zh)));x=(wrap.clientWidth-b.width*z)/2-b.x*z;y=(wrap.clientHeight-b.height*z)/2-b.y*z;render()}
    function build(){
      canvas.innerHTML="";
      var map={};data.nodes.forEach(function(n){map[n.id]=n});
      data.nodes.filter(function(n){return n.type==="segment"}).forEach(function(n){var d=n.data||{},size=dims(n),el=document.createElement("div");el.className="segment";el.style.left=n.position.x+"px";el.style.top=n.position.y+"px";el.style.width=size.w+"px";el.style.height=size.h+"px";el.innerHTML="<b>"+esc((d.collapsed?"▸ ":"▾ ")+(d.name||"Segmento"))+"</b><small>"+esc((d.vlan?"VLAN "+d.vlan:"sin VLAN")+" · "+(d.count||0)+" hosts")+"</small><small>"+esc(d.cidr||"sin CIDR")+"</small>";canvas.appendChild(el)});
      var svg=document.createElementNS(svgns,"svg");svg.setAttribute("class","edges");canvas.appendChild(svg);
      data.edges.forEach(function(e){var s=map[e.source],t=map[e.target];if(!s||!t)return;var sp=handlePoint(s,e.sourceHandle,"bottom"),tp=handlePoint(t,e.targetHandle,"top"),c=curve(sp,tp,Number(e.data&&e.data.parallel_offset)||0),path=document.createElementNS(svgns,"path");path.setAttribute("d",c.d);path.setAttribute("class","edge-line "+(e.className||""));path.setAttribute("style","stroke:"+edgeColor(e));svg.appendChild(path);if(e.label){var lab=document.createElement("div");lab.className="edge-label";lab.style.left=c.label.x+"px";lab.style.top=c.label.y+"px";lab.textContent=e.label;canvas.appendChild(lab)}});
      data.nodes.filter(function(n){return n.type!=="segment"}).forEach(function(n){var d=n.data||{},el=document.createElement("div");el.className="node "+(n.type==="service"?"service ":"")+"status-"+(d.status||"UNKNOWN")+" "+(d.impact?"impact":"");el.style.left=n.position.x+"px";el.style.top=n.position.y+"px";el.innerHTML="<div class='icon'>"+(n.type==="service"?"⚙️":icon(d.icon,d.device_type))+"</div><b>"+esc(d.hostname||d.name||n.id)+"</b><small>"+esc(d.management_ip||d.service_type||"sin IP")+"</small><div class='meta'><span>"+esc(d.device_type||d.criticality||"")+"</span><span>"+esc(d.status||"")+"</span></div>"+(d.is_perimeter?"<span class='tag tag-red'>Perimetral</span>":"")+(d.is_main?"<span class='tag tag-blue'>Principal</span>":"");el.onclick=function(ev){ev.stopPropagation();panel.textContent=JSON.stringify(d,null,2)};canvas.appendChild(el)});
    }
    wrap.onmousedown=function(e){drag=true;lx=e.clientX;ly=e.clientY};
    window.onmouseup=function(){drag=false};
    wrap.onmousemove=function(e){if(!drag)return;x+=e.clientX-lx;y+=e.clientY-ly;lx=e.clientX;ly=e.clientY;render()};
    wrap.onwheel=function(e){e.preventDefault();zoom(e.deltaY > 0 ? 0.9 : 1.1)};
    window.onresize=fit;
    build();fit();
  </script>
</body>
</html>`;
    downloadBlob(html, `netmap-builder-diagrama-interactivo-${VERSION}.html`, 'text/html');
    setMessage('HTML interactivo exportado con fondo claro y mapa completo.');
  }

  function exportHTMLLegacy() {
    const flow = { nodes, edges, state, version: VERSION, exported_at: new Date().toISOString() };
    const html = `<!doctype html><html lang="es"><head><meta charset="utf-8"><title>NetMap Builder Export ${VERSION}</title><style>body{margin:0;background:#0b1220;color:#e5e7eb;font-family:Arial}.toolbar{position:fixed;z-index:10;top:10px;left:10px;background:#111827;border:1px solid #334155;border-radius:12px;padding:10px;display:flex;gap:8px;align-items:center}.wrap{position:relative;width:100vw;height:100vh;overflow:hidden}.canvas{position:absolute;transform-origin:0 0}.node{position:absolute;border:1px solid #334155;border-radius:14px;background:#111827;padding:10px;min-width:170px;text-align:center;cursor:pointer}.segment{position:absolute;border:2px dashed #38bdf8;border-radius:18px;background:rgba(56,189,248,.08);padding:10px}.edge{position:absolute;height:2px;background:#38bdf8;transform-origin:0 0}.dep{background:#a855f7}.badge{font-size:12px;color:#94a3b8}.panel{position:fixed;right:10px;top:10px;width:300px;max-height:85vh;overflow:auto;background:#111827;border:1px solid #334155;border-radius:12px;padding:12px;white-space:pre-wrap}</style></head><body><div class="toolbar"><b>NetMap Builder ${VERSION}</b><button onclick="z*=1.15;render()">+</button><button onclick="z/=1.15;render()">-</button><button onclick="x=40;y=80;z=1;render()">reset</button><span>Arrastra para moverte. Click en nodo para propiedades.</span></div><div id="panel" class="panel">Exportado: ${new Date().toLocaleString()}</div><div id="wrap" class="wrap"><div id="canvas" class="canvas"></div></div><script>const data=${JSON.stringify(flow)};let x=40,y=80,z=1,drag=false,lx=0,ly=0;const canvas=document.getElementById('canvas'),panel=document.getElementById('panel'),wrap=document.getElementById('wrap');function icon(k,t){k=k&&k!=='auto'?k:t;return {firewall:'🧱',router:'🔀',switch:'▦',server:'🖥️',endpoint:'💻',printer:'🖨️',access_point:'📡',cloud:'☁️',internet:'🌐',database:'🗄️',camera:'📷',nas:'▣',ups:'🔋'}[k]||'❔'}function line(x1,y1,x2,y2,cls){const dx=x2-x1,dy=y2-y1,len=Math.sqrt(dx*dx+dy*dy),ang=Math.atan2(dy,dx)*180/Math.PI;const e=document.createElement('div');e.className='edge '+(cls||'');e.style.left=x1+'px';e.style.top=y1+'px';e.style.width=len+'px';e.style.transform='rotate('+ang+'deg)';canvas.appendChild(e)}function build(){canvas.innerHTML='';const map={};data.nodes.forEach(n=>map[n.id]=n);data.edges.forEach(e=>{const s=map[e.source],t=map[e.target];if(s&&t)line(s.position.x+95,s.position.y+60,t.position.x+95,t.position.y+60,e.className?.includes('dependency')?'dep':'')});data.nodes.forEach(n=>{const d=n.data||{};const el=document.createElement('div');el.className=n.type==='segment'?'segment':'node';el.style.left=n.position.x+'px';el.style.top=n.position.y+'px';if(n.style){el.style.width=n.style.width+'px';el.style.height=n.style.height+'px'}el.innerHTML=n.type==='segment'?'<b>'+d.name+'</b><div class="badge">'+(d.cidr||'')+' · '+(d.count||0)+' hosts</div>':'<div style="font-size:28px">'+(n.type==='service'?'⚙️':icon(d.icon,d.device_type))+'</div><b>'+(d.hostname||d.name)+'</b><div class="badge">'+(d.management_ip||d.service_type||'')+'</div><div class="badge">'+(d.device_type||d.criticality||'')+' · '+(d.status||'')+'</div>';el.onclick=(ev)=>{ev.stopPropagation();panel.textContent=JSON.stringify(d,null,2)};canvas.appendChild(el)})}function render(){canvas.style.transform='translate('+x+'px,'+y+'px) scale('+z+')'}wrap.onmousedown=e=>{drag=true;lx=e.clientX;ly=e.clientY};wrap.onmouseup=()=>drag=false;wrap.onmousemove=e=>{if(!drag)return;x+=e.clientX-lx;y+=e.clientY-ly;lx=e.clientX;ly=e.clientY;render()};wrap.onwheel=e=>{e.preventDefault();z*=e.deltaY>0?.9:1.1;render()};build();render();</script></body></html>`;
    downloadBlob(html, `netmap-builder-diagrama-interactivo-${VERSION}.html`, 'text/html');
    setMessage('HTML interactivo exportado.');
  }

  async function exportPDF() {
    if (!canExport) return setMessage('Tu rol no permite exportar información.');
    try {
      const doc = new jsPDF({ orientation: 'landscape', unit: 'pt', format: 'a4' });
      const pageWidth = doc.internal.pageSize.getWidth();
      const pageHeight = doc.internal.pageSize.getHeight();
      doc.setFontSize(20); doc.text(`NetMap Builder ${VERSION}`, 40, 40);
      doc.setFontSize(11); doc.text(`Fecha: ${new Date().toLocaleString()}`, 40, 60);
      doc.text(`Dispositivos: ${state.devices.length} · Relaciones: ${state.links.length} · Dependencias: ${state.dependencies.length}`, 40, 78);
      const image = await renderMapExportImage(1.4);
      const margin = 34;
      const top = 98;
      const maxWidth = pageWidth - margin * 2;
      const maxHeight = pageHeight - top - margin;
      const ratio = Math.min(maxWidth / image.imageWidth, maxHeight / image.imageHeight);
      const drawWidth = image.imageWidth * ratio;
      const drawHeight = image.imageHeight * ratio;
      doc.setFillColor(244, 248, 250);
      doc.roundedRect(margin - 8, top - 8, maxWidth + 16, maxHeight + 16, 8, 8, 'F');
      doc.addImage(image.dataUrl, 'PNG', (pageWidth - drawWidth) / 2, top, drawWidth, drawHeight);
      doc.addPage(); doc.setFontSize(16); doc.text('Resumen de inventario', 40, 40); doc.setFontSize(9);
      state.devices.slice(0, 40).forEach((d, i) => doc.text(`${i + 1}. ${d.hostname} · ${d.management_ip || '-'} · ${d.device_type} · ${d.status}`, 40, 65 + i * 14));
      doc.addPage(); doc.setFontSize(16); doc.text('Relaciones y dependencias', 40, 40); doc.setFontSize(9);
      state.links.slice(0, 35).forEach((l, i) => doc.text(`${i + 1}. ${deviceName(l.source_device_id)} → ${deviceName(l.target_device_id)} · ${l.link_type} · ${l.status}`, 40, 65 + i * 14));
      state.dependencies.slice(0, 35).forEach((d, i) => doc.text(`${i + 1}. ${d.target_name || d.target_id} → ${d.source_name || d.source_id} · ${d.dependency_type}`, 420, 65 + i * 14));
      if (impact) { doc.addPage(); doc.setFontSize(16); doc.text('Último análisis de impacto', 40, 40); doc.setFontSize(11); doc.text(`${impact.severity}: ${impact.summary}`, 40, 65); impact.paths?.slice(0, 20).forEach((p, i) => doc.text(p.map(x=>x.name).join(' → '), 40, 90 + i * 16)); }
      doc.save(`netmap-builder-reporte-${VERSION}.pdf`); setMessage('PDF exportado.');
    } catch (err) { setMessage(`Error exportando PDF: ${err.message}`); }
  }

  async function saveVersion() {
    if (!canEdit) return;
    try { await request('/versions', { method: 'POST', body: versionForm }); await loadState(); setMessage('Versión del mapa guardada.'); }
    catch (err) { setMessage(`Error guardando versión: ${err.message}`); }
  }

  async function restoreVersion(id) {
    if (!canEdit || !confirm('¿Restaurar esta versión? Se reemplazará el mapa actual.')) return;
    try { const data = await request(`/versions/${id}/restore`, { method: 'POST' }); setState(data); setMessage('Versión restaurada.'); }
    catch (err) { setMessage(`Error restaurando: ${err.message}`); }
  }

  async function compareVersions() {
    if (!compare.a || !compare.b) return;
    try { const result = await request(`/versions/compare/${compare.a}/${compare.b}`); setCompare({...compare, result}); }
    catch (err) { setMessage(`Error comparando: ${err.message}`); }
  }

  async function importProjectJSON(file) {
    if (!file || !canEdit) return;
    if (!confirm('¿Cargar este proyecto JSON? Se reemplazará el mapa actual.')) return;
    try {
      const text = await file.text();
      const snapshot = JSON.parse(text);
      const data = await request('/import/project', { method: 'POST', body: snapshot });
      setState(data);
      setMessage(`Proyecto cargado: ${(data.devices||[]).length} dispositivos, ${(data.links||[]).length} enlaces, ${(data.segments||[]).length} segmentos.`);
    } catch (err) { setMessage(`Error cargando proyecto: ${err.message}`); }
  }

  async function addUser(e) {
    e.preventDefault();
    if (user?.role !== 'admin') return setMessage('Solo admin puede administrar usuarios.');
    try {
      const data = await request('/users', { method: 'POST', body: userForm });
      setState(data);
      setUserForm({ username: '', password: '', role: 'viewer', display_name: '', is_active: true });
      setMessage('Usuario creado correctamente.');
    } catch (err) { setMessage(`Error creando usuario: ${err.message}`); }
  }

  async function updateUser(id, patch) {
    if (user?.role !== 'admin') return setMessage('Solo admin puede administrar usuarios.');
    try { const data = await request(`/users/${id}`, { method: 'PATCH', body: patch }); setState(data); setMessage('Usuario actualizado.'); }
    catch (err) { setMessage(`Error actualizando usuario: ${err.message}`); }
  }

  async function deleteUser(id) {
    if (user?.role !== 'admin') return setMessage('Solo admin puede administrar usuarios.');
    if (!confirm('¿Eliminar este usuario?')) return;
    try { const data = await request(`/users/${id}`, { method: 'DELETE' }); setState(data); setMessage('Usuario eliminado.'); }
    catch (err) { setMessage(`Error eliminando usuario: ${err.message}`); }
  }

  const filteredDevices = useMemo(() => {
    const q = search.toLowerCase();
    return (state.devices || []).filter((d) => {
      const seg = state.segments?.find((s) => s.id === d.segment_id);
      const text = [d.hostname, d.management_ip, d.device_type, d.status, seg?.name, seg?.vlan, seg?.cidr, d.role].join(' ').toLowerCase();
      const ipOk = !filter.ip || String(d.management_ip || '').toLowerCase().includes(String(filter.ip).toLowerCase());
      const cidrOk = !filter.cidr || String(seg?.cidr || '').toLowerCase().includes(String(filter.cidr).toLowerCase());
      return (!q || text.includes(q)) && ipOk && cidrOk && (!filter.type || d.device_type === filter.type) && (!filter.segment || d.segment_id === filter.segment) && (!filter.status || d.status === filter.status) && (!filter.vlan || String(seg?.vlan || '') === String(filter.vlan));
    });
  }, [state.devices, state.segments, search, filter]);

  function segmentName(id) { return state.segments?.find((s) => s.id === id)?.name || 'Sin segmento'; }
  function deviceName(id) { return state.devices?.find((d) => d.id === id)?.hostname || id; }
  function entityOptions(type) {
    if (type === 'device') return state.devices.map((d) => ({ id: d.id, name: d.hostname }));
    if (type === 'segment') return state.segments.map((s) => ({ id: s.id, name: s.name }));
    return state.services.map((s) => ({ id: s.id, name: s.name }));
  }

  if (!user) return <LoginScreen onLogin={setUser} />;

  return (
    <div className={`app ${mapFullscreen ? 'map-fullscreen' : ''}`} onClick={() => setContextMenu(null)}>
      <header className="topbar">
        <div className="brand"><Network size={24}/> NetMap Builder <span>{VERSION}</span><a className="author-chip" href="https://www.linkedin.com/in/v4mp3rbl4ck/" target="_blank" rel="noopener noreferrer">by @v4mp3rbl4ck</a></div>
        <div className="user-chip"><Users size={15}/> {user.username} · {user.role}</div>
        <div className="top-actions">
          <button onClick={loadState}><RefreshCw size={16}/> Refrescar</button>
          {canEdit && <button onClick={seedDemo}><Upload size={16}/> Demo</button>}
          {canEdit && <button onClick={resetAll} className="danger"><Trash2 size={16}/> Limpiar DB</button>}
          {canExport && <button onClick={exportPNG}><Download size={16}/> PNG</button>}
          {canExport && <button onClick={exportHTML}><Download size={16}/> HTML</button>}
          {canExport && <button onClick={exportPDF}><Download size={16}/> PDF</button>}
          {canExport && <button onClick={exportJSON}><Database size={16}/> JSON</button>}
          <button onClick={logout}><Lock size={16}/> Salir</button>
        </div>
      </header>

      <div className={`layout enterprise-layout ${mapFullscreen ? 'map-only-layout' : ''} ${rightPanelOpen ? '' : 'right-closed'} ${leftCollapsed ? 'left-collapsed' : ''}`}>
        <aside className="sidebar nav-sidebar">
          <div className="sidebar-toggle-row">
            <button className="panel-toggle-btn" title={leftCollapsed ? 'Expandir panel' : 'Colapsar panel'} onClick={() => setLeftCollapsed(v => !v)}>
              {leftCollapsed ? <ChevronRight size={16}/> : <ChevronLeft size={16}/>}
            </button>
          </div>
          <div className="sidebar-head">
            <span className="eyebrow">Módulos</span>
            <h2>Centro de operación</h2>
            <p>Selecciona un módulo. El contenido se abre en el área central y la configuración contextual vive a la derecha.</p>
          </div>
          <nav className="module-nav">
            <button className={activeTab==='mapa'?'active':''} onClick={()=>setActiveTab('mapa')}><Network size={16}/> Mapa</button>
            <button className={activeTab==='inventario'?'active':''} onClick={()=>setActiveTab('inventario')}><Monitor size={16}/> Inventario</button>
            <button className={activeTab==='relaciones'?'active':''} onClick={()=>setActiveTab('relaciones')}><Link2 size={16}/> Relaciones</button>
            <button className={activeTab==='servicios'?'active':''} onClick={()=>setActiveTab('servicios')}><Server size={16}/> Servicios</button>
            <button className={activeTab==='importar'?'active':''} onClick={()=>setActiveTab('importar')}><FileInput size={16}/> Importar</button>
            <button className={activeTab==='impacto'?'active':''} onClick={()=>setActiveTab('impacto')}><Zap size={16}/> Impacto</button>
            <button className={activeTab==='versiones'?'active':''} onClick={()=>setActiveTab('versiones')}><Save size={16}/> Versiones</button>
            {user.role === 'admin' && <button className={activeTab==='usuarios'?'active':''} onClick={()=>setActiveTab('usuarios')}><Users size={16}/> Usuarios</button>}
            <button className={activeTab==='auditoria'?'active':''} onClick={()=>setActiveTab('auditoria')}><Layers size={16}/> Auditoría</button>
          </nav>
          <div className="sidebar-kpis">
            <div><b>{state.devices.length}</b><span>Dispositivos</span></div>
            <div><b>{state.links.length}</b><span>Relaciones</span></div>
            <div><b>{state.users.length}</b><span>Usuarios</span></div>
          </div>
          <div className="status-box">{message}</div>
          {!canEdit ? <div className="status-box warning">Modo solo lectura: tu rol no puede modificar datos.</div> : null}
        </aside>

        <main className={`workspace-area module-${activeTab}`}>
          {activeTab === 'mapa' && <div className="module-page map-page">
            <div className="module-page-header">
              <div><span className="eyebrow">Topología</span><h1>Mapa de red</h1><p>Canvas operativo con nodos, segmentos, servicios, relaciones y dependencias.</p></div>
              <div className="module-actions"><button onClick={loadState}><RefreshCw size={16}/> Refrescar</button><button className="primary" onClick={enterMapFullscreen}><Maximize2 size={16}/> Fit view</button><button onClick={()=>fitView({padding:0.2,duration:300})}><Globe size={16}/> Centrar</button></div>
            </div>
            <div className="canvas-area embedded-canvas">
              <div className="canvas-toolbar">
                <button className="primary" onClick={mapFullscreen ? exitMapFullscreen : enterMapFullscreen}>{mapFullscreen ? <Minimize2 size={16}/> : <Maximize2 size={16}/>} {mapFullscreen ? 'Salir' : 'Fit view'}</button>
                <select value={layoutMode} onChange={e=>setLayoutMode(e.target.value)}><option value="jerarquia">Por jerarquía</option><option value="segment">Por segmento</option><option value="cidr">Por CIDR / VLAN</option><option value="type">Por tipo</option><option value="status">Por estado</option><option value="dependencia">Por dependencia</option><option value="sede">Por sede</option></select>
                <button onClick={autoLayout}><Layers size={16}/> Reordenar mapa</button>
                <label className="toolbar-check"><input type="checkbox" checked={showServices} onChange={e=>setShowServices(e.target.checked)}/> Servicios</label>
                <label className="toolbar-check"><input type="checkbox" checked={showSegments} onChange={e=>setShowSegments(e.target.checked)}/> Segmentos</label>
                {selectedIds.length > 0 && <button onClick={()=>setActiveTab('inventario')}><Link2 size={16}/> Relacionar selección ({selectedIds.length})</button>}
                {selectedDevice && <button onClick={()=>runImpact(selectedDevice.id)}><Zap size={16}/> Simular falla</button>}
                {selectedDevice && canEdit && <button className="danger" onClick={()=>deleteDevice(selectedDevice.id)}><Trash2 size={16}/> Eliminar seleccionado</button>}
              </div>
              <div className="flow" ref={flowWrapper} onClickCapture={handleFlowClickCapture}>
                <ReactFlow
                  nodes={nodes}
                  edges={edges}
                  nodeTypes={nodeTypes}
                  edgeTypes={edgeTypes}
                  onNodesChange={onNodesChange}
                  onEdgesChange={onEdgesChange}
                  onNodeDragStart={onNodeDragStart}
                  onNodeDrag={onNodeDrag}
                  onNodeDragStop={savePosition}
                  nodesDraggable={canEdit}
                  onConnect={onConnect}
                  onNodeClick={(_, node) => { const t=node.data?.entity_type || node.type; const id=t==='segment'? node.id.replace('segment-','') : t==='service'? node.id.replace('service-','') : node.id; setSelected({ type:t, id }); setSelectedEdgeId(null); }}
                  onEdgeClick={(_, edge) => { setSelectedEdgeId(edge.id); setSelected(null); }}
                  onSelectionChange={({ nodes: selectedNodes }) => { const deviceIds = selectedNodes.filter(n => (n.data?.entity_type || n.type) === 'device').map(n => n.id); if (deviceIds.length > 1) setSelectedIds(deviceIds); }}
                  onNodeContextMenu={(event, node) => { event.preventDefault(); const t=node.data?.entity_type || node.type; const id=t==='segment'? node.id.replace('segment-','') : t==='service'? node.id.replace('service-','') : node.id; setContextMenu({ x:event.clientX, y:event.clientY, type:t, id }); }}
                  fitView
                >
                  <MiniMap zoomable pannable nodeColor={(n)=>n.type==='segment'?'#0085ff':statusColor(n.data?.status)} />
                  <Controls />
                  <Background gap={18} size={1} />
                </ReactFlow>
              </div>
              {contextMenu && <ContextMenu menu={contextMenu} setMenu={setContextMenu} canEdit={canEdit} setSelected={setSelected} updateDevicePatch={updateDevicePatch} deleteDevice={deleteDevice} runImpact={runImpact} setLinkForm={setLinkForm} setActiveTab={setActiveTab} state={state} selectedIds={selectedIds} bulkRelate={bulkRelate} />}
            </div>
          </div>}

          {activeTab === 'inventario' && <div className="module-page"><div className="module-page-header"><div><span className="eyebrow">Inventario</span><h1>Inventario de dispositivos</h1><p>Tabla central para filtrar, crear, editar, eliminar y correlacionar equipos.</p></div><div className="module-actions">{canExport && <button onClick={exportInventory}><Download size={16}/> Exportar CSV</button>}</div></div><InventoryPanel {...{canEdit, canExport, form, setForm, addDevice, search, setSearch, filter, setFilter, state, filteredDevices, selected, setSelected, setSelectedEdgeId, selectedIds, setSelectedIds, bulk, setBulk, bulkUpdate, bulkDelete, bulkRelation, setBulkRelation, bulkRelate, duplicateDevice, deleteDevice, exportInventory, segmentName, importFile, downloadDeviceTemplate, downloadInterfaceTemplate, downloadLinksTemplate, linkForm, setLinkForm, addLink, deviceName}} /></div>}
          {activeTab === 'relaciones' && <div className="module-page"><div className="module-page-header"><div><span className="eyebrow">Conectividad</span><h1>Relaciones y dependencias</h1><p>Crea conexiones gráficas o relaciones entre segmentos, servicios y dispositivos.</p></div></div><RelationsPanel {...{canEdit, state, linkForm, setLinkForm, addLink, depForm, setDepForm, addDependency, selectedEdgeId, setSelectedEdgeId, setSelected, deviceName, entityOptions}} /></div>}
          {activeTab === 'servicios' && <div className="module-page"><div className="module-page-header"><div><span className="eyebrow">Servicios</span><h1>Catálogo de servicios</h1><p>Registra servicios y aplicaciones para análisis de dependencia e impacto.</p></div></div><ServicesPanel {...{canEdit, svcForm, setSvcForm, addService, state}} /></div>}
          {activeTab === 'importar' && <div className="module-page"><div className="module-page-header"><div><span className="eyebrow">Carga de datos</span><h1>Importar información</h1><p>Este módulo muestra solo importación: CSV de inventario, relaciones, dependencias y Nmap XML.</p></div></div><ImportPanel importFile={importFile} canEdit={canEdit} downloadDeviceTemplate={downloadDeviceTemplate} downloadInterfaceTemplate={downloadInterfaceTemplate} downloadLinksTemplate={downloadLinksTemplate} /></div>}
          {activeTab === 'impacto' && <div className="module-page"><div className="module-page-header"><div><span className="eyebrow">Impacto</span><h1>Simulación de falla</h1><p>Selecciona un equipo para calcular dispositivos, segmentos y servicios afectados.</p></div></div><ImpactPanel impact={impact} runImpact={runImpact} devices={state.devices} /></div>}
          {activeTab === 'versiones' && <div className="module-page"><div className="module-page-header"><div><span className="eyebrow">Versiones</span><h1>Versionamiento del mapa</h1><p>Guarda, restaura y compara snapshots del diagrama.</p></div></div><VersionsPanel {...{canEdit, canExport, state, versionForm, setVersionForm, saveVersion, restoreVersion, compare, setCompare, compareVersions, exportJSON, importProjectJSON}} /></div>}
          {activeTab === 'usuarios' && <div className="module-page"><div className="module-page-header"><div><span className="eyebrow">Accesos</span><h1>Portal de usuarios</h1><p>Este módulo muestra solo administración de usuarios, roles y estado de cuentas.</p></div></div><UsersPanel {...{currentUser:user, userForm, setUserForm, users:state.users, addUser, updateUser, deleteUser}} /></div>}
          {activeTab === 'auditoria' && <div className="module-page"><div className="module-page-header"><div><span className="eyebrow">Auditoría</span><h1>Historial de cambios</h1><p>Consulta acciones ejecutadas, usuario, rol y fecha.</p></div></div><AuditPanel audit={state.audit} users={state.users} /></div>}
        </main>

        <aside className="properties config-drawer">
          <div className="config-header">
            <div className="config-header-top">
              <span className="eyebrow">Panel derecho</span>
              <button className="panel-close-btn" title="Cerrar panel" onClick={() => setRightPanelOpen(false)}><X size={15}/></button>
            </div>
            <h3>Configuración</h3>
            <p>{selectedDevice ? `Equipo · ${selectedDevice.hostname}` : selectedSegment ? `Segmento · ${selectedSegment.name}` : selectedService ? `Servicio · ${selectedService.name}` : selectedEdge ? 'Relación gráfica' : selectedDep ? 'Dependencia' : 'Selecciona un elemento para configurar'}</p>
          </div>
          <div className="config-content">
          {selectedDevice ? <DeviceProperties device={selectedDevice} state={state} canEdit={canEdit} updateDevicePatch={updateDevicePatch} deleteDevice={deleteDevice} duplicateDevice={duplicateDevice} runImpact={runImpact} /> : selectedSegment ? <SegmentProperties segment={selectedSegment} canEdit={canEdit} updateSegment={async (patch)=>{await request(`/segments/${selectedSegment.id}`,{method:'PATCH',body:{...selectedSegment,...patch}}); await loadState();}} /> : selectedService ? <ServiceProperties service={selectedService} /> : selectedEdge ? <LinkProperties link={selectedEdge} state={state} canEdit={canEdit} updateLink={updateLink} deleteLink={deleteLink} /> : selectedDep ? <DependencyProperties dep={selectedDep} canEdit={canEdit} deleteDependency={deleteDependency} /> : <div className="empty"><Shield size={40}/> Selecciona un elemento para abrir la configuración contextual. Los módulos se navegan desde el lado izquierdo.</div>}
          </div>
        </aside>
      </div>
    </div>
  );
}

function InventoryPanel(props) {
  const { canEdit, canExport, form, setForm, addDevice, search, setSearch, filter, setFilter, state, filteredDevices, selected, setSelected, setSelectedEdgeId, selectedIds, setSelectedIds, bulk, setBulk, bulkUpdate, bulkDelete, bulkRelation, setBulkRelation, bulkRelate, duplicateDevice, deleteDevice, exportInventory, segmentName, importFile, downloadDeviceTemplate, downloadInterfaceTemplate, downloadLinksTemplate, linkForm, setLinkForm, addLink, deviceName } = props;
  const [inventoryView, setInventoryView] = useState('tabla');
  const toggle = (id) => setSelectedIds(selectedIds.includes(id) ? selectedIds.filter(x=>x!==id) : [...selectedIds, id]);
  const parentName = (id) => state.devices.find(d => d.id === id)?.hostname || 'Sin parent';
  const interfaceCount = (id) => (state.interfaces || []).filter(i => i.device_id === id).length;
  const linkCount = (id) => (state.links || []).filter(l => l.source_device_id === id || l.target_device_id === id).length;
  const groupedInventory = useMemo(() => {
    const map = new Map();
    filteredDevices.forEach((d) => {
      const seg = state.segments.find((s) => s.id === d.segment_id) || {};
      const key = seg.cidr || (seg.vlan ? `VLAN ${seg.vlan}` : 'Sin CIDR / VLAN');
      if (!map.has(key)) map.set(key, { key, cidr: seg.cidr || 'Sin CIDR', vlans: new Set(), segments: new Set(), devices: [] });
      const g = map.get(key);
      if (seg.vlan) g.vlans.add(seg.vlan);
      if (seg.name) g.segments.add(seg.name);
      g.devices.push(d);
    });
    return [...map.values()].map((g) => ({ ...g, vlans: [...g.vlans], segments: [...g.segments] })).sort((a,b) => a.key.localeCompare(b.key));
  }, [filteredDevices, state.segments]);

  const inventoryTabs = [
    { id: 'tabla', label: 'Inventario', icon: Monitor, hint: 'Tabla, filtros y edición por equipo' },
    { id: 'conectividad', label: 'Conectividad', icon: Link2, hint: 'Interfaces, enlaces múltiples y LAG' },
    { id: 'grupos', label: 'CIDR / VLAN', icon: Layers, hint: 'Agrupación automática por red' },
    { id: 'carga', label: 'Carga CSV', icon: Upload, hint: 'Templates e importación masiva' },
    ...(canEdit ? [{ id: 'nuevo', label: 'Nuevo equipo', icon: Plus, hint: 'Alta rápida de dispositivo' }] : []),
  ];

  const inventoryKpis = [
    { label: 'Equipos visibles', value: filteredDevices.length },
    { label: 'Seleccionados', value: selectedIds.length },
    { label: 'Interfaces', value: (state.interfaces || []).length },
    { label: 'Enlaces', value: (state.links || []).length },
    { label: 'Grupos CIDR/VLAN', value: groupedInventory.length },
  ];

  const InventoryFilters = () => <section className="panel-section filter-card inventory-filter-card">
    <div className="section-title-row">
      <div><h3><Filter size={16}/> Filtros de inventario</h3><p>Filtra por tipo, segmento, estado, VLAN, IP o CIDR sin salir del inventario.</p></div>
      <div className="button-row compact-actions">{canExport && <button onClick={exportInventory}><Download size={16}/> Exportar CSV</button>}{canEdit && <button onClick={()=>setSelectedIds(filteredDevices.map(d=>d.id))}>Seleccionar filtrados</button>}{canEdit && <button onClick={()=>setSelectedIds([])}>Limpiar selección</button>}</div>
    </div>
    <div className="inventory-filter-layout">
      <div className="search"><Search size={16}/><input placeholder="Buscar hostname, IP, segmento, estado..." value={search} onChange={e=>setSearch(e.target.value)}/></div>
      <select value={filter.type} onChange={e=>setFilter({...filter,type:e.target.value})}><option value="">Tipo: todos</option>{DEVICE_TYPES.map(x=><option key={x}>{x}</option>)}</select>
      <select value={filter.segment} onChange={e=>setFilter({...filter,segment:e.target.value})}><option value="">Segmento: todos</option>{state.segments.map(s=><option key={s.id} value={s.id}>{s.name}</option>)}</select>
      <select value={filter.status} onChange={e=>setFilter({...filter,status:e.target.value})}><option value="">Estado: todos</option>{STATUSES.map(x=><option key={x}>{x}</option>)}</select>
      <input placeholder="VLAN" value={filter.vlan} onChange={e=>setFilter({...filter,vlan:e.target.value})}/>
      <input placeholder="IP" value={filter.ip} onChange={e=>setFilter({...filter,ip:e.target.value})}/>
      <input placeholder="CIDR" value={filter.cidr} onChange={e=>setFilter({...filter,cidr:e.target.value})}/>
    </div>
  </section>;

  const BulkActions = () => canEdit && selectedIds.length ? <section className="panel-section bulk-box enterprise-bulk inventory-action-card">
    <div className="section-title-row"><div><h3><Link2 size={16}/> Acciones sobre selección</h3><p className="hint">Actualiza datos o relaciona los equipos seleccionados con un router, switch, firewall o core principal.</p></div><span className="selection-pill">{selectedIds.length} seleccionados</span></div>
    <div className="inventory-action-grid">
      <div className="action-subcard">
        <h4>Edición masiva</h4>
        <div className="form-grid wide-form compact-wide-form"><input placeholder="Nuevo segmento" value={bulk.segment_name} onChange={e=>setBulk({...bulk,segment_name:e.target.value})}/><label className="compact-label"><span>VLAN masiva</span><input placeholder="Ej: 50" value={bulk.vlan} onChange={e=>setBulk({...bulk,vlan:e.target.value})}/></label><select value={bulk.status} onChange={e=>setBulk({...bulk,status:e.target.value})}><option value="">Estado sin cambios</option>{STATUSES.map(x=><option key={x}>{x}</option>)}</select><select value={bulk.icon} onChange={e=>setBulk({...bulk,icon:e.target.value})}><option value="">Icono sin cambios</option>{ICONS.map(x=><option key={x}>{x}</option>)}</select><select value={bulk.device_type} onChange={e=>setBulk({...bulk,device_type:e.target.value})}><option value="">Tipo sin cambios</option>{DEVICE_TYPES.map(x=><option key={x}>{x}</option>)}</select><select value={bulk.parent_device_id} onChange={e=>setBulk({...bulk,parent_device_id:e.target.value})}><option value="">Parent sin cambios</option>{state.devices.map(d=><option key={d.id} value={d.id}>{d.hostname}</option>)}</select></div>
        <div className="button-row"><button className="primary" onClick={bulkUpdate}>Aplicar edición</button><button className="danger" onClick={bulkDelete}>Eliminar en bloque</button></div>
      </div>
      <div className="action-subcard relation-subcard">
        <h4>Relación masiva con equipo principal</h4>
        <div className="form-grid wide-form compact-wide-form"><select value={bulkRelation.target_device_id} onChange={e=>setBulkRelation({...bulkRelation,target_device_id:e.target.value})}><option value="">Router / switch / equipo principal</option>{state.devices.filter(d=>!selectedIds.includes(d.id)).map(d=><option key={d.id} value={d.id}>{d.hostname} · {d.device_type}</option>)}</select><select value={bulkRelation.link_type} onChange={e=>setBulkRelation({...bulkRelation,link_type:e.target.value})}>{LINK_TYPES.map(x=><option key={x}>{x}</option>)}</select><select value={bulkRelation.status} onChange={e=>setBulkRelation({...bulkRelation,status:e.target.value})}>{STATUSES.map(x=><option key={x}>{x}</option>)}</select><select value={bulkRelation.direction} onChange={e=>setBulkRelation({...bulkRelation,direction:e.target.value})}><option value="target_to_selected">Principal → seleccionados</option><option value="selected_to_target">Seleccionados → principal</option></select><input placeholder="Etiqueta" value={bulkRelation.label} onChange={e=>setBulkRelation({...bulkRelation,label:e.target.value})}/><label className="checkbox"><input type="checkbox" checked={!!bulkRelation.set_parent} onChange={e=>setBulkRelation({...bulkRelation,set_parent:e.target.checked})}/> Actualizar parent/upstream</label></div>
        <button className="primary relation-cta" onClick={()=>bulkRelate()}><Link2 size={16}/> Relacionar seleccionados</button>
      </div>
    </div>
  </section> : null;

  const InventoryTable = () => <section className="panel-section table-section inventory-table-card">
    <div className="section-title-row"><div><h3><Monitor size={16}/> Tabla de inventario</h3><p>Las columnas de interfaces y enlaces muestran conectividad sin abrir otros módulos.</p></div><span className="selection-summary"><b>{filteredDevices.length}</b> visibles · <b>{selectedIds.length}</b> seleccionados</span></div>
    <div className="table-wrap"><table className="data-table inventory-table"><thead><tr><th></th><th>Equipo</th><th>IP</th><th>Tipo</th><th>Segmento</th><th>VLAN</th><th>Estado</th><th>Interfaces</th><th>Enlaces</th><th>Parent</th><th>Acciones</th></tr></thead><tbody>{filteredDevices.map(d=>{ const seg = state.segments.find(s=>s.id===d.segment_id); return <tr key={d.id} className={selected?.id===d.id?'selected':''} onClick={()=>{setSelected({type:'device',id:d.id});setSelectedEdgeId(null);}}><td>{canEdit && <input type="checkbox" checked={selectedIds.includes(d.id)} onClick={e=>e.stopPropagation()} onChange={()=>toggle(d.id)}/>}</td><td><div className="table-device"><span className="table-icon">{iconFor(d.icon,d.device_type)}</span><div><b>{d.hostname}</b><small>{d.role || 'sin rol'}</small></div></div></td><td>{d.management_ip || '-'}</td><td><span className="type-pill">{d.device_type}</span></td><td>{segmentName(d.segment_id)}</td><td>{seg?.vlan || '-'}</td><td><span className={`status-pill status-pill-${d.status || 'UNKNOWN'}`}>{d.status}</span></td><td><button className="count-button orange" onClick={(e)=>{e.stopPropagation();setSelected({type:'device',id:d.id});setSelectedEdgeId(null);setInventoryView('conectividad');}}>{interfaceCount(d.id)}</button></td><td><button className="count-button blue" onClick={(e)=>{e.stopPropagation();setSelected({type:'device',id:d.id});setSelectedEdgeId(null);setInventoryView('conectividad');}}>{linkCount(d.id)}</button></td><td>{parentName(d.parent_device_id)}</td><td><div className="inline-actions"><button onClick={(e)=>{e.stopPropagation();setSelected({type:'device',id:d.id});setSelectedEdgeId(null);}}>Editar</button>{canEdit && <button onClick={(e)=>{e.stopPropagation();duplicateDevice(d.id)}}>Duplicar</button>}{canEdit && <button className="danger" onClick={(e)=>{e.stopPropagation();deleteDevice(d.id)}}>Eliminar</button>}</div></td></tr>})}</tbody></table></div>
  </section>;

  const GroupView = () => <section className="panel-section cidr-group-section inventory-table-card"><div className="section-title-row"><div><h3><Layers size={16}/> Agrupación por CIDR / VLAN</h3><p>Los hosts con el mismo CIDR quedan en el mismo grupo. Si no hay CIDR, se agrupan por VLAN.</p></div></div><div className="cidr-group-grid">{groupedInventory.map((g) => <div key={g.key} className="cidr-group-card"><div><b>{g.cidr}</b><small>{g.vlans.length ? `VLAN ${g.vlans.join(', ')}` : 'Sin VLAN'} · {g.segments.join(', ') || 'Sin segmento'}</small></div><span>{g.devices.length} hosts</span>{canEdit && <button onClick={()=>setSelectedIds(g.devices.map(d=>d.id))}>Seleccionar grupo</button>}<button onClick={()=>{setFilter({...filter, cidr: g.cidr === 'Sin CIDR' ? '' : g.cidr, vlan: g.vlans[0] || ''});setInventoryView('tabla');}}>Filtrar en tabla</button></div>)}</div></section>;

  const ImportWithinInventory = () => <section className="panel-section inventory-import-module"><div className="section-title-row"><div><h3><Upload size={16}/> Carga masiva desde inventario</h3><p>Importa dispositivos, interfaces, enlaces y dependencias sin salir del módulo Inventario.</p></div></div>{canEdit ? <><div className="template-card unified-template-card"><div><b>Templates compatibles con inventario</b><p>Primero carga devices.csv, luego interfaces.csv y links.csv para representar uplinks múltiples, LAG, Port-Channel o enlaces redundantes.</p></div><div className="template-actions"><button className="primary" onClick={downloadDeviceTemplate}><Download size={16}/> devices.csv</button><button onClick={downloadInterfaceTemplate}><Download size={16}/> interfaces.csv</button><button onClick={downloadLinksTemplate}><Download size={16}/> links.csv</button></div></div><div className="inventory-import-grid"><ImportBox title="devices.csv" kind="devices" onFile={importFile}/><ImportBox title="interfaces.csv" kind="interfaces" onFile={importFile}/><ImportBox title="links.csv" kind="links" onFile={importFile}/><ImportBox title="dependencies.csv" kind="dependencies" onFile={importFile}/></div></> : <p>Tu rol no permite importar.</p>}</section>;

  const NewDevice = () => canEdit ? <section className="panel-section create-card inventory-table-card"><h3><Plus size={16}/> Nuevo dispositivo</h3><form onSubmit={addDevice} className="form-grid wide-form"><input required placeholder="Hostname" value={form.hostname} onChange={e=>setForm({...form, hostname:e.target.value})}/><input placeholder="IP" value={form.management_ip} onChange={e=>setForm({...form, management_ip:e.target.value})}/><select value={form.device_type} onChange={e=>setForm({...form, device_type:e.target.value})}>{DEVICE_TYPES.map(x=><option key={x}>{x}</option>)}</select><select value={form.icon} onChange={e=>setForm({...form, icon:e.target.value})}>{ICONS.map(x=><option key={x}>{x}</option>)}</select><select value={form.status} onChange={e=>setForm({...form, status:e.target.value})}>{STATUSES.map(x=><option key={x}>{x}</option>)}</select><input placeholder="Segmento" value={form.segment_name} onChange={e=>setForm({...form, segment_name:e.target.value})}/><input placeholder="VLAN" value={form.vlan} onChange={e=>setForm({...form, vlan:e.target.value})}/><input placeholder="Rol" value={form.role} onChange={e=>setForm({...form, role:e.target.value})}/><input placeholder="Tier" value={form.tier} onChange={e=>setForm({...form, tier:e.target.value})}/><select value={form.parent_device_id} onChange={e=>setForm({...form, parent_device_id:e.target.value})}><option value="">Sin parent/upstream</option>{state.devices.map(d=><option key={d.id} value={d.id}>{d.hostname}</option>)}</select><button type="submit" className="primary"><Plus size={16}/> Añadir dispositivo</button></form></section> : null;

  return <div className="inventory-module inventory-unified">
    <section className="panel-section inventory-command-center">
      <div className="inventory-command-header"><div><span className="eyebrow">Inventario unificado</span><h3>Dispositivos, grupos y conectividad</h3><p>Todos los cambios de inventario, interfaces y enlaces viven dentro de este módulo.</p></div><div className="inventory-kpis">{inventoryKpis.map(k=><div key={k.label}><b>{k.value}</b><span>{k.label}</span></div>)}</div></div>
      <div className="inventory-tabs">{inventoryTabs.map(t => { const Icon = t.icon; return <button key={t.id} className={inventoryView===t.id?'active':''} onClick={()=>setInventoryView(t.id)}><Icon size={16}/><span>{t.label}</span><small>{t.hint}</small></button> })}</div>
    </section>

    {inventoryView === 'tabla' && <><InventoryFilters/><BulkActions/><InventoryTable/></>}
    {inventoryView === 'conectividad' && <InventoryConnectivityPanel {...{canEdit, state, filteredDevices, selectedIds, setSelectedIds, setSelected, setSelectedEdgeId, importFile, downloadDeviceTemplate, downloadInterfaceTemplate, downloadLinksTemplate, linkForm, setLinkForm, addLink, deviceName}} />}
    {inventoryView === 'grupos' && <GroupView/>}
    {inventoryView === 'carga' && <ImportWithinInventory/>}
    {inventoryView === 'nuevo' && <NewDevice/>}
  </div>
}

function InventoryConnectivityPanel({ canEdit, state, filteredDevices, selectedIds, setSelectedIds, setSelected, setSelectedEdgeId, importFile, downloadDeviceTemplate, downloadInterfaceTemplate, downloadLinksTemplate, linkForm, setLinkForm, addLink, deviceName }) {
  const interfaces = state.interfaces || [];
  const links = state.links || [];
  const devicesById = useMemo(() => Object.fromEntries((state.devices || []).map(d => [d.id, d])), [state.devices]);
  const interfacesFor = (deviceId) => interfaces.filter(i => i.device_id === deviceId);
  const selectedDeviceSet = new Set(selectedIds || []);

  const interfaceCounts = useMemo(() => {
    const map = new Map();
    interfaces.forEach(i => map.set(i.device_id, (map.get(i.device_id) || 0) + 1));
    return map;
  }, [interfaces]);

  const connectionCounts = useMemo(() => {
    const map = new Map();
    links.forEach(l => {
      map.set(l.source_device_id, (map.get(l.source_device_id) || 0) + 1);
      map.set(l.target_device_id, (map.get(l.target_device_id) || 0) + 1);
    });
    return map;
  }, [links]);

  const multiInterfaceDevices = useMemo(() => filteredDevices.filter(d => (interfaceCounts.get(d.id) || 0) > 1), [filteredDevices, interfaceCounts]);

  const linkGroups = useMemo(() => {
    const map = new Map();
    links.forEach(l => {
      const a = l.source_device_id || '';
      const b = l.target_device_id || '';
      const pairKey = [a, b].sort().join('::');
      const groupKey = l.link_group || l.metadata?.link_group || 'sin-grupo';
      const key = `${pairKey}::${groupKey}`;
      if (!map.has(key)) map.set(key, { key, group: groupKey, source: a, target: b, links: [] });
      map.get(key).links.push(l);
    });
    return [...map.values()].sort((a,b) => b.links.length - a.links.length);
  }, [links]);

  const parallelGroups = linkGroups.filter(g => g.links.length > 1);
  const lagGroups = linkGroups.filter(g => g.group && g.group !== 'sin-grupo');

  const selectGroupDevices = (group) => {
    const ids = [...new Set(group.links.flatMap(l => [l.source_device_id, l.target_device_id]).filter(Boolean))];
    setSelectedIds(ids);
  };

  return <section className="panel-section connectivity-inventory compact-card">
    <div className="section-title-row"><div><h3><Link2 size={16}/> Conectividad del inventario</h3><p>Administra interfaces, puertos, múltiples uplinks, LAG, Port-Channel, EtherChannel y enlaces redundantes desde el inventario.</p></div></div>

    <div className="connectivity-kpis">
      <div><b>{interfaces.length}</b><span>Interfaces / puertos</span></div>
      <div><b>{links.length}</b><span>Enlaces registrados</span></div>
      <div><b>{multiInterfaceDevices.length}</b><span>Equipos multi-NIC</span></div>
      <div><b>{parallelGroups.length}</b><span>Enlaces paralelos</span></div>
      <div><b>{lagGroups.length}</b><span>Grupos LAG/Port-Channel</span></div>
    </div>

    {canEdit ? <div className="inventory-import-strip">
      <div className="strip-title"><b>Carga rápida de conectividad</b><small>Usa estos CSV cuando necesites reflejar conexiones reales por puerto/interfaz.</small></div>
      <div className="template-actions compact-actions"><button onClick={downloadDeviceTemplate}><Download size={14}/> devices.csv</button><button onClick={downloadInterfaceTemplate}><Download size={14}/> interfaces.csv</button><button onClick={downloadLinksTemplate}><Download size={14}/> links.csv</button></div>
      <div className="compact-imports"><ImportBox title="interfaces.csv" kind="interfaces" onFile={importFile}/><ImportBox title="links.csv" kind="links" onFile={importFile}/><ImportBox title="dependencies.csv" kind="dependencies" onFile={importFile}/></div>
    </div> : null}

    {canEdit ? <div className="inline-connect-form">
      <h4><Plus size={15}/> Crear conexión por interfaz</h4>
      <form onSubmit={addLink} className="form-grid connection-form">
        <select required value={linkForm.source_device_id} onChange={e=>setLinkForm({...linkForm, source_device_id:e.target.value, source_interface:''})}><option value="">Origen</option>{state.devices.map(d=><option key={d.id} value={d.id}>{d.hostname}</option>)}</select>
        <input list="inventory-source-interfaces" placeholder="Interfaz origen" value={linkForm.source_interface || ''} onChange={e=>setLinkForm({...linkForm, source_interface:e.target.value})}/>
        <datalist id="inventory-source-interfaces">{interfacesFor(linkForm.source_device_id).map(i=><option key={i.id} value={i.name}>{i.name}</option>)}</datalist>
        <select required value={linkForm.target_device_id} onChange={e=>setLinkForm({...linkForm, target_device_id:e.target.value, target_interface:''})}><option value="">Destino</option>{state.devices.map(d=><option key={d.id} value={d.id}>{d.hostname}</option>)}</select>
        <input list="inventory-target-interfaces" placeholder="Interfaz destino" value={linkForm.target_interface || ''} onChange={e=>setLinkForm({...linkForm, target_interface:e.target.value})}/>
        <datalist id="inventory-target-interfaces">{interfacesFor(linkForm.target_device_id).map(i=><option key={i.id} value={i.name}>{i.name}</option>)}</datalist>
        <select value={linkForm.link_type} onChange={e=>setLinkForm({...linkForm, link_type:e.target.value})}>{LINK_TYPES.map(x=><option key={x}>{x}</option>)}</select>
        <select value={linkForm.status} onChange={e=>setLinkForm({...linkForm, status:e.target.value})}>{STATUSES.map(x=><option key={x}>{x}</option>)}</select>
        <input placeholder="Grupo LAG / Port-Channel" value={linkForm.link_group || ''} onChange={e=>setLinkForm({...linkForm, link_group:e.target.value})}/>
        <select value={linkForm.link_role || ''} onChange={e=>setLinkForm({...linkForm, link_role:e.target.value})}><option value="">Rol</option><option value="primary">primary</option><option value="backup">backup</option><option value="redundant">redundant</option><option value="member">member</option></select>
        <input placeholder="Etiqueta" value={linkForm.label || ''} onChange={e=>setLinkForm({...linkForm, label:e.target.value})}/>
        <button className="primary"><Link2 size={15}/> Crear enlace</button>
      </form>
    </div> : null}

    <div className="module-grid two-columns connectivity-tables">
      <div className="mini-table-card"><h4>Equipos con más de una interfaz</h4><div className="mini-table-scroll"><table className="data-table compact-table"><thead><tr><th>Equipo</th><th>Interfaces</th><th>Conexiones</th><th></th></tr></thead><tbody>{multiInterfaceDevices.length ? multiInterfaceDevices.map(d => <tr key={d.id} onClick={()=>{setSelected({type:'device',id:d.id});setSelectedEdgeId(null);}}><td>{d.hostname}</td><td><span className="count-badge orange">{interfaceCounts.get(d.id)}</span></td><td><span className="count-badge blue">{connectionCounts.get(d.id) || 0}</span></td><td><button onClick={(e)=>{e.stopPropagation();setSelectedIds([d.id]);}}>Seleccionar</button></td></tr>) : <tr><td colSpan="4">Aún no hay equipos con múltiples interfaces.</td></tr>}</tbody></table></div></div>
      <div className="mini-table-card"><h4>Enlaces paralelos / LAG detectados</h4><div className="mini-table-scroll"><table className="data-table compact-table"><thead><tr><th>Equipos</th><th>Grupo</th><th>Enlaces</th><th>Roles</th></tr></thead><tbody>{linkGroups.length ? linkGroups.map(g => <tr key={g.key} className={g.links.length>1?'highlight-row':''} onClick={()=>{setSelectedEdgeId(g.links[0].id);setSelected(null);}}><td>{deviceName(g.links[0].source_device_id)} ⇄ {deviceName(g.links[0].target_device_id)}</td><td><span className="lag-pill">{g.group}</span></td><td><button onClick={(e)=>{e.stopPropagation();selectGroupDevices(g)}}>{g.links.length} enlaces</button></td><td>{[...new Set(g.links.map(l=>l.link_role).filter(Boolean))].join(', ') || '-'}</td></tr>) : <tr><td colSpan="4">Aún no hay enlaces cargados.</td></tr>}</tbody></table></div></div>
    </div>

    <div className="link-detail-grid">
      {parallelGroups.slice(0, 6).map(g => <div key={g.key} className="parallel-card" onClick={()=>{setSelectedEdgeId(g.links[0].id);setSelected(null);}}>
        <div className="parallel-header"><b>{deviceName(g.links[0].source_device_id)} ⇄ {deviceName(g.links[0].target_device_id)}</b><span>{g.links.length} enlaces</span></div>
        <small>{g.group !== 'sin-grupo' ? g.group : 'Enlaces paralelos sin grupo'}</small>
        <div className="parallel-lines">{g.links.map(l => <div key={l.id}>• {l.source_interface || '-'} → {l.target_interface || '-'} · {l.link_type} · {l.status}{l.link_role ? ` · ${l.link_role}` : ''}</div>)}</div>
      </div>)}
    </div>
  </section>
}

function RelationsPanel({ canEdit, state, linkForm, setLinkForm, addLink, depForm, setDepForm, addDependency, selectedEdgeId, setSelectedEdgeId, setSelected, deviceName, entityOptions }) {
  const interfacesFor = (deviceId) => (state.interfaces || []).filter(i => i.device_id === deviceId);
  const pairGroups = useMemo(() => {
    const map = new Map();
    (state.links || []).forEach((l) => {
      const key = `${l.source_device_id}::${l.target_device_id}::${l.link_group || l.metadata?.link_group || ''}`;
      if (!map.has(key)) map.set(key, []);
      map.get(key).push(l);
    });
    return [...map.values()].filter(g => g.length > 1);
  }, [state.links]);
  return <section className="panel-section relations-module">{canEdit && <><h3><Link2 size={16}/> Nueva relación gráfica por interfaz</h3><form onSubmit={addLink} className="form-grid"><select required value={linkForm.source_device_id} onChange={e=>setLinkForm({...linkForm, source_device_id:e.target.value, source_interface:''})}><option value="">Origen</option>{state.devices.map(d=><option key={d.id} value={d.id}>{d.hostname}</option>)}</select><select required value={linkForm.target_device_id} onChange={e=>setLinkForm({...linkForm, target_device_id:e.target.value, target_interface:''})}><option value="">Destino</option>{state.devices.map(d=><option key={d.id} value={d.id}>{d.hostname}</option>)}</select><input list="source-interfaces" placeholder="Interfaz origen / puerto" value={linkForm.source_interface} onChange={e=>setLinkForm({...linkForm, source_interface:e.target.value})}/><datalist id="source-interfaces">{interfacesFor(linkForm.source_device_id).map(i=><option key={i.id} value={i.name}>{i.name}</option>)}</datalist><input list="target-interfaces" placeholder="Interfaz destino / puerto" value={linkForm.target_interface} onChange={e=>setLinkForm({...linkForm, target_interface:e.target.value})}/><datalist id="target-interfaces">{interfacesFor(linkForm.target_device_id).map(i=><option key={i.id} value={i.name}>{i.name}</option>)}</datalist><select value={linkForm.link_type} onChange={e=>setLinkForm({...linkForm, link_type:e.target.value})}>{LINK_TYPES.map(x=><option key={x}>{x}</option>)}</select><select value={linkForm.status} onChange={e=>setLinkForm({...linkForm, status:e.target.value})}>{STATUSES.map(x=><option key={x}>{x}</option>)}</select><input placeholder="Etiqueta" value={linkForm.label} onChange={e=>setLinkForm({...linkForm, label:e.target.value})}/><input placeholder="Grupo LAG / Port-Channel" value={linkForm.link_group || ''} onChange={e=>setLinkForm({...linkForm, link_group:e.target.value})}/><select value={linkForm.link_role || ''} onChange={e=>setLinkForm({...linkForm, link_role:e.target.value})}><option value="">Rol del enlace</option><option value="primary">primary</option><option value="backup">backup</option><option value="redundant">redundant</option><option value="member">member</option></select><button type="submit" className="primary"><Plus size={16}/> Crear relación</button></form><h3>Relación entre entidades / segmentos</h3><form onSubmit={addDependency} className="form-grid"><select value={depForm.source_type} onChange={e=>setDepForm({...depForm, source_type:e.target.value, source_id:''})}>{ENTITY_TYPES.map(x=><option key={x}>{x}</option>)}</select><select value={depForm.source_id} onChange={e=>setDepForm({...depForm, source_id:e.target.value})}><option value="">Origen/dependiente</option>{entityOptions(depForm.source_type).map(x=><option key={x.id} value={x.id}>{x.name}</option>)}</select><select value={depForm.target_type} onChange={e=>setDepForm({...depForm, target_type:e.target.value, target_id:''})}>{ENTITY_TYPES.map(x=><option key={x}>{x}</option>)}</select><select value={depForm.target_id} onChange={e=>setDepForm({...depForm, target_id:e.target.value})}><option value="">Destino/base</option>{entityOptions(depForm.target_type).map(x=><option key={x.id} value={x.id}>{x.name}</option>)}</select><input placeholder="Tipo dependencia" value={depForm.dependency_type} onChange={e=>setDepForm({...depForm, dependency_type:e.target.value})}/><select value={depForm.criticality} onChange={e=>setDepForm({...depForm, criticality:e.target.value})}>{['low','medium','high','critical'].map(x=><option key={x}>{x}</option>)}</select><button className="primary">Crear dependencia</button></form></>}
    <h3>Enlaces múltiples detectados</h3><div className="list compact">{pairGroups.length ? pairGroups.map((g)=><div key={`${g[0].source_device_id}-${g[0].target_device_id}-${g[0].link_group}`} className="list-row multi-link-row" onClick={()=>{setSelectedEdgeId(g[0].id);setSelected(null);}}><span>{deviceName(g[0].source_device_id)} ⇄ {deviceName(g[0].target_device_id)}</span><small>{g.length} enlaces · {g[0].link_group || g[0].metadata?.link_group || 'sin grupo'} · {g.map(l=>`${l.source_interface||'-'}→${l.target_interface||'-'}`).join(' | ')}</small></div>) : <div className="empty-inline">No hay enlaces paralelos todavía.</div>}</div>
    <h3>Relaciones cargadas</h3><div className="list compact">{state.links.map(l=><div key={l.id} className={`list-row ${selectedEdgeId===l.id?'selected':''}`} onClick={()=>{setSelectedEdgeId(l.id);setSelected(null);}}><span>{deviceName(l.source_device_id)} → {deviceName(l.target_device_id)}</span><small>{l.link_type} · {l.source_interface || '-'} → {l.target_interface || '-'} · {l.status}{l.link_group ? ` · ${l.link_group}` : ''}{l.link_role ? ` · ${l.link_role}` : ''}</small></div>)}</div>
    <h3>Interfaces registradas</h3><div className="list compact interface-list">{(state.interfaces || []).map(i=><div key={i.id} className="list-row"><span>{deviceName(i.device_id)} · {i.name}</span><small>{i.ip_address || '-'} · VLAN {i.vlan || '-'} · {i.status} · {i.speed || '-'}</small></div>)}</div>
    <h3>Dependencias y segmentos</h3><div className="list compact">{state.dependencies.map(d=><div key={d.id} className={`list-row ${selectedEdgeId===d.id?'selected':''}`} onClick={()=>{setSelectedEdgeId(d.id);setSelected(null);}}><span>{d.target_name || d.target_id} → {d.source_name || d.source_id}</span><small>{d.target_type} → {d.source_type} · {d.dependency_type} · {d.criticality}</small></div>)}</div>
  </section>
}

function ServicesPanel({ canEdit, svcForm, setSvcForm, addService, state }) { return <section className="panel-section"><h3><Server size={16}/> Nuevo servicio</h3>{canEdit && <form onSubmit={addService} className="form-grid"><input required placeholder="Nombre del servicio" value={svcForm.name} onChange={e=>setSvcForm({...svcForm, name:e.target.value})}/><input placeholder="Tipo" value={svcForm.service_type} onChange={e=>setSvcForm({...svcForm, service_type:e.target.value})}/><select value={svcForm.criticality} onChange={e=>setSvcForm({...svcForm, criticality:e.target.value})}>{['low','medium','high','critical'].map(x=><option key={x}>{x}</option>)}</select><select value={svcForm.status} onChange={e=>setSvcForm({...svcForm, status:e.target.value})}>{STATUSES.map(x=><option key={x}>{x}</option>)}</select><input placeholder="Owner" value={svcForm.owner} onChange={e=>setSvcForm({...svcForm, owner:e.target.value})}/><button type="submit" className="primary">Guardar servicio</button></form>}<div className="list compact">{state.services.map(s=><div key={s.id} className="list-row"><span>{s.name}</span><small>{s.service_type} · {s.criticality} · {s.status}</small></div>)}</div></section> }

function DeviceProperties({ device, state, canEdit, updateDevicePatch, deleteDevice, duplicateDevice, runImpact }) {
  const [draft, setDraft] = useState(device);
  useEffect(() => setDraft(device), [device.id, device]);
  const commit = (patch) => { setDraft({...draft, ...patch}); updateDevicePatch(device.id, patch, true); };
  return <div className="prop-form"><label>Hostname<input disabled={!canEdit} value={draft.hostname || ''} onChange={e=>setDraft({...draft, hostname:e.target.value})} onBlur={()=>updateDevicePatch(device.id,{hostname:draft.hostname},true)}/></label><label>IP<input disabled={!canEdit} value={draft.management_ip || ''} onChange={e=>setDraft({...draft, management_ip:e.target.value})} onBlur={()=>updateDevicePatch(device.id,{management_ip:draft.management_ip},true)}/></label><label>Tipo<select disabled={!canEdit} value={draft.device_type || 'unknown'} onChange={e=>commit({device_type:e.target.value})}>{DEVICE_TYPES.map(x=><option key={x}>{x}</option>)}</select></label><label>Icono visual<select disabled={!canEdit} value={draft.icon || 'auto'} onChange={e=>commit({icon:e.target.value})}>{ICONS.map(x=><option key={x}>{x}</option>)}</select></label><label>Estado<select disabled={!canEdit} value={draft.status || 'UNKNOWN'} onChange={e=>commit({status:e.target.value})}>{STATUSES.map(x=><option key={x}>{x}</option>)}</select></label><label>Rol<input disabled={!canEdit} value={draft.role || ''} onChange={e=>setDraft({...draft, role:e.target.value})} onBlur={()=>updateDevicePatch(device.id,{role:draft.role},true)}/></label><label>Tier<input disabled={!canEdit} type="number" value={draft.tier || 6} onChange={e=>setDraft({...draft, tier:Number(e.target.value)})} onBlur={()=>updateDevicePatch(device.id,{tier:Number(draft.tier)},true)}/></label><label>Segmento<select disabled={!canEdit} value={draft.segment_id || ''} onChange={e=>commit({segment_id:e.target.value})}><option value="">Sin segmento</option>{state.segments.map(s=><option key={s.id} value={s.id}>{s.name}</option>)}</select></label><label>Parent / upstream<select disabled={!canEdit} value={draft.parent_device_id || ''} onChange={e=>commit({parent_device_id:e.target.value || null})}><option value="">Sin parent</option>{state.devices.filter(d=>d.id!==device.id).map(d=><option key={d.id} value={d.id}>{d.hostname}</option>)}</select></label><label className="checkbox"><input disabled={!canEdit} type="checkbox" checked={!!draft.is_main} onChange={e=>commit({is_main:e.target.checked})}/> Principal</label><label className="checkbox"><input disabled={!canEdit} type="checkbox" checked={!!draft.is_perimeter} onChange={e=>commit({is_perimeter:e.target.checked})}/> Perimetral</label><div className="button-row"><button onClick={()=>runImpact(device.id)}><Zap size={16}/> Simular falla</button>{canEdit && <button onClick={()=>duplicateDevice(device.id)}>Duplicar</button>}{canEdit && <button className="danger" onClick={()=>deleteDevice(device.id)}><Trash2 size={16}/> Eliminar</button>}</div><div className="metadata"><h4>Interfaces / puertos</h4>{(state.interfaces || []).filter(i=>i.device_id===device.id).length ? (state.interfaces || []).filter(i=>i.device_id===device.id).map(i=><div key={i.id}>• {i.name} · {i.ip_address || '-'} · VLAN {i.vlan || '-'} · {i.status} · {i.speed || '-'}</div>) : <div>Sin interfaces registradas. Carga interfaces.csv o crea enlaces con puertos.</div>}<h4>Conexiones del equipo</h4>{(state.links || []).filter(l=>l.source_device_id===device.id || l.target_device_id===device.id).length ? (state.links || []).filter(l=>l.source_device_id===device.id || l.target_device_id===device.id).map(l=><div key={l.id}>• {state.devices.find(d=>d.id===l.source_device_id)?.hostname || l.source_device_id} {l.source_interface || '-'} → {state.devices.find(d=>d.id===l.target_device_id)?.hostname || l.target_device_id} {l.target_interface || '-'} · {l.link_type}{l.link_group ? ` · ${l.link_group}` : ''}</div>) : <div>Sin relaciones registradas.</div>}</div>{draft.metadata?.nmap_ports?.length ? <div className="metadata"><h4>Puertos Nmap</h4>{draft.metadata.nmap_ports.map((p,i)=><div key={i}>{p.port}/{p.protocol} {p.service} {p.product} {p.version}</div>)}</div> : null}</div>
}

function SegmentProperties({ segment, canEdit, updateSegment }) { const [draft,setDraft]=useState(segment); useEffect(()=>setDraft(segment),[segment.id,segment]); const commit=(patch)=>{setDraft({...draft,...patch}); updateSegment(patch)}; return <div className="prop-form"><label>Nombre<input disabled={!canEdit} value={draft.name||''} onChange={e=>setDraft({...draft,name:e.target.value})} onBlur={()=>updateSegment({name:draft.name})}/></label><label>CIDR<input disabled={!canEdit} value={draft.cidr||''} onChange={e=>setDraft({...draft,cidr:e.target.value})} onBlur={()=>updateSegment({cidr:draft.cidr})}/></label><label>VLAN<input disabled={!canEdit} value={draft.vlan||''} onChange={e=>setDraft({...draft,vlan:e.target.value})} onBlur={()=>updateSegment({vlan:draft.vlan?Number(draft.vlan):null})}/></label><label>Color<input disabled={!canEdit} value={draft.color||''} placeholder="#38bdf8" onChange={e=>setDraft({...draft,color:e.target.value})} onBlur={()=>updateSegment({color:draft.color})}/></label><label className="checkbox"><input disabled={!canEdit} type="checkbox" checked={!!draft.collapsed} onChange={e=>commit({collapsed:e.target.checked})}/> Colapsar segmento</label></div> }
function ServiceProperties({ service }) { return <div className="prop-form"><p><b>{service.name}</b></p><p>Tipo: {service.service_type}</p><p>Criticidad: {service.criticality}</p><p>Estado: {service.status}</p><p>{service.description}</p></div> }
function LinkProperties({ link, state, canEdit, updateLink, deleteLink }) {
  const [draft,setDraft]=useState(link);
  useEffect(()=>setDraft(link),[link.id,link]);
  const name=(id)=>state.devices.find(d=>d.id===id)?.hostname || id;
  const save=()=>updateLink(link.id,draft);
  const parallel = (state.links || []).filter(l => l.source_device_id === link.source_device_id && l.target_device_id === link.target_device_id && (l.link_group || '') === (link.link_group || ''));
  return <div className="prop-form"><p><b>Origen:</b> {name(link.source_device_id)}</p><p><b>Destino:</b> {name(link.target_device_id)}</p><label>Interfaz origen<input disabled={!canEdit} value={draft.source_interface||''} onChange={e=>setDraft({...draft,source_interface:e.target.value})}/></label><label>Interfaz destino<input disabled={!canEdit} value={draft.target_interface||''} onChange={e=>setDraft({...draft,target_interface:e.target.value})}/></label><label>Tipo<select disabled={!canEdit} value={draft.link_type} onChange={e=>setDraft({...draft,link_type:e.target.value})}>{LINK_TYPES.map(x=><option key={x}>{x}</option>)}</select></label><label>Estado<select disabled={!canEdit} value={draft.status} onChange={e=>setDraft({...draft,status:e.target.value})}>{STATUSES.map(x=><option key={x}>{x}</option>)}</select></label><label>Etiqueta<input disabled={!canEdit} value={draft.label||''} onChange={e=>setDraft({...draft,label:e.target.value})}/></label><label>Grupo LAG / Port-Channel<input disabled={!canEdit} value={draft.link_group||''} onChange={e=>setDraft({...draft,link_group:e.target.value})}/></label><label>Rol del enlace<select disabled={!canEdit} value={draft.link_role||''} onChange={e=>setDraft({...draft,link_role:e.target.value})}><option value="">Sin rol</option><option value="primary">primary</option><option value="backup">backup</option><option value="redundant">redundant</option><option value="member">member</option></select></label>{parallel.length > 1 ? <div className="metadata"><h4>Enlaces paralelos entre estos equipos</h4>{parallel.map((l)=><div key={l.id}>• {l.source_interface || '-'} → {l.target_interface || '-'} · {l.link_type} · {l.status} {l.link_role ? `· ${l.link_role}` : ''}</div>)}</div> : null}{canEdit && <div className="button-row"><button className="primary" onClick={save}>Guardar relación</button><button className="danger" onClick={()=>deleteLink(link.id)}>Eliminar relación</button></div>}</div>
}
function DependencyProperties({ dep, canEdit, deleteDependency }) { return <div className="prop-form"><p><b>{dep.target_name}</b> impacta / soporta a <b>{dep.source_name}</b></p><p>{dep.target_type} → {dep.source_type}</p><p>Tipo: {dep.dependency_type}</p><p>Criticidad: {dep.criticality}</p>{canEdit && <button className="danger" onClick={()=>deleteDependency(dep.id)}>Eliminar dependencia</button>}</div> }
function ImportPanel({ importFile, canEdit, downloadDeviceTemplate, downloadInterfaceTemplate, downloadLinksTemplate }) { return <section className="panel-section import-module"><h3><FileInput size={16}/> Importar datos</h3>{canEdit ? <><div className="template-card"><div><b>Templates para carga masiva</b><p>Usa devices.csv para inventario, interfaces.csv para puertos/NICs y links.csv para múltiples enlaces, LAG, Port-Channel o interfaces redundantes.</p></div><div className="template-actions"><button className="primary" onClick={downloadDeviceTemplate}><Download size={16}/> devices.csv</button><button onClick={downloadInterfaceTemplate}><Download size={16}/> interfaces.csv</button><button onClick={downloadLinksTemplate}><Download size={16}/> links.csv</button></div></div><div className="template-columns"><span>devices: hostname</span><span>ip</span><span>segment</span><span>cidr</span><span>vlan</span><span>parent</span><span>interfaces: device</span><span>interface</span><span>links: source_interface</span><span>link_group</span></div><ImportBox title="devices.csv" kind="devices" onFile={importFile}/><ImportBox title="interfaces.csv" kind="interfaces" onFile={importFile}/><ImportBox title="links.csv" kind="links" onFile={importFile}/><ImportBox title="dependencies.csv" kind="dependencies" onFile={importFile}/><ImportBox title="nmap-scan.xml" kind="nmap" onFile={importFile}/></> : <p>Tu rol no permite importar.</p>}<div className="command-box"><b>Comando Nmap exacto para probar contra este Docker:</b><code>nmap -sV -p 8080 --open -T3 -oX nmap-scan.xml 127.0.0.1</code><b>Comando para una red autorizada:</b><code>nmap -sV --open --top-ports 1000 -T3 -oX nmap-scan.xml 192.168.1.0/24</code></div></section> }
function ImportBox({ title, kind, onFile }) { return <label className="import-box"><Upload size={16}/><span>{title}</span><input type="file" onChange={e=>onFile(kind, e.target.files[0])}/></label> }
function ImpactPanel({ impact, runImpact, devices }) {
  const [id,setId]=useState('');
  const radius = impact?.blast_radius || {
    devices: impact?.affected_devices?.length || 0,
    services: impact?.affected_services?.length || 0,
    segments: impact?.affected_segments?.length || 0,
    links: impact?.impact_edges?.filter(e=>e.edge_id)?.length || 0,
    paths: impact?.paths?.length || 0,
    critical_services: 0,
  };
  const pathText = (path) => path.map((step, idx) => idx === 0 ? step.name : `${step.name} (${step.via || 'impacta'})`).join(' -> ');
  return <section className="panel-section impact-module">
    <h3><Zap size={16}/> Simulación de falla / impacto</h3>
    <div className="impact-runner"><select value={id} onChange={e=>setId(e.target.value)}><option value="">Seleccionar equipo</option>{devices.map(d=><option key={d.id} value={d.id}>{d.hostname} · {d.device_type}</option>)}</select><button className="primary" onClick={()=>runImpact(id)}>Simular falla</button></div>
    {impact ? <div className="impact-box">
      <div className="impact-summary-head"><div><span className={`severity-pill severity-${impact.severity}`}>{impact.severity}</span><h4>{impact.root_cause?.hostname}</h4><p>{impact.summary}</p></div></div>
      <div className="impact-kpis"><div><b>{radius.devices}</b><span>Dispositivos</span></div><div><b>{radius.services}</b><span>Servicios</span></div><div><b>{radius.segments}</b><span>Segmentos</span></div><div><b>{radius.links}</b><span>Enlaces usados</span></div><div><b>{radius.paths}</b><span>Rutas</span></div></div>
      <div className="impact-lists">
        <div><b>Dispositivos afectados</b>{impact.affected_devices?.length ? impact.affected_devices.map(d=><div key={d.id}>• {d.hostname} · {d.device_type} · {d.status}</div>) : <small>Sin dispositivos descendentes afectados.</small>}</div>
        <div><b>Servicios afectados</b>{impact.affected_services?.length ? impact.affected_services.map(s=><div key={s.id}>• {s.name} · {s.criticality}</div>) : <small>Sin servicios afectados.</small>}</div>
        <div><b>Segmentos afectados</b>{impact.affected_segments?.length ? impact.affected_segments.map(s=><div key={s.id}>• {s.name} · {s.cidr || 'sin CIDR'}</div>) : <small>Sin segmentos afectados.</small>}</div>
      </div>
      <b>Rutas de propagación</b>
      {impact.paths?.length ? impact.paths.slice(0, 20).map((p,i)=><div key={i} className="path-row">{pathText(p)}</div>) : <div className="path-row">No hay dependencias o equipos descendentes.</div>}
    </div> : <p>Selecciona un equipo para simular cómo se propaga la falla por enlaces, parent/upstream, segmentos y servicios.</p>}
  </section>
}
function VersionsPanel({ canEdit, canExport, state, versionForm, setVersionForm, saveVersion, restoreVersion, compare, setCompare, compareVersions, exportJSON, importProjectJSON }) {
  const projectInputRef = React.useRef(null);
  return <section className="panel-section">
    <h3><Save size={16}/> Versionamiento de mapas</h3>
    {canEdit && <div className="form-grid"><input value={versionForm.name} onChange={e=>setVersionForm({...versionForm,name:e.target.value})} placeholder="Nombre"/><input value={versionForm.version} onChange={e=>setVersionForm({...versionForm,version:e.target.value})} placeholder="v.1.4.0"/><button className="primary" onClick={saveVersion}>Guardar versión</button></div>}

    <h3><Download size={16}/> Exportar / Cargar proyecto</h3>
    <div className="template-card">
      <div><b>Exportar e importar mapa completo como JSON</b><p>Guarda el mapa actual como archivo .json para compartirlo, respaldarlo o cargarlo en otra instancia. Al cargar reemplaza el mapa completo.</p></div>
      <div className="template-actions">
        {canExport && <button className="primary" onClick={exportJSON}><Download size={16}/> Exportar proyecto JSON</button>}
        {canEdit && <><input ref={projectInputRef} type="file" accept=".json,application/json" style={{display:'none'}} onChange={e=>{if(e.target.files[0]){importProjectJSON(e.target.files[0]);e.target.value=''}}}/><button onClick={()=>projectInputRef.current?.click()}><Upload size={16}/> Cargar proyecto JSON</button></>}
      </div>
    </div>

    <h3>Comparar versiones</h3>
    <div className="form-grid"><select value={compare.a} onChange={e=>setCompare({...compare,a:e.target.value})}><option value="">Versión A</option>{state.versions.map(v=><option key={v.id} value={v.id}>{v.name} · {v.version} · {v.created_at}</option>)}</select><select value={compare.b} onChange={e=>setCompare({...compare,b:e.target.value})}><option value="">Versión B</option>{state.versions.map(v=><option key={v.id} value={v.id}>{v.name} · {v.version} · {v.created_at}</option>)}</select><button onClick={compareVersions}>Comparar</button></div>
    {compare.result ? <div className="metadata"><b>Resultado comparación</b><pre>{JSON.stringify(compare.result,null,2)}</pre></div> : null}
    <h3>Historial</h3>
    <div className="list compact">{state.versions.map(v=><div key={v.id} className="list-row"><span>{v.name} · {v.version}</span><small>{v.created_at} · {v.created_by}</small>{canEdit && <button onClick={()=>restoreVersion(v.id)}>Restaurar</button>}</div>)}</div>
  </section>
}
function UsersPanel({ currentUser, userForm, setUserForm, users, addUser, updateUser, deleteUser }) {
  const isAdmin = currentUser?.role === 'admin';
  const [editing, setEditing] = useState({});
  const [query, setQuery] = useState('');
  const filtered = users.filter(u => [u.username, u.display_name, u.role].join(' ').toLowerCase().includes(query.toLowerCase()));
  return <section className="panel-section users-portal">
    <h3><Users size={16}/> Portal de usuarios</h3>
    <div className="portal-note">Administra accesos, roles y estado de cuentas. Los cambios quedan auditados en PostgreSQL.</div>
    {isAdmin ? <form onSubmit={addUser} className="form-grid">
      <input required placeholder="usuario" value={userForm.username} onChange={e=>setUserForm({...userForm,username:e.target.value})}/>
      <input required placeholder="contraseña" type="password" value={userForm.password} onChange={e=>setUserForm({...userForm,password:e.target.value})}/>
      <select value={userForm.role} onChange={e=>setUserForm({...userForm,role:e.target.value})}>{USER_ROLES.map(r=><option key={r}>{r}</option>)}</select>
      <input placeholder="nombre visible" value={userForm.display_name} onChange={e=>setUserForm({...userForm,display_name:e.target.value})}/>
      <label className="checkbox"><input type="checkbox" checked={!!userForm.is_active} onChange={e=>setUserForm({...userForm,is_active:e.target.checked})}/> Activo</label>
      <button type="submit" className="primary"><Plus size={16}/> Crear usuario</button>
    </form> : <div className="status-box warning">Solo el rol admin puede crear, editar o eliminar usuarios.</div>}
    <div className="search"><Search size={16}/><input placeholder="Buscar usuario" value={query} onChange={e=>setQuery(e.target.value)}/></div>
    <div className="list compact">{filtered.map(u=>{ const draft = editing[u.id] || u; return <div key={u.id} className="list-row user-row">
      <div className="row-head"><span>{u.is_active ? '🟢' : '⚪'} {u.username}</span><small className={`role-pill role-${u.role}`}>{u.role}</small></div>
      <small>{u.display_name || 'Sin nombre visible'} · Creado: {u.created_at || '-'}</small>
      {isAdmin ? <div className="user-edit-grid">
        <input value={draft.display_name || ''} placeholder="Nombre visible" onChange={e=>setEditing({...editing,[u.id]:{...draft,display_name:e.target.value}})}/>
        <select value={draft.role} onChange={e=>setEditing({...editing,[u.id]:{...draft,role:e.target.value}})}>{USER_ROLES.map(r=><option key={r}>{r}</option>)}</select>
        <input placeholder="Nueva contraseña opcional" type="password" value={draft.password || ''} onChange={e=>setEditing({...editing,[u.id]:{...draft,password:e.target.value}})}/>
        <label className="checkbox"><input type="checkbox" checked={!!draft.is_active} onChange={e=>setEditing({...editing,[u.id]:{...draft,is_active:e.target.checked}})}/> Activo</label>
        <button onClick={()=>{const patch={display_name:draft.display_name,role:draft.role,is_active:draft.is_active}; if(draft.password) patch.password=draft.password; updateUser(u.id, patch);}}>Guardar</button>
        <button className="danger" onClick={()=>deleteUser(u.id)} disabled={u.username===currentUser.username}>Eliminar</button>
      </div> : null}
    </div>})}</div>
  </section>
}

function AuditPanel({ audit, users }) { return <section className="panel-section"><h3>Usuarios y roles</h3><div className="metadata">{users.map(u=><div key={u.id}>• {u.username} · {u.role}</div>)}</div><h3>Historial de cambios</h3><div className="list compact">{audit.map(a=><div key={a.id} className="list-row"><span>{a.action} · {a.entity_type}</span><small>{a.message}<br/>Usuario: {a.username} · Rol: {a.user_role}<br/>{a.created_at}</small></div>)}</div></section> }
function ContextMenu({ menu, setMenu, canEdit, setSelected, updateDevicePatch, deleteDevice, runImpact, setLinkForm, setActiveTab, state, selectedIds, bulkRelate }) {
  if (!menu) return null;
  const device = state.devices.find(d=>d.id===menu.id);
  const selectionCount = (selectedIds || []).filter(id => id !== menu.id).length;
  return <div className="context-menu" style={{left:menu.x,top:menu.y}} onClick={(e)=>e.stopPropagation()}>
    <button onClick={()=>{setSelected({type:menu.type,id:menu.id});setMenu(null)}}>Editar / ver propiedades</button>
    {menu.type==='device' && <button onClick={()=>{runImpact(menu.id);setMenu(null)}}>Ver impacto</button>}
    {canEdit && menu.type==='device' && selectionCount > 0 && <button onClick={()=>{bulkRelate(menu.id);setMenu(null)}}>Usar como principal para selección ({selectionCount})</button>}
    {canEdit && menu.type==='device' && <button onClick={()=>{setLinkForm(f=>({...f,source_device_id:menu.id}));setActiveTab('relaciones');setMenu(null)}}>Crear relación desde aquí</button>}
    {canEdit && menu.type==='device' && <button onClick={()=>{updateDevicePatch(menu.id,{icon:'firewall'});setMenu(null)}}>Cambiar icono a firewall</button>}
    {canEdit && menu.type==='device' && <button onClick={()=>{updateDevicePatch(menu.id,{is_main:!device?.is_main});setMenu(null)}}>{device?.is_main?'Quitar principal':'Marcar principal'}</button>}
    {canEdit && menu.type==='device' && <button onClick={()=>{updateDevicePatch(menu.id,{is_perimeter:!device?.is_perimeter});setMenu(null)}}>{device?.is_perimeter?'Quitar perimetral':'Marcar perimetral'}</button>}
    {canEdit && menu.type==='device' && <button className="danger" onClick={()=>{deleteDevice(menu.id);setMenu(null)}}>Eliminar dispositivo</button>}
  </div>
}


function Root() { return <ReactFlowProvider><AppShell /></ReactFlowProvider>; }
createRoot(document.getElementById('root')).render(<Root />);
