# -*- coding: utf-8 -*-
"""
Prometheus / OpenMetrics exporter.

MK Apr 2026: One endpoint — /api/metrics — that lets any Prometheus/Grafana stack
scrape PegaProx with zero custom instrumentation. We expose a curated set of gauges
that match what admins typically want to alert on (node down, high CPU, quorum
at risk, etc). Everything is derived from existing in-memory state, no extra
polling against Proxmox.

Auth: Bearer token via existing API tokens (admin-view role is enough), or the
endpoint can be made public by setting `metrics_public: true` in server settings —
some setups put PegaProx behind a mutual-TLS reverse proxy and want to skip auth.
"""
import time
import logging
from flask import Blueprint, request, Response

from pegaprox.globals import (
    cluster_managers, pbs_managers, vmware_managers,
    active_sessions, sessions_lock,
)
from pegaprox.api.helpers import load_server_settings
from pegaprox.utils.auth import validate_api_token


bp = Blueprint('metrics_exporter', __name__)


def _escape_label(s):
    """Prometheus labels can't contain raw quotes, backslashes, or newlines."""
    if s is None:
        return ''
    return str(s).replace('\\', '\\\\').replace('"', '\\"').replace('\n', ' ')


def _sample(name, value, labels=None, help_text=None, mtype=None):
    """Build one or two lines of Prometheus exposition format."""
    lines = []
    # The HELP/TYPE lines appear once per metric name — caller should emit those
    # before the first sample. Kept out of here so repeated _sample() calls don't
    # duplicate metadata.
    if labels:
        lbl = ','.join(f'{k}="{_escape_label(v)}"' for k, v in labels.items())
        lines.append(f'{name}{{{lbl}}} {value}')
    else:
        lines.append(f'{name} {value}')
    return lines


def _auth_ok():
    """Allow scrape if: (a) bearer token is valid API token, or (b) metrics_public=true."""
    settings = load_server_settings()
    if settings.get('metrics_public', False):
        return True
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        token = auth[7:].strip()
        try:
            info = validate_api_token(token)
            if info:
                return True
        except Exception as e:
            logging.debug(f"[metrics] token validate failed: {e}")
    return False


@bp.route('/api/metrics', methods=['GET'])
def prometheus_metrics():
    if not _auth_ok():
        return Response(
            '# unauthorized — set Authorization: Bearer <api_token>, or enable metrics_public\n',
            status=401, mimetype='text/plain; version=0.0.4'
        )

    out = []
    emit = out.append

    # ── PegaProx self metrics ──
    emit('# HELP pegaprox_info Build information')
    emit('# TYPE pegaprox_info gauge')
    try:
        from pegaprox.constants import PEGAPROX_VERSION, PEGAPROX_BUILD
        out.extend(_sample('pegaprox_info', 1, {'version': PEGAPROX_VERSION, 'build': PEGAPROX_BUILD}))
    except Exception:
        pass

    emit('# HELP pegaprox_scrape_timestamp_seconds Unix time of this scrape')
    emit('# TYPE pegaprox_scrape_timestamp_seconds gauge')
    out.extend(_sample('pegaprox_scrape_timestamp_seconds', f'{time.time():.0f}'))

    # ── Session + auth state ──
    with sessions_lock:
        sess_total = len(active_sessions)
        sess_by_user = {}
        for s in active_sessions.values():
            u = s.get('user', '?')
            sess_by_user[u] = sess_by_user.get(u, 0) + 1
    emit('# HELP pegaprox_sessions_active Currently authenticated sessions')
    emit('# TYPE pegaprox_sessions_active gauge')
    out.extend(_sample('pegaprox_sessions_active', sess_total))

    # ── Clusters ──
    emit('# HELP pegaprox_cluster_connected 1 if PegaProx can reach the cluster API')
    emit('# TYPE pegaprox_cluster_connected gauge')
    emit('# HELP pegaprox_cluster_nodes_total Node count per cluster')
    emit('# TYPE pegaprox_cluster_nodes_total gauge')
    emit('# HELP pegaprox_cluster_nodes_online Online node count')
    emit('# TYPE pegaprox_cluster_nodes_online gauge')
    emit('# HELP pegaprox_cluster_vms_total VMs/CTs per cluster')
    emit('# TYPE pegaprox_cluster_vms_total gauge')
    emit('# HELP pegaprox_cluster_vms_running Running VMs/CTs per cluster')
    emit('# TYPE pegaprox_cluster_vms_running gauge')
    emit('# HELP pegaprox_cluster_quorum_held 1 if quorum is currently held')
    emit('# TYPE pegaprox_cluster_quorum_held gauge')

    emit('# HELP pegaprox_node_cpu_percent CPU usage percent per node')
    emit('# TYPE pegaprox_node_cpu_percent gauge')
    emit('# HELP pegaprox_node_mem_percent Memory usage percent per node')
    emit('# TYPE pegaprox_node_mem_percent gauge')
    emit('# HELP pegaprox_node_uptime_seconds Node uptime in seconds')
    emit('# TYPE pegaprox_node_uptime_seconds gauge')
    emit('# HELP pegaprox_node_online 1 if the node is online')
    emit('# TYPE pegaprox_node_online gauge')

    for cid, mgr in cluster_managers.items():
        cname = getattr(getattr(mgr, 'config', None), 'name', cid) or cid
        base = {'cluster_id': cid, 'cluster': cname}
        connected = 1 if getattr(mgr, 'is_connected', False) else 0
        out.extend(_sample('pegaprox_cluster_connected', connected, base))
        if not connected:
            continue

        # Node counts + per-node stats
        try:
            node_status = mgr.get_node_status() or {}
            nodes_total = len(node_status)
            nodes_online = 0
            for name, info in node_status.items():
                is_online = (info.get('status') == 'online') or (not info.get('offline', False))
                if is_online:
                    nodes_online += 1
                nlabels = {**base, 'node': name}
                out.extend(_sample('pegaprox_node_online', 1 if is_online else 0, nlabels))
                out.extend(_sample('pegaprox_node_cpu_percent',
                                   round(info.get('cpu_percent', info.get('cpu', 0) * 100 if info.get('cpu') else 0), 2),
                                   nlabels))
                out.extend(_sample('pegaprox_node_mem_percent',
                                   round(info.get('mem_percent', 0), 2), nlabels))
                out.extend(_sample('pegaprox_node_uptime_seconds',
                                   info.get('uptime', 0), nlabels))
            out.extend(_sample('pegaprox_cluster_nodes_total', nodes_total, base))
            out.extend(_sample('pegaprox_cluster_nodes_online', nodes_online, base))
            # Quorum: >50% online
            quorum = 1 if nodes_online * 2 > nodes_total else 0
            out.extend(_sample('pegaprox_cluster_quorum_held', quorum, base))
        except Exception as e:
            logging.debug(f"[metrics] {cid} node stats failed: {e}")

        # VM counts
        try:
            vms = []
            if hasattr(mgr, 'get_vm_resources'):
                vms = mgr.get_vm_resources() or []
            elif hasattr(mgr, 'get_resources'):
                vms = [r for r in (mgr.get_resources() or []) if r.get('type') in ('qemu', 'lxc')]
            out.extend(_sample('pegaprox_cluster_vms_total', len(vms), base))
            running = sum(1 for v in vms if v.get('status') == 'running')
            out.extend(_sample('pegaprox_cluster_vms_running', running, base))
        except Exception as e:
            logging.debug(f"[metrics] {cid} vm list failed: {e}")

    # ── PBS backup servers ──
    if pbs_managers:
        emit('# HELP pegaprox_pbs_connected 1 if PBS is reachable')
        emit('# TYPE pegaprox_pbs_connected gauge')
        for pid, pmgr in pbs_managers.items():
            labels = {'pbs_id': pid, 'pbs': getattr(pmgr, 'name', '') or pid}
            out.extend(_sample('pegaprox_pbs_connected',
                               1 if getattr(pmgr, 'connected', False) else 0, labels))

    # ── VMware/ESXi ──
    if vmware_managers:
        emit('# HELP pegaprox_esxi_connected 1 if ESXi/vCenter is reachable')
        emit('# TYPE pegaprox_esxi_connected gauge')
        for vid, vmgr in vmware_managers.items():
            labels = {'esxi_id': vid, 'host': getattr(vmgr, 'host', '') or vid}
            out.extend(_sample('pegaprox_esxi_connected',
                               1 if getattr(vmgr, 'connected', False) else 0, labels))

    body = '\n'.join(out) + '\n'
    return Response(body, mimetype='text/plain; version=0.0.4; charset=utf-8')
