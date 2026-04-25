# -*- coding: utf-8 -*-
"""PBS (proxmox backup server) routes - split from monolith dec 2025, NS"""

import logging
import uuid
from flask import Blueprint, jsonify, request

from pegaprox.constants import *
from pegaprox.globals import *
from pegaprox.models.permissions import *
from pegaprox.core.db import get_db

from pegaprox.utils.auth import require_auth
from pegaprox.utils.audit import log_audit
from pegaprox.api.helpers import safe_error
from pegaprox.core.pbs import PBSManager, load_pbs_servers, save_pbs_server

bp = Blueprint('pbs', __name__)

@bp.route('/api/pbs', methods=['GET'])
@require_auth(perms=['pbs.view'])
def list_pbs_servers():
    """List all configured PBS servers"""
    result = []
    for pbs_id, mgr in pbs_managers.items():
        info = mgr.to_dict()
        # Include quick status if connected
        if mgr.connected and mgr.last_status:
            info['status'] = {
                'cpu': mgr.last_status.get('cpu', 0),
                'memory': mgr.last_status.get('memory', {}),
                'uptime': mgr.last_status.get('uptime', 0),
            }
        result.append(info)

    # Also include disabled servers from DB
    try:
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute("SELECT id, name, host, port, enabled, linked_clusters FROM pbs_servers")
        for row in cursor.fetchall():
            row_dict = dict(row)
            if row_dict['id'] not in pbs_managers:
                # NS: parse linked_clusters so frontend can filter by cluster
                linked = []
                try:
                    import json
                    linked = json.loads(row_dict.get('linked_clusters', '[]') or '[]')
                except Exception:
                    pass
                result.append({
                    'id': row_dict['id'],
                    'name': row_dict['name'],
                    'host': row_dict['host'],
                    'port': row_dict['port'],
                    'enabled': bool(row_dict['enabled']),
                    'connected': False,
                    'linked_clusters': linked,
                })
    except Exception:
        pass

    return jsonify(result)


@bp.route('/api/pbs', methods=['POST'])
@require_auth(perms=['pbs.config'])
def add_pbs_server():
    """Add a new PBS server"""
    data = request.json or {}
    
    if not data.get('name') or not data.get('host'):
        return jsonify({'error': 'Name and host are required'}), 400
    
    if not data.get('user'):
        return jsonify({'error': 'Username or API token is required'}), 400
    
    pbs_id = str(uuid.uuid4())[:8]
    
    # Test connection first
    mgr = PBSManager(pbs_id, data)
    if not mgr.connect():
        return jsonify({'error': f'Connection failed: {mgr.last_error}'}), 400
    
    # Save to DB
    save_pbs_server(pbs_id, data)
    pbs_managers[pbs_id] = mgr
    
    log_audit(request.session.get('user', 'admin'), 'pbs.added', 
              f"Added PBS server: {data['name']} ({data['host']})")
    
    return jsonify({'id': pbs_id, 'message': 'PBS server added successfully', **mgr.to_dict()}), 201


@bp.route('/api/pbs/<pbs_id>', methods=['PUT'])
@require_auth(perms=['pbs.config'])
def update_pbs_server(pbs_id):
    """Update a PBS server config"""
    data = request.json or {}
    
    if pbs_id not in pbs_managers:
        # Try loading from DB
        db = get_db()
        row = db.conn.cursor().execute("SELECT * FROM pbs_servers WHERE id = ?", (pbs_id,)).fetchone()
        if not row:
            return jsonify({'error': 'PBS server not found'}), 404
    
    save_pbs_server(pbs_id, data)
    
    # Recreate manager with new config
    if pbs_id in pbs_managers:
        old_mgr = pbs_managers[pbs_id]
        # Preserve credentials if masked
        if data.get('password') == '********':
            data['password'] = old_mgr.password
        if data.get('api_token_secret') == '********':
            data['api_token_secret'] = old_mgr.api_token_secret
        if data.get('ssh_key') == '********':
            data['ssh_key'] = getattr(old_mgr, 'ssh_key', '')
    
    mgr = PBSManager(pbs_id, data)
    if data.get('enabled', True):
        mgr.connect()
    pbs_managers[pbs_id] = mgr
    
    log_audit(request.session.get('user', 'admin'), 'pbs.updated', f"Updated PBS server: {data.get('name', pbs_id)}")
    
    return jsonify(mgr.to_dict())


@bp.route('/api/pbs/<pbs_id>', methods=['DELETE'])
@require_auth(perms=['pbs.config'])
def delete_pbs_server(pbs_id):
    """Delete a PBS server"""
    if pbs_id in pbs_managers:
        name = pbs_managers[pbs_id].name
        del pbs_managers[pbs_id]
    else:
        name = pbs_id
    
    db = get_db()
    db.conn.cursor().execute("DELETE FROM pbs_servers WHERE id = ?", (pbs_id,))
    db.conn.commit()
    
    log_audit(request.session.get('user', 'admin'), 'pbs.deleted', f"Deleted PBS server: {name}")
    
    return jsonify({'message': f'PBS server {name} deleted'})


@bp.route('/api/pbs/test-connection', methods=['POST'])
@require_auth(perms=['pbs.config'])
def test_pbs_new_connection():
    """Test PBS connection with provided credentials (before save)"""
    data = request.json or {}
    if not data.get('host'):
        return jsonify({'error': 'Host is required'}), 400
    test_mgr = PBSManager('test', data)
    success = test_mgr.connect()
    if success:
        version = test_mgr.get_version()
        datastores = test_mgr.get_datastore_usage()
        return jsonify({
            'success': True,
            'version': version.get('data', {}),
            'datastores': len(datastores.get('data', [])),
        })
    return jsonify({'success': False, 'error': test_mgr.last_error}), 400


@bp.route('/api/pbs/<pbs_id>/test', methods=['POST'])
@require_auth(perms=['pbs.config'])
def test_pbs_connection(pbs_id):
    """Test PBS connection (or test with provided credentials)"""
    data = request.json or {}
    
    if data.get('host'):
        # Test with provided credentials (before save)
        test_mgr = PBSManager('test', data)
        success = test_mgr.connect()
        if success:
            version = test_mgr.get_version()
            datastores = test_mgr.get_datastore_usage()
            return jsonify({
                'success': True,
                'version': version.get('data', {}),
                'datastores': len(datastores.get('data', [])),
            })
        return jsonify({'success': False, 'error': test_mgr.last_error}), 400
    
    # Test existing connection
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    
    mgr = pbs_managers[pbs_id]
    success = mgr.connect()
    if success:
        version = mgr.get_version()
        return jsonify({'success': True, 'version': version.get('data', {})})
    return jsonify({'success': False, 'error': mgr.last_error}), 400


@bp.route('/api/pbs/<pbs_id>/status', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_status(pbs_id):
    """Get PBS server status (CPU, RAM, disk, uptime)"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    if not mgr.connected:
        return jsonify({'error': 'Not connected', 'connected': False}), 503
    
    status = mgr.get_server_status()
    version = mgr.get_version()
    datastores = mgr.get_datastore_usage()

    # NS: Mar 2026 - propagate errors so frontend can show what went wrong (#107)
    errors = []
    if 'error' in status:
        errors.append(f"Status: {status['error']}")
        logging.warning(f"[PBS:{mgr.name}] get_server_status failed: {status['error']}")
    if 'error' in datastores:
        errors.append(f"Datastores: {datastores['error']}")
        logging.warning(f"[PBS:{mgr.name}] get_datastore_usage failed: {datastores['error']}")

    return jsonify({
        'server': status.get('data', {}),
        'version': version.get('data', {}),
        'datastores': datastores.get('data', []),
        'connected': mgr.connected,
        'name': mgr.name,
        'errors': errors if errors else None,
    })


@bp.route('/api/pbs/<pbs_id>/apt/updates', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_apt_updates(pbs_id):
    """List available APT updates on PBS server"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    if not mgr.connected:
        return jsonify({'error': 'Not connected'}), 503
    result = mgr.get_apt_updates()
    if 'error' in result:
        return jsonify({'error': result['error']}), 500
    return jsonify({'updates': result.get('data', []), 'count': len(result.get('data', []))})


@bp.route('/api/pbs/<pbs_id>/apt/refresh', methods=['POST'])
@require_auth(perms=['pbs.view'])
def refresh_pbs_apt(pbs_id):
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    if not mgr.connected:
        return jsonify({'error': 'Not connected'}), 503
    result = mgr.refresh_apt()
    if 'error' in result:
        return jsonify({'error': result['error']}), 500
    return jsonify({'success': True, 'data': result.get('data')})


# NS Apr 2026: actually execute apt dist-upgrade via SSH. PBS API has no upgrade endpoint.
@bp.route('/api/pbs/<pbs_id>/update', methods=['POST'])
@require_auth(perms=['admin.settings'])
def start_pbs_update(pbs_id):
    """Start apt-get dist-upgrade on PBS host via SSH"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.get_json(silent=True) or {}
    reboot = bool(data.get('reboot', False))

    existing = mgr.get_update_status()
    if existing and existing.status in ('starting', 'updating', 'rebooting', 'waiting_online'):
        return jsonify({'error': 'Update already in progress', 'status': existing.status}), 409

    task = mgr.start_update(reboot=reboot)
    if not task:
        return jsonify({'error': 'Could not start update'}), 500
    log_audit(request.session.get('user', 'admin'), 'pbs.update_started',
              f"Started apt upgrade on PBS {mgr.name}" + (' (with reboot)' if reboot else ''))
    return jsonify({'success': True, 'status': task.status, 'phase': task.phase})


@bp.route('/api/pbs/<pbs_id>/update', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_update_status(pbs_id):
    """Get current PBS update status"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    task = mgr.get_update_status()
    if not task:
        return jsonify({'is_updating': False})
    return jsonify({
        'is_updating': task.status in ('starting', 'updating', 'rebooting', 'waiting_online'),
        'status': task.status,
        'phase': task.phase,
        'error': task.error,
        'output_lines': task.output_lines[-50:] if hasattr(task, 'output_lines') else [],
        'packages_upgraded': getattr(task, 'packages_upgraded', 0),
        'reboot': getattr(task, 'reboot', False),
        'started_at': task.started_at.isoformat() if getattr(task, 'started_at', None) else None,
        'completed_at': task.completed_at.isoformat() if getattr(task, 'completed_at', None) else None,
    })


@bp.route('/api/pbs/<pbs_id>/update', methods=['DELETE'])
@require_auth(perms=['admin.settings'])
def clear_pbs_update_status(pbs_id):
    """Clear completed/failed update status"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    ok = pbs_managers[pbs_id].clear_update_status()
    return jsonify({'cleared': ok})


@bp.route('/api/pbs/<pbs_id>/datastores', methods=['GET'])
@require_auth(perms=['pbs.datastore.view'])
def get_pbs_datastores(pbs_id):
    """List datastores with detailed status"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    if not mgr.connected:
        return jsonify({'error': 'Not connected'}), 503
    
    # Get list of datastores
    config_resp = mgr.get_datastores()
    usage_resp = mgr.get_datastore_usage()
    
    datastores = config_resp.get('data', [])
    usage_list = {u.get('store'): u for u in usage_resp.get('data', [])}
    
    # Merge config with usage
    result = []
    for ds in datastores:
        name = ds.get('name', '')
        info = {**ds, **(usage_list.get(name, {}))}
        
        # Try to get detailed status (GC info, counts)
        try:
            detail = mgr.get_datastore_status(name)
            if 'data' in detail:
                info['detail'] = detail['data']
        except Exception:
            pass
        
        result.append(info)
    
    return jsonify(result)


@bp.route('/api/pbs/<pbs_id>/datastores/<store>/snapshots', methods=['GET'])
@require_auth(perms=['pbs.datastore.view'])
def get_pbs_snapshots(pbs_id, store):
    """List snapshots in a datastore"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    ns = request.args.get('ns', None)
    backup_type = request.args.get('backup-type', None)
    backup_id = request.args.get('backup-id', None)
    result = mgr.get_snapshots(store, ns=ns, backup_type=backup_type, backup_id=backup_id)
    # #143: don't mask errors as empty arrays
    if 'error' in result:
        return jsonify({'error': result['error']}), result.get('status_code', 502)
    return jsonify(result.get('data', []))


@bp.route('/api/pbs/<pbs_id>/datastores/<store>/groups', methods=['GET'])
@require_auth(perms=['pbs.datastore.view'])
def get_pbs_groups(pbs_id, store):
    """List backup groups in a datastore"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    ns = request.args.get('ns', None)
    result = mgr.get_groups(store, ns=ns)
    if 'error' in result:
        return jsonify({'error': result['error']}), result.get('status_code', 502)
    return jsonify(result.get('data', []))


@bp.route('/api/pbs/<pbs_id>/datastores/<store>/gc', methods=['POST'])
@require_auth(perms=['pbs.datastore.gc'])
def pbs_start_gc(pbs_id, store):
    """Start garbage collection"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    result = mgr.start_gc(store)
    if 'error' not in result:
        log_audit(request.session.get('user', 'admin'), 'pbs.gc', f"Started GC on {mgr.name}/{store}")
    return jsonify(result)


@bp.route('/api/pbs/<pbs_id>/datastores/<store>/verify', methods=['POST'])
@require_auth(perms=['pbs.datastore.verify'])
def pbs_start_verify(pbs_id, store):
    """Start verification"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.json or {}
    result = mgr.start_verify(store, ignore_verified=data.get('ignore_verified', True))
    if 'error' not in result:
        log_audit(request.session.get('user', 'admin'), 'pbs.verify', f"Started verify on {mgr.name}/{store}")
    return jsonify(result)


@bp.route('/api/pbs/<pbs_id>/datastores/<store>/prune', methods=['POST'])
@require_auth(perms=['pbs.datastore.prune'])
def pbs_prune(pbs_id, store):
    """Prune old backups"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.json or {}
    result = mgr.prune_datastore(
        store, ns=data.get('ns'),
        keep_last=data.get('keep_last'), keep_daily=data.get('keep_daily'),
        keep_weekly=data.get('keep_weekly'), keep_monthly=data.get('keep_monthly'),
        keep_yearly=data.get('keep_yearly'),
        backup_type=data.get('backup_type'), backup_id=data.get('backup_id'),
        dry_run=data.get('dry_run', True),
    )
    action = "dry-run prune" if data.get('dry_run', True) else "PRUNE"
    if 'error' not in result:
        log_audit(request.session.get('user', 'admin'), 'pbs.prune', f"{action} on {mgr.name}/{store}")
    return jsonify(result)


@bp.route('/api/pbs/<pbs_id>/datastores/<store>/snapshots', methods=['DELETE'])
@require_auth(perms=['pbs.snapshot.delete'])
def pbs_delete_snapshot(pbs_id, store):
    """Delete a specific snapshot"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.json or {}
    
    required = ['backup_type', 'backup_id', 'backup_time']
    for field in required:
        if field not in data:
            return jsonify({'error': f'Missing: {field}'}), 400
    
    result = mgr.delete_snapshot(store, data['backup_type'], data['backup_id'], 
                                  data['backup_time'], ns=data.get('ns'))
    if 'error' not in result:
        log_audit(request.session.get('user', 'admin'), 'pbs.snapshot.delete',
                  f"Deleted {data['backup_type']}/{data['backup_id']} @ {data['backup_time']} from {mgr.name}/{store}")
    return jsonify(result)


@bp.route('/api/pbs/<pbs_id>/tasks', methods=['GET'])
@require_auth(perms=['pbs.tasks.view'])
def get_pbs_tasks(pbs_id):
    """List PBS tasks"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    limit = int(request.args.get('limit', 50))
    typefilter = request.args.get('typefilter', None)
    running = request.args.get('running', None)
    result = mgr.get_tasks(limit=limit, typefilter=typefilter,
                            running=bool(int(running)) if running is not None else None)
    return jsonify(result.get('data', []))


@bp.route('/api/pbs/<pbs_id>/tasks/<path:upid>', methods=['GET'])
@require_auth(perms=['pbs.tasks.view'])
def get_pbs_task_detail(pbs_id, upid):
    """Get task status and log"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    status = mgr.get_task_status(upid)
    log = mgr.get_task_log(upid)
    return jsonify({
        'status': status.get('data', {}),
        'log': log.get('data', []),
    })


@bp.route('/api/pbs/<pbs_id>/jobs', methods=['GET'])
@require_auth(perms=['pbs.jobs.view'])
def get_pbs_jobs(pbs_id):
    """List all PBS jobs (sync, verify, prune)"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    
    sync = mgr.get_sync_jobs()
    verify = mgr.get_verify_jobs()
    prune = mgr.get_prune_jobs()
    
    return jsonify({
        'sync': sync.get('data', []),
        'verify': verify.get('data', []),
        'prune': prune.get('data', []),
    })


@bp.route('/api/pbs/<pbs_id>/jobs/<job_type>/<job_id>/run', methods=['POST'])
@require_auth(perms=['pbs.jobs.run'])
def run_pbs_job(pbs_id, job_type, job_id):
    """Manually trigger a PBS job"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    
    if job_type == 'sync':
        result = mgr.run_sync_job(job_id)
    elif job_type == 'verify':
        result = mgr.run_verify_job(job_id)
    elif job_type == 'prune':
        result = mgr.run_prune_job(job_id)
    else:
        return jsonify({'error': f'Unknown job type: {job_type}'}), 400
    
    if 'error' not in result:
        log_audit(request.session.get('user', 'admin'), f'pbs.job.{job_type}', 
                  f"Started {job_type} job '{job_id}' on {mgr.name}")
    return jsonify(result)


@bp.route('/api/pbs/<pbs_id>/datastores/<store>/namespaces', methods=['GET'])
@require_auth(perms=['pbs.datastore.view'])
def get_pbs_namespaces(pbs_id, store):
    """List namespaces in a datastore"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    result = mgr.get_namespaces(store)
    return jsonify(result.get('data', []))


@bp.route('/api/pbs/<pbs_id>/disks', methods=['GET'])
@require_auth(perms=['pbs.disks.view'])
def get_pbs_disks(pbs_id):
    """List disks on PBS server"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    result = mgr.get_disks()
    return jsonify(result.get('data', []))


@bp.route('/api/pbs/<pbs_id>/remotes', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_remotes(pbs_id):
    """List configured remotes"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    result = mgr.get_remotes()
    return jsonify(result.get('data', []))


@bp.route('/api/pbs/<pbs_id>/subscription', methods=['GET'])
@require_auth(perms=['pbs.subscription.view'])
def get_pbs_subscription(pbs_id):
    """Get PBS subscription status"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    result = mgr.get_subscription()
    return jsonify(result.get('data', {}))


@bp.route('/api/pbs/<pbs_id>/datastores/<store>/rrd', methods=['GET'])
@require_auth(perms=['pbs.datastore.view'])
def get_pbs_datastore_rrd(pbs_id, store):
    """Get RRD performance data for a datastore"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    timeframe = request.args.get('timeframe', 'hour')  # hour, day, week, month, year
    cf = request.args.get('cf', 'AVERAGE')  # AVERAGE, MAX
    result = mgr.get_datastore_rrd(store, timeframe=timeframe, cf=cf)
    return jsonify(result.get('data', []))


# ── PBS Snapshot & Group Notes ──

@bp.route('/api/pbs/<pbs_id>/datastores/<store>/notes', methods=['GET'])
@require_auth(perms=['pbs.datastore.view'])
def get_pbs_snapshot_notes(pbs_id, store):
    """Get notes for a specific snapshot"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    bt = request.args.get('backup-type')
    bid = request.args.get('backup-id')
    btime = request.args.get('backup-time')
    if not all([bt, bid, btime]):
        return jsonify({'error': 'Missing backup-type, backup-id, or backup-time'}), 400
    result = mgr.get_snapshot_notes(store, bt, bid, int(btime))
    if 'error' in result:
        return jsonify(result), 500
    return jsonify({'notes': result.get('data', '')})

@bp.route('/api/pbs/<pbs_id>/datastores/<store>/notes', methods=['PUT'])
@require_auth(perms=['pbs.snapshot.notes'])
def set_pbs_snapshot_notes(pbs_id, store):
    """Set notes for a specific snapshot"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.get_json() or {}
    bt = data.get('backup-type')
    bid = data.get('backup-id')
    btime = data.get('backup-time')
    notes = data.get('notes', '')
    if not all([bt, bid, btime is not None]):
        return jsonify({'error': 'Missing backup-type, backup-id, or backup-time'}), 400
    result = mgr.set_snapshot_notes(store, bt, bid, int(btime), notes)
    if 'error' in result:
        return jsonify(result), 500
    return jsonify({'success': True})

@bp.route('/api/pbs/<pbs_id>/datastores/<store>/group-notes', methods=['GET'])
@require_auth(perms=['pbs.datastore.view'])
def get_pbs_group_notes(pbs_id, store):
    """Get notes for a backup group"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    bt = request.args.get('backup-type')
    bid = request.args.get('backup-id')
    if not all([bt, bid]):
        return jsonify({'error': 'Missing backup-type or backup-id'}), 400
    result = mgr.get_group_notes(store, bt, bid)
    if 'error' in result:
        return jsonify(result), 500
    return jsonify({'notes': result.get('data', '')})

@bp.route('/api/pbs/<pbs_id>/datastores/<store>/group-notes', methods=['PUT'])
@require_auth(perms=['pbs.snapshot.notes'])
def set_pbs_group_notes(pbs_id, store):
    """Set notes for a backup group"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.get_json() or {}
    bt = data.get('backup-type')
    bid = data.get('backup-id')
    notes = data.get('notes', '')
    if not all([bt, bid]):
        return jsonify({'error': 'Missing backup-type or backup-id'}), 400
    result = mgr.set_group_notes(store, bt, bid, notes)
    if 'error' in result:
        return jsonify(result), 500
    return jsonify({'success': True})

# ── PBS Snapshot Protection ──

@bp.route('/api/pbs/<pbs_id>/datastores/<store>/protected', methods=['PUT'])
@require_auth(perms=['pbs.snapshot.protect'])
def set_pbs_snapshot_protected(pbs_id, store):
    """Set protected flag on a snapshot"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.get_json() or {}
    bt = data.get('backup-type')
    bid = data.get('backup-id')
    btime = data.get('backup-time')
    protected = data.get('protected', True)
    if not all([bt, bid, btime is not None]):
        return jsonify({'error': 'Missing backup-type, backup-id, or backup-time'}), 400
    result = mgr.set_snapshot_protected(store, bt, bid, int(btime), protected)
    if 'error' in result:
        return jsonify(result), 500
    return jsonify({'success': True})

# ── PBS Traffic Control ──

@bp.route('/api/pbs/<pbs_id>/traffic-control', methods=['GET'])
@require_auth(perms=['pbs.traffic.view'])
def get_pbs_traffic_control(pbs_id):
    """Get traffic control / bandwidth limit configuration"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    result = mgr.get_traffic_control()
    return jsonify(result.get('data', []))

# ── PBS Syslog ──

@bp.route('/api/pbs/<pbs_id>/syslog', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_syslog(pbs_id):
    """Get PBS server syslog entries"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    limit = request.args.get('limit', 100, type=int)
    since = request.args.get('since')
    result = mgr.get_syslog(limit=limit, since=since)
    return jsonify(result.get('data', []))

# ── PBS Node RRD ──

@bp.route('/api/pbs/<pbs_id>/rrd', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_node_rrd(pbs_id):
    """Get PBS node-level RRD performance data"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    timeframe = request.args.get('timeframe', 'hour')
    cf = request.args.get('cf', 'AVERAGE')
    result = mgr.get_node_rrd(timeframe=timeframe, cf=cf)
    return jsonify(result.get('data', []))

# ── PBS Notifications ──

@bp.route('/api/pbs/<pbs_id>/notifications', methods=['GET'])
@require_auth(perms=['pbs.notifications.view'])
def get_pbs_notifications(pbs_id):
    """Get PBS notification config (targets + matchers)"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    # Try to get both targets and matchers
    targets_result = mgr.get_notification_targets()
    matchers_result = mgr.get_notification_matchers()
    # Notification endpoints may differ between PBS versions, handle gracefully
    targets = targets_result.get('data', []) if isinstance(targets_result, dict) and 'error' not in targets_result else []
    matchers = matchers_result.get('data', []) if isinstance(matchers_result, dict) and 'error' not in matchers_result else []
    return jsonify({'targets': targets, 'matchers': matchers})

# ── PBS Catalog / File-Level Restore ──

@bp.route('/api/pbs/<pbs_id>/datastores/<store>/catalog', methods=['GET'])
@require_auth(perms=['pbs.snapshot.browse'])
def browse_pbs_catalog(pbs_id, store):
    """Browse file catalog of a backup snapshot"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    bt = request.args.get('backup-type')
    bid = request.args.get('backup-id')
    btime = request.args.get('backup-time')
    filepath = request.args.get('filepath', '/')
    if not all([bt, bid, btime]):
        return jsonify({'error': 'Missing backup-type, backup-id, or backup-time'}), 400
    result = mgr.browse_catalog(store, bt, bid, int(btime), filepath)
    if 'error' in result:
        return jsonify(result), 500
    return jsonify(result.get('data', []))

@bp.route('/api/pbs/<pbs_id>/datastores/<store>/file-download', methods=['GET'])
@require_auth(perms=['pbs.snapshot.browse'])
def download_pbs_file(pbs_id, store):
    """Download a file from a backup snapshot (file-level restore)"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    bt = request.args.get('backup-type')
    bid = request.args.get('backup-id')
    btime = request.args.get('backup-time')
    filepath = request.args.get('filepath')
    if not all([bt, bid, btime, filepath]):
        return jsonify({'error': 'Missing parameters'}), 400
    try:
        resp = mgr.download_file_from_snapshot(store, bt, bid, int(btime), filepath)
        if resp is None or resp.status_code != 200:
            status = resp.status_code if resp else 502
            return jsonify({'error': f'Download failed: HTTP {status}'}), status
        # Extract filename from filepath + sanitize for Content-Disposition header injection
        import re as _re
        filename = filepath.rstrip('/').split('/')[-1] or 'download'
        filename = _re.sub(r'["\r\n\x00-\x1f]', '', filename)  # NS Feb 2026 - strip control chars
        content_type = resp.headers.get('content-type', 'application/octet-stream')
        from flask import Response
        return Response(
            resp.content,
            mimetype=content_type,
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Content-Length': str(len(resp.content))
            }
        )
    except Exception as e:
        logging.error(f"[PBS:{pbs_id}] File download error: {e}")
        return jsonify({'error': safe_error(e, 'PBS operation failed')}), 500


# ── PBS Datastore CRUD ── NS: Feb 2026 ──

@bp.route('/api/pbs/<pbs_id>/datastores/<store>/config', methods=['GET'])
@require_auth(perms=['pbs.datastore.view'])
def get_pbs_datastore_config(pbs_id, store):
    """Get datastore configuration (retention, GC schedule, notifications, etc.)"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    result = mgr.get_datastore_config(store)
    if 'error' in result:
        return jsonify(result), result.get('status_code', 500)
    return jsonify(result.get('data', result))


@bp.route('/api/pbs/<pbs_id>/datastores', methods=['POST'])
@require_auth(perms=['pbs.datastore.create'])
def create_pbs_datastore(pbs_id):
    """Create a new datastore on a PBS server
    
    NS: This creates the datastore config on the PBS. The path must already exist 
    on the PBS filesystem - we can't create directories remotely.
    """
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.json or {}
    
    name = data.get('name', '').strip()
    path = data.get('path', '').strip()
    
    if not name:
        return jsonify({'error': 'Datastore name is required'}), 400
    if not path:
        return jsonify({'error': 'Path is required'}), 400
    
    # Validate name format (PBS only allows alphanumeric + dash + underscore)
    import re as _re
    if not _re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-_]*$', name):
        return jsonify({'error': 'Datastore name must start with a letter/number and contain only alphanumeric, dash, or underscore'}), 400
    
    # Build kwargs for PBSManager method
    kwargs = {}
    if data.get('comment'):
        kwargs['comment'] = data['comment']
    if data.get('gc_schedule') is not None:
        kwargs['gc_schedule'] = data['gc_schedule']
    for retention_key in ['keep_last', 'keep_daily', 'keep_weekly', 'keep_monthly', 'keep_yearly']:
        if data.get(retention_key) is not None:
            try:
                kwargs[retention_key] = int(data[retention_key])
            except (ValueError, TypeError):
                pass
    if data.get('verify_new') is not None:
        kwargs['verify_new'] = bool(data['verify_new'])
    if data.get('notify') is not None:
        kwargs['notify'] = data['notify']
    if data.get('notify_user') is not None:
        kwargs['notify_user'] = data['notify_user']
    
    result = mgr.create_datastore(name=name, path=path, **kwargs)
    
    if 'error' in result:
        return jsonify(result), 400
    
    log_audit(request.session.get('user', 'admin'), 'pbs.datastore.created',
              f"Created datastore '{name}' at '{path}' on PBS {mgr.name}")
    
    return jsonify({'message': f'Datastore {name} created successfully', 'data': result.get('data')}), 201


@bp.route('/api/pbs/<pbs_id>/datastores/<store>/config', methods=['PUT'])
@require_auth(perms=['pbs.datastore.modify'])
def update_pbs_datastore_config(pbs_id, store):
    """Update datastore configuration (retention, GC schedule, etc.)"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.json or {}
    
    kwargs = {}
    if 'comment' in data:
        kwargs['comment'] = data['comment']
    if 'gc_schedule' in data:
        kwargs['gc_schedule'] = data['gc_schedule']
    for retention_key in ['keep_last', 'keep_daily', 'keep_weekly', 'keep_monthly', 'keep_yearly']:
        if retention_key in data:
            try:
                kwargs[retention_key] = int(data[retention_key]) if data[retention_key] is not None else None
            except (ValueError, TypeError):
                pass
    if 'verify_new' in data:
        kwargs['verify_new'] = bool(data['verify_new'])
    if 'notify' in data:
        kwargs['notify'] = data['notify']
    if 'notify_user' in data:
        kwargs['notify_user'] = data['notify_user']
    if data.get('delete'):
        kwargs['delete'] = data['delete'] if isinstance(data['delete'], list) else [data['delete']]
    
    if not kwargs:
        return jsonify({'error': 'No changes provided'}), 400
    
    result = mgr.update_datastore(store=store, **kwargs)
    
    if 'error' in result:
        return jsonify(result), 400
    
    log_audit(request.session.get('user', 'admin'), 'pbs.datastore.updated',
              f"Updated datastore '{store}' config on PBS {mgr.name}: {list(kwargs.keys())}")
    
    return jsonify({'message': f'Datastore {store} updated successfully', 'data': result.get('data')})


@bp.route('/api/pbs/<pbs_id>/datastores/<store>', methods=['DELETE'])
@require_auth(perms=['pbs.datastore.delete'])
def delete_pbs_datastore(pbs_id, store):
    """Remove a datastore from PBS configuration
    
    NS: By default this only removes the config - actual backup data on disk stays.
    This is the safe default. To also destroy data, send keep_data=false (dangerous!).
    """
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.json or {}
    
    keep_data = data.get('keep_data', True)
    
    # Extra safety: require explicit confirmation for data destruction
    if not keep_data and not data.get('confirm_destroy'):
        return jsonify({
            'error': 'Data destruction requires explicit confirmation',
            'hint': 'Send confirm_destroy=true to permanently delete all backup data'
        }), 400
    
    result = mgr.delete_datastore(store=store, keep_data=keep_data)
    
    if 'error' in result:
        return jsonify(result), 400
    
    action = 'removed (data kept)' if keep_data else 'DESTROYED (data deleted!)'
    log_audit(request.session.get('user', 'admin'), 'pbs.datastore.deleted',
              f"Datastore '{store}' {action} on PBS {mgr.name}")
    
    return jsonify({'message': f'Datastore {store} {action}', 'data': result.get('data')})



# ── PBS Job CRUD ── NS: Feb 2026 ──

@bp.route('/api/pbs/<pbs_id>/jobs/<job_type>', methods=['POST'])
@require_auth(perms=['pbs.jobs.create'])
def create_pbs_job(pbs_id, job_type):
    """Create a new sync/verify/prune job"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.json or {}
    
    job_id = data.get('id', '').strip()
    store = data.get('store', '').strip()
    if not job_id or not store:
        return jsonify({'error': 'Job ID and store are required'}), 400
    
    if job_type == 'sync':
        if not data.get('remote') or not data.get('remote_store'):
            return jsonify({'error': 'Remote and remote_store are required for sync jobs'}), 400
        result = mgr.create_sync_job(job_id, store, data['remote'], data['remote_store'],
                                     schedule=data.get('schedule'), comment=data.get('comment'),
                                     remove_vanished=data.get('remove_vanished'),
                                     ns=data.get('ns'), max_depth=data.get('max_depth'))
    elif job_type == 'verify':
        result = mgr.create_verify_job(job_id, store, schedule=data.get('schedule'),
                                       ignore_verified=data.get('ignore_verified'),
                                       outdated_after=data.get('outdated_after'),
                                       comment=data.get('comment'), ns=data.get('ns'))
    elif job_type == 'prune':
        result = mgr.create_prune_job(job_id, store, schedule=data.get('schedule'),
                                      keep_last=data.get('keep_last'), keep_daily=data.get('keep_daily'),
                                      keep_weekly=data.get('keep_weekly'), keep_monthly=data.get('keep_monthly'),
                                      keep_yearly=data.get('keep_yearly'),
                                      comment=data.get('comment'), ns=data.get('ns'))
    else:
        return jsonify({'error': f'Unknown job type: {job_type}'}), 400
    
    if 'error' in result:
        return jsonify(result), 400
    log_audit(request.session.get('user', 'admin'), f'pbs.job.{job_type}.created',
              f"Created {job_type} job '{job_id}' on PBS {mgr.name}")
    return jsonify({'message': f'{job_type} job created', 'data': result.get('data')}), 201


@bp.route('/api/pbs/<pbs_id>/jobs/<job_type>/<job_id>', methods=['PUT'])
@require_auth(perms=['pbs.jobs.modify'])
def update_pbs_job(pbs_id, job_type, job_id):
    """Update a job configuration"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    data = request.json or {}
    
    if job_type == 'sync':
        result = mgr.update_sync_job(job_id, **data)
    elif job_type == 'verify':
        result = mgr.update_verify_job(job_id, **data)
    elif job_type == 'prune':
        result = mgr.update_prune_job(job_id, **data)
    else:
        return jsonify({'error': f'Unknown job type: {job_type}'}), 400
    
    if 'error' in result:
        return jsonify(result), 400
    log_audit(request.session.get('user', 'admin'), f'pbs.job.{job_type}.updated',
              f"Updated {job_type} job '{job_id}' on PBS {mgr.name}")
    return jsonify({'message': f'{job_type} job updated', 'data': result.get('data')})


@bp.route('/api/pbs/<pbs_id>/jobs/<job_type>/<job_id>', methods=['DELETE'])
@require_auth(perms=['pbs.jobs.delete'])
def delete_pbs_job(pbs_id, job_type, job_id):
    """Delete a job"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    
    if job_type == 'sync':
        result = mgr.delete_sync_job(job_id)
    elif job_type == 'verify':
        result = mgr.delete_verify_job(job_id)
    elif job_type == 'prune':
        result = mgr.delete_prune_job(job_id)
    else:
        return jsonify({'error': f'Unknown job type: {job_type}'}), 400
    
    if 'error' in result:
        return jsonify(result), 400
    log_audit(request.session.get('user', 'admin'), f'pbs.job.{job_type}.deleted',
              f"Deleted {job_type} job '{job_id}' on PBS {mgr.name}")
    return jsonify({'message': f'{job_type} job {job_id} deleted'})


# ── PBS Task Stop ──

@bp.route('/api/pbs/<pbs_id>/tasks/<path:upid>', methods=['DELETE'])
@require_auth(perms=['pbs.tasks.stop'])
def stop_pbs_task(pbs_id, upid):
    """Stop a running PBS task"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    result = mgr.stop_task(upid)
    if 'error' in result:
        return jsonify(result), 400
    log_audit(request.session.get('user', 'admin'), 'pbs.task.stopped',
              f"Stopped task on PBS {mgr.name}: {upid[-20:]}")
    return jsonify({'message': 'Task stop requested'})


# ── PBS Notification CRUD ──

@bp.route('/api/pbs/<pbs_id>/notifications/targets/<target_type>', methods=['POST'])
@require_auth(perms=['pbs.notifications.manage'])
def create_pbs_notification_target(pbs_id, target_type):
    """Create a notification target (sendmail, gotify, smtp, webhook)"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    data = request.json or {}
    name = data.pop('name', '').strip()
    if not name:
        return jsonify({'error': 'Target name is required'}), 400
    result = pbs_managers[pbs_id].create_notification_target(target_type, name, **data)
    if 'error' in result:
        return jsonify(result), 400
    log_audit(request.session.get('user', 'admin'), 'pbs.notification.target.created',
              f"Created {target_type} notification target '{name}'")
    return jsonify({'message': f'Notification target created', 'data': result.get('data')}), 201


@bp.route('/api/pbs/<pbs_id>/notifications/targets/<target_type>/<name>', methods=['PUT'])
@require_auth(perms=['pbs.notifications.manage'])
def update_pbs_notification_target(pbs_id, target_type, name):
    """Update a notification target"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    data = request.json or {}
    result = pbs_managers[pbs_id].update_notification_target(target_type, name, **data)
    if 'error' in result:
        return jsonify(result), 400
    return jsonify({'message': f'Notification target updated'})


@bp.route('/api/pbs/<pbs_id>/notifications/targets/<target_type>/<name>', methods=['DELETE'])
@require_auth(perms=['pbs.notifications.manage'])
def delete_pbs_notification_target(pbs_id, target_type, name):
    """Delete a notification target"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    result = pbs_managers[pbs_id].delete_notification_target(target_type, name)
    if 'error' in result:
        return jsonify(result), 400
    log_audit(request.session.get('user', 'admin'), 'pbs.notification.target.deleted',
              f"Deleted notification target '{name}'")
    return jsonify({'message': f'Notification target deleted'})


@bp.route('/api/pbs/<pbs_id>/notifications/matchers', methods=['POST'])
@require_auth(perms=['pbs.notifications.manage'])
def create_pbs_notification_matcher(pbs_id):
    """Create a notification matcher"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    data = request.json or {}
    name = data.pop('name', '').strip()
    if not name:
        return jsonify({'error': 'Matcher name is required'}), 400
    result = pbs_managers[pbs_id].create_notification_matcher(name, **data)
    if 'error' in result:
        return jsonify(result), 400
    return jsonify({'message': 'Matcher created', 'data': result.get('data')}), 201


@bp.route('/api/pbs/<pbs_id>/notifications/matchers/<name>', methods=['PUT'])
@require_auth(perms=['pbs.notifications.manage'])
def update_pbs_notification_matcher(pbs_id, name):
    """Update a notification matcher"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    data = request.json or {}
    result = pbs_managers[pbs_id].update_notification_matcher(name, **data)
    if 'error' in result:
        return jsonify(result), 400
    return jsonify({'message': 'Matcher updated'})


@bp.route('/api/pbs/<pbs_id>/notifications/matchers/<name>', methods=['DELETE'])
@require_auth(perms=['pbs.notifications.manage'])
def delete_pbs_notification_matcher(pbs_id, name):
    """Delete a notification matcher"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    result = pbs_managers[pbs_id].delete_notification_matcher(name)
    if 'error' in result:
        return jsonify(result), 400
    return jsonify({'message': 'Matcher deleted'})


# ── PBS Traffic Control CRUD ──

@bp.route('/api/pbs/<pbs_id>/traffic-control', methods=['POST'])
@require_auth(perms=['pbs.traffic.manage'])
def create_pbs_traffic_control(pbs_id):
    """Create a traffic control rule"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    data = request.json or {}
    name = data.get('name', '').strip()
    if not name:
        return jsonify({'error': 'Rule name is required'}), 400
    result = pbs_managers[pbs_id].create_traffic_control(**data)
    if 'error' in result:
        return jsonify(result), 400
    log_audit(request.session.get('user', 'admin'), 'pbs.traffic.created',
              f"Created traffic control rule '{name}'")
    return jsonify({'message': 'Traffic control rule created'}), 201


@bp.route('/api/pbs/<pbs_id>/traffic-control/<name>', methods=['PUT'])
@require_auth(perms=['pbs.traffic.manage'])
def update_pbs_traffic_control(pbs_id, name):
    """Update a traffic control rule"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    data = request.json or {}
    result = pbs_managers[pbs_id].update_traffic_control(name, **data)
    if 'error' in result:
        return jsonify(result), 400
    return jsonify({'message': 'Traffic control rule updated'})


@bp.route('/api/pbs/<pbs_id>/traffic-control/<name>', methods=['DELETE'])
@require_auth(perms=['pbs.traffic.manage'])
def delete_pbs_traffic_control_rule(pbs_id, name):
    """Delete a traffic control rule"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    result = pbs_managers[pbs_id].delete_traffic_control(name)
    if 'error' in result:
        return jsonify(result), 400
    log_audit(request.session.get('user', 'admin'), 'pbs.traffic.deleted',
              f"Deleted traffic control rule '{name}'")
    return jsonify({'message': 'Traffic control rule deleted'})


# ── PBS Disk SMART ──

@bp.route('/api/pbs/<pbs_id>/disks/<path:disk>/smart', methods=['GET'])
@require_auth(perms=['pbs.disks.smart'])
def get_pbs_disk_smart(pbs_id, disk):
    """Get SMART data for a disk"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    result = pbs_managers[pbs_id].get_disk_smart(disk)
    if 'error' in result:
        return jsonify(result), result.get('status_code', 500)
    return jsonify(result.get('data', result))


# ── PBS Subscription Set ──

@bp.route('/api/pbs/<pbs_id>/subscription', methods=['POST'])
@require_auth(perms=['pbs.subscription.set'])
def set_pbs_subscription(pbs_id):
    """Set subscription key"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    data = request.json or {}
    key = data.get('key', '').strip()
    if not key:
        return jsonify({'error': 'Subscription key is required'}), 400
    result = pbs_managers[pbs_id].set_subscription(key)
    if 'error' in result:
        return jsonify(result), 400
    log_audit(request.session.get('user', 'admin'), 'pbs.subscription.set',
              f"Updated subscription on PBS {pbs_managers[pbs_id].name}")
    return jsonify({'message': 'Subscription updated'})


# ── PBS Network/DNS/Time (read-only) ──

@bp.route('/api/pbs/<pbs_id>/network', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_network(pbs_id):
    """Get PBS server network config"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    result = pbs_managers[pbs_id].get_network()
    return jsonify(result.get('data', []))


@bp.route('/api/pbs/<pbs_id>/dns', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_dns(pbs_id):
    """Get PBS server DNS config"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    result = pbs_managers[pbs_id].get_dns()
    return jsonify(result.get('data', {}))


@bp.route('/api/pbs/<pbs_id>/time', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_time(pbs_id):
    """Get PBS server time/timezone"""
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    result = pbs_managers[pbs_id].get_time()
    return jsonify(result.get('data', {}))


# ============================================================================
# Backup Verification — NS Apr 2026
# ============================================================================

# ============================================================================
# PBS Reports — issue #273 (Bradley-Radomski, cberr2024)
# Exportable backup reports for audit use cases (ISO 27001, SOC2, CMMC).
# Main question the reporter wanted answered: "prove that <VM X> was backed up
# on <day Y>, and where". Covered by summary + inventory endpoints below.
# ----------------------------------------------------------------------------
# Helpers shared by the three endpoints below.

def _pbs_collect_snapshots(mgr, protected_only=False, min_backup_time=0):
    """Walk all datastores and namespaces and return a flat list of snapshots.

    Each entry carries the originating datastore + namespace. We purposely do
    not cache — the report is refreshed on demand and the numbers must be
    current for audit use.
    """
    entries = []
    ds_resp = mgr.get_datastores() or {}
    for ds in (ds_resp.get('data', []) or []):
        store = ds.get('name', '')
        if not store:
            continue
        # Figure out which namespaces live under this store. Empty '' is the
        # root namespace and always exists even if there are no sub-namespaces.
        namespaces = ['']
        try:
            ns_resp = mgr.get_namespaces(store) or {}
            ns_list = [n.get('ns', '') for n in (ns_resp.get('data', []) or [])]
            namespaces = list({'', *ns_list})
        except Exception:
            pass
        for ns in namespaces:
            try:
                snap_resp = mgr.get_snapshots(store, ns=ns or None) or {}
            except Exception:
                continue
            for s in (snap_resp.get('data', []) or []):
                if min_backup_time and s.get('backup-time', 0) < min_backup_time:
                    continue
                if protected_only and not s.get('protected'):
                    continue
                s['_datastore'] = store
                s['_namespace'] = ns or ''
                entries.append(s)
    return entries


def _pbs_resolve_vm_names(mgr):
    """Walk each linked PVE cluster and build (type, vmid_str) -> name.
    type is normalized to 'vm' / 'ct' to match PBS worker-id conventions.
    """
    names = {}
    for cid in (mgr.linked_clusters or []):
        pve_mgr = cluster_managers.get(cid)
        if not pve_mgr or not getattr(pve_mgr, 'is_connected', False):
            continue
        try:
            resources = pve_mgr.get_vm_resources() or []
        except Exception:
            continue
        for r in resources:
            t = r.get('type')
            if t == 'qemu':
                vt = 'vm'
            elif t == 'lxc':
                vt = 'ct'
            else:
                continue
            names[(vt, str(r.get('vmid', '')))] = r.get('name', '')
    return names


@bp.route('/api/pbs/<pbs_id>/reports/summary', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_reports_summary(pbs_id):
    """Aggregated backup report over a time window.

    Covers the executive-summary + per-VM rollup reports from #273.

    Query params:
      days      time window (default 30, max 365)
    """
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    if not mgr.connected:
        return jsonify({'error': 'Not connected'}), 503

    import time
    import datetime as _dt

    try:
        days = max(1, min(365, int(request.args.get('days', 30))))
    except Exception:
        days = 30
    now_ts = int(time.time())
    since_ts = now_ts - days * 86400

    # ── Backup tasks in window ─────────────────────────────────────────────
    tasks_resp = mgr.get_tasks(limit=500, typefilter='backup', since=since_ts) or {}
    tasks = tasks_resp.get('data', []) or []

    totals = {'jobs': 0, 'success': 0, 'warning': 0, 'failed': 0}
    per_day = {}          # YYYY-MM-DD -> {date, success, warning, failed}
    per_vm_latest = {}    # (type, vmid) -> latest task dict

    for t in tasks:
        # PBS task shape: {upid, starttime, endtime, status, worker_type, worker_id}
        if t.get('worker_type') != 'backup':
            continue
        totals['jobs'] += 1

        status_raw = (t.get('status') or '').strip()
        status_upper = status_raw.upper()
        if status_upper == 'OK':
            bucket = 'success'
        elif 'WARN' in status_upper:
            bucket = 'warning'
        else:
            bucket = 'failed'
        totals[bucket] += 1

        end_ts = t.get('endtime') or t.get('starttime') or 0
        if end_ts:
            day = _dt.datetime.fromtimestamp(end_ts).strftime('%Y-%m-%d')
            if day not in per_day:
                per_day[day] = {'date': day, 'success': 0, 'warning': 0, 'failed': 0}
            per_day[day][bucket] += 1

        worker_id = t.get('worker_id') or t.get('id') or ''
        if '/' in worker_id:
            vm_type, vmid = worker_id.split('/', 1)
            key = (vm_type, vmid)
            prev = per_vm_latest.get(key)
            if (prev is None
                    or (t.get('endtime') or 0) > (prev.get('endtime') or 0)):
                per_vm_latest[key] = t

    # ── Snapshot inventory for size/verify info ────────────────────────────
    snapshots = _pbs_collect_snapshots(mgr)
    snapshots_by_key = {}   # (type, vmid_str) -> [snap, ...]
    for s in snapshots:
        key = (s.get('backup-type', ''), str(s.get('backup-id', '')))
        snapshots_by_key.setdefault(key, []).append(s)

    # unverified older than 30 days — used as a compliance-warning gauge
    cutoff_verify = now_ts - 30 * 86400
    unverified_old = 0
    for s in snapshots:
        v = s.get('verification') or {}
        state = v.get('state') if isinstance(v, dict) else None
        if state != 'ok' and s.get('backup-time', 0) < cutoff_verify:
            unverified_old += 1

    # ── Resolve VM names from linked clusters ──────────────────────────────
    vm_names = _pbs_resolve_vm_names(mgr)

    # ── Build per-VM rollup (Veeam-style last N per job) ───────────────────
    per_vm = []
    for (vm_type, vmid), task in per_vm_latest.items():
        snaps = snapshots_by_key.get((vm_type, vmid), [])
        latest_snap = max(snaps, key=lambda x: x.get('backup-time', 0)) if snaps else None

        end_ts = task.get('endtime') or 0
        start_ts = task.get('starttime') or 0
        duration = (end_ts - start_ts) if end_ts and start_ts else 0
        status_upper = (task.get('status') or '').upper()
        if status_upper == 'OK':
            status_label = 'success'
        elif 'WARN' in status_upper:
            status_label = 'warning'
        else:
            status_label = 'failed'

        latest_verify = {}
        if latest_snap:
            latest_verify = latest_snap.get('verification') or {}
            if not isinstance(latest_verify, dict):
                latest_verify = {}
        per_vm.append({
            'type': vm_type,
            'vmid': vmid,
            'vm_name': vm_names.get((vm_type, str(vmid)), ''),
            'datastore': latest_snap.get('_datastore') if latest_snap else '',
            'namespace': latest_snap.get('_namespace') if latest_snap else '',
            'last_backup_ts': end_ts,
            'status': status_label,
            'size': latest_snap.get('size', 0) if latest_snap else 0,
            'duration_s': duration,
            'verified': latest_verify.get('state') == 'ok',
            'snapshot_count': len(snaps),
            'upid': task.get('upid', ''),
        })
    per_vm.sort(key=lambda x: x.get('last_backup_ts', 0), reverse=True)

    # ── Fill missing days so frontend chart renders gaps as zeros ──────────
    per_day_filled = []
    for i in range(days - 1, -1, -1):
        day = (_dt.datetime.fromtimestamp(now_ts) - _dt.timedelta(days=i)).strftime('%Y-%m-%d')
        per_day_filled.append(per_day.get(day, {'date': day, 'success': 0, 'warning': 0, 'failed': 0}))

    success_rate = (totals['success'] / totals['jobs'] * 100.0) if totals['jobs'] else 0.0

    return jsonify({
        'window': {'days': days, 'since_ts': since_ts, 'until_ts': now_ts},
        'totals': {**totals, 'success_rate': round(success_rate, 1)},
        'per_day': per_day_filled,
        'per_vm': per_vm,
        'inventory_snapshot_count': len(snapshots),
        'unverified_older_than_30d': unverified_old,
    })


@bp.route('/api/pbs/<pbs_id>/reports/inventory', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_reports_inventory(pbs_id):
    """Flat list of every snapshot across all datastores/namespaces.

    Primary use-case from #273: audit question "prove X was backed up on day Y
    and where". This endpoint is the answer.

    Query params:
      days=0         filter to snapshots newer than N days (0 = no filter)
      protected=1    only protected snapshots
    """
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    if not mgr.connected:
        return jsonify({'error': 'Not connected'}), 503

    import time
    try:
        days = int(request.args.get('days', 0))
    except Exception:
        days = 0
    protected_only = str(request.args.get('protected', '')).lower() in ('1', 'true', 'yes')
    now_ts = int(time.time())
    min_bt = (now_ts - days * 86400) if days > 0 else 0

    raw = _pbs_collect_snapshots(mgr, protected_only=protected_only, min_backup_time=min_bt)

    vm_names = _pbs_resolve_vm_names(mgr)

    entries = []
    for s in raw:
        verify = s.get('verification') or {}
        if not isinstance(verify, dict):
            verify = {}
        vtype = s.get('backup-type', '')
        vmid = str(s.get('backup-id', ''))
        entries.append({
            'type': vtype,
            'vmid': vmid,
            'vm_name': vm_names.get((vtype, vmid), ''),
            'datastore': s.get('_datastore', ''),
            'namespace': s.get('_namespace', ''),
            'backup_time': s.get('backup-time', 0),
            'size': s.get('size', 0),
            'owner': s.get('owner', ''),
            'protected': bool(s.get('protected', False)),
            'comment': s.get('comment', '') or '',
            'verified': verify.get('state') == 'ok',
            'verified_state': verify.get('state') or None,
            'verified_time': verify.get('upid_time') if isinstance(verify, dict) else None,
            'files_count': len(s.get('files', []) or []),
        })
    entries.sort(key=lambda x: x['backup_time'], reverse=True)
    return jsonify({'entries': entries, 'count': len(entries)})


@bp.route('/api/pbs/<pbs_id>/reports/protected-vms', methods=['GET'])
@require_auth(perms=['pbs.view'])
def get_pbs_reports_protected_vms(pbs_id):
    """Gap analysis — which cluster VMs/CTs are actually backed up.

    Essential for SOC2 "protected workloads" audit evidence (#273).

    Query params:
      cluster_id   (required) PVE cluster to check
      days=7       a VM counts as protected if its most recent snapshot is
                   within this window. Older ones land in 'stale'.
    """
    if pbs_id not in pbs_managers:
        return jsonify({'error': 'PBS server not found'}), 404
    mgr = pbs_managers[pbs_id]
    if not mgr.connected:
        return jsonify({'error': 'Not connected'}), 503

    cluster_id = request.args.get('cluster_id', '')
    if not cluster_id:
        return jsonify({'error': 'cluster_id query param required'}), 400
    pve_mgr = cluster_managers.get(cluster_id)
    if not pve_mgr:
        return jsonify({'error': 'Cluster not found'}), 404

    import time
    try:
        days = max(1, min(365, int(request.args.get('days', 7))))
    except Exception:
        days = 7
    cutoff = int(time.time()) - days * 86400

    try:
        resources = pve_mgr.get_vm_resources() or []
    except Exception as e:
        return jsonify({'error': f'Could not load cluster resources: {e}'}), 502

    # Most recent backup timestamp + datastore per (type, vmid)
    most_recent = {}
    snaps = _pbs_collect_snapshots(mgr)
    for s in snaps:
        key = (s.get('backup-type', ''), str(s.get('backup-id', '')))
        bt = s.get('backup-time', 0)
        cur = most_recent.get(key)
        if cur is None or bt > cur['ts']:
            most_recent[key] = {
                'ts': bt,
                'datastore': s.get('_datastore', ''),
                'namespace': s.get('_namespace', ''),
            }

    protected, unprotected, stale = [], [], []
    for r in resources:
        rtype = r.get('type')
        if rtype not in ('qemu', 'lxc'):
            continue
        vt = 'vm' if rtype == 'qemu' else 'ct'
        vmid = str(r.get('vmid', ''))
        info = most_recent.get((vt, vmid))
        entry = {
            'type': vt,
            'vmid': vmid,
            'vm_name': r.get('name', ''),
            'node': r.get('node', ''),
            'status': r.get('status', ''),
            'last_backup_ts': info['ts'] if info else 0,
            'datastore': info['datastore'] if info else '',
            'namespace': info['namespace'] if info else '',
        }
        if not info:
            unprotected.append(entry)
        elif info['ts'] < cutoff:
            stale.append(entry)
        else:
            protected.append(entry)

    protected.sort(key=lambda x: (x['vm_name'] or x['vmid']).lower())
    unprotected.sort(key=lambda x: (x['vm_name'] or x['vmid']).lower())
    stale.sort(key=lambda x: x['last_backup_ts'])

    return jsonify({
        'window': {'days': days, 'cutoff_ts': cutoff},
        'counts': {
            'protected': len(protected),
            'unprotected': len(unprotected),
            'stale': len(stale),
            'total': len(protected) + len(unprotected) + len(stale),
        },
        'protected': protected,
        'unprotected': unprotected,
        'stale': stale,
    })


# End of PBS Reports (#273)
# ============================================================================


@bp.route('/api/clusters/<cluster_id>/backup-verify', methods=['POST'])
@require_auth(perms=['vm.backup'])
def start_backup_verification(cluster_id):
    """Start a PBS backup verification (restore → boot → check → cleanup)"""
    from pegaprox.core.backup_verify import start_verification

    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404

    data = request.json or {}
    required = ['node', 'vmid', 'backup_volid']
    for f in required:
        if f not in data:
            return jsonify({'error': f'Missing: {f}'}), 400

    data['cluster_id'] = cluster_id
    pve_mgr = cluster_managers[cluster_id]

    if not pve_mgr.is_connected:
        return jsonify({'error': 'Cluster not connected'}), 503

    try:
        task_id = start_verification(pve_mgr, data)
    except Exception as e:
        return jsonify({'error': str(e)}), 409

    user = request.session.get('user', 'system')
    log_audit(user, 'backup.verify_started',
              f"Backup verification started for VM {data.get('vmid')} on {data.get('node')}")

    return jsonify({'success': True, 'task_id': task_id})


@bp.route('/api/clusters/<cluster_id>/backup-verify/<task_id>', methods=['GET'])
@require_auth(perms=['vm.backup'])
def get_backup_verification_status(cluster_id, task_id):
    """Get status of a running or completed verification"""
    from pegaprox.core.backup_verify import get_verification, get_verification_history

    # check active first
    status = get_verification(task_id)
    if status:
        return jsonify(status)

    # check database
    db = get_db()
    try:
        row = db.query_one('SELECT * FROM backup_verifications WHERE id = ?', (task_id,))
        if row:
            result = dict(row)
            import json
            result['details'] = json.loads(result.get('details', '{}'))
            result['logs'] = result['details'].get('logs', [])
            return jsonify(result)
    except Exception:
        pass

    return jsonify({'error': 'Verification not found'}), 404


@bp.route('/api/clusters/<cluster_id>/backup-verify/history', methods=['GET'])
@require_auth(perms=['vm.backup'])
def get_backup_verification_history(cluster_id):
    """Get verification history, optionally filtered by vmid"""
    from pegaprox.core.backup_verify import get_verification_history

    vmid = request.args.get('vmid', type=int)
    limit = request.args.get('limit', 50, type=int)

    results = get_verification_history(cluster_id, vmid, limit)
    return jsonify(results)


@bp.route('/api/clusters/<cluster_id>/backup-verify/active', methods=['GET'])
@require_auth(perms=['vm.backup'])
def get_active_verifications(cluster_id):
    """Get all currently running verifications"""
    from pegaprox.core.backup_verify import get_active_verifications

    active = get_active_verifications()
    # filter by cluster
    cluster_active = {k: v for k, v in active.items() if v.get('cluster_id') == cluster_id}
    return jsonify(cluster_active)


# End PBS API endpoints
# ============================================================================

