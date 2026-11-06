#!/usr/bin/env python3
"""Validate encrypted persistence and scope isolation through real worker IPC."""
import argparse
import base64
import json
import os
import selectors
import sqlite3
import subprocess
import time
from pathlib import Path
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--worker', required=True, type=Path, help='Built ExtendDB worker executable')
parser.add_argument('--work', required=True, type=Path, help='New private evidence/state directory')
args = parser.parse_args()
binary = args.worker.resolve()
if not binary.is_file() or not os.access(binary, os.X_OK):
    parser.error('--worker must name an executable file')
base = args.work.absolute()
try:
    base.mkdir(mode=448)
except FileExistsError:
    parser.error('--work must be a new directory; existing state will not be modified')
os.chmod(base, 448)
db = base / 'database.sqlite'
key = base64.b64encode(bytes(range(32))).decode()
children = []

def receive(p, timeout=15):
    selector = selectors.DefaultSelector()
    selector.register(p.stdout, selectors.EVENT_READ)
    try:
        if not selector.select(timeout):
            raise TimeoutError('worker response timeout')
        line = p.stdout.readline()
        if not line:
            return None
        return json.loads(line)
    finally:
        selector.close()

def start(keyvalue=key, region='us-east-1', account='000000000000', expect_ready=True):
    log = open(base / 'worker.stderr.log', 'a')
    p = subprocess.Popen([str(binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True)
    log.close()
    children.append(p)
    p.stdin.write(json.dumps(dict(version=1, key=keyvalue, database=str(db), account_id=account, region=region)) + '\n')
    p.stdin.flush()
    response = receive(p)
    if expect_ready:
        assert response == dict(version=1, ready=True), response
    else:
        assert response is None, response
        assert p.wait(timeout=10) != 0
    return p

def call(p, operation, body):
    p.stdin.write(json.dumps(dict(id=1, operation=operation, body=body)) + '\n')
    p.stdin.flush()
    result = receive(p)
    assert result is not None
    return result

def stop(p):
    if p.poll() is None:
        p.stdin.close()
        assert p.wait(timeout=12) == 0
results = {}
try:
    p = start()
    result = call(p, 'CreateTable', dict(TableName='probe', KeySchema=[dict(AttributeName='pk', KeyType='HASH')], AttributeDefinitions=[dict(AttributeName='pk', AttributeType='S')], BillingMode='PAY_PER_REQUEST'))
    assert result['status'] == 200, result
    deadline = time.monotonic() + 15
    while True:
        result = call(p, 'DescribeTable', dict(TableName='probe'))
        if result['body']['Table']['TableStatus'] == 'ACTIVE':
            break
        assert time.monotonic() < deadline, result
        time.sleep(0.1)
    marker = 'plain-text-marker-should-not-exist-in-sqlcipher-83e40b'
    item = dict(pk=dict(S='key1'), payload=dict(S=marker))
    assert call(p, 'PutItem', dict(TableName='probe', Item=item))['status'] == 200
    assert call(p, 'GetItem', dict(TableName='probe', Key=dict(pk=dict(S='key1'))))['body']['Item'] == item
    results['official_engine_crud'] = True
    duplicate = call(p, 'PutItem', dict(TableName='probe', Item=item, ConditionExpression='attribute_not_exists(pk)'))
    assert duplicate['status'] == 400 and duplicate['body']['__type'].endswith('#ConditionalCheckFailedException'), duplicate
    results['conditional_failure_shape'] = True
    for path in [db, Path(str(db) + '-wal')]:
        if path.exists():
            assert marker.encode() not in path.read_bytes(), path
    assert db.read_bytes()[:16] != b'SQLite format 3\x00'
    try:
        conn = sqlite3.connect(db)
        try:
            conn.execute('SELECT * FROM sqlite_master').fetchall()
        finally:
            conn.close()
    except sqlite3.DatabaseError:
        pass
    else:
        raise AssertionError('ordinary SQLite read encrypted database')
    results['encrypted_database_and_wal'] = True
    stop(p)
    p = start()
    assert call(p, 'GetItem', dict(TableName='probe', Key=dict(pk=dict(S='key1'))))['body']['Item'] == item
    stop(p)
    results['restart_persists_items'] = True
    start(keyvalue=base64.b64encode(bytes([99]) * 32).decode(), expect_ready=False)
    results['wrong_key_refused'] = True
    start(region='us-east-2', expect_ready=False)
    start(account='111111111111', expect_ready=False)
    results['wrong_scope_refused'] = True
    p = start()
    assert call(p, 'GetItem', dict(TableName='probe', Key=dict(pk=dict(S='key1'))))['body']['Item'] == item
    stop(p)
    results['failed_open_preserves_original_data'] = True
    results['verified'] = True
finally:
    for p in children:
        if p.poll() is None:
            p.kill()
            p.wait(timeout=10)
        for pipe in (p.stdin, p.stdout):
            if pipe is not None:
                pipe.close()
    (base / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
print(json.dumps(results, indent=2))
