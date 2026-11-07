#!/usr/bin/env python3
"""Exercise a downloaded component as a regular user; CI-only, no AWS endpoint needed."""
import argparse
import asyncio
import base64
from contextlib import asynccontextmanager
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def cli(binary, environment, *arguments):
    result = subprocess.run(
        [binary, 'component', *map(str, arguments)], env=environment,
        check=True, capture_output=True, text=True, timeout=30,
    )
    return result.stdout


@asynccontextmanager
async def session(binary, database, key, environment, stderr, capabilities):
    process = await asyncio.create_subprocess_exec(
        str(binary), stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=stderr, env=environment, limit=1024 * 1024,
    )
    identifier = 0
    completed = False

    async def exchange(message):
        process.stdin.write((json.dumps(message) + '\n').encode())
        await asyncio.wait_for(process.stdin.drain(), timeout=15)
        reply = await asyncio.wait_for(process.stdout.readline(), timeout=15)
        if not reply:
            raise RuntimeError('worker exited before replying')
        return json.loads(reply)

    async def call(operation, body):
        nonlocal identifier
        identifier += 1
        result = await exchange({'id':identifier, 'operation':operation, 'body':body})
        if result.get('id') != identifier:
            raise RuntimeError('worker response identifier mismatch')
        return result

    try:
        ready = await exchange({
            'version':1, 'database':str(database), 'key':key,
            'account_id':'000000000000', 'region':'us-east-1',
        })
        if ready.get('version') != 1 or ready.get('ready') is not True:
            raise RuntimeError('worker initialization failed')
        if not capabilities <= set(ready.get('features', [])):
            raise RuntimeError('worker capabilities are incompatible')
        yield call
        completed = True
    finally:
        process.stdin.close()
        try:
            # The worker drains up to seven background tasks with a 5s deadline each.
            status = await asyncio.wait_for(process.wait(), timeout=40)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            if completed:
                raise RuntimeError('worker did not stop after closing its input')
        else:
            if completed and status != 0:
                raise RuntimeError(f'worker exited with status {status}')


def expect(result, operation, status=200):
    if result.get('status') != status:
        raise RuntimeError(f'{operation} returned unexpected status {result.get("status")}')
    return result['body']


async def active_table(call, table):
    deadline = asyncio.get_running_loop().time() + 15
    while True:
        body = expect(await call('DescribeTable', {'TableName':table}), 'DescribeTable')
        if (body['Table']['TableStatus'] == 'ACTIVE'
                and all(index.get('IndexStatus', 'ACTIVE') == 'ACTIVE'
                        for index in body['Table'].get('GlobalSecondaryIndexes', []))):
            return body['Table']
        if asyncio.get_running_loop().time() >= deadline:
            raise RuntimeError('table did not become active')
        await asyncio.sleep(0.1)


async def available_backup(call, backup):
    deadline = asyncio.get_running_loop().time() + 15
    while True:
        body = expect(await call('DescribeBackup', {'BackupArn':backup}), 'DescribeBackup')
        if body['BackupDescription']['BackupDetails']['BackupStatus'] == 'AVAILABLE':
            return
        if asyncio.get_running_loop().time() >= deadline:
            raise RuntimeError('backup did not become available')
        await asyncio.sleep(0.1)


async def absent_table(call, table):
    deadline = asyncio.get_running_loop().time() + 15
    while True:
        result = await call('DescribeTable', {'TableName':table})
        if result.get('status') == 400 and result['body'].get('__type', '').endswith('#ResourceNotFoundException'):
            return
        expect(result, 'DescribeTable while deleting')
        if asyncio.get_running_loop().time() >= deadline:
            raise RuntimeError('source table was not deleted')
        await asyncio.sleep(0.1)


async def indexed_item(call, table, item):
    deadline = asyncio.get_running_loop().time() + 15
    while True:
        body = expect(await call('Query', {
            'TableName':table, 'IndexName':'lookup-index', 'KeyConditionExpression':'#lookup = :value',
            'ExpressionAttributeNames':{'#lookup':'lookup'},
            'ExpressionAttributeValues':{':value':item['lookup']},
        }), 'Query GSI')
        if body.get('Items') == [item]:
            return
        if asyncio.get_running_loop().time() >= deadline:
            raise RuntimeError('GSI did not preserve the expected item')
        await asyncio.sleep(0.1)


async def exercise(binary, database, key, environment, stderr, capabilities):
    item = {'pk':{'S':'item'}, 'lookup':{'S':'initial'},
            'payload':{'S':'encrypted-component-smoke-marker'}}
    table = 'component-smoke'
    async with session(binary, database, key, environment, stderr, capabilities) as call:
        expect(await call('CreateTable', {
            'TableName':table, 'BillingMode':'PAY_PER_REQUEST',
            'AttributeDefinitions':[{'AttributeName':'pk', 'AttributeType':'S'}, {'AttributeName':'lookup', 'AttributeType':'S'}],
            'KeySchema':[{'AttributeName':'pk', 'KeyType':'HASH'}],
            'GlobalSecondaryIndexes':[{'IndexName':'lookup-index',
                'KeySchema':[{'AttributeName':'lookup', 'KeyType':'HASH'}], 'Projection':{'ProjectionType':'ALL'}}],
        }), 'CreateTable')
        await active_table(call, table)
        expect(await call('PutItem', {'TableName':table, 'Item':item}), 'PutItem')
        item['payload'] = {'S':'encrypted-component-smoke-updated-marker'}
        updated = expect(await call('UpdateItem', {
            'TableName':table, 'Key':{'pk':{'S':'item'}},
            'UpdateExpression':'SET #payload = :value',
            'ExpressionAttributeNames':{'#payload':'payload'},
            'ExpressionAttributeValues':{':value':item['payload']}, 'ReturnValues':'ALL_NEW',
        }), 'UpdateItem')
        if updated.get('Attributes') != item:
            raise RuntimeError('update did not return the changed item')
        result = await call('PutItem', {
            'TableName':table, 'Item':item, 'ConditionExpression':'attribute_not_exists(pk)',
        })
        body = expect(result, 'conditional PutItem', 400)
        if not body['__type'].endswith('#ConditionalCheckFailedException'):
            raise RuntimeError('conditional write returned an incompatible error')
        await indexed_item(call, table, item)
        snapshot_item = dict(item)
        created = expect(await call('CreateBackup', {'TableName':table, 'BackupName':'component-snapshot'}), 'CreateBackup')
        backup = created['BackupDetails']['BackupArn']
        await available_backup(call, backup)
        listed = expect(await call('ListBackups', {'TableName':table, 'Limit':1, 'BackupType':'USER'}), 'ListBackups')
        if [entry['BackupArn'] for entry in listed.get('BackupSummaries', [])] != [backup]:
            raise RuntimeError('backup is missing from the table inventory')
        item['payload'] = {'S':'encrypted-component-smoke-after-backup'}
        item['lookup'] = {'S':'mutated'}
        changed = expect(await call('UpdateItem', {
            'TableName':table, 'Key':{'pk':{'S':'item'}},
            'UpdateExpression':'SET #payload = :payload, #lookup = :lookup',
            'ExpressionAttributeNames':{'#payload':'payload', '#lookup':'lookup'},
            'ExpressionAttributeValues':{':payload':item['payload'], ':lookup':item['lookup']}, 'ReturnValues':'ALL_NEW',
        }), 'UpdateItem after backup')
        if changed.get('Attributes') != item:
            raise RuntimeError('source mutation after backup did not apply')
    for path in (database, Path(str(database) + '-wal')):
        if path.exists() and b'encrypted-component-smoke-' in path.read_bytes():
            raise RuntimeError('plaintext payload found in encrypted database')
    if database.read_bytes().startswith(b'SQLite format 3\x00'):
        raise RuntimeError('database is not encrypted')
    async with session(binary, database, key, environment, stderr, capabilities) as call:
        body = expect(await call('GetItem', {'TableName':table, 'Key':{'pk':{'S':'item'}}}), 'GetItem')
        if body.get('Item') != item:
            raise RuntimeError('restart did not preserve the stored item')
        deleted = expect(await call('DeleteItem', {
            'TableName':table, 'Key':{'pk':{'S':'item'}}, 'ReturnValues':'ALL_OLD',
        }), 'DeleteItem')
        if deleted.get('Attributes') != item:
            raise RuntimeError('delete did not return the removed item')
        body = expect(await call('GetItem', {'TableName':table, 'Key':{'pk':{'S':'item'}}}), 'GetItem after delete')
        if body.get('Item'):
            raise RuntimeError('deleted item is still visible')
        expect(await call('DeleteTable', {'TableName':table}), 'DeleteTable source')
        await absent_table(call, table)
        await available_backup(call, backup)
        retained = expect(await call('ListBackups', {'TableName':table, 'BackupType':'USER'}), 'ListBackups deleted source')
        if [entry['BackupArn'] for entry in retained.get('BackupSummaries', [])] != [backup]:
            raise RuntimeError('source deletion removed its retained backup')
        restored = expect(await call('RestoreTableFromBackup', {
            'BackupArn':backup, 'TargetTableName':'component-restored',
        }), 'RestoreTableFromBackup')
        if restored['TableDescription']['TableName'] != 'component-restored':
            raise RuntimeError('backup restore returned the wrong target')
        description = await active_table(call, 'component-restored')
        indexes = description.get('GlobalSecondaryIndexes', [])
        if (len(indexes) != 1 or indexes[0]['IndexName'] != 'lookup-index'
                or indexes[0]['KeySchema'] != [{'AttributeName':'lookup', 'KeyType':'HASH'}]
                or indexes[0]['Projection']['ProjectionType'] != 'ALL'):
            raise RuntimeError('backup restore did not preserve the GSI schema')
        body = expect(await call('GetItem', {'TableName':'component-restored', 'Key':{'pk':{'S':'item'}}}), 'GetItem restored')
        if body.get('Item') != snapshot_item:
            raise RuntimeError('backup was changed by a later source mutation')
        await indexed_item(call, 'component-restored', snapshot_item)
        removed = expect(await call('DeleteBackup', {'BackupArn':backup}), 'DeleteBackup')
        if removed['BackupDescription']['BackupDetails']['BackupArn'] != backup:
            raise RuntimeError('backup deletion returned the wrong identity')
        listed = expect(await call('ListBackups', {'TableName':table, 'BackupType':'USER'}), 'ListBackups after delete')
        if any(entry['BackupArn'] == backup and entry.get('BackupStatus') != 'DELETED'
               for entry in listed.get('BackupSummaries', [])):
            raise RuntimeError('deleted backup remains available')
    async with session(binary, database, key, environment, stderr, capabilities) as call:
        body = expect(await call('GetItem', {'TableName':'component-restored', 'Key':{'pk':{'S':'item'}}}), 'GetItem restored after restart')
        if body.get('Item') != snapshot_item:
            raise RuntimeError('restart did not preserve the restored snapshot')
        await indexed_item(call, 'component-restored', snapshot_item)
        await absent_table(call, table)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog', required=True, type=Path)
    parser.add_argument('--work-dir', required=True, type=Path)
    parser.add_argument('--binary', default='locallycloud')
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error('run this validation as an unprivileged user')
    with tempfile.TemporaryDirectory(prefix='locallycloud-component-', dir=args.work_dir) as directory:
        root = Path(directory).resolve()
        environment = dict(os.environ, LOCALLYCLOUD_COMPONENTS_DIR=str(root / 'components'),
                           XDG_DATA_HOME=str(root / 'data'), XDG_CACHE_HOME=str(root / 'cache'))
        environment.pop('LOCALLYCLOUD_KMS_MASTER_KEY', None)
        catalog = json.loads(args.catalog.read_text())
        architecture = {'x86_64':'x86_64', 'aarch64':'arm64'}[os.uname().machine]
        artifact = next(item for item in catalog['artifacts'] if item['architecture'] == architecture)
        capabilities = set(catalog['capabilities'])
        if not {'stream-cursors-v1', 'mrec-outbox-v1', 'backups-v1', 'migration-ttl-v1'} <= capabilities:
            raise RuntimeError('catalog lacks required component capabilities')
        cli(args.binary, environment, 'install', 'extenddb', '--catalog', args.catalog.resolve())
        active = json.loads(cli(args.binary, environment, 'list'))['extenddb']
        worker = Path(active['path']).resolve()
        worker.relative_to(root)
        if active['sha256'] != artifact['binary']['sha256'] or digest(worker) != artifact['binary']['sha256']:
            raise RuntimeError('installed worker checksum mismatch')
        notices = worker.parent / 'LICENSES.txt'
        if not notices.is_file() or digest(notices) != artifact['notices']['sha256']:
            raise RuntimeError('installed component notices do not match the catalog')
        check = json.loads(cli(args.binary, environment, 'check-updates', 'extenddb',
                               '--catalog', args.catalog.resolve()))
        if check['updateAvailable'] or check['availableSha256'] != active['sha256']:
            raise RuntimeError('update check did not recognize the installed component')
        database = root / 'database.sqlite3'
        key = base64.b64encode(os.urandom(32)).decode()
        with (root / 'worker.stderr.log').open('wb') as stderr:
            asyncio.run(exercise(worker, database, key, environment, stderr, capabilities))
        before = digest(database)
        cli(args.binary, environment, 'remove', 'extenddb')
        if json.loads(cli(args.binary, environment, 'list'))['extenddb'] is not None:
            raise RuntimeError('component removal did not clear the active version')
        if digest(database) != before:
            raise RuntimeError('component removal changed the user database')
    print(json.dumps({'component':'extenddb', 'unprivileged':True, 'verified':True,
                      'checks':['install', 'checksum', 'notices', 'check-updates', 'CRUD',
                                'conditional-error', 'encryption', 'restart', 'backup-snapshot', 'backup-inventory',
                                'backup-survives-source-deletion', 'backup-restore-GSI', 'backup-delete', 'remove-preserves-data']}))


if __name__ == '__main__':
    main()
