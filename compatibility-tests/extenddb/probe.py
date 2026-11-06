#!/usr/bin/env python3
"""Validate an explicitly configured DynamoDB engine through real AWS CLI calls."""

import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import time
import uuid


class Probe:
    def __init__(self, args):
        self.args = args
        self.work = args.work.resolve()
        self.work.mkdir(parents=True, exist_ok=False, mode=0o700)
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(('LOCALLYCLOUD_', 'LOCALSTACK_', 'AWS_'))}
        self.env.update(LOCALLYCLOUD_DYNAMODB_ENGINE='extenddb',
                        LOCALLYCLOUD_COMPONENTS_DIR=str(self.work / 'components'))
        self.sentinel = 'extenddb-plaintext-sentinel-' + uuid.uuid4().hex
        self.env.update(AWS_ACCESS_KEY_ID='test', AWS_SECRET_ACCESS_KEY='test',
                        AWS_CONFIG_FILE='/dev/null', AWS_SHARED_CREDENTIALS_FILE='/dev/null',
                        AWS_EC2_METADATA_DISABLED='true', AWS_PAGER='', AWS_MAX_ATTEMPTS='1',
                        XDG_CACHE_HOME=str(self.work / 'cache'),
                        XDG_DATA_HOME=str(self.work / 'data'),
                        XDG_CONFIG_HOME=str(self.work / 'config'))
        self.server = self.log = self.endpoint = None
        self.starts = 0
        self.report = {'verified': False, 'cases': [], 'cleanup': [],
                       'measurements': {'serverStartSeconds': [], 'firstDynamoRequestSeconds': [],
                                        'peakObservedWorkerRssKiB': 0, 'peakObservedWorkers': 0}}
        if args.model:
            model = args.model.resolve()
            provenance = json.loads(Path(__file__).with_name('fixtures').joinpath('provenance.json').read_text())
            if hashlib.sha256(model.read_bytes()).hexdigest() != provenance['sha256']:
                raise ValueError('official model checksum differs from pinned provenance')
            if model.parts[-3:] != ('dynamodb', '2012-08-10', 'service-2.json'):
                raise ValueError('model must be under dynamodb/2012-08-10/service-2.json')
            self.env['AWS_DATA_PATH'] = str(model.parents[2])
            self.report['sdkModel'] = provenance

    def save(self):
        (self.work / 'results.json').write_text(json.dumps(self.report, indent=2) + '\n')

    def check(self, name, passed, observation):
        self.report['cases'].append({'name': name, 'verified': bool(passed), 'observation': observation})
        self.save()
        if not passed:
            raise AssertionError(name)

    def aws(self, operation, payload, region='us-east-1', error=None, message=None):
        command = ['aws', '--endpoint-url', self.endpoint, '--region', region,
                   '--output', 'json', '--cli-connect-timeout', '3', '--cli-read-timeout', '30',
                   'dynamodb', operation, '--cli-input-json', json.dumps(payload)]
        started = time.monotonic()
        result = subprocess.run(command, env=self.env, capture_output=True, text=True, timeout=40)
        if self.first_request:
            self.report['measurements']['firstDynamoRequestSeconds'].append({
                'operation': operation, 'seconds': round(time.monotonic() - started, 3)})
            self.first_request = False
        self.sample_workers()
        if error:
            self.check(operation + ' rejects ' + error,
                       result.returncode != 0 and error in result.stderr
                       and (message is None or message in result.stderr),
                       {'exitCode': result.returncode, 'stderr': result.stderr[-1500:]})
            return None
        if result.returncode:
            raise RuntimeError(operation + ': ' + result.stderr[-2000:])
        return json.loads(result.stdout) if result.stdout.strip() else {}

    def start(self, account):
        self.starts += 1
        self.first_request = True
        started = time.monotonic()
        environment = dict(self.env, LOCALLYCLOUD_ACCOUNT_ID=account,
                           LOCALLYCLOUD_STATE_DB=str(self.work / 'state.sqlite3'),
                           LOCALLYCLOUD_KMS_MASTER_KEY=base64.b64encode(b'\x51' * 32).decode(),
                           LOCALLYCLOUD_HOST='127.0.0.1', LOCALLYCLOUD_PORT='0',
                           LOCALLYCLOUD_IAM_ENFORCEMENT='permissive',
                           LOCALLYCLOUD_LEGACY_BACKEND_URL='http://127.0.0.1:1',
                           LOCALLYCLOUD_WORK_DIR=str(self.work / 'lambda'), RUST_LOG='info')
        self.server_env = environment
        path = self.work / f'server-{self.starts}.log'
        self.log = path.open('w')
        self.server = subprocess.Popen([str(self.args.binary.resolve())], env=environment,
                                       stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            for line in path.read_text(errors='replace').splitlines():
                if 'locallycloud listening' in line:
                    match = re.search(r'127\.0\.0\.1:(\d+)', line)
                    if match:
                        self.endpoint = 'http://127.0.0.1:' + match.group(1)
                        self.report['measurements']['serverStartSeconds'].append(round(time.monotonic() - started, 3))
                        self.check('no worker process before first DynamoDB request',
                                   not self.children(), {'serverPid': self.server.pid, 'children': self.children()})
                        return
            if self.server.poll() is not None:
                raise RuntimeError('isolated server exited before readiness; see ' + path.name)
            time.sleep(0.05)
        raise RuntimeError('isolated server startup timeout; see ' + path.name)

    def children(self):
        if self.server is None or self.server.poll() is not None:
            return []
        children = set()
        for task in Path(f'/proc/{self.server.pid}/task').glob('*'):
            try:
                children.update(int(pid) for pid in (task / 'children').read_text().split())
            except FileNotFoundError:
                continue
        return sorted(children)

    def sample_workers(self):
        children = self.children()
        rss = 0
        for pid in children:
            try:
                for line in Path(f'/proc/{pid}/status').read_text().splitlines():
                    if line.startswith('VmRSS:'):
                        rss += int(line.split()[1])
                        break
            except FileNotFoundError:
                continue
        measurements = self.report['measurements']
        measurements['peakObservedWorkerRssKiB'] = max(measurements['peakObservedWorkerRssKiB'], rss)
        measurements['peakObservedWorkers'] = max(measurements['peakObservedWorkers'], len(children))
        return children

    def idle_shutdown(self):
        initial = self.sample_workers()
        self.check('real worker processes exist after DynamoDB use', bool(initial), {'children': initial})
        started = time.monotonic()
        remaining = initial
        while time.monotonic() - started < 35:
            remaining = self.sample_workers()
            if not remaining or self.server.poll() is not None:
                break
            time.sleep(0.1)
        self.check('workers stop after idle timeout while server remains available',
                   not remaining and self.server.poll() is None,
                   {'idleSeconds': round(time.monotonic() - started, 3), 'remainingChildren': remaining})

    def stop(self):
        if self.server and self.server.poll() is None:
            self.server.send_signal(signal.SIGTERM)
            try:
                self.server.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.server.kill()
                self.server.wait(timeout=10)
                self.report['cleanup'].append('private server required SIGKILL')
        if self.server and self.server.returncode != 0:
            self.report['cleanup'].append('private server exit ' + str(self.server.returncode))
        if self.log:
            self.log.close()
        self.server = self.log = self.endpoint = None

    def ready_table(self, table, region):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            description = self.aws('describe-table', {'TableName': table}, region)['Table']
            indexes = description.get('VectorIndexes', [])
            if description['TableStatus'] == 'ACTIVE' and all(i['IndexStatus'] == 'ACTIVE' for i in indexes):
                return description
            time.sleep(0.1)
        raise RuntimeError('table/index did not become ACTIVE')

    def seed(self, account, region):
        table = 'extenddb-contract'
        payload = {'TableName': table, 'BillingMode': 'PAY_PER_REQUEST',
                   'AttributeDefinitions': [{'AttributeName': 'pk', 'AttributeType': 'S'},
                                            {'AttributeName': 'sk', 'AttributeType': 'N'}],
                   'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'},
                                 {'AttributeName': 'sk', 'KeyType': 'RANGE'}]}
        self.aws('create-table', payload, region)
        description = self.ready_table(table, region)
        self.check('table ARN retains account and region',
                   description['TableArn'] == f'arn:aws:dynamodb:{region}:{account}:table/{table}',
                   {'arn': description['TableArn']})
        marker = account + '/' + region
        for n in range(3):
            self.aws('put-item', {'TableName': table, 'Item': {'pk': {'S': 'tenant'}, 'sk': {'N': str(n)},
                                                            'marker': {'S': marker}, 'secret': {'S': self.sentinel}}}, region)
        tx = {'TableName': table, 'Item': {'pk': {'S': 'txn'}, 'sk': {'N': '1'}, 'marker': {'S': marker}}}
        self.aws('transact-write-items', {'TransactItems': [{'Put': tx}]}, region)
        self.aws('transact-write-items', {'TransactItems': [
            {'Put': dict(tx, ConditionExpression='attribute_not_exists(pk)')},
            {'Put': {'TableName': table, 'Item': {'pk': {'S': 'aborted'}, 'sk': {'N': '1'}}}}
        ]}, region, error='TransactionCanceledException')
        absent = self.aws('get-item', {'TableName': table, 'Key': {'pk': {'S': 'aborted'}, 'sk': {'N': '1'}},
                                       'ConsistentRead': True}, region)
        self.check('failed transaction has no partial write', 'Item' not in absent, absent)
        self.verify_rows(account, region)

    def verify_rows(self, account, region):
        marker = account + '/' + region
        request = {'TableName': 'extenddb-contract', 'KeyConditionExpression': 'pk = :pk',
                   'ExpressionAttributeValues': {':pk': {'S': 'tenant'}}, 'ConsistentRead': True, 'Limit': 2}
        first = self.aws('query', request, region)
        second = self.aws('query', dict(request, ExclusiveStartKey=first['LastEvaluatedKey']), region)
        rows = first['Items'] + second['Items']
        self.check('query pagination preserves namespace ' + marker,
                   [i['sk']['N'] for i in rows] == ['0', '1', '2']
                   and all(i['marker']['S'] == marker for i in rows), {'items': rows})
        tx = self.aws('transact-get-items', {'TransactItems': [{'Get': {
            'TableName': 'extenddb-contract', 'Key': {'pk': {'S': 'txn'}, 'sk': {'N': '1'}}}}]}, region)
        self.check('transaction survives in namespace ' + marker,
                   tx['Responses'][0]['Item']['marker']['S'] == marker, tx)

    def vectors(self):
        table = 'extenddb-vectors'
        self.aws('create-table', {'TableName': table, 'BillingMode': 'PAY_PER_REQUEST',
            'AttributeDefinitions': [{'AttributeName': 'pk', 'AttributeType': 'S'}],
            'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}],
            'VectorIndexes': [{'IndexName': 'semantic', 'VectorAttribute': {'AttributeName': 'embedding'},
                               'Dimensions': 3, 'DistanceFunction': 'COSINE', 'Projection': {'ProjectionType': 'ALL'}}]})
        self.ready_table(table, 'us-east-1')
        for key, vector in [('near', [1, 0, 0]), ('far', [0, 1, 0])]:
            self.aws('put-item', {'TableName': table, 'Item': {'pk': {'S': key},
                'embedding': {'L': [{'N': str(n)} for n in vector]}}})
        request = {'TableName': table, 'IndexName': 'semantic',
                   'SearchVector': [{'N': '1'}, {'N': '0'}, {'N': '0'}], 'TopK': 2}
        deadline = time.monotonic() + 30
        result = {}
        while time.monotonic() < deadline:
            result = self.aws('search-vectors', request)
            if len(result.get('SearchResults', [])) == 2:
                break
            time.sleep(0.1)
        rows = result.get('SearchResults', [])
        self.check('real SDK SearchVectors returns expected cosine ranking',
                   [r['Item']['pk']['S'] for r in rows] == ['near', 'far']
                   and all(math.isfinite(r['Score']) for r in rows)
                   and abs(rows[0]['Score']) < 0.0001 and abs(rows[1]['Score'] - 1) < 0.0001, result)
        self.aws('search-vectors', dict(request, SearchVector=[{'N': '1'}]), error='ValidationException')
        self.aws('delete-table', {'TableName': table})

    def install(self):
        with self.args.worker.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        command = [str(self.args.binary.resolve()), 'component', 'install', 'extenddb',
                   '--source', str(self.args.worker.resolve()), '--sha256', digest]
        result = subprocess.run(command, env=self.env, capture_output=True, text=True, timeout=40)
        self.check('install explicitly pinned local worker with product CLI', result.returncode == 0,
                   {'sha256': digest, 'exitCode': result.returncode, 'stderr': result.stderr[-1500:]})

    def encrypted_files(self):
        directory = Path(str(self.work / 'state.sqlite3') + '.extenddb')
        files = sorted(directory.glob('*/*.sqlite3'))
        self.check('four account/region SQLite files exist in shared state namespace', len(files) == 4,
                   {'files': [str(p.relative_to(self.work)) for p in files]})
        needle = self.sentinel.encode()
        for path in files:
            with path.open('rb') as stream:
                header = stream.read(16)
                stream.seek(0)
                plaintext = False
                tail = b''
                while block := stream.read(1024 * 1024):
                    plaintext |= needle in tail + block
                    tail = block[-len(needle):]
            self.check('SQLite file is encrypted: ' + str(path.relative_to(directory)),
                       len(header) == 16 and header != b'SQLite format 3\x00' and not plaintext,
                       {'bytes': path.stat().st_size, 'sqlitePlaintextHeader': header == b'SQLite format 3\x00',
                        'plaintextSentinelFound': plaintext})

    def wrong_key(self):
        environment = dict(self.server_env,
                           LOCALLYCLOUD_KMS_MASTER_KEY=base64.b64encode(b'\x52' * 32).decode())
        result = subprocess.run([str(self.args.binary.resolve())], env=environment,
                                capture_output=True, text=True, timeout=20)
        (self.work / 'wrong-master-key.log').write_text(result.stdout + result.stderr)
        self.check('restart with wrong master key fails before serving', result.returncode != 0,
                   {'exitCode': result.returncode, 'log': 'wrong-master-key.log'})

    def unavailable_component(self):
        installed = self.env['LOCALLYCLOUD_COMPONENTS_DIR']
        self.env['LOCALLYCLOUD_COMPONENTS_DIR'] = str(self.work / 'missing-components')
        try:
            self.start('000000000000')
            self.aws('list-tables', {}, error='InternalServerError', message='not installed')
        finally:
            self.stop()
            self.env['LOCALLYCLOUD_COMPONENTS_DIR'] = installed

    def run(self):
        try:
            self.install()
            self.report['cliVersion'] = subprocess.run(['aws', '--version'], capture_output=True, text=True, check=True).stdout.strip()
            for account in ('000000000000', '111111111111'):
                self.start(account)
                for region in ('us-east-1', 'us-east-2'):
                    self.seed(account, region)
                if account == '000000000000' and self.args.model:
                    self.vectors()
                if account == '000000000000':
                    self.idle_shutdown()
                self.stop()
            self.encrypted_files()
            self.wrong_key()
            for account in ('000000000000', '111111111111'):
                self.start(account)
                for region in ('us-east-1', 'us-east-2'):
                    self.verify_rows(account, region)
                    self.aws('delete-table', {'TableName': 'extenddb-contract'}, region)
                self.stop()
            self.unavailable_component()
            if not self.args.model:
                self.report['pending'] = ['SearchVectors requires the pinned official model']
            self.report['verified'] = True
        except Exception as error:
            self.report['failure'] = str(error)
        finally:
            self.stop()
            self.report['verified'] = self.report['verified'] and not self.report['cleanup']
            self.save()
        print(json.dumps(self.report, indent=2))
        return 0 if self.report['verified'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--worker', required=True, type=Path, help='built official-engine worker to install by SHA-256')
    parser.add_argument('--work', required=True, type=Path, help='new private directory on disk')
    parser.add_argument('--model', type=Path, help='pinned official DynamoDB service-2.json; no downloads performed')
    args = parser.parse_args()
    raise SystemExit(Probe(args).run())


if __name__ == '__main__':
    main()
