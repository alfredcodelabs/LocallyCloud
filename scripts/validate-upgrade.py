#!/usr/bin/env python3
"""Check two existing binaries against disposable state through the AWS CLI."""
import argparse
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import signal
import subprocess
import time
import urllib.error
import urllib.request


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def identity(binary):
    with binary.open('rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    version = subprocess.check_output([str(binary), '--version'], text=True, timeout=10).strip()
    return {'path': str(binary), 'version': version, 'sha256': digest}


@contextlib.contextmanager
def server(binary, work, environment, phase, timeout):
    log = work / (phase + '.log')
    started = time.monotonic()
    with log.open('wb') as output:
        process = subprocess.Popen([str(binary)], env=environment, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            endpoint = None
            with log.open() as reader:
                while time.monotonic() - started < timeout:
                    require(process.poll() is None, f'{phase}: server exited; inspect {log}')
                    for line in reader:
                        try:
                            fields = json.loads(line).get('fields', {})
                        except json.JSONDecodeError:
                            continue
                        if fields.get('message') == 'locallycloud listening':
                            address = fields.get('addr', '')
                            require(address.startswith('127.0.0.1:'), 'Unexpected listen address')
                            endpoint = 'http://' + address
                    if endpoint:
                        try:
                            with urllib.request.urlopen(endpoint + '/_locallycloud/health', timeout=1) as response:
                                ready = response.status == 200
                        except (OSError, urllib.error.URLError):
                            ready = False
                        if ready:
                            break
                    time.sleep(0.05)
                else:
                    raise RuntimeError(f'{phase}: readiness timed out; inspect {log}')
            yield endpoint, process.pid, time.monotonic() - started
            return
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                    raise RuntimeError(f'{phase}: server required forced termination')


class Client:
    def __init__(self, endpoint, environment):
        self.endpoint, self.environment = endpoint, environment
        self.calls = 0

    def call(self, region, service, operation, *positionals, **parameters):
        command = ['aws', '--endpoint-url', self.endpoint, '--region', region,
                   '--no-cli-pager', '--output', 'json', '--cli-connect-timeout', '2',
                   '--cli-read-timeout', '15', service, operation]
        for name, value in parameters.items():
            command += ['--' + name.replace('_', '-'),
                        json.dumps(value) if isinstance(value, (dict, list)) else str(value)]
        command += [str(value) for value in positionals]
        result = subprocess.run(command, env=self.environment, text=True, capture_output=True, timeout=30)
        self.calls += 1
        require(result.returncode == 0, f'{service} {operation}: {result.stderr[-2000:]}')
        return json.loads(result.stdout) if result.stdout.strip() else {}


def resources(client, work, region, names, expected, seed=False):
    bucket, table, queue, group = names
    call = lambda service, operation, *args, **kwargs: client.call(region, service, operation, *args, **kwargs)
    payload = work / (region + '-payload')
    payload.write_bytes(expected.encode())
    if seed:
        args = {} if region == 'us-east-1' else {'create_bucket_configuration': {'LocationConstraint': region}}
        call('s3api', 'create-bucket', bucket=bucket, **args)
        call('s3api', 'put-bucket-versioning', bucket=bucket, versioning_configuration={'Status': 'Enabled'})
        call('dynamodb', 'create-table', table_name=table, billing_mode='PAY_PER_REQUEST',
             attribute_definitions=[{'AttributeName': 'id', 'AttributeType': 'S'}],
             key_schema=[{'AttributeName': 'id', 'KeyType': 'HASH'}])
        call('sqs', 'create-queue', queue_name=queue)
        call('logs', 'create-log-group', log_group_name=group)
        call('logs', 'create-log-stream', log_group_name=group, log_stream_name='upgrade')
    else:
        received = work / (region + '-received')
        call('s3api', 'get-object', received, bucket=bucket, key='proof')
        require(received.read_bytes() == expected.encode(), f'{region}: S3 body changed')
        version = call('s3api', 'get-bucket-versioning', bucket=bucket)
        require(version.get('Status') == 'Enabled', f'{region}: S3 versioning changed')
        item = call('dynamodb', 'get-item', table_name=table, key={'id': {'S': 'proof'}})
        require(item.get('Item', {}).get('value') == {'S': expected}, f'{region}: DynamoDB item changed')
        events = call('logs', 'filter-log-events', log_group_name=group).get('events', [])
        require(any(e.get('message') == expected for e in events), f'{region}: log event missing')
    url = call('sqs', 'get-queue-url', queue_name=queue)['QueueUrl']
    if not seed:
        messages = call('sqs', 'receive-message', queue_url=url, max_number_of_messages=1).get('Messages', [])
        require(len(messages) == 1 and messages[0]['Body'] == expected, f'{region}: SQS message changed')
        call('sqs', 'delete-message', queue_url=url, receipt_handle=messages[0]['ReceiptHandle'])
    return call, url, payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--previous', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--work-dir', type=Path, required=True, help='New private directory on disk; never existing user state')
    args = parser.parse_args()
    previous, candidate, work = args.previous.resolve(), args.candidate.resolve(), args.work_dir.resolve()
    report = {'previous': identity(previous), 'candidate': identity(candidate),
              'platform': platform.platform(), 'architecture': platform.machine(),
              'regions': ['us-east-1', 'us-east-2'], 'services': ['s3', 'dynamodb', 'sqs', 'logs', 'iam'],
              'dynamodb_engine': 'native', 'oci_tested': False, 'phases': [], 'passed': False}
    require(report['previous']['sha256'] != report['candidate']['sha256'],
            'Choose different builds; identical binaries only test restarts.')
    filesystem = subprocess.check_output(['findmnt', '-n', '-o', 'FSTYPE', '--target', str(work.parent)], text=True).strip()
    require(filesystem not in {'tmpfs', 'ramfs'}, 'Choose a disk-backed work directory')
    work.mkdir(mode=0o700)
    key = base64.b64encode(secrets.token_bytes(32)).decode()
    keyfile = work / 'kms.key'
    keyfile.write_text(key)
    keyfile.chmod(0o600)
    env = {k: os.environ[k] for k in ['PATH', 'LANG', 'LC_ALL'] if k in os.environ}
    env.update({'HOME': str(work / 'home'), 'XDG_CACHE_HOME': str(work / 'cache'),
                'XDG_DATA_HOME': str(work / 'data'), 'XDG_CONFIG_HOME': str(work / 'config'),
                'LOCALLYCLOUD_HOST': '127.0.0.1', 'LOCALLYCLOUD_PORT': '0',
                'LOCALLYCLOUD_STATE_DB': str(work / 'state.sqlite3'),
                'LOCALLYCLOUD_WORK_DIR': str(work / 'lambda'),
                'LOCALLYCLOUD_KMS_MASTER_KEY': key,
                'LOCALLYCLOUD_DYNAMODB_ENGINE': 'native', 'LOCALLYCLOUD_IAM_ENFORCEMENT': 'permissive',
                'LOCALLYCLOUD_LEGACY_BACKEND_URL': 'http://127.0.0.1:1',
                'AWS_ACCESS_KEY_ID': 'test', 'AWS_SECRET_ACCESS_KEY': 'test',
                'AWS_EC2_METADATA_DISABLED': 'true', 'AWS_CONFIG_FILE': str(work / 'aws-config'),
                'AWS_SHARED_CREDENTIALS_FILE': str(work / 'aws-credentials'), 'RUST_LOG': 'info'})
    nonce = secrets.token_hex(5)
    names = {r: [f'upgrade-{nonce}-{r}-{kind}' for kind in ['bucket', 'table', 'queue', 'logs']] for r in report['regions']}
    role = 'upgrade-' + nonce
    try:
        for phase, binary, expected in [('previous', previous, 'before-upgrade'),
                                        ('candidate', candidate, 'before-upgrade'),
                                        ('restart', candidate, 'after-upgrade')]:
            with server(binary, work, env, phase, 60) as (endpoint, pid, startup):
                client = Client(endpoint, env)
                begun = time.monotonic()
                for region in report['regions']:
                    call, url, payload = resources(client, work, region, names[region], expected, seed=phase == 'previous')
                    if phase != 'restart':
                        new_value = 'before-upgrade' if phase == 'previous' else 'after-upgrade'
                        payload.write_text(new_value)
                        call('s3api', 'put-object', bucket=names[region][0], key='proof', body=str(payload))
                        call('dynamodb', 'put-item', table_name=names[region][1], item={'id': {'S': 'proof'}, 'value': {'S': new_value}})
                        call('sqs', 'send-message', queue_url=url, message_body=new_value)
                        call('logs', 'put-log-events', log_group_name=names[region][3], log_stream_name='upgrade',
                             log_events=[{'timestamp': int(time.time() * 1000), 'message': new_value}])
                    if phase != 'previous':
                        versions = call('s3api', 'list-object-versions', bucket=names[region][0]).get('Versions', [])
                        require(len(versions) == 2, f'{region}: S3 version history was not preserved')
                        for version in versions:
                            received = work / (region + '-version')
                            call('s3api', 'get-object', received, bucket=names[region][0], key='proof', version_id=version['VersionId'])
                            value = 'after-upgrade' if version['IsLatest'] else 'before-upgrade'
                            require(received.read_text() == value, f'{region}: historical S3 body changed')
                if phase == 'previous':
                    client.call('us-east-1', 'iam', 'create-role', role_name=role, description='upgrade-proof',
                                assume_role_policy_document={'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]})
                else:
                    result = client.call('us-east-1', 'iam', 'get-role', role_name=role)
                    require(result['Role'].get('Description') == 'upgrade-proof', 'IAM role changed')
                memory = {}
                for line in Path(f'/proc/{pid}/status').read_text().splitlines():
                    if line.startswith(('VmRSS:', 'VmHWM:')):
                        name, value = line.split(':', 1)
                        memory[name + '_kib'] = int(value.split()[0])
                report['phases'].append({'name': phase, 'startup_seconds': round(startup, 3),
                                         'validation_seconds': round(time.monotonic() - begun, 3),
                                         'api_calls': client.calls, **memory})
            print(phase + ': PASS', flush=True)
        report['passed'] = True
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        report['error'] = str(error) or 'Interrupted'
    finally:
        (work / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    require(report['passed'], f"Upgrade validation failed; inspect {work / 'report.json'}")
    print('Report: ' + str(work / 'report.json'))


def interrupted(_signal, _frame):
    raise KeyboardInterrupt


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, interrupted)
    main()
