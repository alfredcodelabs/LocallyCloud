#!/usr/bin/env python3
"""Exercise official managed runtime images through the product CLI and AWS CLI."""
import argparse
import base64
import os
import re
import signal
import time
import json
from pathlib import Path
import subprocess
import zipfile

NODE = """let count=0;exports.handler=async(e)=>{console.log('runtime-probe');if(e.fail)throw new Error('deliberate-provider-error');if(e.sleep)await new Promise(r=>setTimeout(r,10000));return {count:++count,version:process.version,value:e.value};};"""
PYTHON = """import sys,time
count=0
def handler(event,context):
 global count
 print('runtime-probe')
 if event.get('fail'): raise ValueError('deliberate-provider-error')
 if event.get('sleep'): time.sleep(10)
 count+=1
 return {'count':count,'version':sys.version,'value':event.get('value')}
"""
RUBY = """require 'json'
require 'aws-sdk-s3'
$count = 0
def handler(event:, context:)
 puts 'runtime-probe'
 raise 'deliberate-provider-error' if event['fail']
 sleep 10 if event['sleep']
 $count += 1
 {count: $count, version: RUBY_VERSION, sdk: Aws::S3::GEM_VERSION, value: event['value']}
end
"""

class Families:
    def __init__(self, args):
        self.args = args
        self.work = args.work.resolve()
        self.work.mkdir(parents=True, exist_ok=False, mode=0o700)
        pinned = self.work / 'locallycloud'
        os.link(args.binary.resolve(), pinned)
        self.args.binary = pinned
        self.store = args.store.resolve() if args.store else self.work / 'catalog/store'
        self.report = {'cases': [], 'verified': False}
        self.server = self.endpoint = self.function = self.role = self.log = None
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(('LOCALLYCLOUD_', 'LOCALSTACK_', 'AWS_'))}
        self.env.update(XDG_CACHE_HOME=str(self.work / 'cache'),
                        XDG_DATA_HOME=str(self.work / 'data'),
                        XDG_CONFIG_HOME=str(self.work / 'config'))
        self.aws_env = dict(self.env, AWS_ACCESS_KEY_ID='test', AWS_SECRET_ACCESS_KEY='test',
                            AWS_DEFAULT_REGION='us-east-1', AWS_CONFIG_FILE='/dev/null',
                            AWS_SHARED_CREDENTIALS_FILE='/dev/null', AWS_EC2_METADATA_DISABLED='true', AWS_PAGER='')

    def command(self, *arguments, timeout=20):
        command = [str(self.args.binary), 'runtime', *map(str, arguments), '--directory', str(self.store)]
        started = time.monotonic()
        output = subprocess.run(command, env=self.env, text=True, capture_output=True, timeout=timeout)
        return {'arguments': list(map(str, arguments)), 'exitCode': output.returncode,
                'elapsedSeconds': round(time.monotonic() - started, 3),
                'stdout': output.stdout, 'stderr': output.stderr}

    def check(self, name, passed, observation):
        self.report['cases'].append({'name': name, 'verified': bool(passed), 'observation': observation})
        self.save()
        if not passed:
            raise AssertionError(name)

    def save(self):
        (self.work / 'results.json').write_text(json.dumps(self.report, indent=2) + '\n')

    def json_command(self, *arguments, **options):
        result = self.command(*arguments, '--json', **options)
        parsed = None
        if result['exitCode'] == 0:
            try:
                parsed = json.loads(result['stdout'])
            except json.JSONDecodeError:
                pass
        return (result, parsed)

    def aws(self, service, operation, *arguments):
        result = subprocess.run(['aws', '--endpoint-url', self.endpoint, '--region', 'us-east-1', '--output', 'json', '--cli-binary-format', 'raw-in-base64-out', '--cli-read-timeout', '60', service, operation, *map(str, arguments)], env=self.aws_env, capture_output=True, text=True, timeout=70)
        if result.returncode:
            raise RuntimeError(f'{service} {operation}: {result.stderr[-2000:]}')
        return json.loads(result.stdout) if result.stdout.strip() else {}

    def start_server(self):
        data = self.work / 'server-data'
        data.mkdir(mode=448)
        environment = dict(self.env, LOCALLYCLOUD_KMS_MASTER_KEY=base64.b64encode(b'3' * 32).decode(), LOCALLYCLOUD_STATE_DB=str(data / 'state.sqlite3'), LOCALLYCLOUD_HOST='127.0.0.1', LOCALLYCLOUD_PORT='0', LOCALLYCLOUD_RUNTIME='youki', LOCALLYCLOUD_IAM_ENFORCEMENT='permissive', LOCALLYCLOUD_RUNTIME_PACKS_DIR=str(self.store), LOCALLYCLOUD_WORK_DIR=str(self.work / 'server-work'), RUST_LOG='info')
        self.log = (self.work / 'server.log').open('w')
        self.server = subprocess.Popen([str(self.args.binary.resolve())], env=environment, stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            text = (self.work / 'server.log').read_text(errors='replace')
            for line in text.splitlines():
                if 'locallycloud listening' in line:
                    match = re.search('127\\.0\\.0\\.1:(\\d+)', line)
                    if match:
                        self.endpoint = 'http://127.0.0.1:' + match.group(1)
                        self.check('real server binds ephemeral endpoint with private state', self.server.poll() is None, {'endpoint': self.endpoint})
                        return
            if self.server.poll() is not None:
                raise RuntimeError('private server exited before readiness; see server.log')
            time.sleep(0.05)
        raise RuntimeError('private server readiness timeout; see server.log')

    def cleanup(self):
        errors = []
        if self.server and self.server.poll() is None:
            for service, operation, option, name in [('lambda', 'delete-function', '--function-name', self.function), ('iam', 'delete-role', '--role-name', self.role)]:
                if name:
                    try:
                        self.aws(service, operation, option, name)
                    except Exception as error:
                        errors.append(str(error))
            self.server.send_signal(signal.SIGTERM)
            try:
                self.server.wait(timeout=40)
            except subprocess.TimeoutExpired:
                self.server.kill()
                self.server.wait(timeout=10)
                errors.append('server did not drain gracefully')
        if self.server and self.server.returncode != 0:
            errors.append('server exit status ' + str(self.server.returncode))
        if self.log:
            self.log.close()
        self.report['cleanup'] = {'errors': errors, 'serverExitCode': self.server.returncode if self.server else None}
        return not errors

    def run(self):
        try:
            self.live()
            self.report['verified'] = True
        except Exception as error:
            self.report['failure'] = str(error)
        finally:
            if not self.cleanup():
                self.report['verified'] = False
            self.save()
            print(json.dumps(self.report, indent=2))
        return 0 if self.report['verified'] else 1

    def result(self, payload):
        output = self.work / 'response.json'
        meta = self.aws('lambda', 'invoke', '--function-name', self.function,
                        '--payload', json.dumps(payload), output)
        return meta, json.loads(output.read_text())

    def live(self):
        runtimes = self.args.runtimes
        for runtime in runtimes:
            result, data = self.json_command('install', runtime, timeout=900)
            self.check(runtime + ' official image installed', result['exitCode'] == 0, result)
        self.start_server()
        self.role = 'runtime-families-role'
        trust = {'Version':'2012-10-17','Statement':[{'Effect':'Allow','Principal':{'Service':'lambda.amazonaws.com'},'Action':'sts:AssumeRole'}]}
        role = self.aws('iam','create-role','--role-name',self.role,'--assume-role-policy-document',json.dumps(trust))['Role']['Arn']
        for runtime in runtimes:
            archive = self.work / (runtime + '.zip')
            if runtime.startswith('dotnet'):
                archive.write_bytes((self.args.dotnet_fixtures / (runtime + '.zip')).read_bytes())
                handler = 'Probe::Probe.Function::Handle'
            else:
                name, source = ('index.js', NODE) if runtime.startswith('nodejs') else (('index.py', PYTHON) if runtime.startswith('python') else ('index.rb', RUBY))
                with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
                    z.writestr(name,source)
                handler = 'index.handler'
            self.function = 'runtime-family-' + runtime.replace('.','-')
            self.aws('lambda','create-function','--function-name',self.function,'--runtime',runtime,'--handler',handler,
                     '--role',role,'--timeout',3,'--memory-size',512,'--zip-file','fileb://' + str(archive))
            first_meta, first = self.result({'value':42})
            second_meta, second = self.result({'value':43})
            if 'FunctionError' in first_meta or 'FunctionError' in second_meta:
                logs = self.aws('logs','filter-log-events','--log-group-name','/aws/lambda/' + self.function)
                (self.work / (runtime + '-failure-logs.json')).write_text(json.dumps(logs, indent=2))
            self.check(runtime + ' cold and warm invocation', 'FunctionError' not in first_meta and 'FunctionError' not in second_meta and first.get('count') == 1 and second.get('count') == 2 and first.get('value') == 42 and second.get('value') == 43, {'first':first,'second':second,'metadata':first_meta})
            meta, error = self.result({'fail':True})
            self.check(runtime + ' handler error propagates', meta.get('FunctionError') == 'Unhandled' and 'deliberate-provider-error' in json.dumps(error), {'meta':meta,'error':error})
            meta, response = self.result({'value':44})
            self.check(runtime + ' recovers after handler error', 'FunctionError' not in meta and response.get('value') == 44, response)
            self.aws('lambda','update-function-configuration','--function-name',self.function,'--timeout',1)
            meta, error = self.result({'sleep':True})
            self.check(runtime + ' timeout propagates', bool(meta.get('FunctionError')) and ('timed out' in json.dumps(error).lower() or 'timeout' in json.dumps(error).lower()), {'meta':meta,'error':error})
            self.aws('lambda','update-function-configuration','--function-name',self.function,'--timeout',3)
            meta, response = self.result({'value':45})
            self.check(runtime + ' cold recovery after timeout', 'FunctionError' not in meta and response.get('value') == 45, response)
            self.aws('lambda','delete-function','--function-name',self.function)
            self.function = None
            checked, data = self.json_command('check-updates',runtime,timeout=90)
            self.check(runtime + ' update metadata resolves correct image tag', checked['exitCode'] == 0 and data is not None, checked)
        self.aws('iam','delete-role','--role-name',self.role)
        self.role = None

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--work',type=Path,required=True)
    parser.add_argument('--dotnet-fixtures',type=Path)
    parser.add_argument('--store',type=Path)
    parser.add_argument('--runtimes',nargs='+',required=True)
    raise SystemExit(Families(parser.parse_args()).run())
