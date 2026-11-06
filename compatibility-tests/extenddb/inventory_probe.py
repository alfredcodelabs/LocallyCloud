#!/usr/bin/env python3
"""Check five-region inventory and safe component removal against real workers."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.dont_write_bytecode = True
from probe import Probe


class InventoryProbe(Probe):
    def remove_component(self):
        return subprocess.run([str(self.args.binary.resolve()), 'component', 'remove', 'extenddb'],
                              env=self.env, capture_output=True, text=True, timeout=20)

    def run(self):
        regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'eu-west-1']
        try:
            self.install()
            self.start('000000000000')
            for region in regions:
                self.aws('create-table', {'TableName': 'inventory-contract', 'BillingMode': 'PAY_PER_REQUEST',
                    'AttributeDefinitions': [{'AttributeName': 'pk', 'AttributeType': 'S'}],
                    'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}]}, region)
                self.ready_table('inventory-contract', region)
                self.aws('put-item', {'TableName': 'inventory-contract',
                    'Item': {'pk': {'S': region}, 'value': {'S': 'retained-after-component-remove'}}}, region)
            self.stop()
            self.start('000000000000')
            request = urllib.request.Request(self.endpoint + '/_locallycloud/explore/regions',
                data=json.dumps({'profile': 'instance', 'region': 'us-east-1'}).encode(),
                headers={'Content-Type': 'application/json'}, method='POST')
            started = time.monotonic()
            try:
                with urllib.request.urlopen(request, timeout=90) as response:
                    inventory = json.load(response)
            except urllib.error.HTTPError as error:
                raise RuntimeError(f'inventory HTTP {error.code}: {error.read(4096).decode(errors="replace")}') from error
            actual = inventory.get('services', {}).get('dynamodb', {}).get('regions', [])
            self.check('dashboard inventory includes five populated regions beyond four-worker limit',
                       set(actual) == set(regions),
                       {'regions': actual, 'seconds': round(time.monotonic() - started, 3)})
            self.sample_workers()
            self.check('observed inventory workers stay within four-process budget',
                       self.report['measurements']['peakObservedWorkers'] <= 4,
                       {'observedWorkers': self.children()})
            lock = self.work / 'components/.extenddb-usage.lock'
            inode = lock.stat().st_ino
            result = self.remove_component()
            self.check('component removal rejects a worker currently in use',
                       result.returncode != 0 and 'in use' in result.stderr,
                       {'exitCode': result.returncode, 'stderr': result.stderr.strip()})
            self.stop()
            directory = Path(str(self.work / 'state.sqlite3') + '.extenddb')
            files = sorted(directory.glob('*/*.sqlite3'))
            before = {str(p.relative_to(directory)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
            result = self.remove_component()
            after = {str(p.relative_to(directory)): hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in sorted(directory.glob('*/*.sqlite3'))}
            self.check('component removal succeeds after shutdown and preserves five databases',
                       result.returncode == 0 and len(before) == 5 and before == after,
                       {'exitCode': result.returncode, 'databaseFiles': sorted(after), 'unchanged': before == after})
            self.check('removal preserves stable usage lock inode and removes component binaries',
                       lock.is_file() and lock.stat().st_ino == inode
                       and not (self.work / 'components/extenddb').exists(),
                       {'usageLockPreserved': lock.exists(), 'componentRemoved': not (self.work / 'components/extenddb').exists()})
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
    parser.add_argument('--worker', required=True, type=Path)
    parser.add_argument('--work', required=True, type=Path)
    args = parser.parse_args()
    args.model = None
    raise SystemExit(InventoryProbe(args).run())


if __name__ == '__main__':
    main()
