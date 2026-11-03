/* Test fixtures: an illustrative design and a server-shaped stack snapshot. Not shipped. */
import * as M from '../model.js';

export function demo() {
  const nodes = [
    ['client', 'Browser / client', 'External actor', 'external', 45, 150],
    ['bucket', 'Documents', 'AWS::S3::Bucket', 'application', 300, 150],
    ['rule', 'Object-created rule', 'AWS::Events::Rule', 'application', 555, 150],
    ['queue', 'Presentation queue', 'AWS::SQS::Queue', 'application', 810, 150],
    ['worker', 'Presentation worker', 'AWS::Lambda::Function', 'application', 810, 340],
    ['table', 'Delivery projection', 'AWS::DynamoDB::Table', 'data', 555, 340],
  ].map(([id, name, type, zone, x, y]) => ({ id, name, type, zone, x, y, status: 'ILLUSTRATIVE' }));
  const edges = [['client', 'bucket', 'upload'], ['bucket', 'rule', 'object created'], ['rule', 'queue', 'enqueue'], ['queue', 'worker', 'consume'], ['worker', 'table', 'project']]
    .map(([from, to, label], i) => ({ id: 'demo-' + i, from, to, label, kind: 'proposed', evidence: 'Illustrative design, not read from a running emulator' }));
  return M.validate({ version: 1, id: 'demo:delivery', title: 'Serverless delivery', source: 'demo', scope: {}, nodes, edges,
    zones: [{ id: 'external', name: 'External clients' }, { id: 'application', name: 'Application — reviewer assigned' }, { id: 'data', name: 'Data — reviewer assigned' }], threats: [] });
}

/** The shape returned by POST /_locallycloud/views/architecture/topology. */
export function snapshot({ region = 'us-east-1', only } = {}) {
  const resources = [
    ['Queue', 'AWS::SQS::Queue', 'CREATE_COMPLETE', 'http://localhost/q'],
    ['Worker', 'AWS::Lambda::Function', 'CREATE_COMPLETE', 'worker-physical'],
    ['Table', 'AWS::DynamoDB::Table', 'CREATE_COMPLETE', 'ledger'],
    ['Mapping', 'AWS::Lambda::EventSourceMapping', 'CREATE_COMPLETE', 'uuid'],
    ['Rule', 'AWS::Events::Rule', 'CREATE_COMPLETE', 'rule'],
    ['Other', 'AWS::Lambda::Function', 'CREATE_COMPLETE', 'other'],
  ].filter(([id]) => !only || only.includes(id));
  const present = new Set(resources.map(([id]) => id));
  const edges = [
    ['configured:Queue:Worker:event mapping', 'Queue', 'Worker', 'configured', 'event mapping', 'Mapping.Properties.EventSourceArn → FunctionName'],
    ['configured:Rule:Queue:target', 'Rule', 'Queue', 'configured', 'target', 'Rule.Properties.Targets[].Arn (configuration only; delivery not observed)'],
    ['dependency:Table:Worker:reference', 'Table', 'Worker', 'dependency', 'reference', 'Worker.Properties contains Ref/GetAtt/Sub; data flow is unverified'],
    ['dependency:Worker:Other:reference', 'Worker', 'Other', 'dependency', 'reference', 'Other.Properties contains Ref/GetAtt/Sub; data flow is unverified'],
    ['dependency:Table:Other:DependsOn', 'Table', 'Other', 'dependency', 'DependsOn', 'Provisioning order only'],
  ].filter(([, from, to]) => present.has(from) && present.has(to));
  return {
    version: 1, documentType: 'snapshot', source: 'snapshot', id: 'stack-1', title: 'example',
    scope: { account: '000000000000', region, stack: 'stack-1', capturedAt: '2026-11-03T00:00:00Z' },
    zones: [], threats: [],
    nodes: resources.map(([id, type, status, physicalId], i) => ({ id, name: id, type, status, physicalId, zone: '', x: 60 + (i % 4) * 260, y: 100 + Math.floor(i / 4) * 160 })),
    edges: edges.map(([id, from, to, kind, label, evidence]) => ({ id, from, to, kind, label, evidence })),
    unresolved: present.has('Rule') ? [{ target: 'Rule', property: 'EventBusName', reason: 'External, default or unresolved event bus' }] : [],
  };
}
