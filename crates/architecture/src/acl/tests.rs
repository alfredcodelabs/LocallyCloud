//! ACL behavior against canned AWS replies (no network, no ports).

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use async_trait::async_trait;
use locallycloud_core::views::architecture::{
    ArchitectureSource, AwsRead, AwsReader, AwsReply, ReadError, Scope, TopologyError,
};
use serde_json::{json, Value};

use super::{CloudFormationTopology, Limits};

const ACCOUNT: &str = "000000000000";
const REGION: &str = "us-east-1";
const STACK_ID: &str = "arn:aws:cloudformation:us-east-1:000000000000:stack/demo/1";

/// What the fake saw: service, operation (target, Action or REST path) and parameters.
struct Seen {
    service: &'static str,
    op: String,
    json: Value,
}

type Reply = Result<(u16, String), ReadError>;
type Handler = dyn Fn(&Seen) -> Option<Reply> + Send + Sync;

struct FakeAws {
    template: Value,
    resources: Vec<(String, String, String, String)>,
    stack_id: String,
    handler: Box<Handler>,
    calls: Mutex<Vec<String>>,
    in_flight: AtomicUsize,
    peak: AtomicUsize,
}

impl FakeAws {
    fn new(template: Value, resources: &[(&str, &str, &str)]) -> Self {
        Self {
            template,
            resources: resources
                .iter()
                .map(|(logical, ty, physical)| {
                    (
                        (*logical).to_owned(),
                        (*ty).to_owned(),
                        (*physical).to_owned(),
                        "CREATE_COMPLETE".to_owned(),
                    )
                })
                .collect(),
            stack_id: STACK_ID.into(),
            handler: Box::new(|_| None),
            calls: Mutex::new(Vec::new()),
            in_flight: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        }
    }

    fn with(mut self, handler: impl Fn(&Seen) -> Option<Reply> + Send + Sync + 'static) -> Self {
        self.handler = Box::new(handler);
        self
    }

    fn cloudformation(&self, seen: &Seen) -> Reply {
        let body = match seen.op.as_str() {
            "DescribeStacks" => format!(
                "<Stacks><member><StackId>{}</StackId><StackName>demo</StackName>\
                 <StackStatus>CREATE_COMPLETE</StackStatus><Parameters><member>\
                 <ParameterKey>BusName</ParameterKey><ParameterValue>acct</ParameterValue>\
                 </member></Parameters></member></Stacks>",
                self.stack_id
            ),
            "DescribeStackResources" => {
                let members: String = self
                    .resources
                    .iter()
                    .map(|(logical, ty, physical, status)| {
                        format!(
                            "<member><LogicalResourceId>{logical}</LogicalResourceId>\
                             <PhysicalResourceId>{}</PhysicalResourceId>\
                             <ResourceType>{ty}</ResourceType>\
                             <ResourceStatus>{status}</ResourceStatus></member>",
                            escape(physical)
                        )
                    })
                    .collect();
                format!("<StackResources>{members}</StackResources>")
            }
            "GetTemplate" => format!(
                "<TemplateBody>{}</TemplateBody>",
                escape(&self.template.to_string())
            ),
            other => panic!("unexpected CloudFormation read {other}"),
        };
        Ok((
            200,
            format!(
                "<{op}Response xmlns=\"x\"><{op}Result>{body}</{op}Result></{op}Response>",
                op = seen.op
            ),
        ))
    }
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[async_trait]
impl AwsReader for FakeAws {
    async fn read(&self, read: AwsRead) -> Result<AwsReply, ReadError> {
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        tokio::task::yield_now().await;
        let body = std::str::from_utf8(&read.body)
            .unwrap_or_default()
            .to_owned();
        let (op, json) = if let Some(target) = read.headers.get("x-amz-target") {
            let target = target.to_str().unwrap_or_default();
            let op = target
                .rsplit_once('.')
                .map_or(target, |(_, op)| op)
                .to_owned();
            (op, serde_json::from_str(&body).unwrap_or(Value::Null))
        } else if read.method == http::Method::POST {
            let form: HashMap<String, String> = body
                .split('&')
                .filter_map(|pair| pair.split_once('='))
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect();
            let op = form.get("Action").cloned().unwrap_or_default();
            (op, json!(form))
        } else {
            (read.uri.to_string(), Value::Null)
        };
        let seen = Seen {
            service: read.service,
            op,
            json,
        };
        self.calls
            .lock()
            .unwrap()
            .push(format!("{} {}", seen.service, seen.op));
        let reply = match (self.handler)(&seen) {
            Some(reply) => reply,
            None if seen.service == "cloudformation" => self.cloudformation(&seen),
            None => Ok((
                404,
                json!({"__type": "ResourceNotFoundException"}).to_string(),
            )),
        };
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        let (status, body) = reply?;
        Ok(AwsReply {
            status,
            body: body.into(),
        })
    }
}

fn scope() -> Scope {
    Scope {
        account: ACCOUNT.into(),
        region: REGION.into(),
    }
}

async fn topology(fake: &FakeAws) -> Result<Value, TopologyError> {
    CloudFormationTopology::default()
        .topology(fake, &scope(), "demo")
        .await
}

fn ok(body: Value) -> Option<Reply> {
    Some(Ok((200, body.to_string())))
}

fn has_edge(model: &Value, kind: &str, from: &str, to: &str) -> bool {
    model["edges"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["kind"] == kind && e["from"] == from && e["to"] == to)
}

fn has_gap(model: &Value, target: &str, property: &str) -> bool {
    model["unresolved"]
        .as_array()
        .unwrap()
        .iter()
        .any(|u| u["target"] == target && u["property"].as_str().unwrap().contains(property))
}

fn node<'a>(model: &'a Value, id: &str) -> &'a Value {
    model["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["id"] == id)
        .unwrap_or_else(|| panic!("node {id}"))
}

const QUEUE_URL: &str = "http://sqs.us-east-1.localhost:4566/000000000000/inbox";
const QUEUE_ARN: &str = "arn:aws:sqs:us-east-1:000000000000:inbox";
const WORKER_ARN: &str = "arn:aws:lambda:us-east-1:000000000000:function:worker";

#[tokio::test]
async fn rules_and_event_source_mappings_become_configured_edges() {
    let template = json!({"Resources": {
        "Inbox": {"Type": "AWS::SQS::Queue"},
        "Bus": {"Type": "AWS::Events::EventBus", "Properties": {"Name": "acct"}},
        "Worker": {"Type": "AWS::Lambda::Function", "Properties": {
            "Environment": {"Variables": {"SECRET": "must-not-leak"}}}},
        "Deliver": {"Type": "AWS::Events::Rule", "Properties": {
            "EventBusName": {"Ref": "Bus"}, "EventPattern": {"source": ["x"]},
            "Targets": [{"Id": "q", "Arn": {"Fn::GetAtt": ["Inbox", "Arn"]}}]}},
        "Mapping": {"Type": "AWS::Lambda::EventSourceMapping", "Properties": {
            "EventSourceArn": {"Fn::GetAtt": ["Inbox", "Arn"]}, "FunctionName": {"Ref": "Worker"}}}
    }});
    let fake = FakeAws::new(
        template,
        &[
            ("Inbox", "AWS::SQS::Queue", QUEUE_URL),
            ("Bus", "AWS::Events::EventBus", "acct"),
            ("Worker", "AWS::Lambda::Function", "worker"),
            ("Deliver", "AWS::Events::Rule", "deliver"),
            ("Mapping", "AWS::Lambda::EventSourceMapping", "uuid-1"),
        ],
    )
    .with(|seen| match seen.op.as_str() {
        "DescribeRule" if seen.json["EventBusName"] == "acct" => {
            ok(json!({"Name": "deliver", "EventBusName": "acct", "EventPattern": "{}"}))
        }
        "ListTargetsByRule" => ok(json!({"Targets": [
            {"Id": "q", "Arn": QUEUE_ARN},
            {"Id": "x", "Arn": "arn:aws:sqs:us-east-1:999999999999:foreign"}
        ]})),
        "/2015-03-31/event-source-mappings/uuid-1" => ok(json!({
            "UUID": "uuid-1", "EventSourceArn": QUEUE_ARN, "FunctionArn": WORKER_ARN})),
        _ => None,
    });
    let model = topology(&fake).await.unwrap();
    assert_eq!(model["version"], 1);
    assert_eq!(model["documentType"], "snapshot");
    assert_eq!(model["source"], "snapshot");
    assert_eq!(model["id"], STACK_ID);
    assert_eq!(model["title"], "demo");
    assert_eq!(model["scope"]["stack"], STACK_ID);
    assert_eq!(model["scope"]["account"], ACCOUNT);
    assert_eq!(model["nodes"].as_array().unwrap().len(), 5);
    assert!(has_edge(&model, "configured", "Bus", "Deliver"));
    assert!(has_edge(&model, "configured", "Deliver", "Inbox"));
    assert!(has_edge(&model, "configured", "Inbox", "Worker"));
    assert!(has_edge(&model, "dependency", "Bus", "Deliver"));
    assert!(has_edge(&model, "dependency", "Inbox", "Mapping"));
    assert!(has_gap(&model, "Deliver", "Targets[].Arn"));
    assert_eq!(node(&model, "Inbox")["physicalId"], QUEUE_URL);
    let raw = model.to_string();
    for secret in ["must-not-leak", "EventPattern", "foreign"] {
        assert!(!raw.contains(secret), "{secret} leaked");
    }
    // Environment variables are classified by name only.
    let worker = node(&model, "Worker");
    let secrets = worker["facts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == "secrets-in-environment")
        .unwrap();
    assert_eq!(secrets["value"], "suspected");
    assert!(worker["configHash"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    let edge = model["edges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["kind"] == "configured" && e["from"] == "Deliver")
        .unwrap();
    assert_eq!(edge["id"], "configured:Deliver:Inbox:target");
}

#[tokio::test]
async fn state_machine_tasks_resolve_through_nested_map_and_parallel() {
    let definition = json!({"StartAt": "Map", "States": {
        "Map": {"Type": "Map", "ItemProcessor": {"States": {
            "Invoke": {"Type": "Task", "Resource": "arn:aws:states:::lambda:invoke",
                "Parameters": {"FunctionName": WORKER_ARN, "Payload": {"SECRET": "never-export-asl"}}},
            "Query": {"Type": "Task", "Resource": "arn:aws:states:::aws-sdk:dynamodb:query",
                "Parameters": {"TableName": "ledger"}},
            "Fan": {"Type": "Parallel", "Branches": [{"States": {
                "Send": {"Type": "Task", "Resource": "arn:aws:states:::sqs:sendMessage",
                    "Parameters": {"QueueUrl": QUEUE_URL}},
                "Publish": {"Type": "Task", "Resource": "arn:aws:states:::events:putEvents",
                    "Parameters": {"Entries": [{"EventBusName": "acct"}]}},
                "Default": {"Type": "Task", "Resource": "arn:aws:states:::events:putEvents",
                    "Parameters": {"Entries": [{"Source": "x"}]}}
            }}]},
            "Missing": {"Type": "Task", "Resource": "arn:aws:states:::lambda:invoke",
                "Parameters": {"FunctionName.$": "$.dynamic"}},
            "Glue": {"Type": "Task", "Resource": "arn:aws:states:::glue:startJobRun"}
        }}}
    }});
    let template = json!({"Resources": {
        "Worker": {"Type": "AWS::Lambda::Function"},
        "Queue": {"Type": "AWS::SQS::Queue"},
        "Table": {"Type": "AWS::DynamoDB::GlobalTable"},
        "Bus": {"Type": "AWS::Events::EventBus"},
        "Machine": {"Type": "AWS::StepFunctions::StateMachine"}
    }});
    let machine_arn = "arn:aws:states:us-east-1:000000000000:stateMachine:m";
    let fake = FakeAws::new(
        template,
        &[
            ("Worker", "AWS::Lambda::Function", "worker"),
            ("Queue", "AWS::SQS::Queue", QUEUE_URL),
            ("Table", "AWS::DynamoDB::GlobalTable", "ledger"),
            ("Bus", "AWS::Events::EventBus", "acct"),
            ("Machine", "AWS::StepFunctions::StateMachine", machine_arn),
        ],
    )
    .with(move |seen| match seen.op.as_str() {
        "DescribeStateMachine" if seen.json["stateMachineArn"] == machine_arn => {
            ok(json!({"stateMachineArn": machine_arn, "definition": definition.to_string()}))
        }
        _ => None,
    });
    let model = topology(&fake).await.unwrap();
    for to in ["Worker", "Queue", "Table", "Bus"] {
        assert!(has_edge(&model, "configured", "Machine", to), "{to}");
    }
    assert!(model["edges"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["id"] == "configured:Machine:Table:dynamodb:query"));
    let gaps = model["unresolved"].as_array().unwrap();
    assert!(gaps.iter().any(|u| u["target"] == "Machine"
        && u["property"] == "Definition.Parameters.FunctionName"
        && u["reason"].as_str().unwrap().contains("Dynamic")));
    assert!(has_gap(&model, "Machine", "Definition.Resource"));
    assert!(has_gap(&model, "Machine", "Entries.EventBusName"));
    assert!(!model.to_string().contains("never-export-asl"));
    assert!(!model.to_string().contains("StartAt"));
}

#[tokio::test]
async fn rest_lambda_integrations_add_the_inferred_http_client() {
    let template = json!({"Resources": {
        "Api": {"Type": "AWS::ApiGateway::RestApi"},
        "Worker": {"Type": "AWS::Lambda::Function"},
        "Method": {"Type": "AWS::ApiGateway::Method", "Properties": {"RestApiId": {"Ref": "Api"}}},
        "Mock": {"Type": "AWS::ApiGateway::Method", "Properties": {"RestApiId": {"Ref": "Api"}}}
    }});
    let fake = FakeAws::new(
        template,
        &[
            ("Api", "AWS::ApiGateway::RestApi", "api1"),
            ("Worker", "AWS::Lambda::Function", "worker"),
            ("Method", "AWS::ApiGateway::Method", "api1:res1:POST"),
            ("Mock", "AWS::ApiGateway::Method", "api1:res1:GET"),
        ],
    )
    .with(|seen| match seen.op.as_str() {
        "/restapis/api1/resources/res1/methods/POST/integration" => ok(json!({
            "type": "AWS_PROXY",
            "uri": format!("arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/{WORKER_ARN}/invocations")
        })),
        "/restapis/api1/resources/res1/methods/GET/integration" => ok(json!({"type": "MOCK"})),
        _ => None,
    });
    let model = topology(&fake).await.unwrap();
    assert!(has_edge(&model, "configured", "Method", "Worker"));
    assert!(!has_edge(&model, "configured", "Mock", "Worker"));
    let client = node(&model, "inferred:http-client");
    assert_eq!(client["status"], "INFERRED");
    assert_eq!(client["origin"], "declared");
    assert_eq!(client["zone"], "");
    assert_eq!(
        (client["x"].as_u64(), client["y"].as_u64()),
        (Some(60), Some(260))
    );
    let proposed: Vec<_> = model["edges"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["from"] == "inferred:http-client")
        .collect();
    assert_eq!(proposed.len(), 1);
    assert_eq!(proposed[0]["kind"], "proposed");
    assert_eq!(proposed[0]["to"], "Api");
    assert!(proposed[0]["evidence"]
        .as_str()
        .unwrap()
        .contains("public exposure"));
}

#[tokio::test]
async fn bucket_notifications_resolve_local_and_record_external_destinations() {
    let template = json!({"Resources": {
        "Bucket": {"Type": "AWS::S3::Bucket"},
        "Queue": {"Type": "AWS::SQS::Queue"},
        "Worker": {"Type": "AWS::Lambda::Function"}
    }});
    let fake = FakeAws::new(
        template,
        &[
            ("Bucket", "AWS::S3::Bucket", "docs"),
            ("Queue", "AWS::SQS::Queue", QUEUE_URL),
            ("Worker", "AWS::Lambda::Function", "worker"),
        ],
    )
    .with(|seen| match seen.op.as_str() {
        "/docs?notification" => Some(Ok((
            200,
            format!(
                "<NotificationConfiguration xmlns=\"x\">\
                 <QueueConfiguration><Id>q</Id><Queue>{QUEUE_ARN}</Queue><Event>s3:ObjectCreated:*</Event></QueueConfiguration>\
                 <CloudFunctionConfiguration><Id>f</Id><CloudFunction>{WORKER_ARN}</CloudFunction></CloudFunctionConfiguration>\
                 <TopicConfiguration><Id>t</Id><Topic>arn:aws:sns:us-east-1:111111111111:elsewhere</Topic></TopicConfiguration>\
                 </NotificationConfiguration>"
            ),
        ))),
        _ => None,
    });
    let model = topology(&fake).await.unwrap();
    assert!(has_edge(&model, "configured", "Bucket", "Queue"));
    assert!(has_edge(&model, "configured", "Bucket", "Worker"));
    assert!(has_gap(
        &model,
        "Bucket",
        "NotificationConfiguration.TopicConfigurations"
    ));
    assert!(!model.to_string().contains("elsewhere"));
}

#[tokio::test]
async fn undeployed_conditional_resources_are_declared_without_flows() {
    let template = json!({"Resources": {
        "Worker": {"Type": "AWS::Lambda::Function"},
        "Optional": {"Type": "AWS::Events::Rule", "Condition": "Enabled", "Properties": {
            "Targets": [{"Arn": {"Fn::GetAtt": ["Worker", "Arn"]}}]}},
        "Declared": {"Type": "AWS::SQS::Queue"}
    }});
    let fake = FakeAws::new(template, &[("Worker", "AWS::Lambda::Function", "worker")]);
    let model = topology(&fake).await.unwrap();
    assert_eq!(
        node(&model, "Optional")["status"],
        "CONDITIONAL_NOT_RECORDED"
    );
    assert_eq!(node(&model, "Optional")["physicalId"], "");
    assert_eq!(node(&model, "Declared")["status"], "NOT_RECORDED");
    assert!(!has_edge(&model, "configured", "Optional", "Worker"));
    assert!(has_edge(&model, "dependency", "Worker", "Optional"));
    let calls = fake.calls.lock().unwrap();
    assert!(!calls.iter().any(|c| c.starts_with("events")));
}

#[tokio::test]
async fn rules_on_external_or_default_buses_are_unresolved() {
    let template = json!({"Resources": {
        "Worker": {"Type": "AWS::Lambda::Function"},
        "ExternalRule": {"Type": "AWS::Events::Rule", "Properties": {
            "EventBusName": {"Ref": "BusName"}}},
        "DefaultRule": {"Type": "AWS::Events::Rule", "Properties": {}}
    }});
    let fake = FakeAws::new(
        template,
        &[
            ("Worker", "AWS::Lambda::Function", "worker"),
            ("ExternalRule", "AWS::Events::Rule", "external-rule"),
            ("DefaultRule", "AWS::Events::Rule", "default-rule"),
        ],
    )
    .with(
        |seen| match (seen.op.as_str(), seen.json["Name"].as_str()) {
            ("DescribeRule", Some("external-rule")) if seen.json["EventBusName"] == "acct" => {
                ok(json!({"Name": "external-rule", "EventBusName": "acct"}))
            }
            ("DescribeRule", Some("default-rule")) if seen.json["EventBusName"] == "default" => {
                ok(json!({"Name": "default-rule", "EventBusName": "default"}))
            }
            ("ListTargetsByRule", Some(_)) => None,
            ("ListTargetsByRule", None) if seen.json["Rule"] == "default-rule" => ok(json!({
            "Targets": [{"Id": "w", "Arn": format!("{WORKER_ARN}:live")}]})),
            ("ListTargetsByRule", None) => ok(json!({
            "Targets": [{"Id": "e", "Arn": "arn:aws:lambda:us-west-2:000000000000:function:x"}]})),
            _ => None,
        },
    );
    let model = topology(&fake).await.unwrap();
    assert!(has_gap(&model, "ExternalRule", "EventBusName"));
    assert!(has_gap(&model, "ExternalRule", "Targets[].Arn"));
    assert!(has_gap(&model, "DefaultRule", "EventBusName"));
    assert!(has_edge(&model, "configured", "DefaultRule", "Worker"));
}

#[tokio::test]
async fn read_refusals_and_denials_are_access_denied() {
    let refused = FakeAws::new(json!({"Resources": {}}), &[])
        .with(|seen| (seen.op == "DescribeStacks").then_some(Err(ReadError::NotRead)));
    assert!(matches!(
        topology(&refused).await,
        Err(TopologyError::AccessDenied(_))
    ));
    let template = json!({"Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}}});
    let denied = FakeAws::new(template, &[("Bucket", "AWS::S3::Bucket", "docs")]).with(|seen| {
        (seen.service == "s3").then(|| {
            Ok((
                403,
                "<Error><Code>AccessDenied</Code><Message>no</Message></Error>".to_owned(),
            ))
        })
    });
    assert!(matches!(
        topology(&denied).await,
        Err(TopologyError::AccessDenied(_))
    ));
}

#[tokio::test]
async fn missing_or_foreign_stacks_are_not_found() {
    let missing = FakeAws::new(json!({"Resources": {}}), &[]).with(|seen| {
        (seen.op == "DescribeStacks").then(|| {
            Ok((
                400,
                "<ErrorResponse><Error><Type>Sender</Type><Code>ValidationError</Code>\
                 <Message>Stack with id demo does not exist</Message></Error></ErrorResponse>"
                    .to_owned(),
            ))
        })
    });
    assert!(matches!(
        topology(&missing).await,
        Err(TopologyError::NotFound(_))
    ));
    let mut foreign = FakeAws::new(json!({"Resources": {}}), &[]);
    foreign.stack_id = "arn:aws:cloudformation:us-east-1:111111111111:stack/demo/1".into();
    assert!(matches!(
        topology(&foreign).await,
        Err(TopologyError::NotFound(_))
    ));
}

#[tokio::test]
async fn limits_and_unusable_replies_are_unprocessable() {
    let resources: Vec<(String, String, String)> = (0..513)
        .map(|i| {
            (
                format!("Q{i}"),
                "AWS::SQS::Queue".to_owned(),
                format!("q{i}"),
            )
        })
        .collect();
    let borrowed: Vec<(&str, &str, &str)> = resources
        .iter()
        .map(|(a, b, c)| (a.as_str(), b.as_str(), c.as_str()))
        .collect();
    let large = FakeAws::new(json!({"Resources": {}}), &borrowed);
    assert!(matches!(
        topology(&large).await,
        Err(TopologyError::Unprocessable(_))
    ));

    let template =
        json!({"Resources": {"A": {"Type": "AWS::S3::Bucket"}, "B": {"Type": "AWS::S3::Bucket"}}});
    let budget = FakeAws::new(
        template.clone(),
        &[
            ("A", "AWS::S3::Bucket", "bucket-a"),
            ("B", "AWS::S3::Bucket", "bucket-b"),
        ],
    );
    let limited = CloudFormationTopology::new(Limits {
        reads: 4,
        ..Limits::default()
    });
    assert!(matches!(
        limited.topology(&budget, &scope(), "demo").await,
        Err(TopologyError::Unprocessable(_))
    ));

    let garbage = FakeAws::new(template, &[("A", "AWS::S3::Bucket", "bucket-a")])
        .with(|seen| (seen.service == "s3").then(|| Ok((200, "<not-xml".to_owned()))));
    assert!(matches!(
        topology(&garbage).await,
        Err(TopologyError::Unprocessable(_))
    ));

    let mut deep = json!({"Type": "AWS::S3::Bucket"});
    for _ in 0..40 {
        deep = json!({ "nested": deep });
    }
    let deep = FakeAws::new(json!({"Resources": {"A": deep}}), &[]);
    assert!(matches!(
        topology(&deep).await,
        Err(TopologyError::Unprocessable(_))
    ));
}

#[tokio::test]
async fn concurrent_reads_stay_within_the_in_flight_bound() {
    let names: Vec<(String, String, String)> = (0..40)
        .map(|i| {
            (
                format!("B{i}"),
                "AWS::S3::Bucket".to_owned(),
                format!("bucket-{i}"),
            )
        })
        .collect();
    let borrowed: Vec<(&str, &str, &str)> = names
        .iter()
        .map(|(a, b, c)| (a.as_str(), b.as_str(), c.as_str()))
        .collect();
    let fake = FakeAws::new(json!({"Resources": {}}), &borrowed).with(|seen| {
        (seen.service == "s3").then(|| Ok((200, "<NotificationConfiguration/>".to_owned())))
    });
    let model = CloudFormationTopology::new(Limits {
        in_flight: 3,
        ..Limits::default()
    })
    .topology(&fake, &scope(), "demo")
    .await
    .unwrap();
    assert_eq!(model["nodes"].as_array().unwrap().len(), 40);
    assert!(fake.peak.load(Ordering::SeqCst) <= 3);
    assert_eq!(fake.calls.lock().unwrap().len(), 43);
}

#[tokio::test]
async fn catch_send_message_is_a_dead_letter_target_with_deployed_evidence() {
    for (integration, args) in [
        ("arn:aws:states:::sqs:sendMessage", "Parameters"),
        ("arn:aws:states:::aws-sdk:sqs:sendMessage", "Arguments"),
    ] {
        for mode in ["caught", "shared", "dynamic", "redrive", "receive"] {
            let queue = match mode {
                "dynamic" => json!({"QueueUrl.$":"$.queue"}),
                _ => json!({"QueueUrl":QUEUE_URL,"MessageBody":"must-not-export-error-payload"}),
            };
            let mut definition = json!({"StartAt":"Work","States":{
                "Work":{"Type":"Task","Resource":WORKER_ARN,"Catch":[{"ErrorEquals":["States.ALL"],"Next":"Prepare"}],"Next":"Done"},
                "Done":{"Type":"Succeed"},"Prepare":{"Type":"Pass","Next":"Send"},
                "Send":{"Type":"Task","Resource":integration,"End":true}
            }});
            definition["States"]["Send"][args] = queue;
            if mode == "shared" {
                definition["States"]["Work"]["Next"] = json!("Send");
            }
            if mode == "receive" {
                definition["States"]["Send"]["Resource"] =
                    json!("arn:aws:states:::aws-sdk:sqs:receiveMessage");
            }
            let mut template = json!({"Resources":{
                "Machine":{"Type":"AWS::StepFunctions::StateMachine"},
                "Queue":{"Type":"AWS::SQS::Queue"},"Worker":{"Type":"AWS::Lambda::Function"}
            }});
            if mode == "redrive" {
                template["Resources"]["Queue"]["Properties"] = json!({"RedrivePolicy":{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:000000000000:other"}});
            }
            let fake = FakeAws::new(
                template,
                &[
                    ("Queue", "AWS::SQS::Queue", QUEUE_URL),
                    ("Worker", "AWS::Lambda::Function", WORKER_ARN),
                    ("Machine", "AWS::StepFunctions::StateMachine", "machine"),
                ],
            )
            .with(move |seen| match seen.op.as_str() {
                "DescribeStateMachine" => ok(json!({"definition":definition.to_string()})),
                _ => None,
            });
            let model = topology(&fake).await.unwrap();
            let facts = node(&model, "Queue")["facts"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|f| f["id"] == "dead-letter")
                .collect::<Vec<_>>();
            assert_eq!(facts.len(), 1);
            let expected = match mode {
                "caught" => "dead-letter-target",
                "redrive" => "configured",
                _ => "not-declared",
            };
            assert_eq!(facts[0]["value"], expected, "{integration} {mode}");
            if mode == "caught" {
                assert!(facts[0]["evidence"].as_str().unwrap().contains(&format!(
                    "DescribeStateMachine Definition.States.Send.{args}.QueueUrl (Catch path)"
                )));
                assert!(has_edge(&model, "configured", "Machine", "Queue"));
            }
            assert!(!model.to_string().contains("must-not-export-error-payload"));
        }
    }
}
