use locallycloud_core::views::architecture::AwsRead;

/// Read-only admission: REST reads must be GET; JSON/Query reads must name a
/// `Describe*`, `Get*` or `List*` operation.
pub(crate) fn is_read(read: &AwsRead) -> bool {
    let read_name = |name: &str| {
        ["Describe", "Get", "List"]
            .iter()
            .any(|p| name.starts_with(p))
    };
    if let Some(target) = read.headers.get("x-amz-target") {
        return read.method == http::Method::POST
            && target
                .to_str()
                .ok()
                .and_then(|t| t.rsplit_once('.'))
                .is_some_and(|(_, operation)| read_name(operation));
    }
    let form = read
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/x-www-form-urlencoded"));
    if form {
        return read.method == http::Method::POST
            && std::str::from_utf8(&read.body).is_ok_and(|body| {
                let actions: Vec<_> = body
                    .split('&')
                    .filter_map(|pair| pair.strip_prefix("Action="))
                    .collect();
                actions.len() == 1 && read_name(actions[0])
            });
    }
    read.method == http::Method::GET && read.body.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(method: http::Method, headers: &[(&'static str, &str)], body: &'static str) -> AwsRead {
        let mut map = http::HeaderMap::new();
        for (name, value) in headers {
            map.insert(*name, value.parse().unwrap());
        }
        AwsRead {
            service: "test",
            method,
            uri: http::Uri::from_static("/"),
            headers: map,
            body: bytes::Bytes::from_static(body.as_bytes()),
        }
    }

    #[test]
    fn admits_reads_and_refuses_mutations_in_every_protocol() {
        let json = |target| read(http::Method::POST, &[("x-amz-target", target)], "{}");
        let form = [("content-type", "application/x-www-form-urlencoded")];
        assert!(is_read(&json("AWSStepFunctions.DescribeStateMachine")));
        assert!(!is_read(&json("AWSStepFunctions.StartExecution")));
        assert!(!is_read(&json("AmazonSQS.DeleteQueue")));
        assert!(is_read(&read(
            http::Method::POST,
            &form,
            "Action=DescribeStacks&Version=2010-05-15"
        )));
        assert!(!is_read(&read(
            http::Method::POST,
            &form,
            "Action=DeleteStack"
        )));
        assert!(!is_read(&read(
            http::Method::POST,
            &form,
            "Action=GetRole&Action=DeleteRole"
        )));
        assert!(is_read(&read(http::Method::GET, &[], "")));
        assert!(!is_read(&read(http::Method::PUT, &[], "")));
        assert!(!is_read(&read(http::Method::DELETE, &[], "")));
        assert!(!is_read(&read(http::Method::POST, &[], "")));
    }
}
