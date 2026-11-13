//! Change-set listing and shared execution-state projection.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use super::*;
use crate::store::ChangeSetSummary;

// Leave room for the Query envelope and a maximum-sized continuation token.
const PAGE_BYTES: usize = 1024 * 1024 - 2048;

impl CfnHandler {
    pub(super) fn list_change_sets(
        &self,
        q: &Query,
        region: &str,
        account: &str,
    ) -> Result<String, CfnError> {
        let name = q
            .get("StackName")
            .ok_or_else(|| CfnError::Validation("StackName is required".into()))?;
        let stack = self
            .store
            .find(account, region, &name)
            .or_else(|| {
                self.store
                    .review_change_set(account, region, &name)
                    .map(|change| review_stack(&change))
            })
            .ok_or_else(|| CfnError::Validation(format!("Stack [{name}] does not exist")))?;
        let after = q
            .params
            .get("NextToken")
            .map(|token| decode_cursor(token, account, region, &stack.stack_id))
            .transpose()?;
        let (summaries, next) = summary_page(
            self.store
                .change_set_summaries(account, region, &stack.stack_id),
            after.as_deref(),
            Some(stack.status),
            PAGE_BYTES,
        )?;
        let next = next
            .map(|last| {
                let bytes = serde_json::to_vec(&(account, region, &stack.stack_id, last))
                    .map_err(|_| CfnError::Internal)?;
                let token = URL_SAFE_NO_PAD.encode(bytes);
                if token.len() > 1024 {
                    return Err(CfnError::Internal);
                }
                Ok(text_el("NextToken", &token))
            })
            .transpose()?
            .unwrap_or_default();
        Ok(format!("<Summaries>{summaries}</Summaries>{next}"))
    }

    pub(super) fn change_set_execution_status(
        &self,
        change: &ChangeSet,
        region: &str,
        account: &str,
    ) -> &'static str {
        execution_status(
            change.executed,
            &change.status,
            self.store
                .find(account, region, &change.stack_id)
                .map(|stack| stack.status),
        )
    }
}

fn execution_status(executed: bool, status: &str, stack: Option<StackStatus>) -> &'static str {
    if !executed {
        return if status == "CREATE_COMPLETE" {
            "AVAILABLE"
        } else {
            "UNAVAILABLE"
        };
    }
    match stack {
        Some(status) if status.is_in_progress() => "EXECUTE_IN_PROGRESS",
        Some(
            StackStatus::CreateFailed
            | StackStatus::UpdateFailed
            | StackStatus::DeleteFailed
            | StackStatus::RollbackComplete
            | StackStatus::RollbackFailed
            | StackStatus::UpdateRollbackComplete
            | StackStatus::UpdateRollbackFailed,
        )
        | None => "EXECUTE_FAILED",
        Some(_) => "EXECUTE_COMPLETE",
    }
}

fn decode_cursor(
    token: &str,
    account: &str,
    region: &str,
    stack_id: &str,
) -> Result<String, CfnError> {
    let invalid = || CfnError::Validation("Invalid NextToken".into());
    if token.is_empty() || token.len() > 1024 {
        return Err(invalid());
    }
    let bytes = URL_SAFE_NO_PAD.decode(token).map_err(|_| invalid())?;
    let (owner, area, stack, after): (String, String, String, String) =
        serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if owner != account || area != region || stack != stack_id || after.is_empty() {
        return Err(invalid());
    }
    Ok(after)
}

fn summary_xml(summary: &ChangeSetSummary, stack: Option<StackStatus>) -> String {
    let mut body = String::from("<member>");
    for (key, value) in [
        ("ChangeSetId", summary.id.as_str()),
        ("ChangeSetName", summary.name.as_str()),
        ("StackId", summary.stack_id.as_str()),
        ("StackName", summary.stack_name.as_str()),
        ("Status", summary.status.as_str()),
        (
            "ExecutionStatus",
            execution_status(summary.executed, &summary.status, stack),
        ),
    ] {
        body.push_str(&text_el(key, value));
    }
    for (key, value) in [
        ("CreationTime", &summary.creation_time),
        ("Description", &summary.description),
        ("StatusReason", &summary.reason),
    ] {
        if let Some(value) = value {
            body.push_str(&text_el(key, value));
        }
    }
    body.push_str("</member>");
    body
}

fn summary_page(
    summaries: impl Iterator<Item = ChangeSetSummary>,
    after: Option<&str>,
    stack: Option<StackStatus>,
    limit: usize,
) -> Result<(String, Option<String>), CfnError> {
    let mut page = BTreeMap::new();
    let mut bytes = 0;
    let mut cutoff: Option<String> = None;
    for summary in summaries {
        if after.is_some_and(|after| summary.id.as_str() <= after)
            || cutoff.as_ref().is_some_and(|cutoff| summary.id >= *cutoff)
        {
            continue;
        }
        let xml = summary_xml(&summary, stack);
        bytes += xml.len();
        page.insert(summary.id, xml);
        while bytes > limit {
            let Some((id, xml)) = page.pop_last() else {
                return Err(CfnError::Internal);
            };
            bytes -= xml.len();
            cutoff = Some(id);
        }
    }
    let next = match (cutoff, page.last_key_value()) {
        (Some(_), Some((last, _))) => Some(last.clone()),
        (Some(_), None) => {
            return Err(CfnError::LimitExceeded(
                "A change set summary exceeds the response size limit".into(),
            ))
        }
        (None, _) => None,
    };
    Ok((page.into_values().collect(), next))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn change(id: &str, stack_id: &str) -> ChangeSet {
        ChangeSet {
            id: id.into(),
            name: id.into(),
            stack_name: "review".into(),
            stack_id: stack_id.into(),
            change_type: "CREATE".into(),
            status: "CREATE_COMPLETE".into(),
            reason: None,
            executed: false,
            creation_time: Some("2026-11-13T00:00:00Z".into()),
            request: Query {
                params: [("Description".into(), "<review> & retain".into())].into(),
            },
            changes: Vec::new(),
        }
    }

    #[test]
    fn list_change_sets_scopes_review_stacks_and_reports_stable_summaries() {
        let registry = Arc::new(ServiceRegistry::new());
        let handler = CfnHandler::new(Arc::downgrade(&registry));
        for (account, region, id, stack) in [
            ("owner", "us-east-1", "b", "stack-id"),
            ("owner", "us-east-1", "a", "stack-id"),
            ("foreign", "us-east-1", "foreign-account", "stack-id"),
            ("owner", "us-east-2", "foreign-region", "stack-id"),
            ("owner", "us-east-1", "old-stack", "retired-stack-id"),
        ] {
            handler
                .store
                .insert_change_set(account, region, change(id, stack))
                .unwrap();
        }
        let query = Query {
            params: [("StackName".into(), "stack-id".into())].into(),
        };
        let result = handler
            .list_change_sets(&query, "us-east-1", "owner")
            .unwrap();
        assert_eq!(result.matches("<member>").count(), 2);
        assert!(
            result.find("<ChangeSetId>a</ChangeSetId>").unwrap()
                < result.find("<ChangeSetId>b</ChangeSetId>").unwrap()
        );
        assert!(result.contains("<CreationTime>2026-11-13T00:00:00Z</CreationTime>"));
        assert!(result.contains("&lt;review&gt; &amp; retain"));
        assert!(result.contains("<ExecutionStatus>AVAILABLE</ExecutionStatus>"));
        assert!(!result.contains("foreign"));
        assert!(!result.contains("old-stack"));
        let empty = Query {
            params: Default::default(),
        };
        assert!(handler
            .list_change_sets(&empty, "us-east-1", "owner")
            .is_err());
        let unknown = Query {
            params: [("StackName".into(), "missing".into())].into(),
        };
        assert!(handler
            .list_change_sets(&unknown, "us-east-1", "owner")
            .is_err());
    }

    #[test]
    fn pagination_keeps_a_contiguous_prefix_and_tokens_are_scope_bound() {
        let store = CfnStore::new();
        for id in ["c", "a", "b"] {
            store
                .insert_change_set("owner", "region", change(id, "stack"))
                .unwrap();
        }
        let summaries = || store.change_set_summaries("owner", "region", "stack");
        let single = summary_xml(&summaries().next().unwrap(), None).len();
        let (first, next) = summary_page(summaries(), None, None, single * 2).unwrap();
        assert!(first.contains("<ChangeSetId>a</ChangeSetId>"));
        assert!(first.contains("<ChangeSetId>b</ChangeSetId>"));
        assert!(!first.contains("<ChangeSetId>c</ChangeSetId>"));
        assert_eq!(next.as_deref(), Some("b"));
        let (last, next) = summary_page(summaries(), Some("b"), None, single * 2).unwrap();
        assert!(last.contains("<ChangeSetId>c</ChangeSetId>"));
        assert_eq!(next, None);
        // A later small row must not jump over an earlier row that did not fit.
        let mut rows: Vec<_> = summaries().collect();
        rows.sort_by(|left, right| left.id.cmp(&right.id));
        rows[0].description = Some("x".repeat(100));
        rows[1].description = Some("x".repeat(300));
        rows[2].description = None;
        let limit = summary_xml(&rows[0], None).len() + summary_xml(&rows[2], None).len();
        let (first, next) = summary_page(rows.into_iter(), None, None, limit).unwrap();
        assert_eq!(first.matches("<member>").count(), 1);
        assert!(first.contains("<ChangeSetId>a</ChangeSetId>"));
        assert_eq!(next.as_deref(), Some("a"));
        let token =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&("owner", "region", "stack", "b")).unwrap());
        assert_eq!(
            decode_cursor(&token, "owner", "region", "stack").unwrap(),
            "b"
        );
        for (owner, region, stack) in [
            ("other", "region", "stack"),
            ("owner", "other", "stack"),
            ("owner", "region", "other"),
        ] {
            assert!(decode_cursor(&token, owner, region, stack).is_err());
        }
        assert!(decode_cursor("", "owner", "region", "stack").is_err());
        assert!(decode_cursor("malformed", "owner", "region", "stack").is_err());
        assert_eq!(
            execution_status(false, "CREATE_PENDING", None),
            "UNAVAILABLE"
        );
        assert_eq!(
            execution_status(
                true,
                "CREATE_COMPLETE",
                Some(StackStatus::UpdateRollbackComplete)
            ),
            "EXECUTE_FAILED"
        );
        assert_eq!(
            execution_status(true, "CREATE_COMPLETE", Some(StackStatus::UpdateInProgress)),
            "EXECUTE_IN_PROGRESS"
        );
    }
}
