//! Embedded dashboard assets, revalidated by content hash instead of re-sent on every load.

use std::collections::HashMap;
use std::sync::OnceLock;

use axum::body::Body;
use axum::response::Response;

pub(crate) struct Asset {
    pub path: &'static str,
    content_type: &'static str,
    body: &'static str,
}

const SVG: &str = "image/svg+xml";
const JS: &str = "text/javascript; charset=utf-8";
const CSS: &str = "text/css; charset=utf-8";

pub(crate) const PAGE: Asset = Asset {
    path: "/_locallycloud/ui",
    content_type: "text/html; charset=utf-8",
    body: crate::status::DASHBOARD_HTML,
};

pub(crate) const ASSETS: &[Asset] = &[
    Asset {
        path: "/_locallycloud/dashboard.js",
        content_type: JS,
        body: crate::status::DASHBOARD_JS,
    },
    Asset {
        path: "/_locallycloud/dashboard-i18n.js",
        content_type: JS,
        body: crate::status::DASHBOARD_I18N,
    },
    Asset {
        path: "/_locallycloud/dashboard.css",
        content_type: CSS,
        body: crate::status::DASHBOARD_CSS,
    },
    Asset {
        path: "/_locallycloud/icons.svg",
        content_type: SVG,
        body: crate::status::SERVICE_ICONS_SVG,
    },
    Asset {
        path: "/_locallycloud/brand/icon.svg",
        content_type: SVG,
        body: include_str!("../../../../packaging/assets/locallycloud.svg"),
    },
    Asset {
        path: "/_locallycloud/brand/wordmark.svg",
        content_type: SVG,
        body: include_str!("../../../../packaging/assets/locallycloud-wordmark.svg"),
    },
    Asset {
        path: "/_locallycloud/brand/wordmark-light.svg",
        content_type: SVG,
        body: include_str!("../../../../packaging/assets/locallycloud-wordmark-light.svg"),
    },
    // Architecture review: ES modules and stylesheet imported only when the view opens.
    Asset {
        path: "/_locallycloud/views/architecture/page.js",
        content_type: JS,
        body: include_str!("architecture/page.js"),
    },
    Asset {
        path: "/_locallycloud/views/architecture/model.js",
        content_type: JS,
        body: include_str!("architecture/model.js"),
    },
    Asset {
        path: "/_locallycloud/views/architecture/engine.js",
        content_type: JS,
        body: include_str!("architecture/engine.js"),
    },
    Asset {
        path: "/_locallycloud/views/architecture/catalog.js",
        content_type: JS,
        body: include_str!("architecture/catalog.js"),
    },
    Asset {
        path: "/_locallycloud/views/architecture/catalog.json",
        content_type: "application/json",
        body: include_str!("architecture/catalog.json"),
    },
    Asset {
        path: "/_locallycloud/views/architecture/i18n.js",
        content_type: JS,
        body: include_str!("architecture/i18n.js"),
    },
    Asset {
        path: "/_locallycloud/views/architecture/page.css",
        content_type: CSS,
        body: include_str!("architecture/page.css"),
    },
];

fn etag(asset: &Asset) -> &'static str {
    use sha2::Digest;
    static ETAGS: OnceLock<HashMap<&'static str, String>> = OnceLock::new();
    ETAGS
        .get_or_init(|| {
            std::iter::once(&PAGE)
                .chain(ASSETS)
                .map(|a| (a.path, format!("\"{:x}\"", sha2::Sha256::digest(a.body))))
                .collect()
        })
        .get(asset.path)
        .map(String::as_str)
        .unwrap_or_default()
}

fn unchanged(headers: &http::HeaderMap, etag: &str) -> bool {
    headers
        .get(http::header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(',').any(|candidate| {
                let candidate = candidate.trim();
                candidate == "*" || candidate.strip_prefix("W/").unwrap_or(candidate) == etag
            })
        })
}

/// Serve an embedded asset; an unchanged client copy gets `304` without a body.
pub(crate) fn serve(asset: &'static Asset, headers: &http::HeaderMap) -> Response {
    let etag = etag(asset);
    let fresh = unchanged(headers, etag);
    Response::builder()
        .status(if fresh { 304 } else { 200 })
        .header("content-type", asset.content_type)
        .header("cache-control", "no-cache")
        .header("etag", etag)
        .body(if fresh {
            Body::empty()
        } else {
            Body::from(asset.body)
        })
        .expect("embedded dashboard asset response is always valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conditional(value: &str) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::IF_NONE_MATCH, value.parse().unwrap());
        headers
    }

    #[tokio::test]
    async fn every_asset_revalidates_by_its_own_content() {
        for asset in std::iter::once(&PAGE).chain(ASSETS) {
            let first = serve(asset, &http::HeaderMap::new());
            assert_eq!(first.status(), 200, "{}", asset.path);
            assert_eq!(first.headers()["cache-control"], "no-cache");
            assert_eq!(first.headers()["content-type"], asset.content_type);
            let etag = first.headers()["etag"].to_str().unwrap().to_owned();
            assert!(etag.len() > 2, "{}", asset.path);
            let body = axum::body::to_bytes(first.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(body.as_ref(), asset.body.as_bytes());
            for candidate in [
                etag.clone(),
                format!("W/{etag}"),
                format!("\"old\", {etag}"),
                "*".into(),
            ] {
                let response = serve(asset, &conditional(&candidate));
                assert_eq!(response.status(), 304, "{} {candidate}", asset.path);
                assert!(axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap()
                    .is_empty());
            }
            assert_eq!(serve(asset, &conditional("\"old\"")).status(), 200);
        }
    }

    #[test]
    fn asset_paths_are_unique() {
        let mut paths: Vec<_> = std::iter::once(&PAGE)
            .chain(ASSETS)
            .map(|a| a.path)
            .collect();
        paths.sort_unstable();
        paths.dedup();
        assert_eq!(paths.len(), ASSETS.len() + 1);
    }
}
