use std::collections::HashMap;
use std::io::Read;
use std::sync::OnceLock;

use axum::body::Body;
use axum::response::Response;

pub(crate) struct Asset {
    pub path: &'static str,
    content_type: &'static str,
    gzip: &'static [u8],
}

macro_rules! gzip {
    ($path:literal) => {
        include_bytes!(concat!(env!("OUT_DIR"), "/", $path, ".gz"))
    };
}

const SVG: &str = "image/svg+xml";
const JS: &str = "text/javascript; charset=utf-8";
const CSS: &str = "text/css; charset=utf-8";

pub(crate) const PAGE: Asset = Asset {
    path: "/_locallycloud/ui",
    content_type: "text/html; charset=utf-8",
    gzip: gzip!("crates/core/src/dashboard.html"),
};

pub(crate) const ASSETS: &[Asset] = &[
    Asset {
        path: "/_locallycloud/dashboard.js",
        content_type: JS,
        gzip: gzip!("crates/core/src/dashboard.js"),
    },
    Asset {
        path: "/_locallycloud/dashboard-i18n.js",
        content_type: JS,
        gzip: gzip!("crates/core/src/dashboard-i18n.js"),
    },
    Asset {
        path: "/_locallycloud/dashboard.css",
        content_type: CSS,
        gzip: gzip!("crates/core/src/dashboard.css"),
    },
    Asset {
        path: "/_locallycloud/icons.svg",
        content_type: SVG,
        gzip: gzip!("crates/core/src/icons/sprite.svg"),
    },
    Asset {
        path: "/_locallycloud/brand/icon.svg",
        content_type: SVG,
        gzip: gzip!("packaging/assets/locallycloud.svg"),
    },
    Asset {
        path: "/_locallycloud/brand/wordmark.svg",
        content_type: SVG,
        gzip: gzip!("packaging/assets/locallycloud-wordmark.svg"),
    },
    Asset {
        path: "/_locallycloud/brand/wordmark-light.svg",
        content_type: SVG,
        gzip: gzip!("packaging/assets/locallycloud-wordmark-light.svg"),
    },
    // Architecture review: ES modules and stylesheet imported only when the view opens.
    Asset {
        path: "/_locallycloud/views/architecture/page.js",
        content_type: JS,
        gzip: gzip!("crates/core/src/views/architecture/page.js"),
    },
    Asset {
        path: "/_locallycloud/views/architecture/model.js",
        content_type: JS,
        gzip: gzip!("crates/core/src/views/architecture/model.js"),
    },
    Asset {
        path: "/_locallycloud/views/architecture/engine.js",
        content_type: JS,
        gzip: gzip!("crates/core/src/views/architecture/engine.js"),
    },
    Asset {
        path: "/_locallycloud/views/architecture/catalog.js",
        content_type: JS,
        gzip: gzip!("crates/core/src/views/architecture/catalog.js"),
    },
    Asset {
        path: "/_locallycloud/views/architecture/assessment.js",
        content_type: JS,
        gzip: gzip!("crates/core/src/views/architecture/assessment.js"),
    },
    Asset {
        path: "/_locallycloud/views/architecture/threatdragon.js",
        content_type: JS,
        gzip: gzip!("crates/core/src/views/architecture/threatdragon.js"),
    },
    Asset {
        path: "/_locallycloud/views/architecture/catalog.json",
        content_type: "application/json",
        gzip: gzip!("crates/core/src/views/architecture/catalog.json"),
    },
    Asset {
        path: "/_locallycloud/views/architecture/i18n.js",
        content_type: JS,
        gzip: gzip!("crates/core/src/views/architecture/i18n.js"),
    },
    Asset {
        path: "/_locallycloud/views/architecture/page.css",
        content_type: CSS,
        gzip: gzip!("crates/core/src/views/architecture/page.css"),
    },
];

struct Etags {
    gzip: String,
    identity: String,
}

fn etags(asset: &Asset) -> &'static Etags {
    use sha2::Digest;
    static ETAGS: OnceLock<HashMap<&'static str, Etags>> = OnceLock::new();
    ETAGS
        .get_or_init(|| {
            std::iter::once(&PAGE)
                .chain(ASSETS)
                .map(|a| {
                    let hash = sha2::Sha256::digest(a.gzip);
                    let etags = Etags {
                        gzip: format!("\"{hash:x}\""),
                        identity: format!("\"{hash:x}-identity\""),
                    };
                    (a.path, etags)
                })
                .collect()
        })
        .get(asset.path)
        .expect("every served asset is in the table")
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

fn accepts_gzip(headers: &http::HeaderMap) -> bool {
    headers
        .get_all(http::header::ACCEPT_ENCODING)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|entry| {
            let mut parts = entry.split(';');
            let coding = parts.next().unwrap_or_default().trim();
            let refused = parts.any(|p| {
                p.trim()
                    .strip_prefix("q=")
                    .and_then(|q| q.trim().parse::<f32>().ok())
                    .is_some_and(|q| q <= 0.0)
            });
            !refused
                && ["gzip", "x-gzip", "*"]
                    .iter()
                    .any(|c| coding.eq_ignore_ascii_case(c))
        })
}

fn decoded(asset: &Asset) -> Vec<u8> {
    let mut body = Vec::new();
    flate2::read::GzDecoder::new(asset.gzip)
        .read_to_end(&mut body)
        .expect("embedded asset is gzip written by build.rs");
    body
}

pub(crate) fn serve(asset: &'static Asset, headers: &http::HeaderMap) -> Response {
    let etags = etags(asset);
    let gzip = accepts_gzip(headers);
    let etag = if gzip { &etags.gzip } else { &etags.identity };
    let fresh = unchanged(headers, etag);
    let mut response = Response::builder()
        .status(if fresh { 304 } else { 200 })
        .header("content-type", asset.content_type)
        .header("cache-control", "no-cache")
        .header("vary", "accept-encoding")
        .header("etag", etag.as_str());
    if gzip {
        response = response.header("content-encoding", "gzip");
    }
    let body = match (fresh, gzip) {
        (true, _) => Body::empty(),
        (false, true) => Body::from(asset.gzip),

        (false, false) => Body::from(decoded(asset)),
    };
    response
        .body(body)
        .expect("embedded dashboard asset response is always valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::{ACCEPT_ENCODING, IF_NONE_MATCH};

    fn request(pairs: &[(http::header::HeaderName, &str)]) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        for (name, value) in pairs {
            headers.append(name.clone(), value.parse().unwrap());
        }
        headers
    }

    async fn body(response: Response) -> Vec<u8> {
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    #[tokio::test]
    async fn every_asset_revalidates_by_its_own_content_in_each_encoding() {
        for asset in std::iter::once(&PAGE).chain(ASSETS) {
            for gzip in [true, false] {
                let encoding = if gzip {
                    "gzip, deflate, br"
                } else {
                    "identity"
                };
                let first = serve(asset, &request(&[(ACCEPT_ENCODING, encoding)]));
                assert_eq!(first.status(), 200, "{}", asset.path);
                assert_eq!(first.headers()["cache-control"], "no-cache");
                assert_eq!(first.headers()["vary"], "accept-encoding");
                assert_eq!(first.headers()["content-type"], asset.content_type);
                assert_eq!(first.headers().contains_key("content-encoding"), gzip);
                let etag = first.headers()["etag"].to_str().unwrap().to_owned();
                let expected = if gzip {
                    asset.gzip.to_vec()
                } else {
                    decoded(asset)
                };
                assert_eq!(body(first).await, expected, "{}", asset.path);
                for candidate in [
                    etag.clone(),
                    format!("W/{etag}"),
                    format!("\"old\", {etag}"),
                    "*".into(),
                ] {
                    let headers =
                        request(&[(ACCEPT_ENCODING, encoding), (IF_NONE_MATCH, &candidate)]);
                    let response = serve(asset, &headers);
                    assert_eq!(response.status(), 304, "{} {candidate}", asset.path);
                    assert!(body(response).await.is_empty());
                }
                let stale = request(&[(ACCEPT_ENCODING, encoding), (IF_NONE_MATCH, "\"old\"")]);
                assert_eq!(serve(asset, &stale).status(), 200);
            }
        }
    }

    #[test]
    fn a_validator_from_one_encoding_does_not_match_the_other() {
        let gzipped = serve(&PAGE, &request(&[(ACCEPT_ENCODING, "gzip")]));
        let etag = gzipped.headers()["etag"].to_str().unwrap().to_owned();
        let plain = request(&[(ACCEPT_ENCODING, "identity"), (IF_NONE_MATCH, &etag)]);
        assert_eq!(serve(&PAGE, &plain).status(), 200);
    }

    #[test]
    fn embedded_gzip_decodes_to_the_source_file() {
        const MACRO: &str = "gzip!(\"";
        let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let table =
            std::fs::read_to_string(workspace.join("crates/core/src/views/assets.rs")).unwrap();
        let sources: Vec<_> = table
            .match_indices(MACRO)
            .map(|(start, _)| {
                let rest = &table[start + MACRO.len()..];
                &rest[..rest.find('"').unwrap()]
            })
            .collect();
        assert_eq!(sources.len(), ASSETS.len() + 1);
        for (asset, source) in std::iter::once(&PAGE).chain(ASSETS).zip(sources) {
            let original = std::fs::read(workspace.join(source)).unwrap();
            assert_eq!(decoded(asset), original, "{source}");
            assert!(
                asset.gzip.len() < original.len(),
                "{source} does not shrink"
            );
        }
    }

    #[test]
    fn gzip_negotiation_follows_accept_encoding() {
        for (value, gzip) in [
            ("gzip", true),
            ("br;q=1.0, GZIP;q=0.5", true),
            ("x-gzip", true),
            ("*", true),
            ("gzip;q=0", false),
            ("gzip; q=0.0, identity", false),
            ("br, deflate", false),
            ("", false),
        ] {
            let headers = request(&[(ACCEPT_ENCODING, value)]);
            assert_eq!(accepts_gzip(&headers), gzip, "{value}");
        }
        assert!(!accepts_gzip(&http::HeaderMap::new()));
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
