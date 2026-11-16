//! The single ordered table of dashboard routes.
//!
//! Both UI modes are derived from it: with the UI on every entry is served, with the UI off
//! every entry answers 404. The reserved namespace closes the rest of `/_locallycloud/`, so
//! an unknown internal path never falls through to AWS dispatch. Regional page paths
//! (`/<region>/...`, `/dashboard/...`) are HTML requests recognized by the dispatcher, not
//! table entries, because they share the AWS path space.

use super::assets::{Asset, ASSETS, PAGE};

/// What a path serves; its HTTP method is fixed by the endpoint, not repeated per route.
#[derive(Clone, Copy)]
pub(crate) enum Endpoint {
    Page,
    Asset(&'static Asset),
    Context,
    Activity,
    ExploreRegions,
    ExploreRead,
    ExploreS3,
    ArchitectureTopology,
    Reserved,
}

#[derive(Clone, Copy)]
pub(crate) struct Route {
    pub path: &'static str,
    pub endpoint: Endpoint,
}

const fn route(path: &'static str, endpoint: Endpoint) -> Route {
    Route { path, endpoint }
}

const ENDPOINTS: &[Route] = &[
    route(PAGE.path, Endpoint::Page),
    route("/_locallycloud/ui/", Endpoint::Page),
    route("/_locallycloud/context", Endpoint::Context),
    route("/_locallycloud/activity", Endpoint::Activity),
    route("/_locallycloud/explore/regions", Endpoint::ExploreRegions),
    route("/_locallycloud/explore/read", Endpoint::ExploreRead),
    route("/_locallycloud/explore/s3", Endpoint::ExploreS3),
    route(
        "/_locallycloud/views/architecture/topology",
        Endpoint::ArchitectureTopology,
    ),
];

const RESERVED: Route = route("/_locallycloud/{*rest}", Endpoint::Reserved);

/// Endpoints first, then embedded assets, then the reserved namespace.
pub(crate) fn routes() -> impl Iterator<Item = Route> {
    ENDPOINTS
        .iter()
        .copied()
        .chain(
            ASSETS
                .iter()
                .map(|asset| route(asset.path, Endpoint::Asset(asset))),
        )
        .chain(std::iter::once(RESERVED))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn served(path: &str) -> bool {
        routes().any(|r| !matches!(r.endpoint, Endpoint::Reserved) && r.path == path)
    }

    #[test]
    fn every_internal_path_used_by_the_client_is_served() {
        let sources = [
            crate::status::DASHBOARD_HTML,
            crate::status::DASHBOARD_JS,
            crate::status::DASHBOARD_I18N,
        ];
        let mut checked = 0;
        for source in sources {
            for (start, _) in source.match_indices("/_locallycloud/") {
                let path: String = source[start..]
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || "/_.-".contains(*c))
                    .collect();
                // `/_locallycloud/status` is served outside the dashboard and stays with UI=off.
                if path != "/_locallycloud/status" {
                    assert!(served(&path), "client uses unserved {path}");
                    checked += 1;
                }
            }
        }
        assert!(checked >= 10);
    }

    #[test]
    fn table_has_unique_paths_and_ends_with_the_reserved_namespace() {
        let mut paths: Vec<_> = routes().map(|r| r.path).collect();
        assert_eq!(paths.last(), Some(&RESERVED.path));
        paths.sort_unstable();
        let total = paths.len();
        paths.dedup();
        assert_eq!(paths.len(), total);
    }
}
