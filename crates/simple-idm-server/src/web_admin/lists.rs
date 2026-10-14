use super::*;
use sqlx::{Postgres, QueryBuilder};

pub(super) const PAGE_SIZE: i64 = 25;

// The read-only selection request uses exactly the same predicates as the list.
pub(super) fn page_size(total: i64, bulk_selection: Option<bool>) -> Result<i64, Response> {
    if bulk_selection != Some(true) {
        return Ok(PAGE_SIZE);
    }
    if total > bulk::MAX_BATCH as i64 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Too many filtered objects for one batch. Select a page instead.",
        )
            .into_response());
    }
    Ok(bulk::MAX_BATCH as i64)
}

pub(super) struct ListFilters {
    pub q: String,
    pub status: String,
    pub kind: String,
    pub claim_maps: String,
}

impl ListFilters {
    pub fn groups(query: &PageQuery) -> Self {
        Self {
            q: query.q.clone().unwrap_or_default(),
            status: normalize_filter(query.status.as_deref(), &["current", "archived"], "current"),
            kind: normalize_filter(query.kind.as_deref(), &["regular", "virtual"], "all"),
            claim_maps: "all".into(),
        }
    }

    pub fn clients(query: &PageQuery) -> Self {
        Self {
            q: query.q.clone().unwrap_or_default(),
            status: normalize_filter(
                query.status.as_deref(),
                &["active", "inactive", "archived"],
                "all",
            ),
            kind: normalize_filter(query.kind.as_deref(), &["public", "confidential"], "all"),
            claim_maps: normalize_filter(query.claim_maps.as_deref(), &["yes", "no"], "all"),
        }
    }

    pub fn group_predicates(&self, sql: &mut QueryBuilder<Postgres>) {
        sql.push(" WHERE (deleted_at IS NOT NULL) = ")
            .push_bind(self.status == "archived");
        if self.kind != "all" {
            sql.push(" AND is_virtual = ")
                .push_bind(self.kind == "virtual");
        }
        for word in self.q.split_whitespace() {
            sql.push(" AND lower(concat_ws(' ', name, description)) LIKE ")
                .push_bind(literal_pattern(word));
        }
    }

    pub fn client_predicates(&self, sql: &mut QueryBuilder<Postgres>) {
        sql.push(" WHERE (deleted_at IS NOT NULL) = ")
            .push_bind(self.status == "archived");
        if matches!(self.status.as_str(), "active" | "inactive") {
            sql.push(" AND is_active = ")
                .push_bind(self.status == "active");
        }
        if self.kind != "all" {
            sql.push(" AND is_public = ")
                .push_bind(self.kind == "public");
        }
        if self.claim_maps != "all" {
            sql.push(" AND include_claim_maps = ")
                .push_bind(self.claim_maps == "yes");
        }
        for word in self.q.split_whitespace() {
            sql.push(" AND lower(concat_ws(' ', client_id, name, scope, array_to_string(redirect_uris, ' '), array_to_string(grant_types, ' '), groups_claim_mode)) LIKE ")
                .push_bind(literal_pattern(word));
        }
    }
}

pub(super) struct ListPagination {
    pub total: i64,
    pub page: u32,
    pub pages: u32,
    pub prev: String,
    pub next: String,
    page_size: i64,
}

impl ListPagination {
    pub fn new(total: i64, requested: Option<u32>, path: &str, filters: &ListFilters) -> Self {
        Self::with_page_size(total, requested, path, filters, PAGE_SIZE)
    }

    pub fn with_page_size(
        total: i64,
        requested: Option<u32>,
        path: &str,
        filters: &ListFilters,
        page_size: i64,
    ) -> Self {
        let pages = ((total + page_size - 1) / page_size).max(1) as u32;
        let page = requested.unwrap_or(1).clamp(1, pages);
        let link = |page: u32| {
            let query = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("q", filters.q.trim())
                .append_pair("status", &filters.status)
                .append_pair("type", &filters.kind)
                .append_pair("claim_maps", &filters.claim_maps)
                .append_pair("page", &page.to_string())
                .finish();
            format!("{path}?{query}")
        };
        Self {
            total,
            page_size,
            page,
            pages,
            prev: link(page.saturating_sub(1).max(1)),
            next: link(page.saturating_add(1).min(pages)),
        }
    }

    pub fn offset(&self) -> i64 {
        i64::from(self.page - 1) * self.page_size
    }
}

pub(super) fn literal_pattern(word: &str) -> String {
    format!(
        "%{}%",
        word.to_lowercase()
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_")
    )
}
