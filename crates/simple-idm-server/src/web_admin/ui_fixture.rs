//! Opt-in loopback fixture for browser checks. No DB, real identities or writes.
use super::*;

fn user(name: &str, id: u128) -> UserRow {
    UserRow {
        id: Uuid::from_u128(id),
        username: name.into(),
        email: format!("{name}@example.test"),
        first_name: Some(name.into()),
        last_name: Some("Example".into()),
        recovery_email: None,
        phone_e164: None,
        last_sign_in_at: None,
        note: Some("Fixture account".into()),
        auth_mode: "local".into(),
        auth_provider_id: None,
        auth_provider_slug: None,
        is_active: true,
        external_user_id: None,
        external_user_id_type: None,
        external_login_name: None,
        external_upn: None,
        external_last_seen_at: None,
        federated_provider_slug: None,
        federated_provider_type: None,
        federated_subject: None,
        federated_approval_status: None,
        mfa_status: "active".into(),
        recovery_codes_remaining: 10,
        passkey_count: 1,
    }
}
fn group(id: u128, name: &str, virtual_group: bool) -> GroupRow {
    GroupRow {
        id: Uuid::from_u128(id),
        tenant_id: Uuid::from_u128(1),
        name: name.into(),
        description: Some(format!("{name} description")),
        is_virtual: virtual_group,
    }
}
fn pages(query: &PageQuery) -> HashMap<String, String> {
    let mut pages = HashMap::new();
    pages.insert(
        "users".into(),
        UsersTemplate {
            sections: nav_items(AdminSection::Users),
            message: query.message.clone(),
            error: query.error.clone(),
            ad_link: None,
            federated_link: None,
            rows: vec![user("mares", 10), user("alice", 11)],
            bulk_groups: vec![group(2, "admin:all", true)],
            deleted_rows: vec![],
            ad_modal_data: vec![],
            ad_onboarding_tokens: vec![],
            identity_providers: vec![],
            filter_q: String::new(),
            filter_status: "all".into(),
            filter_note: String::new(),
            filter_auth: "all".into(),
            filter_mfa: "all".into(),
            filter_passkeys: "all".into(),
            filter_group: String::new(),
            filter_sort: "username".into(),
            current_page: 1,
            total_pages: 1,
            has_prev: false,
            has_next: false,
            prev_page_url: String::new(),
            next_page_url: String::new(),
            total_items: 2,
        }
        .render()
        .unwrap(),
    );
    let parent = group(2, "admin:all", true);
    let leaf = group(3, "gitlab-admins", false);
    let archived = group(4, "old-admins", false);
    let group_filters = lists::ListFilters::groups(query);
    let matches = |g: &GroupRow| {
        group_filters.q.split_whitespace().all(|word| {
            format!(
                "{} {}",
                g.name,
                g.description.as_deref().unwrap_or_default()
            )
            .to_lowercase()
            .contains(&word.to_lowercase())
        }) && (group_filters.kind == "all" || g.is_virtual == (group_filters.kind == "virtual"))
    };
    let visible_ids: Vec<_> = [&parent, &leaf]
        .into_iter()
        .filter(|g| group_filters.status != "archived" && matches(g))
        .map(|g| g.id)
        .collect();
    let deleted_rows = if group_filters.status == "archived" && matches(&archived) {
        vec![archived.clone()]
    } else {
        vec![]
    };
    let group_pagination = lists::ListPagination::new(
        (visible_ids.len() + deleted_rows.len()) as i64,
        query.page,
        "/admin/ui/groups",
        &group_filters,
    );

    pages.insert(
        "groups".into(),
        GroupsTemplate {
            sections: nav_items(AdminSection::Groups),
            message: query.message.clone(),
            error: query.error.clone(),
            rows: vec![
                GroupView {
                    id: parent.id,
                    tenant_id: parent.tenant_id,
                    name: parent.name.clone(),
                    description: parent.description.clone(),
                    is_virtual: true,
                    members: vec![leaf.clone()],
                    archived_members: vec![archived.clone()],
                    included_in: vec![],
                    choices: vec![GroupChoice {
                        archived: false,
                        id: leaf.id,
                        name: leaf.name.clone(),
                        is_virtual: false,
                        selected: true,
                    }],
                    claim_maps: vec![],
                },
                GroupView {
                    id: leaf.id,
                    tenant_id: leaf.tenant_id,
                    name: leaf.name.clone(),
                    description: leaf.description.clone(),
                    is_virtual: false,
                    members: vec![],
                    archived_members: vec![],
                    included_in: vec![parent.clone()],
                    choices: vec![],
                    claim_maps: vec![GroupClaimReference {
                        client_id: "gitlab".into(),
                        claim_name: "role".into(),
                        value: "admin".into(),
                        source: "direct UUID".into(),
                    }],
                },
            ],
            deleted_rows,
            visible_ids,
            filters: group_filters,
            pagination: group_pagination,
        }
        .render()
        .unwrap(),
    );
    let client = ClientRow {
        id: Uuid::from_u128(5),
        client_id: "gitlab".into(),
        name: "GitLab".into(),
        redirect_uris: vec!["https://gitlab.example.test/oauth/callback".into()],
        grant_types: vec!["authorization_code".into()],
        scope: "openid profile email groups".into(),
        is_active: true,
        is_public: false,
        groups_claim_mode: "effective".into(),
        include_claim_maps: true,
        ignore_virtual_groups: false,
    };
    let client_filters = lists::ListFilters::clients(query);
    let client_matches = client_filters.status != "archived"
        && client_filters.status != "inactive"
        && client_filters.kind != "public"
        && client_filters.claim_maps != "no"
        && client_filters.q.split_whitespace().all(|word| {
            format!("{} {} {}", client.name, client.client_id, client.scope)
                .to_lowercase()
                .contains(&word.to_lowercase())
        });
    pages.insert(
        "clients".into(),
        ClientsTemplate {
            sections: nav_items(AdminSection::Clients),
            message: query.message.clone(),
            error: query.error.clone(),
            rows: if client_matches {
                vec![client.clone()]
            } else {
                vec![]
            },
            deleted_rows: vec![],
            client_patterns: vec![],
            filter_q: query.q.clone().unwrap_or_default(),
            filters: client_filters,
            pagination: lists::ListPagination::new(
                i64::from(client_matches),
                query.page,
                "/admin/ui/clients",
                &lists::ListFilters::clients(query),
            ),
        }
        .render()
        .unwrap(),
    );
    let member = MembershipUserOption {
        id: Uuid::from_u128(10),
        username: "mares".into(),
        email: "mares@example.test".into(),
        first_name: Some("Martin".into()),
        last_name: Some("Example".into()),
        auth_mode: "local".into(),
        is_active: true,
        selected: true,
    };
    let bundle = MembershipGroupOption {
        id: parent.id,
        name: parent.name.clone(),
        description: parent.description.clone(),
        is_virtual: true,
        selected: true,
    };
    let regular = MembershipGroupOption {
        id: leaf.id,
        name: leaf.name.clone(),
        description: leaf.description.clone(),
        is_virtual: false,
        selected: false,
    };
    pages.insert(
        "memberships".into(),
        MembershipsTemplate {
            sections: nav_items(AdminSection::Memberships),
            message: query.message.clone(),
            error: query.error.clone(),
            users: std::iter::once(member.clone())
                .chain((12..24).map(|id| MembershipUserOption {
                    id: Uuid::from_u128(id),
                    username: format!("fixture-user-{id}"),
                    email: format!("user-{id}@example.test"),
                    selected: false,
                    ..member.clone()
                }))
                .collect(),
            groups: [bundle.clone(), regular.clone()]
                .into_iter()
                .chain((30..46).map(|id| MembershipGroupOption {
                    id: Uuid::from_u128(id),
                    name: format!("fixture-group-{id}"),
                    description: Some("Fixture group".into()),
                    is_virtual: false,
                    selected: false,
                }))
                .collect(),
            selected_user: Some(member.clone()),
            selected_group: Some(bundle.clone()),
            selected_user_groups: vec![UserAssignedGroupRow {
                ordinal: 1,
                id: parent.id,
                name: parent.name.clone(),
                description: parent.description.clone(),
                is_virtual: true,
            }],
            effective_user_groups: vec![
                EffectiveMembershipRow {
                    id: parent.id,
                    name: parent.name.clone(),
                    is_virtual: true,
                    direct: true,
                    sources: vec![parent.name.clone()],
                },
                EffectiveMembershipRow {
                    id: leaf.id,
                    name: leaf.name.clone(),
                    is_virtual: false,
                    direct: false,
                    sources: vec![parent.name.clone()],
                },
            ],
            selected_user_patterns: vec![],
            selected_group_users: vec![GroupAssignedUserRow {
                ordinal: 1,
                id: member.id,
                username: member.username.clone(),
                email: member.email.clone(),
                first_name: member.first_name.clone(),
                last_name: member.last_name.clone(),
                auth_mode: member.auth_mode.clone(),
                is_active: member.is_active,
            }],
            available_groups: vec![regular],
            available_users: vec![],
            user_filter: String::new(),
            group_filter: String::new(),
        }
        .render()
        .unwrap(),
    );
    let client_selection = ClientClaimsRow {
        id: client.id,
        name: client.name.clone(),
        selected: true,
        claims_count: 0,
    };
    let group_selection = GroupClaimsRow {
        id: Some(parent.id),
        name: parent.name.clone(),
        selected: true,
        claims_count: 0,
    };
    pages.insert(
        "claims".into(),
        ClaimsTemplate {
            sections: nav_items(AdminSection::Claims),
            message: query.message.clone(),
            error: query.error.clone(),
            client_rows: vec![client_selection.clone()],
            groups: vec![(parent.id, parent.name)],
            selected_client: Some(client_selection),
            selected_client_claim_maps: vec![],
            group_rows: vec![group_selection.clone()],
            clients: vec![(client.id, client.name)],
            selected_group: Some(group_selection),
            selected_group_claim_maps: vec![],
            deleted_claim_maps: vec![],
            claim_patterns: vec![],
        }
        .render()
        .unwrap(),
    );
    pages.insert(
        "identity-providers".into(),
        IdentityProvidersTemplate {
            sections: nav_items(AdminSection::IdentityProviders),
            message: query.message.clone(),
            error: query.error.clone(),
            rows: vec![],
            deleted_rows: vec![],
            filter_q: String::new(),
        }
        .render()
        .unwrap(),
    );
    pages
}

#[tokio::test]
#[ignore = "opt-in browser fixture; ADMIN_UI_FIXTURE_INFO specifies the launch file"]
async fn admin_ui_browser_fixture() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let stop = shutdown.clone();
    let router = Router::new()
        .route("/admin/ui/static/users.js", get(users_js))
        .route("/admin/ui/static/{*path}", get(admin_static_asset))
        .route(
            "/admin/ui/{page}",
            get(
                move |Path(page): Path<String>, Query(query): Query<PageQuery>| async move {
                    match pages(&query).get(&page) {
                        Some(html) => Html(html.clone()).into_response(),
                        None => StatusCode::NOT_FOUND.into_response(),
                    }
                },
            ),
        )
        .route(
            "/quit",
            post(move || {
                let stop = stop.clone();
                async move {
                    stop.notify_one();
                    StatusCode::OK
                }
            }),
        );
    tokio::fs::write(
        std::env::var("ADMIN_UI_FIXTURE_INFO").unwrap(),
        json!({"origin":format!("http://{address}")}).to_string(),
    )
    .await
    .unwrap();
    tokio::select! {result=axum::serve(listener,router)=>result.unwrap(),_=shutdown.notified()=>{}}
}
