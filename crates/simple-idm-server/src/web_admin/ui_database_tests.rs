use super::*;
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
    rand_core::OsRng,
};

pub(super) async fn state(pool: DbPool) -> WebAdminState {
    let dir = tempfile::tempdir().unwrap();
    let key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let private = dir.path().join("private.pem");
    let public = dir.path().join("public.pem");
    std::fs::write(
        &private,
        key.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();
    std::fs::write(
        &public,
        RsaPublicKey::from(&key)
            .to_public_key_pem(LineEnding::LF)
            .unwrap(),
    )
    .unwrap();
    let jwt = Arc::new(
        simple_idm_core::auth::JwtService::new(
            private.to_str().unwrap(),
            public.to_str().unwrap(),
            "https://idm.example.test".into(),
            "test".into(),
            vec![],
        )
        .unwrap(),
    );
    let oauth_state = Arc::new(OAuth2State {
        db_pool: pool.clone(),
        jwt_service: jwt.clone(),
        access_token_expiry: 3600,
        refresh_token_expiry: 3600,
        auth_session_expiry: 3600,
        allow_username_login: true,
        allowed_email_domains: vec![],
        trust_proxy_headers: false,
        force_secure_cookies: false,
        passkeys: None,
        device_flow_config: simple_idm_core::config::DeviceFlowConfig {
            expiry_seconds: 600,
            polling_interval_seconds: 1,
            user_code_length: 8,
            user_code_format: "XXXX-XXXX".into(),
            cleanup_interval_seconds: 60,
            max_verification_attempts: 5,
        },
        auth_protection: simple_idm_core::config::AuthProtectionConfig {
            enabled: false,
            failure_window_seconds: 60,
            max_failures: 5,
            lockout_seconds: 60,
            clear_on_start: false,
        },
    });
    WebAdminState {
        db_pool: pool.clone(),
        oauth_state,
        admin_auth: AdminAuth {
            admin_root_token: Some("test-only-root".into()),
            allow_legacy_admin_group: false,
            allow_admin_substring_claim: false,
            oauth_client_ids: vec!["cli-tools".into()],
            jwt_service: jwt,
            db_pool: pool,
        },
        secure_cookies: false,
        ad_onboarding_token_ttl_seconds: 3600,
        federated_invitation_token_ttl_seconds: 3600,
        admin_sessions: Arc::new(RwLock::new(HashMap::from([(
            "test-session".into(),
            (
                "test-only-root".into(),
                Utc::now() + chrono::Duration::hours(1),
            ),
        )]))),
    }
}

#[tokio::test]
#[ignore = "requires disposable ADMIN_UI_TEST_DATABASE_URL"]
async fn authenticated_admin_events_record_actor_separately_from_target() {
    use axum::{body::Body, http::Request, middleware};
    use tower::Service;
    let pool = DbPool::connect(&std::env::var("ADMIN_UI_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    simple_idm_core::db::run_migrations(&pool).await.unwrap();
    let mut state = state(pool.clone()).await;
    let client_id = format!("audit-client-{}", Uuid::new_v4());
    let client_uuid = Uuid::new_v4();
    sqlx::query("INSERT INTO oauth_clients (id,client_id,client_secret_hash,name,redirect_uris,grant_types,scope,is_public,is_active) VALUES ($1,$2,'unused','Audit test',ARRAY[]::text[],ARRAY['client_credentials'],'admin:*',false,true)")
        .bind(client_uuid).bind(&client_id).execute(&pool).await.unwrap();
    state.admin_auth.oauth_client_ids = vec![client_id.clone()];
    let token = state
        .admin_auth
        .jwt_service
        .create_access_token(
            client_uuid,
            client_id.clone(),
            None,
            None,
            Some("admin:*".into()),
            vec![],
            HashMap::new(),
            vec![],
            None,
            600,
        )
        .unwrap();
    let mut app = Router::new()
        .route(
            "/groups",
            post(simple_idm_core::admin::handlers::create_group),
        )
        .layer(middleware::from_fn_with_state(
            state.admin_auth.clone(),
            simple_idm_core::admin::middleware::admin_auth_middleware,
        ))
        .with_state(pool.clone());
    let prefix = format!("actor-test-{}", Uuid::new_v4());
    let mut targets = vec![];
    for (credential, root) in [(token.as_str(), false), ("test-only-root", true)] {
        let request = Request::builder()
            .method("POST")
            .uri("/groups")
            .header(header::AUTHORIZATION, format!("Bearer {credential}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({"name":format!("{prefix}-{root}"),"is_virtual":false}).to_string(),
            ))
            .unwrap();
        let response = app.call(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let response: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1_000_000)
                .await
                .unwrap(),
        )
        .unwrap();
        let target = Uuid::parse_str(response["id"].as_str().unwrap()).unwrap();
        targets.push(target);
        let event = sqlx::query("SELECT actor_sub,actor_client_id,details FROM audit_events WHERE resource_id=$1 AND action='admin.group.create'").bind(target).fetch_one(&pool).await.unwrap();
        if root {
            assert_eq!(event.get::<Option<String>, _>("actor_sub"), None);
            assert_eq!(event.get::<Option<String>, _>("actor_client_id"), None);
            assert_eq!(
                event.get::<serde_json::Value, _>("details")["actor_kind"],
                "root_token"
            );
        } else {
            assert_eq!(event.get::<String, _>("actor_sub"), client_uuid.to_string());
            assert_eq!(event.get::<String, _>("actor_client_id"), client_id);
            assert_ne!(client_uuid, target);
        }
    }
    let request = Request::builder()
        .method("POST")
        .uri("/groups")
        .header(header::AUTHORIZATION, "Bearer invalid")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({"name":format!("{prefix}-denied")}).to_string(),
        ))
        .unwrap();
    assert_eq!(
        app.call(request).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(
        !sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM groups WHERE name=$1)")
            .bind(format!("{prefix}-denied"))
            .fetch_one(&pool)
            .await
            .unwrap()
    );
    sqlx::query("DELETE FROM groups WHERE id=ANY($1)")
        .bind(&targets)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM oauth_clients WHERE id=$1")
        .bind(client_uuid)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM audit_events WHERE resource_id=ANY($1)")
        .bind(&targets)
        .execute(&pool)
        .await
        .unwrap();
}

async fn users_html(state: &WebAdminState, query: &str) -> String {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        "sidm_admin_session=test-session".parse().unwrap(),
    );
    let response = users_page(
        State(state.clone()),
        headers,
        Query(serde_urlencoded::from_str(query).unwrap()),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "query failed: {query}; headers: {:?}",
        response.headers()
    );
    String::from_utf8(
        axum::body::to_bytes(response.into_body(), 4_000_000)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

async fn list_html(state: &WebAdminState, query: &str, groups: bool) -> String {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        "sidm_admin_session=test-session".parse().unwrap(),
    );
    let query = Query(serde_urlencoded::from_str(query).unwrap());
    let response = if groups {
        groups_page(State(state.clone()), headers, query).await
    } else {
        clients_page(State(state.clone()), headers, query).await
    };
    assert_eq!(response.status(), StatusCode::OK, "List handler failed");
    String::from_utf8(
        axum::body::to_bytes(response.into_body(), 8_000_000)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

#[tokio::test]
#[ignore = "requires disposable ADMIN_UI_TEST_DATABASE_URL"]
async fn group_and_client_pages_filter_archives_and_keep_graph_metadata() {
    let pool = DbPool::connect(&std::env::var("ADMIN_UI_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    simple_idm_core::db::run_migrations(&pool).await.unwrap();
    let state = state(pool.clone()).await;
    let prefix = format!("lists-{}", Uuid::new_v4().simple());
    let mut groups = Vec::new();
    for archived in [false, true] {
        for n in 0..28 {
            let id = Uuid::new_v4();
            let name = format!(
                "{prefix}-{}-{n:02}",
                if archived { "archived" } else { "current" }
            );
            sqlx::query("INSERT INTO groups (id,name,is_virtual,description,deleted_at) VALUES ($1,$2,$3,'page-test',CASE WHEN $4 THEN NOW() ELSE NULL END)")
                .bind(id).bind(&name).bind(n % 2 == 0).bind(archived).execute(&pool).await.unwrap();
            if !archived {
                groups.push(id);
            }
            let client = Uuid::new_v4();
            sqlx::query("INSERT INTO oauth_clients (id,client_id,client_secret_hash,name,redirect_uris,grant_types,scope,is_public,is_active,include_claim_maps,deleted_at) VALUES ($1,$2,CASE WHEN $4 THEN NULL ELSE 'unused' END,$3,ARRAY['https://example.test/callback'],ARRAY['authorization_code'],'openid profile', $4,$5,$6, CASE WHEN $7 THEN NOW() ELSE NULL END)")
                .bind(client).bind(client.to_string()).bind(&name).bind(n % 2 == 0).bind(n != 0).bind(n % 3 == 0).bind(archived).execute(&pool).await.unwrap();
        }
    }
    simple_idm_core::db::groups::set_members(&pool, groups[0], &[groups[27]])
        .await
        .unwrap();
    let q = format!("q={prefix}-CURRENT");
    let first = list_html(&state, &q, true).await;
    assert!(first.contains("28 results · page 1 / 2"));
    let row = |html: &str, id: Uuid| {
        let start = html.find(&format!("<tr id=\"group-{id}\"")).unwrap();
        html[start..].split('>').next().unwrap().to_owned()
    };
    assert!(!row(&first, groups[0]).contains("hidden"));
    assert!(row(&first, groups[27]).contains("hidden"));
    let selection = list_html(&state, &format!("{q}&bulk_selection=true&page=2"), true).await;
    assert!(selection.contains("28 results · page 1 / 1"));
    assert!(!row(&selection, groups[27]).contains("hidden"));
    assert!(first.contains(&format!("data-child-id=\"{}\"", groups[27])));
    assert!(first.contains(&format!("id=\"group-edit-{}\"", groups[27])));
    let second = list_html(&state, &format!("{q}&page=99"), true).await;
    assert!(second.contains("28 results · page 2 / 2"));
    assert!(!row(&second, groups[27]).contains("hidden"));
    assert!(row(&second, groups[0]).contains("hidden"));
    let virtuals = list_html(&state, &format!("{q}&type=virtual"), true).await;
    assert!(virtuals.contains("14 results · page 1 / 1"));
    let archive = list_html(
        &state,
        &format!("q={prefix}&status=archived&type=regular&page=2"),
        true,
    )
    .await;
    assert!(archive.contains("14 results · page 1 / 1"));
    assert!(archive.contains(&format!("{prefix}-archived-27")));
    let archive = list_html(&state, &format!("q={prefix}&status=archived&page=2"), true).await;
    assert!(archive.contains("28 results · page 2 / 2"));
    assert!(archive.contains(&format!("{prefix}-archived-27")));
    assert!(!archive.contains(&format!("<td>{prefix}-archived-00</td>")));

    let clients = list_html(&state, &q, false).await;
    assert!(clients.contains("28 results · page 1 / 2"));
    assert!(clients.contains(&format!("{prefix}-current-24")));
    assert!(!clients.contains(&format!("{prefix}-current-25")));
    let last = list_html(&state, &format!("{q}&page=2"), false).await;
    assert!(last.contains(&format!("{prefix}-current-27")));
    let filtered = list_html(
        &state,
        &format!("{q}&type=public&status=active&claim_maps=yes"),
        false,
    )
    .await;
    assert!(filtered.contains("4 results · page 1 / 1"));
    let archive = list_html(&state, &format!("q={prefix}&status=archived&page=2"), false).await;
    assert!(archive.contains("28 results · page 2 / 2"));
    assert!(archive.contains(&format!("{prefix}-archived-27")));
    let none = list_html(&state, &format!("q={prefix}-current-NONE"), true).await;
    assert!(none.contains("0 results · page 1 / 1"));
    assert!(none.contains("No groups found"));

    // Search treats punctuation literally instead of SQL wildcard syntax.
    sqlx::query("INSERT INTO groups (name) VALUES ($1)")
        .bind(format!("{prefix}_100%\\tag"))
        .execute(&pool)
        .await
        .unwrap();
    let literal = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("q", &format!("{prefix}_100%\\tag"))
        .finish();
    assert!(
        list_html(&state, &literal, true)
            .await
            .contains("1 results · page 1 / 1")
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        header::REFERER,
        format!("https://idm.example.test/admin/ui/groups?{q}&type=virtual&page=2")
            .parse()
            .unwrap(),
    );
    headers.insert(
        header::COOKIE,
        "sidm_admin_session=test-session".parse().unwrap(),
    );
    let response = groups_deactivate(State(state), headers, Path(groups[0])).await;
    let location = response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        location.contains("type=virtual")
            && location.contains("page=2")
            && location.contains(&prefix)
    );
}

#[tokio::test]
#[ignore = "requires disposable ADMIN_UI_TEST_DATABASE_URL"]
async fn picker_actions_keep_view_selection_and_filters() {
    let pool = DbPool::connect(&std::env::var("ADMIN_UI_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    simple_idm_core::db::run_migrations(&pool).await.unwrap();
    let state = state(pool).await;
    let client = Uuid::new_v4();
    let group = Uuid::new_v4();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        "sidm_admin_session=test-session".parse().unwrap(),
    );
    headers.insert(header::REFERER, format!("https://idm.example.test/admin/ui/claims?client_id={client}&group_id={group}&view=by-group&by-client-filter=gitlab&by-group-filter=admin&by-client-rules=with&by-group-rules=without").parse().unwrap());
    let response = client_claims_create(
        State(state),
        headers,
        Form(ClaimMapCreateForm {
            client_id: "invalid".into(),
            group_id: None,
            claim_name: "role".into(),
            claim_value: "admin".into(),
            claim_value_kind: "single".into(),
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let url = Url::parse(&format!(
        "https://idm.example.test{}",
        response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
    ))
    .unwrap();
    let params: HashMap<_, _> = url.query_pairs().into_owned().collect();
    for (key, value) in [
        ("view", "by-group"),
        ("by-client-filter", "gitlab"),
        ("by-group-filter", "admin"),
        ("by-client-rules", "with"),
        ("by-group-rules", "without"),
    ] {
        assert_eq!(params.get(key).map(String::as_str), Some(value));
    }
    assert_eq!(params.get("client_id"), Some(&client.to_string()));
    assert_eq!(params.get("group_id"), Some(&group.to_string()));
    let mut headers = HeaderMap::new();
    headers.insert(header::REFERER, "https://idm.example.test/admin/ui/memberships?view=by-group&user_auth=local&user_status=inactive&group_type=virtual&user_filter=mares&group_filter=admin".parse().unwrap());
    let path = memberships_return_path_from_referer(&headers, "/admin/ui/memberships");
    assert!(
        path.contains("view=by-group")
            && path.contains("user_status=inactive")
            && path.contains("group_type=virtual")
            && path.contains("user_auth=local")
    );
}

#[tokio::test]
#[ignore = "requires disposable ADMIN_UI_TEST_DATABASE_URL"]
async fn user_filters_share_counts_pagination_and_sorting() {
    let pool = DbPool::connect(&std::env::var("ADMIN_UI_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    simple_idm_core::db::run_migrations(&pool).await.unwrap();
    let state = state(pool.clone()).await;
    let prefix = format!("ui-{}", Uuid::new_v4().simple());
    let mut ids = Vec::new();
    for n in 0..27 {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO users (id, username, email, password_hash, first_name, last_name, note, is_active, last_sign_in_at) VALUES ($1,$2,$3,'unused','Test',$4,'filter-note', $5, NOW() - $6 * interval '1 minute')")
            .bind(id).bind(format!("{prefix}-{n:02}")).bind(format!("{id}@example.test"))
            .bind(format!("Surname-{:02}", 26-n)).bind(n != 26).bind(n as f64).execute(&pool).await.unwrap();
        ids.push(id);
    }
    sqlx::query("INSERT INTO user_authenticators (tenant_id,user_id,kind,secret_encrypted,status) VALUES ($1,$2,'totp','unused','pending')")
        .bind(default_tenant_id()).bind(ids[0]).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO user_passkeys (tenant_id,user_id,credential_id,passkey_data,label) VALUES ($1,$2,$3,'{}'::jsonb,'Test')")
        .bind(default_tenant_id()).bind(ids[0]).bind(ids[0].as_bytes().to_vec()).execute(&pool).await.unwrap();
    let group = Uuid::new_v4();
    sqlx::query("INSERT INTO groups (id,name) VALUES ($1,$2)")
        .bind(group)
        .bind(format!("{prefix}-group"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO user_groups (user_id, group_id) VALUES ($1,$2)")
        .bind(ids[0])
        .bind(group)
        .execute(&pool)
        .await
        .unwrap();

    let first = users_html(
        &state,
        &format!("q={prefix}&auth=local&sort=username&group_id="),
    )
    .await;
    assert!(first.contains("27 users • page 1 / 2"));
    let selection = users_html(
        &state,
        &format!("q={prefix}&bulk_selection=true&page=2&auth=local"),
    )
    .await;
    assert!(selection.contains("27 users • page 1 / 1"));
    assert!(selection.contains(&format!("data-bulk-name=\"{prefix}-26\"")));
    assert!(first.contains(&format!("data-bulk-name=\"{prefix}-24\"")));
    assert!(!first.contains(&format!("data-bulk-name=\"{prefix}-25\"")));
    let second = users_html(
        &state,
        &format!("q={prefix}&auth=local&sort=username&page=2"),
    )
    .await;
    assert!(second.contains("27 users • page 2 / 2"));
    assert!(second.contains(&format!("data-bulk-name=\"{prefix}-26\"")));
    for filter in [
        "mfa=pending".into(),
        "passkeys=yes".into(),
        format!("group_id={group}"),
        "mfa=pending&passkeys=yes&note=filter-note".into(),
    ] {
        let html = users_html(&state, &format!("q={prefix}&{filter}")).await;
        assert!(html.contains("1 users • page 1 / 1"), "filter {filter}");
        assert!(html.contains(&format!("data-bulk-name=\"{prefix}-00\"")));
    }
    let none = users_html(&state, &format!("q={prefix}&auth=ad&mfa=pending")).await;
    assert!(none.contains("0 users • page 1 / 1"));
    let enrolled = users_html(&state, &format!("q={prefix}&mfa=not_enrolled&passkeys=no")).await;
    assert!(enrolled.contains("26 users • page 1 / 2"));
    let sorted = users_html(&state, &format!("q={prefix}&sort=name")).await;
    let position = |n: usize| {
        sorted
            .find(&format!("data-bulk-name=\"{prefix}-{n:02}\""))
            .unwrap()
    };
    assert!(position(26) < position(25));
    let inactive = users_html(
        &state,
        &format!("q={prefix}&status=inactive&sort=last_sign_in"),
    )
    .await;
    assert!(inactive.contains("1 users • page 1 / 1"));

    let response = bulk::users_bulk(
        State(state.clone()),
        HeaderMap::new(),
        Form(bulk::BulkForm {
            ids: ids[0].to_string(),
            action: "archive".into(),
            group_id: None,
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT deleted_at IS NULL FROM users WHERE id=$1")
            .bind(ids[0])
            .fetch_one(&pool)
            .await
            .unwrap()
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        "sidm_admin_session=test-session".parse().unwrap(),
    );
    let response = bulk::users_bulk(
        State(state),
        headers,
        Form(bulk::BulkForm {
            ids: format!("{},{}", ids[0], ids[1]),
            action: "archive".into(),
            group_id: None,
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = String::from_utf8(
        axum::body::to_bytes(response.into_body(), 1_000_000)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(html.contains("2 succeeded · 0 skipped · 0 failed"));
    assert!(html.contains(&format!("{prefix}-00")));
    assert_eq!(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM audit_events WHERE resource_id=ANY($1) AND action='user.archive' AND actor_sub IS NULL AND details->>'actor_kind'='root_token' AND details->>'changed'='true'")
        .bind(&ids[..2]).fetch_one(&pool).await.unwrap(), 2);
}

#[tokio::test]
#[ignore = "requires disposable ADMIN_UI_TEST_DATABASE_URL"]
async fn filtered_selection_is_bounded_before_loading_all_objects() {
    let pool = DbPool::connect(&std::env::var("ADMIN_UI_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    simple_idm_core::db::run_migrations(&pool).await.unwrap();
    let state = state(pool.clone()).await;
    let prefix = format!("selection-{}", Uuid::new_v4().simple());
    for n in 0..101 {
        let id = Uuid::new_v4();
        sqlx::query("WITH inserted_user AS (INSERT INTO users (id,username,email,password_hash) VALUES ($1,$2,$3,'unused')) INSERT INTO groups (id,name) VALUES ($1,$2)")
            .bind(id).bind(format!("{prefix}-{n:03}")).bind(format!("{id}@example.test")).execute(&pool).await.unwrap();
    }
    let allowed = users_html(&state, &format!("q={prefix}-0&bulk_selection=true")).await;
    assert!(allowed.contains("100 users • page 1 / 1"));
    let allowed = list_html(&state, &format!("q={prefix}-0&bulk_selection=true"), true).await;
    assert!(allowed.contains("100 results · page 1 / 1"));
    for groups in [false, true] {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "sidm_admin_session=test-session".parse().unwrap(),
        );
        let query =
            Query(serde_urlencoded::from_str(&format!("q={prefix}&bulk_selection=true")).unwrap());
        let response = if groups {
            groups_page(State(state.clone()), headers, query).await
        } else {
            users_page(State(state.clone()), headers, query).await
        };
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
