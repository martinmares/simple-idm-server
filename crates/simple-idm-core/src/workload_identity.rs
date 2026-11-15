//! Explicit Kubernetes workload trust. Disabled unless an administrator loads a config.
//!
//! Signature verification does not perform TokenReview: deletion/revocation is bounded
//! by token expiration. Issued access tokens never outlive their subject token.
use crate::auth::JwtService;
use axum::{
    Json,
    extract::{Form, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::{AlgorithmParameters, EllipticCurve, JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

pub const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
pub const SUBJECT_TYPE: &str = "urn:ietf:params:oauth:token-type:jwt";
pub const ACCESS_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
pub const AUDIENCE: &str = "simple-config-server";
const MAX_DOCUMENT: usize = 256 * 1024;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub issuers: Vec<TrustedIssuer>,
    /// Optional internal CA bundle for the configured Kubernetes JWKS endpoints.
    #[serde(default)]
    pub jwks_ca_file: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedIssuer {
    pub name: String,
    pub issuer: String,
    pub jwks_url: String,
    pub subject_audience: String,
    pub grants: Vec<Grant>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub namespace: String,
    pub service_account: String,
    pub service_account_uid: String,
    pub application: String,
}

fn safe_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && value.as_bytes()[0] != b'-'
        && !value.ends_with('-')
}

fn trusted_url(value: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(value) else {
        return false;
    };
    url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && (url.scheme() == "https"
            || (url.scheme() == "http" && matches!(url.host_str(), Some("127.0.0.1" | "[::1]"))))
}

impl Config {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.issuers.is_empty() || self.issuers.len() > 32 {
            return Err("invalid workload issuer count");
        }
        let mut names = HashSet::new();
        let mut issuers = HashSet::new();
        for issuer in &self.issuers {
            if !safe_name(&issuer.name)
                || !names.insert(&issuer.name)
                || !issuers.insert(&issuer.issuer)
                || !trusted_url(&issuer.issuer)
                || !trusted_url(&issuer.jwks_url)
                || issuer.subject_audience.is_empty()
                || issuer.subject_audience.len() > 256
                || issuer.subject_audience.chars().any(char::is_whitespace)
                || issuer.grants.is_empty()
                || issuer.grants.len() > 4096
            {
                return Err("invalid workload issuer configuration");
            }
            let mut accounts = HashSet::new();
            for grant in &issuer.grants {
                if !safe_name(&grant.namespace)
                    || !safe_name(&grant.service_account)
                    || grant.service_account == "default"
                    || !safe_name(&grant.application)
                    || uuid::Uuid::parse_str(&grant.service_account_uid).is_err()
                    || !accounts.insert((&grant.namespace, &grant.service_account))
                {
                    return Err("invalid or duplicate workload grant");
                }
            }
        }
        Ok(())
    }
}

struct CachedKeys {
    loaded: Instant,
    keys: JwkSet,
}

fn verification_key(
    keys: &JwkSet,
    kid: &str,
    algorithm: Algorithm,
) -> Result<DecodingKey, &'static str> {
    let mut matches = keys
        .keys
        .iter()
        .filter(|key| key.common.key_id.as_deref() == Some(kid));
    let key = matches.next().ok_or("invalid_subject_token")?;
    let matching_key_type = match (&key.algorithm, algorithm) {
        (AlgorithmParameters::RSA(_), Algorithm::RS256) => true,
        (AlgorithmParameters::EllipticCurve(ec), Algorithm::ES256) => {
            ec.curve == EllipticCurve::P256
        }
        _ => false,
    };
    if !matching_key_type
        || matches.next().is_some()
        || key
            .common
            .public_key_use
            .as_ref()
            .is_some_and(|usage| *usage != PublicKeyUse::Signature)
        || key
            .common
            .key_algorithm
            .as_ref()
            .is_some_and(|alg| *alg != KeyAlgorithm::from(algorithm))
        || key
            .common
            .key_operations
            .as_ref()
            .is_some_and(|ops| !ops.contains(&KeyOperations::Verify))
    {
        return Err("invalid_subject_token");
    }
    DecodingKey::from_jwk(key).map_err(|_| "invalid_subject_token")
}

pub struct WorkloadIdentity {
    config: Config,
    signing: Arc<JwtService>,
    http: reqwest::Client,
    keys: Mutex<HashMap<String, CachedKeys>>,
}

impl WorkloadIdentity {
    pub fn new(config: Config, signing: Arc<JwtService>) -> Result<Self, &'static str> {
        config.validate()?;
        let mut http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none());
        if let Some(path) = &config.jwks_ca_file {
            let pem = std::fs::read(path).map_err(|_| "cannot read workload JWKS CA bundle")?;
            let certificates = reqwest::Certificate::from_pem_bundle(&pem)
                .map_err(|_| "invalid workload JWKS CA bundle")?;
            if certificates.is_empty() {
                return Err("empty workload JWKS CA bundle");
            }
            for certificate in certificates {
                http = http.add_root_certificate(certificate);
            }
        }
        let http = http
            .build()
            .map_err(|_| "cannot initialize workload verification")?;
        Ok(Self {
            config,
            signing,
            http,
            keys: Mutex::new(HashMap::new()),
        })
    }

    async fn decoding_key(
        &self,
        issuer: &TrustedIssuer,
        kid: &str,
        algorithm: Algorithm,
    ) -> Result<DecodingKey, &'static str> {
        // Serialize refreshes, including unknown kids, to avoid attacker-triggered fetch storms.
        let mut cache = self.keys.lock().await;
        if !cache
            .get(&issuer.name)
            .is_some_and(|entry| entry.loaded.elapsed() < Duration::from_secs(60))
        {
            let mut response = self
                .http
                .get(&issuer.jwks_url)
                .send()
                .await
                .map_err(|_| "jwks_unavailable")?;
            if response.status() != reqwest::StatusCode::OK {
                return Err("jwks_unavailable");
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| "jwks_unavailable")? {
                if bytes.len() + chunk.len() > MAX_DOCUMENT {
                    return Err("jwks_unavailable");
                }
                bytes.extend_from_slice(&chunk);
            }
            let keys: JwkSet = serde_json::from_slice(&bytes).map_err(|_| "jwks_unavailable")?;
            if keys.keys.is_empty() || keys.keys.len() > 64 {
                return Err("jwks_unavailable");
            }
            cache.insert(
                issuer.name.clone(),
                CachedKeys {
                    loaded: Instant::now(),
                    keys,
                },
            );
        }
        let keys = &cache.get(&issuer.name).ok_or("jwks_unavailable")?.keys;
        verification_key(keys, kid, algorithm)
    }

    async fn exchange(&self, request: ExchangeRequest) -> Result<TokenResponse, &'static str> {
        if request.grant_type != GRANT_TYPE
            || request.subject_token_type != SUBJECT_TYPE
            || request
                .requested_token_type
                .as_deref()
                .is_some_and(|s| s != ACCESS_TYPE)
            || request.scope.as_deref().is_some_and(|s| s != "config:read")
        {
            return Err("invalid_request");
        }
        if request.audience != AUDIENCE {
            return Err("invalid_target");
        }
        if request.subject_token.len() > 32 * 1024 {
            return Err("invalid_subject_token");
        }
        let header = decode_header(&request.subject_token).map_err(|_| "invalid_subject_token")?;
        if !matches!(header.alg, Algorithm::RS256 | Algorithm::ES256) {
            return Err("invalid_subject_token");
        }
        let kid = header
            .kid
            .filter(|s| !s.is_empty() && s.len() <= 256)
            .ok_or("invalid_subject_token")?;
        // Unverified payload selects ONLY a preconfigured issuer. It grants no authority.
        let payload = request
            .subject_token
            .split('.')
            .nth(1)
            .ok_or("invalid_subject_token")?;
        let bytes = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| "invalid_subject_token")?;
        #[derive(Deserialize)]
        struct IssuerHint {
            iss: String,
        }
        let hint: IssuerHint =
            serde_json::from_slice(&bytes).map_err(|_| "invalid_subject_token")?;
        let issuer = self
            .config
            .issuers
            .iter()
            .find(|i| i.issuer == hint.iss)
            .ok_or("invalid_subject_token")?;
        let key = self.decoding_key(issuer, &kid, header.alg).await?;
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&issuer.issuer]);
        validation.set_audience(&[&issuer.subject_audience]);
        validation.set_required_spec_claims(&["exp", "iat", "iss", "aud", "sub", "nbf"]);
        validation.validate_nbf = true;
        validation.leeway = 5;
        let claims = decode::<SubjectClaims>(&request.subject_token, &key, &validation)
            .map_err(|_| "invalid_subject_token")?
            .claims;
        let grant = verified_grant(issuer, &claims, Utc::now().timestamp())?;
        let subject = format!(
            "workload:{}:{}:{}:{}",
            issuer.name, grant.namespace, grant.service_account, grant.service_account_uid
        );
        let groups = vec![
            format!("simple-config:tenant:{}", grant.namespace),
            "simple-config:env:default".into(),
            format!("simple-config:app:{}", grant.application),
        ];
        let (access_token, ttl) = self
            .signing
            .create_workload_token(subject, groups, claims.exp)
            .map_err(|_| "server_error")?;
        tracing::info!(
            issuer = issuer.name,
            namespace = grant.namespace,
            service_account = grant.service_account,
            service_account_uid = grant.service_account_uid,
            application = grant.application,
            pod = claims.kubernetes.pod.name,
            pod_uid = claims.kubernetes.pod.uid,
            "workload token issued"
        );
        Ok(TokenResponse {
            access_token,
            issued_token_type: ACCESS_TYPE,
            token_type: "Bearer",
            expires_in: ttl,
            scope: "config:read",
        })
    }
}

#[derive(Clone, Deserialize)]
struct SubjectClaims {
    sub: String,
    exp: i64,
    iat: i64,
    #[serde(rename = "kubernetes.io")]
    kubernetes: KubernetesIdentity,
}
#[derive(Clone, Deserialize)]
struct KubernetesIdentity {
    namespace: String,
    serviceaccount: BoundObject,
    pod: BoundObject,
}
#[derive(Clone, Deserialize)]
struct BoundObject {
    name: String,
    uid: String,
}

fn verified_grant<'a>(
    issuer: &'a TrustedIssuer,
    claims: &SubjectClaims,
    now: i64,
) -> Result<&'a Grant, &'static str> {
    let identity = &claims.kubernetes;
    if claims.iat > now + 5
        || claims.exp <= now
        || claims.exp <= claims.iat
        || claims
            .exp
            .checked_sub(claims.iat)
            .is_none_or(|ttl| ttl > 3600)
        || identity.pod.name.is_empty()
        || uuid::Uuid::parse_str(&identity.pod.uid).is_err()
        || claims.sub
            != format!(
                "system:serviceaccount:{}:{}",
                identity.namespace, identity.serviceaccount.name
            )
    {
        return Err("invalid_subject_token");
    }
    issuer
        .grants
        .iter()
        .find(|g| {
            g.namespace == identity.namespace
                && g.service_account == identity.serviceaccount.name
                && g.service_account_uid == identity.serviceaccount.uid
        })
        .ok_or("access_denied")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeRequest {
    grant_type: String,
    subject_token: String,
    subject_token_type: String,
    audience: String,
    requested_token_type: Option<String>,
    scope: Option<String>,
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    issued_token_type: &'static str,
    token_type: &'static str,
    expires_in: i64,
    scope: &'static str,
}

pub async fn handle_exchange(
    State(state): State<Arc<WorkloadIdentity>>,
    Form(request): Form<ExchangeRequest>,
) -> Response {
    let result = state.exchange(request).await;
    let response = match result {
        Ok(token) => Json(token).into_response(),
        Err(error) => {
            let status = match error {
                "access_denied" => StatusCode::FORBIDDEN,
                "jwks_unavailable" => StatusCode::SERVICE_UNAVAILABLE,
                "server_error" => StatusCode::INTERNAL_SERVER_ERROR,
                _ => StatusCode::BAD_REQUEST,
            };
            tracing::warn!(reason = error, "workload token rejected");
            (status, Json(serde_json::json!({"error": error}))).into_response()
        }
    };
    no_store(response).await
}

pub async fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert("Cache-Control", "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert("Pragma", "no-cache".parse().unwrap());
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::Body,
        http::Request,
        routing::{get, post},
    };
    use jsonwebtoken::{EncodingKey, Header, encode};
    use rsa::{
        RsaPrivateKey, RsaPublicKey,
        pkcs8::{EncodePrivateKey, EncodePublicKey},
        traits::PublicKeyParts,
    };
    use serde_json::{Value, json};
    use std::sync::{
        OnceLock,
        atomic::{AtomicUsize, Ordering},
    };
    use tower::ServiceExt;

    const UID: &str = "c0ec7a83-6652-43e4-b27c-a20a8fa95034";
    fn key_material() -> &'static (String, String, Value) {
        static KEYS: OnceLock<(String, String, Value)> = OnceLock::new();
        KEYS.get_or_init(|| {
            let private = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
            let public = RsaPublicKey::from(&private);
            let jwks = json!({"keys":[{"kty":"RSA","kid":"cluster-key","use":"sig","alg":"RS256",
                "n":URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),"e":URL_SAFE_NO_PAD.encode(public.e().to_bytes_be())}]});
            (private.to_pkcs8_pem(Default::default()).unwrap().to_string(), public.to_public_key_pem(Default::default()).unwrap(), jwks)
        })
    }
    fn issuer(url: &str) -> TrustedIssuer {
        TrustedIssuer {
            name: "test-cluster".into(),
            issuer: url.into(),
            jwks_url: format!("{url}/jwks"),
            subject_audience: "simple-idm-workload".into(),
            grants: vec![Grant {
                namespace: "test-namespace".into(),
                service_account: "scs-calendar".into(),
                service_account_uid: UID.into(),
                application: "calendar".into(),
            }],
        }
    }
    fn claims(url: &str) -> Value {
        let now = Utc::now().timestamp();
        json!({"iss":url,"aud":["simple-idm-workload"],"sub":"system:serviceaccount:test-namespace:scs-calendar",
            "exp":now+600,"iat":now,"nbf":now,
            "kubernetes.io":{"namespace":"test-namespace","serviceaccount":{"name":"scs-calendar","uid":UID},
                "pod":{"name":"calendar-test","uid":"011fdc36-f73d-4654-944b-03425272f19d"}}})
    }
    fn request(claims: &Value) -> ExchangeRequest {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("cluster-key".into());
        ExchangeRequest {
            grant_type: GRANT_TYPE.into(),
            subject_token: encode(
                &header,
                claims,
                &EncodingKey::from_rsa_pem(key_material().0.as_bytes()).unwrap(),
            )
            .unwrap(),
            subject_token_type: SUBJECT_TYPE.into(),
            audience: AUDIENCE.into(),
            requested_token_type: None,
            scope: None,
        }
    }
    async fn fixture() -> (
        Arc<WorkloadIdentity>,
        String,
        tempfile::TempDir,
        tokio::task::JoinHandle<()>,
        Arc<AtomicUsize>,
    ) {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let router = Router::new().route(
            "/jwks",
            get(move || {
                counter.fetch_add(1, Ordering::SeqCst);
                async { Json(key_material().2.clone()) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let dir = tempfile::tempdir().unwrap();
        // Independent keys: possession of the cluster key must not permit IDM impersonation.
        static SIGNING: OnceLock<(String, String)> = OnceLock::new();
        let signing_keys = SIGNING.get_or_init(|| {
            let private = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
            let public = RsaPublicKey::from(&private);
            (
                private
                    .to_pkcs8_pem(Default::default())
                    .unwrap()
                    .to_string(),
                public.to_public_key_pem(Default::default()).unwrap(),
            )
        });
        std::fs::write(dir.path().join("private.pem"), &signing_keys.0).unwrap();
        std::fs::write(dir.path().join("public.pem"), &signing_keys.1).unwrap();
        let signing = Arc::new(
            JwtService::new(
                dir.path().join("private.pem").to_str().unwrap(),
                dir.path().join("public.pem").to_str().unwrap(),
                "https://idm.test".into(),
                "idm-key".into(),
                vec![],
            )
            .unwrap(),
        );
        let state = Arc::new(
            WorkloadIdentity::new(
                Config {
                    issuers: vec![issuer(&url)],
                    jwks_ca_file: None,
                },
                signing,
            )
            .unwrap(),
        );
        (state, url, dir, task, calls)
    }

    #[test]
    fn configuration_rejects_ambiguous_or_unsafe_trust() {
        let valid = Config {
            issuers: vec![issuer("https://cluster.test")],
            jwks_ca_file: None,
        };
        assert!(valid.validate().is_ok());
        let mut invalid = valid.clone();
        invalid.issuers[0].jwks_url = "http://cluster.test/jwks".into();
        assert!(invalid.validate().is_err());
        let mut invalid = valid.clone();
        invalid.issuers.push(valid.issuers[0].clone());
        assert!(invalid.validate().is_err());
        let mut invalid = valid.clone();
        invalid.issuers[0]
            .grants
            .push(valid.issuers[0].grants[0].clone());
        assert!(invalid.validate().is_err());
        let mut invalid = valid.clone();
        invalid.issuers[0].grants[0].application = "calendar simple-config:role:admin".into();
        assert!(invalid.validate().is_err());
        let mut invalid = valid;
        invalid.issuers[0].grants[0].service_account_uid.clear();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn rejects_encryption_keys_wrong_algorithm_operations_and_ambiguous_kids() {
        let valid: JwkSet = serde_json::from_value(key_material().2.clone()).unwrap();
        assert!(verification_key(&valid, "cluster-key", Algorithm::RS256).is_ok());
        let mut invalid = valid.clone();
        invalid.keys[0].common.public_key_use = Some(PublicKeyUse::Encryption);
        assert!(verification_key(&invalid, "cluster-key", Algorithm::RS256).is_err());
        let mut invalid = valid.clone();
        invalid.keys[0].common.key_algorithm = Some(KeyAlgorithm::RS512);
        assert!(verification_key(&invalid, "cluster-key", Algorithm::RS256).is_err());
        let mut invalid = valid.clone();
        invalid.keys[0].common.key_operations = Some(vec![KeyOperations::Sign]);
        assert!(verification_key(&invalid, "cluster-key", Algorithm::RS256).is_err());
        let mut invalid = valid.clone();
        invalid.keys.push(valid.keys[0].clone());
        assert!(verification_key(&invalid, "cluster-key", Algorithm::RS256).is_err());
    }

    #[tokio::test]
    async fn verifies_es256_cluster_identity_and_rejects_algorithm_confusion() {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let (state, url, _dir, task, _) = fixture().await;
        let private = p256::SecretKey::random(&mut rsa::rand_core::OsRng);
        let point = private.public_key().to_encoded_point(false);
        let keys: JwkSet = serde_json::from_value(json!({"keys":[{
            "kty":"EC","kid":"cluster-ec","alg":"ES256","use":"sig","crv":"P-256",
            "x":URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y":URL_SAFE_NO_PAD.encode(point.y().unwrap())
        }]}))
        .unwrap();
        assert!(verification_key(&keys, "cluster-ec", Algorithm::ES256).is_ok());
        assert!(verification_key(&keys, "cluster-ec", Algorithm::RS256).is_err());
        assert!(verification_key(&keys, "cluster-ec", Algorithm::HS256).is_err());
        let mut wrong_algorithm = keys.clone();
        wrong_algorithm.keys[0].common.key_algorithm = Some(KeyAlgorithm::RS256);
        assert!(verification_key(&wrong_algorithm, "cluster-ec", Algorithm::ES256).is_err());
        let mut wrong_curve = keys.clone();
        if let AlgorithmParameters::EllipticCurve(ec) = &mut wrong_curve.keys[0].algorithm {
            ec.curve = EllipticCurve::P384;
        }
        assert!(verification_key(&wrong_curve, "cluster-ec", Algorithm::ES256).is_err());
        state.keys.lock().await.insert(
            "test-cluster".into(),
            CachedKeys {
                loaded: Instant::now(),
                keys,
            },
        );
        let encoding =
            EncodingKey::from_ec_pem(private.to_pkcs8_pem(Default::default()).unwrap().as_bytes())
                .unwrap();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("cluster-ec".into());
        let mut exchange = request(&claims(&url));
        exchange.subject_token = encode(&header, &claims(&url), &encoding).unwrap();
        let issued = state.exchange(exchange).await.unwrap();
        assert_eq!(
            decode_header(&issued.access_token).unwrap().alg,
            Algorithm::RS256
        );
        let verified = state
            .signing
            .verify_access_token(
                &issued.access_token,
                &[AUDIENCE.into()],
                &["config:read".into()],
            )
            .unwrap();
        assert!(
            verified
                .groups
                .contains(&"simple-config:app:calendar".to_string())
        );
        let mut altered = claims(&url);
        altered["kubernetes.io"]["serviceaccount"]["uid"] =
            json!("011fdc36-f73d-4654-944b-03425272f19d");
        let mut exchange = request(&altered);
        exchange.subject_token = encode(&header, &altered, &encoding).unwrap();
        assert_eq!(state.exchange(exchange).await.err(), Some("access_denied"));
        task.abort();
    }

    #[tokio::test]
    async fn issues_only_bound_workload_access_and_caches_public_keys() {
        let (state, url, _dir, task, calls) = fixture().await;
        let issued = state.exchange(request(&claims(&url))).await.unwrap();
        let verified = state
            .signing
            .verify_access_token(
                &issued.access_token,
                &[AUDIENCE.into()],
                &["config:read".into()],
            )
            .unwrap();
        assert_eq!(
            verified.sub,
            format!("workload:test-cluster:test-namespace:scs-calendar:{UID}")
        );
        assert_eq!(
            verified.groups,
            vec![
                "simple-config:tenant:test-namespace",
                "simple-config:env:default",
                "simple-config:app:calendar"
            ]
        );
        assert_eq!(verified.amr, vec!["workload"]);
        assert!(verified.email.is_none());
        assert!(issued.expires_in <= 300);
        assert!(
            state
                .signing
                .verify_access_token(&issued.access_token, &["other-service".into()], &[])
                .is_err()
        );
        let mut nearly_expired = claims(&url);
        nearly_expired["exp"] = json!(Utc::now().timestamp() + 45);
        assert!(
            state
                .exchange(request(&nearly_expired))
                .await
                .unwrap()
                .expires_in
                <= 45
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        state
            .keys
            .lock()
            .await
            .get_mut("test-cluster")
            .unwrap()
            .loaded = Instant::now() - Duration::from_secs(61);
        state.exchange(request(&claims(&url))).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        task.abort();
    }

    #[tokio::test]
    async fn rejects_wrong_identity_scope_target_signature_and_lifetime() {
        let (state, url, _dir, task, _) = fixture().await;
        for (pointer, value) in [
            ("/aud", json!(["kubernetes"])),
            ("/iss", json!("https://untrusted.test")),
            ("/sub", json!("system:serviceaccount:other:scs-calendar")),
            (
                "/kubernetes.io/serviceaccount/uid",
                json!("d81c238b-05be-48db-9be1-ae61e00b7362"),
            ),
            ("/kubernetes.io/namespace", json!("other")),
            ("/kubernetes.io/pod/uid", json!("")),
            ("/exp", json!(Utc::now().timestamp() - 60)),
            ("/exp", json!(Utc::now().timestamp() + 7200)),
            ("/iat", json!(Utc::now().timestamp() + 100)),
            ("/nbf", json!(Utc::now().timestamp() + 100)),
        ] {
            let mut invalid = claims(&url);
            *invalid.pointer_mut(pointer).unwrap() = value;
            assert!(
                state.exchange(request(&invalid)).await.is_err(),
                "accepted invalid bound claim at {pointer}"
            );
        }
        let mut invalid = request(&claims(&url));
        invalid.audience = "simple-runtime-catalog".into();
        assert_eq!(state.exchange(invalid).await.err(), Some("invalid_target"));
        let mut invalid = request(&claims(&url));
        invalid.scope = Some("admin:*".into());
        assert_eq!(state.exchange(invalid).await.err(), Some("invalid_request"));
        let mut invalid = request(&claims(&url));
        invalid.subject_token.push('x');
        assert!(state.exchange(invalid).await.is_err());
        task.abort();
    }

    #[tokio::test]
    async fn http_errors_are_private_and_caller_cannot_choose_application() {
        let (state, url, _dir, task, _) = fixture().await;
        let token = request(&claims(&url)).subject_token;
        let form = serde_urlencoded::to_string([
            ("grant_type", GRANT_TYPE),
            ("subject_token_type", SUBJECT_TYPE),
            ("subject_token", &token),
            ("audience", AUDIENCE),
            ("application", "user-management"),
        ])
        .unwrap();
        let app = Router::new()
            .route("/token", post(handle_exchange))
            .layer(axum::middleware::map_response(no_store))
            .with_state(state);
        let response = app
            .oneshot(
                Request::post("/token")
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(Body::from(form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(!response.status().is_success());
        assert_eq!(response.headers()["Cache-Control"], "no-store");
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&body).contains(&token));
        task.abort();
    }

    /// Opt-in cross-language test. Uses the production IDM handler/signing service,
    /// the real Go proxy and real SCS; no human DB, cluster or customer secrets.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[cfg(unix)]
    #[ignore = "requires SIMPLE_TOKEN_PROXY_E2E_BIN and SIMPLE_CONFIG_SERVER_E2E_BIN"]
    async fn real_go_proxy_and_scs_accept_only_idm_issued_identity() {
        use std::process::{Child, Command, Stdio};
        struct Children(Vec<Child>);
        impl Drop for Children {
            fn drop(&mut self) {
                for child in self.0.iter_mut().rev() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
        fn port() -> u16 {
            std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port()
        }
        fn write_private(path: &std::path::Path, text: &str) {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .mode(0o600)
                .open(path)
                .unwrap();
            file.write_all(text.as_bytes()).unwrap();
        }
        async fn ready(client: &reqwest::Client, url: &str, child: &mut Child) {
            for _ in 0..200 {
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "test process exited; no credentials logged"
                );
                if client
                    .get(url)
                    .send()
                    .await
                    .is_ok_and(|r| r.status().is_success())
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            panic!("local test readiness timeout");
        }
        let go = std::env::var("SIMPLE_TOKEN_PROXY_E2E_BIN").expect("Go binary path required");
        let scs = std::env::var("SIMPLE_CONFIG_SERVER_E2E_BIN").expect("SCS binary path required");
        let (state, cluster_issuer, dir, cluster_task, _) = fixture().await;
        let signing = state.signing.clone();
        let idm = Router::new()
            .route("/oauth2/workload/token", post(handle_exchange))
            .layer(axum::middleware::map_response(no_store))
            .with_state(state)
            .route(
                "/.well-known/jwks.json",
                get(move || {
                    let signing = signing.clone();
                    async move { Json(signing.get_jwks().unwrap()) }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let idm_url = format!("http://{}", listener.local_addr().unwrap());
        let idm_task = tokio::spawn(async move {
            axum::serve(listener, idm).await.unwrap();
        });
        let scs_port = port();
        let mut proxy_port = port();
        while proxy_port == scs_port {
            proxy_port = port();
        }
        let scs_url = format!("http://127.0.0.1:{scs_port}");
        let proxy_url = format!("http://127.0.0.1:{proxy_port}");
        let templates = dir.path().join("templates");
        std::fs::create_dir(&templates).unwrap();
        write_private(&templates.join("calendar.yml"), "synthetic: true\n");
        write_private(&templates.join("user-management.yml"), "synthetic: true\n");
        let config = json!({"server":{"bind":format!("127.0.0.1:{scs_port}")},"tenancy":{"mode":"multi"},
            "tenants":{"test-namespace":{"environments":{"default":{"source":{"backend":"filesystem","root":templates}}}}},
            "auth":{"bearer":{"enabled":true,"issuers":[{"name":"test-idm","kind":"simple-idm-jwt",
                "issuer":"https://idm.test","audience":AUDIENCE,"jwks_url":format!("{idm_url}/.well-known/jwks.json")}]}}});
        let config_file = dir.path().join("scs.json");
        write_private(&config_file, &config.to_string());
        let subject_file = dir.path().join("subject.token");
        write_private(
            &subject_file,
            &request(&claims(&cluster_issuer)).subject_token,
        );
        let mut children = Children(vec![]);
        let mut scs_command = Command::new(scs);
        scs_command
            .arg("--config")
            .arg(&config_file)
            .current_dir(dir.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (key, _) in std::env::vars().filter(|(k, _)| k.starts_with("SIMPLE_CONFIG_")) {
            scs_command.env_remove(key);
        }
        children.0.push(scs_command.spawn().unwrap());
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        ready(&client, &format!("{scs_url}/healthz"), &mut children.0[0]).await;
        let mut proxy_command = Command::new(go);
        proxy_command
            .args([
                "serve",
                "--listen",
                &format!("127.0.0.1:{proxy_port}"),
                "--upstream",
                &scs_url,
                "--token-file",
                subject_file.to_str().unwrap(),
                "--token-exchange-url",
                &format!("{idm_url}/oauth2/workload/token"),
                "--token-audience",
                AUDIENCE,
            ])
            .current_dir(dir.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (key, _) in std::env::vars().filter(|(k, _)| k.starts_with("SIMPLE_TOKEN_PROXY_")) {
            proxy_command.env_remove(key);
        }
        children.0.push(proxy_command.spawn().unwrap());
        ready(&client, &format!("{proxy_url}/healthz"), &mut children.0[1]).await;
        let path = "/api/v1/tenants/test-namespace/envs/default/calendar/default";
        assert_eq!(
            client
                .get(format!("{proxy_url}{path}"))
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::OK
        );
        let denied = client
            .get(format!(
                "{proxy_url}/api/v1/tenants/test-namespace/envs/default/user-management/default"
            ))
            .header("X-Auth-Groups", "simple-config:role:admin")
            .header("X-Application", "user-management")
            .send()
            .await
            .unwrap();
        // The existing simple-idm-jwt SCS path uses 401 for a denied grant.
        assert_eq!(denied.status(), reqwest::StatusCode::UNAUTHORIZED);
        let original = request(&claims(&cluster_issuer)).subject_token;
        assert_eq!(
            client
                .get(format!("{scs_url}{path}"))
                .bearer_auth(&original)
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::UNAUTHORIZED
        );
        let mut forged = claims(&cluster_issuer);
        forged["iss"] = json!("https://idm.test");
        forged["aud"] = json!([AUDIENCE]);
        forged["groups"] = json!([
            "simple-config:tenant:test-namespace",
            "simple-config:env:default",
            "simple-config:app:calendar"
        ]);
        forged["scope"] = json!("config:read");
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("idm-key".into());
        let forged = encode(
            &header,
            &forged,
            &EncodingKey::from_rsa_pem(key_material().0.as_bytes()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            client
                .get(format!("{scs_url}{path}"))
                .bearer_auth(forged)
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::UNAUTHORIZED
        );
        let mut wrong = claims(&cluster_issuer);
        wrong["kubernetes.io"]["serviceaccount"]["uid"] =
            json!("68a6e0ab-ddff-4d8f-9499-b865738ca2ba");
        write_private(&subject_file, &request(&wrong).subject_token);
        let response = client
            .get(format!("{proxy_url}{path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);
        let body = response.text().await.unwrap();
        assert!(!body.contains(&original));
        write_private(&subject_file, &original);
        assert_eq!(
            client
                .get(format!("{proxy_url}{path}"))
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::OK
        );
        idm_task.abort();
        cluster_task.abort();
    }
}
