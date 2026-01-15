    use super::helpers::*;

    /// Creates an org app with audit logging enabled so we can test the audit endpoint
    fn org_app_with_audit() -> (Router, AppState) {
        let master_key = test_master_key();

        let manager = SqliteConnectionManager::memory();
        let pool = Pool::builder().max_size(4).build(manager).unwrap();
        {
            let conn = pool.get().unwrap();
            paycheck::db::init_db(&conn).unwrap();
        }

        let audit_manager = SqliteConnectionManager::memory();
        let audit_pool = Pool::builder().max_size(4).build(audit_manager).unwrap();
        {
            let conn = audit_pool.get().unwrap();
            paycheck::db::init_audit_db(&conn).unwrap();
        }

        let state = AppState {
            db: pool,
            audit: audit_pool,
            base_url: "http://localhost:3000".to_string(),
            audit_log_enabled: true, // Enable audit logging
            master_key,
        email_hasher: paycheck::crypto::EmailHasher::from_bytes([0xAA; 32]),
            success_page_url: "http://localhost:3000/success".to_string(),
            activation_rate_limiter: std::sync::Arc::new(
                paycheck::rate_limit::ActivationRateLimiter::default(),
            ),
            email_service: std::sync::Arc::new(paycheck::email::EmailService::new(
                None,
                "test@example.com".to_string(),
            )),
            jwks_cache: std::sync::Arc::new(paycheck::jwt::JwksCache::new()),
            trusted_issuers: vec![],
        };

        let app =
            handlers::orgs::router(state.clone(), paycheck::config::RateLimitConfig::disabled())
                .with_state(state.clone());

        (app, state)
    }

    #[tokio::test]
    async fn org_member_can_access_own_audit_logs() {
        let (app, state) = org_app_with_audit();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let (_user, _member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/audit-logs", org.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "org member should be able to access their own org's audit logs"
        );
    }

    #[tokio::test]
    async fn org_member_cannot_access_another_orgs_audit_logs() {
        let (app, state) = org_app_with_audit();
        let conn = state.db.get().unwrap();

        // Create two orgs
        let org1 = create_test_org(&conn, "Org 1");
        let org2 = create_test_org(&conn, "Org 2");

        // Create member in org1
        let (_user, _member1, key1) =
            create_test_org_member(&conn, &org1.id, "user@org1.com", OrgMemberRole::Owner);

        // Try to access org2's audit logs with org1's key
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/audit-logs", org2.id))
                    .header("Authorization", format!("Bearer {}", key1))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "org member should be forbidden from accessing another org's audit logs"
        );
    }

    #[tokio::test]
    async fn audit_logs_only_return_own_org_data() {
        use paycheck::models::{ActorType, AuditLogNames};

        let (app, state) = org_app_with_audit();
        let conn = state.db.get().unwrap();
        let audit_conn = state.audit.get().unwrap();

        // Create two orgs with members
        let org1 = create_test_org(&conn, "Org 1");
        let org2 = create_test_org(&conn, "Org 2");

        let (_user, _member1, key1) =
            create_test_org_member(&conn, &org1.id, "user@org1.com", OrgMemberRole::Owner);
        let (_user2, _member2, _key2) =
            create_test_org_member(&conn, &org2.id, "user@org2.com", OrgMemberRole::Owner);

        // Create audit logs for both orgs
        queries::create_audit_log(
            &audit_conn,
            true,
            ActorType::User,
            Some("member1"),
            "test_action_org1",
            "test_resource",
            "resource1",
            None,
            Some(&org1.id),
            None,
            None,
            None,
            &AuditLogNames::default(),
            None, // auth_type
            None, // auth_credential
        )
        .unwrap();

        queries::create_audit_log(
            &audit_conn,
            true,
            ActorType::User,
            Some("member2"),
            "test_action_org2",
            "test_resource",
            "resource2",
            None,
            Some(&org2.id),
            None,
            None,
            None,
            &AuditLogNames::default(),
            None, // auth_type
            None, // auth_credential
        )
        .unwrap();

        // Query org1's audit logs
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/audit-logs", org1.id))
                    .header("Authorization", format!("Bearer {}", key1))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "audit log request should succeed for authorized org member"
        );

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let logs = result["items"].as_array().unwrap();

        // Should only see org1's log
        assert_eq!(
            logs.len(),
            1,
            "should return exactly one audit log entry for org1"
        );
        assert_eq!(
            logs[0]["action"], "test_action_org1",
            "returned log should be org1's action, not org2's"
        );
        assert_eq!(
            logs[0]["org_id"], org1.id,
            "returned log should belong to org1"
        );
    }

    #[tokio::test]
    async fn query_param_org_id_cannot_override_path_org_id() {
        use paycheck::models::{ActorType, AuditLogNames};

        let (app, state) = org_app_with_audit();
        let conn = state.db.get().unwrap();
        let audit_conn = state.audit.get().unwrap();

        // Create two orgs
        let org1 = create_test_org(&conn, "Org 1");
        let org2 = create_test_org(&conn, "Org 2");

        let (_user, _member1, key1) =
            create_test_org_member(&conn, &org1.id, "user@org1.com", OrgMemberRole::Owner);

        // Create audit logs for both orgs
        queries::create_audit_log(
            &audit_conn,
            true,
            ActorType::User,
            Some("member1"),
            "org1_action",
            "test_resource",
            "resource1",
            None,
            Some(&org1.id),
            None,
            None,
            None,
            &AuditLogNames::default(),
            None, // auth_type
            None, // auth_credential
        )
        .unwrap();

        queries::create_audit_log(
            &audit_conn,
            true,
            ActorType::User,
            Some("member2"),
            "org2_action",
            "test_resource",
            "resource2",
            None,
            Some(&org2.id),
            None,
            None,
            None,
            &AuditLogNames::default(),
            None, // auth_type
            None, // auth_credential
        )
        .unwrap();

        // Try to query with org_id query param pointing to org2
        // The path org_id (org1) should take precedence
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/audit-logs?org_id={}", org1.id, org2.id))
                    .header("Authorization", format!("Bearer {}", key1))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "request with query param org_id override attempt should still succeed"
        );

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let logs = result["items"].as_array().unwrap();

        // Should only see org1's log, NOT org2's - path org_id takes precedence
        assert_eq!(
            logs.len(),
            1,
            "should return exactly one log entry despite query param override attempt"
        );
        assert_eq!(
            logs[0]["action"], "org1_action",
            "path org_id should take precedence over query param org_id"
        );
        assert_eq!(
            logs[0]["org_id"], org1.id,
            "returned log should belong to path org (org1), not query param org (org2)"
        );
    }

    #[tokio::test]
    async fn missing_token_cannot_access_org_audit_logs() {
        let (app, state) = org_app_with_audit();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/audit-logs", org.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "request without authorization token should be rejected as unauthorized"
        );
    }

