
    use super::helpers::*;

    // ------------------------------------------------------------------------
    // Missing/Invalid Token Tests
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn missing_token_returns_401() {
        let (app, _state) = operator_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "request without Authorization header should return 401"
        );
    }

    #[tokio::test]
    async fn invalid_token_returns_401() {
        let (app, _state) = operator_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators")
                    .header("Authorization", "Bearer invalid-token-12345")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "invalid API key should return 401"
        );
    }

    #[tokio::test]
    async fn malformed_auth_header_returns_401() {
        let (app, _state) = operator_app();

        // Missing "Bearer " prefix
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators")
                    .header("Authorization", "some-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Authorization header without Bearer prefix should return 401"
        );
    }

    // ------------------------------------------------------------------------
    // Owner-Only Endpoints (/operators/*)
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn view_role_cannot_access_operator_list() {
        let (app, state) = operator_app();
        let conn = state.db.get().unwrap();

        let (_user, _view_op, view_key) =
            create_test_operator(&conn, "view@test.com", OperatorRole::View);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators")
                    .header("Authorization", format!("Bearer {}", view_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "view role should not access operator list (owner-only endpoint)"
        );
    }

    #[tokio::test]
    async fn admin_role_cannot_access_operator_list() {
        let (app, state) = operator_app();
        let conn = state.db.get().unwrap();

        let (_user, _admin_op, admin_key) =
            create_test_operator(&conn, "admin@test.com", OperatorRole::Admin);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators")
                    .header("Authorization", format!("Bearer {}", admin_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "admin role should not access operator list (owner-only endpoint)"
        );
    }

    #[tokio::test]
    async fn owner_role_can_access_operator_list() {
        let (app, state) = operator_app();
        let conn = state.db.get().unwrap();

        let (_user, _owner_op, owner_key) =
            create_test_operator(&conn, "owner@test.com", OperatorRole::Owner);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators")
                    .header("Authorization", format!("Bearer {}", owner_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "owner role should access operator list"
        );
    }

    #[tokio::test]
    async fn admin_cannot_create_operator() {
        let (app, state) = operator_app();
        let conn = state.db.get().unwrap();

        let (_user, _admin_op, admin_key) =
            create_test_operator(&conn, "admin@test.com", OperatorRole::Admin);

        // Create a user to add as operator
        let new_user = create_test_user(&conn, "new@test.com", "New Op");

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operators")
                    .header("Authorization", format!("Bearer {}", admin_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"user_id": "{}", "role": "view"}}"#,
                        new_user.id
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "admin role should not create operators (owner-only action)"
        );
    }

    #[tokio::test]
    async fn owner_can_create_operator() {
        let (app, state) = operator_app();
        let conn = state.db.get().unwrap();

        let (_user, _owner_op, owner_key) =
            create_test_operator(&conn, "owner@test.com", OperatorRole::Owner);

        // Create a user to add as operator
        let new_user = create_test_user(&conn, "new@test.com", "New Op");

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operators")
                    .header("Authorization", format!("Bearer {}", owner_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"user_id": "{}", "role": "view"}}"#,
                        new_user.id
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "owner role should create operators successfully"
        );
    }

    // ------------------------------------------------------------------------
    // Admin-Level Endpoints (/operators/organizations/*)
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn view_role_cannot_list_organizations() {
        let (app, state) = operator_app();
        let conn = state.db.get().unwrap();

        let (_user, _view_op, view_key) =
            create_test_operator(&conn, "view@test.com", OperatorRole::View);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/organizations")
                    .header("Authorization", format!("Bearer {}", view_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "view role should not list organizations (admin+ required)"
        );
    }

    #[tokio::test]
    async fn admin_role_can_list_organizations() {
        let (app, state) = operator_app();
        let conn = state.db.get().unwrap();

        let (_user, _admin_op, admin_key) =
            create_test_operator(&conn, "admin@test.com", OperatorRole::Admin);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/organizations")
                    .header("Authorization", format!("Bearer {}", admin_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "admin role should list organizations"
        );
    }

    #[tokio::test]
    async fn owner_role_can_list_organizations() {
        let (app, state) = operator_app();
        let conn = state.db.get().unwrap();

        let (_user, _owner_op, owner_key) =
            create_test_operator(&conn, "owner@test.com", OperatorRole::Owner);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/organizations")
                    .header("Authorization", format!("Bearer {}", owner_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "owner role should list organizations"
        );
    }

    #[tokio::test]
    async fn view_cannot_create_organization() {
        let (app, state) = operator_app();
        let conn = state.db.get().unwrap();

        let (_user, _view_op, view_key) =
            create_test_operator(&conn, "view@test.com", OperatorRole::View);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operators/organizations")
                    .header("Authorization", format!("Bearer {}", view_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"name": "New Org"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "view role should not create organizations (admin+ required)"
        );
    }

    #[tokio::test]
    async fn admin_can_create_organization() {
        let (app, state) = operator_app();
        let conn = state.db.get().unwrap();

        let (_user, _admin_op, admin_key) =
            create_test_operator(&conn, "admin@test.com", OperatorRole::Admin);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operators/organizations")
                    .header("Authorization", format!("Bearer {}", admin_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"name": "New Org"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "admin role should create organizations successfully"
        );
    }

    // ------------------------------------------------------------------------
    // View-Level Endpoints (/operators/audit-logs)
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn view_role_can_access_audit_logs() {
        let (app, state) = operator_app();
        let conn = state.db.get().unwrap();

        let (_user, _view_op, view_key) =
            create_test_operator(&conn, "view@test.com", OperatorRole::View);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/audit-logs")
                    .header("Authorization", format!("Bearer {}", view_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "view role should access audit logs (view+ required)"
        );
    }

    #[tokio::test]
    async fn admin_role_can_access_audit_logs() {
        let (app, state) = operator_app();
        let conn = state.db.get().unwrap();

        let (_user, _admin_op, admin_key) =
            create_test_operator(&conn, "admin@test.com", OperatorRole::Admin);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/audit-logs")
                    .header("Authorization", format!("Bearer {}", admin_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "admin role should access audit logs"
        );
    }

    #[tokio::test]
    async fn missing_token_cannot_access_audit_logs() {
        let (app, _state) = operator_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/audit-logs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "request without Authorization header should not access audit logs"
        );
    }

