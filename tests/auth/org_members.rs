
    use super::helpers::*;

    // ------------------------------------------------------------------------
    // Missing/Invalid Token Tests
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn missing_token_returns_401() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members", org.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "missing Authorization header should return 401"
        );
    }

    #[tokio::test]
    async fn invalid_token_returns_401() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members", org.id))
                    .header("Authorization", "Bearer invalid-token-12345")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "invalid Bearer token should return 401"
        );
    }

    // ------------------------------------------------------------------------
    // Cross-Org Access Prevention
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn cannot_access_another_orgs_members() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        // Create two orgs
        let org1 = create_test_org(&conn, "Org 1");
        let org2 = create_test_org(&conn, "Org 2");

        // Create member in org1
        let (_user, _member1, key1) =
            create_test_org_member(&conn, &org1.id, "user@org1.com", OrgMemberRole::Owner);

        // Try to access org2's members with org1's key
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members", org2.id))
                    .header("Authorization", format!("Bearer {}", key1))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "org1 member should not access org2 members"
        );
    }

    #[tokio::test]
    async fn cannot_access_another_orgs_projects() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org1 = create_test_org(&conn, "Org 1");
        let org2 = create_test_org(&conn, "Org 2");

        let (_user, _member1, key1) =
            create_test_org_member(&conn, &org1.id, "user@org1.com", OrgMemberRole::Owner);

        // Create a project in org2
        let project2 = create_test_project(&conn, &org2.id, "Org2 Project", &state.master_key);

        // Try to access org2's project with org1's key
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects/{}", org2.id, project2.id))
                    .header("Authorization", format!("Bearer {}", key1))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "org1 member should not access org2 project"
        );
    }

    // ------------------------------------------------------------------------
    // Org Member Role Checks (Owner-Only Operations)
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn member_role_cannot_create_org_member() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let (_user, _member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        // Create a user to add as org member
        let new_user = create_test_user(&conn, "new@org.com", "New Member");

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/orgs/{}/members", org.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"user_id": "{}", "role": "member"}}"#,
                        new_user.id
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "member role should not create org members"
        );
    }

    #[tokio::test]
    async fn admin_role_cannot_create_org_member() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let (_user, _admin, admin_key) =
            create_test_org_member(&conn, &org.id, "admin@org.com", OrgMemberRole::Admin);

        // Create a user to add as org member
        let new_user = create_test_user(&conn, "new@org.com", "New Member");

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/orgs/{}/members", org.id))
                    .header("Authorization", format!("Bearer {}", admin_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"user_id": "{}", "role": "member"}}"#,
                        new_user.id
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "admin role should not create org members"
        );
    }

    #[tokio::test]
    async fn owner_role_can_create_org_member() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let (_user, _owner, owner_key) =
            create_test_org_member(&conn, &org.id, "owner@org.com", OrgMemberRole::Owner);

        // Create a user to add as org member
        let new_user = create_test_user(&conn, "new@org.com", "New Member");

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/orgs/{}/members", org.id))
                    .header("Authorization", format!("Bearer {}", owner_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"user_id": "{}", "role": "member"}}"#,
                        new_user.id
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "owner role should create org members"
        );
    }

    #[tokio::test]
    async fn member_cannot_update_org_member() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let (_user1, target, _target_key) =
            create_test_org_member(&conn, &org.id, "target@org.com", OrgMemberRole::Member);
        let (_user, _member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/orgs/{}/members/{}", org.id, target.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"name": "Updated Name"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "member role should not update other org members"
        );
    }

    #[tokio::test]
    async fn member_cannot_delete_org_member() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let (_user1, target, _target_key) =
            create_test_org_member(&conn, &org.id, "target@org.com", OrgMemberRole::Member);
        let (_user, _member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/orgs/{}/members/{}", org.id, target.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "member role should not delete org members"
        );
    }

    // ------------------------------------------------------------------------
    // Project Creation (Admin+ Only)
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn member_role_cannot_create_project() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let (_user, _member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/orgs/{}/projects", org.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"name": "New Project", "domain": "test.example.com", "license_key_prefix": "TEST"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "member role should not create projects"
        );
    }

    #[tokio::test]
    async fn admin_role_can_create_project() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let (_user, _admin, admin_key) =
            create_test_org_member(&conn, &org.id, "admin@org.com", OrgMemberRole::Admin);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/orgs/{}/projects", org.id))
                    .header("Authorization", format!("Bearer {}", admin_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"name": "New Project", "domain": "test.example.com", "license_key_prefix": "TEST"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "admin role should create projects"
        );
    }

    // ------------------------------------------------------------------------
    // Read Operations (Any Org Member)
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn member_can_list_org_members() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let (_user, _member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members", org.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "member role should list org members"
        );
    }

    #[tokio::test]
    async fn member_can_list_projects() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let (_user, _member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects", org.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "member role should list projects"
        );
    }

