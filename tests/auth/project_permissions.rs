
    use super::helpers::*;

    // ------------------------------------------------------------------------
    // Member Without Project Access
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn member_without_project_access_cannot_read_project() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        // Create a member with no project membership
        let (_user, _member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects/{}", org.id, project.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Returns 404 (not 403) to avoid leaking project existence to unauthorized users
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "member without project access should get 404 (not 403) to hide project existence"
        );
    }

    #[tokio::test]
    async fn member_without_project_access_cannot_list_products() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);
        let (_user, _member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects/{}/products", org.id, project.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Returns 404 (not 403) to avoid leaking project existence to unauthorized users
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "member without project access should get 404 when listing products to hide project existence"
        );
    }

    // ------------------------------------------------------------------------
    // Member With View Project Role
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn member_with_view_role_can_read_project() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        let (_user, member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        // Add project membership with View role
        let pm_input = CreateProjectMember {
            org_member_id: member.id.clone(),
            role: ProjectMemberRole::View,
        };
        queries::create_project_member(&conn, &project.id, &pm_input).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects/{}", org.id, project.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "member with view project role should be able to read project details"
        );
    }

    #[tokio::test]
    async fn member_with_view_role_can_list_products() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        let (_user, member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let pm_input = CreateProjectMember {
            org_member_id: member.id.clone(),
            role: ProjectMemberRole::View,
        };
        queries::create_project_member(&conn, &project.id, &pm_input).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects/{}/products", org.id, project.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "member with view project role should be able to list products"
        );
    }

    #[tokio::test]
    async fn member_with_view_role_cannot_create_product() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        let (_user, member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let pm_input = CreateProjectMember {
            org_member_id: member.id.clone(),
            role: ProjectMemberRole::View,
        };
        queries::create_project_member(&conn, &project.id, &pm_input).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/orgs/{}/projects/{}/products",
                        org.id, project.id
                    ))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"name": "New Product", "tier": "pro", "activation_limit": 5, "device_limit": 3, "features": []}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "member with view-only project role should not be able to create products"
        );
    }

    #[tokio::test]
    async fn member_with_view_role_cannot_update_project() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        let (_user, member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let pm_input = CreateProjectMember {
            org_member_id: member.id.clone(),
            role: ProjectMemberRole::View,
        };
        queries::create_project_member(&conn, &project.id, &pm_input).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/orgs/{}/projects/{}", org.id, project.id))
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
            "member with view-only project role should not be able to update project"
        );
    }

    // ------------------------------------------------------------------------
    // Member With Admin Project Role
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn member_with_admin_project_role_can_create_product() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        let (_user, member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let pm_input = CreateProjectMember {
            org_member_id: member.id.clone(),
            role: ProjectMemberRole::Admin,
        };
        queries::create_project_member(&conn, &project.id, &pm_input).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/orgs/{}/projects/{}/products",
                        org.id, project.id
                    ))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"name": "New Product", "tier": "pro", "activation_limit": 5, "device_limit": 3, "features": []}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "member with admin project role should be able to create products"
        );
    }

    #[tokio::test]
    async fn member_with_admin_project_role_can_update_project() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        let (_user, member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let pm_input = CreateProjectMember {
            org_member_id: member.id.clone(),
            role: ProjectMemberRole::Admin,
        };
        queries::create_project_member(&conn, &project.id, &pm_input).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/orgs/{}/projects/{}", org.id, project.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"name": "Updated Name"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "member with admin project role should be able to update project"
        );
    }

    #[tokio::test]
    async fn member_with_admin_project_role_cannot_delete_project() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        let (_user, member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let pm_input = CreateProjectMember {
            org_member_id: member.id.clone(),
            role: ProjectMemberRole::Admin,
        };
        queries::create_project_member(&conn, &project.id, &pm_input).unwrap();

        // Project deletion requires org-level Admin or Owner
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/orgs/{}/projects/{}", org.id, project.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "project-level admin role should not be able to delete project (requires org-level admin+)"
        );
    }

    // ------------------------------------------------------------------------
    // Org-Level Admin Has Implicit Project Access
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn org_admin_has_implicit_project_write_access() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        // Admin org member - no project_members entry needed
        let (_user, _admin, admin_key) =
            create_test_org_member(&conn, &org.id, "admin@org.com", OrgMemberRole::Admin);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/orgs/{}/projects/{}/products",
                        org.id, project.id
                    ))
                    .header("Authorization", format!("Bearer {}", admin_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"name": "New Product", "tier": "pro", "activation_limit": 5, "device_limit": 3, "features": []}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "org-level admin should have implicit write access to all projects without explicit project membership"
        );
    }

    #[tokio::test]
    async fn org_owner_has_implicit_project_write_access() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        let (_user, _owner, owner_key) =
            create_test_org_member(&conn, &org.id, "owner@org.com", OrgMemberRole::Owner);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/orgs/{}/projects/{}/products",
                        org.id, project.id
                    ))
                    .header("Authorization", format!("Bearer {}", owner_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"name": "New Product", "tier": "pro", "activation_limit": 5, "device_limit": 3, "features": []}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "org owner should have implicit write access to all projects without explicit project membership"
        );
    }

    #[tokio::test]
    async fn org_admin_can_delete_project() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        let (_user, _admin, admin_key) =
            create_test_org_member(&conn, &org.id, "admin@org.com", OrgMemberRole::Admin);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/orgs/{}/projects/{}", org.id, project.id))
                    .header("Authorization", format!("Bearer {}", admin_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "org-level admin should be able to delete projects"
        );
    }

