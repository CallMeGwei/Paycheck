
    use super::helpers::*;

    #[tokio::test]
    async fn member_with_view_role_cannot_create_license() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);
        let _product = create_test_product(&conn, &project.id, "Pro", "pro");

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
                    .uri(format!("/orgs/{}/projects/{}/licenses", org.id, project.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"product_id": "some-id"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "member with view project role should not be able to create licenses"
        );
    }

    #[tokio::test]
    async fn member_with_view_role_can_list_licenses() {
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
                    .uri(format!("/orgs/{}/projects/{}/licenses", org.id, project.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "member with view project role should be able to list licenses"
        );
    }

    #[tokio::test]
    async fn member_with_view_role_cannot_revoke_license() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);
        let product = create_test_product(&conn, &project.id, "Pro", "pro");
        let license = create_test_license(&conn, &project.id, &product.id, None);

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
                        "/orgs/{}/projects/{}/licenses/{}/revoke",
                        org.id, project.id, license.id
                    ))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "member with view project role should not be able to revoke licenses"
        );
    }

    #[tokio::test]
    async fn member_with_admin_project_role_can_revoke_license() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);
        let product = create_test_product(&conn, &project.id, "Pro", "pro");
        let license = create_test_license(&conn, &project.id, &product.id, None);

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
                        "/orgs/{}/projects/{}/licenses/{}/revoke",
                        org.id, project.id, license.id
                    ))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "member with admin project role should be able to revoke licenses"
        );
    }

