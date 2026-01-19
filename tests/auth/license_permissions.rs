use super::helpers::*;

// ------------------------------------------------------------------------
// Member Without Project Access
// ------------------------------------------------------------------------

#[tokio::test]
async fn member_without_project_access_cannot_list_licenses() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &state.master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let _license = create_test_license(&mut conn, &project.id, &product.id, None);

    // Create a member with no project membership
    let (_user, _member, member_key) =
        create_test_org_member(&mut conn, &org.id, "member@org.com", OrgMemberRole::Member);

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

    // Returns 404 (not 403) to avoid leaking project existence to unauthorized users
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "member without project access should get 404 when listing licenses to hide project existence"
    );
}

#[tokio::test]
async fn member_without_project_access_cannot_get_license() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &state.master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, None);

    // Create a member with no project membership
    let (_user, _member, member_key) =
        create_test_org_member(&mut conn, &org.id, "member@org.com", OrgMemberRole::Member);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/orgs/{}/projects/{}/licenses/{}",
                    org.id, project.id, license.id
                ))
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
        "member without project access should get 404 when getting license to hide project existence"
    );
}

// ------------------------------------------------------------------------
// Member With View Project Role
// ------------------------------------------------------------------------

#[tokio::test]
async fn member_with_view_role_cannot_create_license() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &state.master_key);
    let _product = create_test_product(&mut conn, &project.id, "Pro", "pro");

    let (_user, member, member_key) =
        create_test_org_member(&mut conn, &org.id, "member@org.com", OrgMemberRole::Member);

    queries::create_project_member(&mut conn, &member.id, &project.id, ProjectMemberRole::View)
        .unwrap();

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
    let mut conn = state.db.get().unwrap();

    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &state.master_key);

    let (_user, member, member_key) =
        create_test_org_member(&mut conn, &org.id, "member@org.com", OrgMemberRole::Member);

    queries::create_project_member(&mut conn, &member.id, &project.id, ProjectMemberRole::View)
        .unwrap();

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
    let mut conn = state.db.get().unwrap();

    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &state.master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, None);

    let (_user, member, member_key) =
        create_test_org_member(&mut conn, &org.id, "member@org.com", OrgMemberRole::Member);

    queries::create_project_member(&mut conn, &member.id, &project.id, ProjectMemberRole::View)
        .unwrap();

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
    let mut conn = state.db.get().unwrap();

    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &state.master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, None);

    let (_user, member, member_key) =
        create_test_org_member(&mut conn, &org.id, "member@org.com", OrgMemberRole::Member);

    queries::create_project_member(&mut conn, &member.id, &project.id, ProjectMemberRole::Admin)
        .unwrap();

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
