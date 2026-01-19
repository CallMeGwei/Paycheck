use super::helpers::*;

#[tokio::test]
async fn member_with_view_role_cannot_add_project_member() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &state.master_key);

    let (_user, member, member_key) =
        create_test_org_member(&mut conn, &org.id, "member@org.com", OrgMemberRole::Member);
    let (user2, _other_member, _) =
        create_test_org_member(&mut conn, &org.id, "other@org.com", OrgMemberRole::Member);

    queries::create_project_member(&mut conn, &member.id, &project.id, ProjectMemberRole::View)
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orgs/{}/projects/{}/members", org.id, project.id))
                .header("Authorization", format!("Bearer {}", member_key))
                .header("Content-Type", "application/json")
                .body(Body::from(format!(
                    r#"{{"user_id": "{}", "role": "view"}}"#,
                    user2.id
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "member with view project role should not be able to add project members"
    );
}

#[tokio::test]
async fn member_with_admin_project_role_can_add_project_member() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &state.master_key);

    let (_user, member, member_key) =
        create_test_org_member(&mut conn, &org.id, "member@org.com", OrgMemberRole::Member);
    let (user2, _other_member, _) =
        create_test_org_member(&mut conn, &org.id, "other@org.com", OrgMemberRole::Member);

    queries::create_project_member(&mut conn, &member.id, &project.id, ProjectMemberRole::Admin)
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orgs/{}/projects/{}/members", org.id, project.id))
                .header("Authorization", format!("Bearer {}", member_key))
                .header("Content-Type", "application/json")
                .body(Body::from(format!(
                    r#"{{"user_id": "{}", "role": "view"}}"#,
                    user2.id
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "member with admin project role should be able to add project members"
    );
}

#[tokio::test]
async fn member_can_list_project_members_with_view_role() {
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
                .uri(format!("/orgs/{}/projects/{}/members", org.id, project.id))
                .header("Authorization", format!("Bearer {}", member_key))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "member with view project role should be able to list project members"
    );
}
