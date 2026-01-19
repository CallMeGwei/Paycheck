use super::helpers::*;
use paycheck::models::DeviceType;

#[tokio::test]
async fn member_with_view_role_cannot_deactivate_device() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &state.master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, None);
    let device = create_test_device(&mut conn, &license.id, "device-123", DeviceType::Uuid);

    let (_user, member, member_key) =
        create_test_org_member(&mut conn, &org.id, "member@org.com", OrgMemberRole::Member);

    queries::create_project_member(&mut conn, &member.id, &project.id, ProjectMemberRole::View)
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/orgs/{}/projects/{}/licenses/{}/devices/{}",
                    org.id, project.id, license.id, device.device_id
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
        "member with view project role should not be able to deactivate devices"
    );
}

#[tokio::test]
async fn member_with_admin_project_role_can_deactivate_device() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &state.master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, None);
    let device = create_test_device(&mut conn, &license.id, "device-123", DeviceType::Uuid);

    let (_user, member, member_key) =
        create_test_org_member(&mut conn, &org.id, "member@org.com", OrgMemberRole::Member);

    queries::create_project_member(&mut conn, &member.id, &project.id, ProjectMemberRole::Admin)
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/orgs/{}/projects/{}/licenses/{}/devices/{}",
                    org.id, project.id, license.id, device.device_id
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
        "member with admin project role should be able to deactivate devices"
    );
}
