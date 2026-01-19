use super::helpers::*;

#[tokio::test]
async fn cannot_access_product_from_another_project() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    let org = create_test_org(&mut conn, "Test Org");
    let project1 = create_test_project(&mut conn, &org.id, "Project 1", &state.master_key);
    let project2 = create_test_project(&mut conn, &org.id, "Project 2", &state.master_key);

    // Create product in project1
    let product = create_test_product(&mut conn, &project1.id, "Product 1", "pro");

    let (_user, _owner, owner_key) =
        create_test_org_member(&mut conn, &org.id, "owner@org.com", OrgMemberRole::Owner);

    // Try to access product1 via project2's URL
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/orgs/{}/projects/{}/products/{}",
                    org.id, project2.id, product.id
                ))
                .header("Authorization", format!("Bearer {}", owner_key))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be NOT_FOUND because the product belongs to project1, not project2
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "product from project1 should not be accessible via project2's URL"
    );
}

#[tokio::test]
async fn cannot_access_license_from_another_project() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    let org = create_test_org(&mut conn, "Test Org");
    let project1 = create_test_project(&mut conn, &org.id, "Project 1", &state.master_key);
    let project2 = create_test_project(&mut conn, &org.id, "Project 2", &state.master_key);

    let product = create_test_product(&mut conn, &project1.id, "Product 1", "pro");
    let license = create_test_license(&mut conn, &project1.id, &product.id, None);

    let (_user, _owner, owner_key) =
        create_test_org_member(&mut conn, &org.id, "owner@org.com", OrgMemberRole::Owner);

    // Try to access license via project2's URL
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/orgs/{}/projects/{}/licenses/{}",
                    org.id, project2.id, license.id
                ))
                .header("Authorization", format!("Bearer {}", owner_key))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "license from project1 should not be accessible via project2's URL"
    );
}

#[tokio::test]
async fn member_with_access_to_project1_cannot_access_project2() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    let org = create_test_org(&mut conn, "Test Org");
    let project1 = create_test_project(&mut conn, &org.id, "Project 1", &state.master_key);
    let project2 = create_test_project(&mut conn, &org.id, "Project 2", &state.master_key);

    let (_user, member, member_key) =
        create_test_org_member(&mut conn, &org.id, "member@org.com", OrgMemberRole::Member);

    // Give member access to project1 only
    queries::create_project_member(&mut conn, &member.id, &project1.id, ProjectMemberRole::View)
        .unwrap();

    // Should be able to access project1
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/orgs/{}/projects/{}", org.id, project1.id))
                .header("Authorization", format!("Bearer {}", member_key))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "member with project1 access should be able to access project1"
    );

    // Should NOT be able to access project2
    // Returns 404 (not 403) to avoid leaking project existence to unauthorized users
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/orgs/{}/projects/{}", org.id, project2.id))
                .header("Authorization", format!("Bearer {}", member_key))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "member without project2 access should receive NOT_FOUND (not FORBIDDEN)"
    );
}
