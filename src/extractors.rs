//! Custom extractors that return JSON errors instead of plain text.
//!
//! These wrap Axum's built-in extractors to ensure all error responses
//! are consistent JSON format.

use axum::{
    extract::{FromRequest, FromRequestParts, Request},
    http::request::Parts,
    response::{IntoResponse, Response},
};
use serde::{Serialize, de::DeserializeOwned};

use crate::error::AppError;

/// JSON extractor that returns `AppError` on failure.
///
/// Use this instead of `axum::Json` to get JSON error responses.
#[derive(Debug, Clone, Copy, Default)]
pub struct Json<T>(pub T);

impl<S, T> FromRequest<S> for Json<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let result = axum::Json::<T>::from_request(req, state).await?;
        Ok(Json(result.0))
    }
}

impl<T> std::ops::Deref for Json<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> std::ops::DerefMut for Json<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: Serialize> IntoResponse for Json<T> {
    fn into_response(self) -> Response {
        axum::Json(self.0).into_response()
    }
}

/// Query extractor that returns `AppError` on failure.
///
/// Use this instead of `axum::extract::Query` to get JSON error responses.
#[derive(Debug, Clone, Copy, Default)]
pub struct Query<T>(pub T);

impl<S, T> FromRequestParts<S> for Query<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let result = axum::extract::Query::<T>::from_request_parts(parts, state).await?;
        Ok(Query(result.0))
    }
}

impl<T> std::ops::Deref for Query<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> std::ops::DerefMut for Query<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Path extractor that returns `AppError` on failure.
///
/// Use this instead of `axum::extract::Path` to get JSON error responses.
#[derive(Debug, Clone, Copy, Default)]
pub struct Path<T>(pub T);

impl<S, T> FromRequestParts<S> for Path<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Send,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let result = axum::extract::Path::<T>::from_request_parts(parts, state).await?;
        Ok(Path(result.0))
    }
}

impl<T> std::ops::Deref for Path<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> std::ops::DerefMut for Path<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
