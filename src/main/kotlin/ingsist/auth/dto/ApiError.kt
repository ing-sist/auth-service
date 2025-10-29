package ingsist.auth.dto

data class ApiError(
    val message: String?,
    val code: String,
    val path: String
)