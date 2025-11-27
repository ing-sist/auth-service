package ingsist.auth.dto

import ingsist.auth.entity.AuthorizationTypes

data class SnippetAuthorizationDto(
    val id: String?,
    val snippetId: String,
    val userId: String,
    val userEmail: String,
    val permission: AuthorizationTypes,
)
