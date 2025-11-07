package ingsist.auth.dto

import ingsist.auth.entity.AuthorizationTypes

data class GrantPermissionDto(
    val userId: String,
    val permission: AuthorizationTypes,
)
