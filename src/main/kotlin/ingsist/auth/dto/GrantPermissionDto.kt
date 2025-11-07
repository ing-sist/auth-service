package ingsist.auth.dto

import ingsist.auth.entity.AuthorizationTypes

data class GrantPermissionDto(
    val userId: String, // El 'targetUserId' a quien se le da el permiso
    val permission: AuthorizationTypes
)