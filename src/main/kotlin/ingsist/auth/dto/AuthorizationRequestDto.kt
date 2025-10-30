package ingsist.auth.dto

import ingsist.auth.entity.AuthorizationTypes

data class AuthorizationRequestDto(val userId: String, val snippetId: String, val permission: AuthorizationTypes)
