package ingsist.auth.controller

import ingsist.auth.entity.AuthorizationTypes
import ingsist.auth.service.AuthorizationService
import org.springframework.http.ResponseEntity
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.web.bind.annotation.*
import ingsist.auth.dto.AuthorizationRequestDto

@RestController
@RequestMapping("/permissions")
class AuthorizationController(private val authorizationService: AuthorizationService) {

    @GetMapping("/check")
    fun check(
        @RequestParam userId: String,
        @RequestParam snippetId: String,
        @RequestParam requiredPermission: AuthorizationTypes
    ): ResponseEntity<Unit> {
        authorizationService.checkPermission(userId, snippetId, requiredPermission)
        return ResponseEntity.ok().build()
    }

    @PostMapping
    fun grant(@RequestBody request: AuthorizationRequestDto, @AuthenticationPrincipal jwt: Jwt): ResponseEntity<Unit> {
        val requestingUserId = jwt.subject // El usuario que está autenticado
        authorizationService.grantPermission(request.targetUserId, request.snippetId, request.permission, requestingUserId)
        return ResponseEntity.status(201).build()
    }

    @DeleteMapping
    fun revoke(@RequestBody request: AuthorizationRequestDto, @AuthenticationPrincipal jwt: Jwt): ResponseEntity<Unit> {
        val requestingUserId = jwt.subject
        authorizationService.revokePermission(request.targetUserId, request.snippetId, requestingUserId)
        return ResponseEntity.noContent().build()
    }
}