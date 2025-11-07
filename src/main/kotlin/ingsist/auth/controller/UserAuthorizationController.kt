package ingsist.auth.controller

import ingsist.auth.entity.SnippetsAuthorization
import ingsist.auth.exceptions.UnauthorizedException
import ingsist.auth.service.UserAuthorizationService
import org.springframework.http.ResponseEntity
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/users")
class UserAuthorizationController(private val userAuthorizationService: UserAuthorizationService) {
    /**
     * Listar todos los permisos de un usuario.
     * GET /users/{userId}/permissions
     */
    @GetMapping("/{userId}/permissions")
    fun getPermissionsForUser(
        @PathVariable userId: String,
        @AuthenticationPrincipal jwt: Jwt,
    ): ResponseEntity<List<SnippetsAuthorization>> {
        val requestingUserId = jwt.subject
        if (userId != requestingUserId) {
            throw UnauthorizedException("No puedes ver los permisos de otro usuario.")
        }

        val permissions = userAuthorizationService.getPermissionsForUser(userId)
        return ResponseEntity.ok(permissions)
    }
}
