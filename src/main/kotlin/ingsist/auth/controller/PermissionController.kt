package ingsist.auth.controller

import ingsist.auth.dto.GrantPermissionDto
import ingsist.auth.dto.SharedSnippetDto
import ingsist.auth.entity.SnippetsAuthorization
import ingsist.auth.exceptions.UnauthorizedException
import ingsist.auth.service.PermissionService
import org.springframework.http.ResponseEntity
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/permissions")
class PermissionController(
    private val permissionService: PermissionService,
) {
    @PostMapping
    fun grantPermission(
        @RequestBody request: GrantPermissionDto,
        @AuthenticationPrincipal jwt: Jwt,
    ): ResponseEntity<SnippetsAuthorization> {
        val requestingUserId = jwt.subject
        val result = permissionService.createAuthorization(request, requestingUserId)
        return ResponseEntity.ok(result)
    }

    @GetMapping("/user/{userId}")
    fun getSnippetsForUser(
        @PathVariable userId: String,
        @AuthenticationPrincipal jwt: Jwt,
    ): ResponseEntity<List<SharedSnippetDto>> {
        if (userId != jwt.subject) {
            throw UnauthorizedException("No puedes ver los permisos de otro usuario.")
        }
        val permissions = permissionService.getPermissionsForUser(userId)
        return ResponseEntity.ok(permissions)
    }

    @GetMapping("/snippet/{snippetId}")
    fun hasAccess(
        @PathVariable snippetId: String,
        @RequestParam permission: ingsist.auth.entity.AuthorizationTypes,
        @AuthenticationPrincipal jwt: Jwt,
    ): ResponseEntity<Boolean> {
        val userId = jwt.subject
        val hasAccess = permissionService.hasPermission(userId, snippetId, permission)
        return ResponseEntity.ok(hasAccess)
    }

    @DeleteMapping("/snippet/{snippetId}")
    fun deleteSnippetPermissions(
        @PathVariable snippetId: String,
        @AuthenticationPrincipal jwt: Jwt,
    ): ResponseEntity<Void> {
        val requestingUserId = jwt.subject
        permissionService.deleteSnippet(snippetId, requestingUserId)
        return ResponseEntity.noContent().build()
    }
}
