package ingsist.auth.controller

import ingsist.auth.dto.GrantPermissionDto
import ingsist.auth.dto.SharedSnippetDto
import ingsist.auth.entity.SnippetsAuthorization
import ingsist.auth.exceptions.UnauthorizedException
import ingsist.auth.service.PermissionService
import org.slf4j.LoggerFactory
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
    val log = LoggerFactory.getLogger(PermissionController::class.java)

    @PostMapping
    fun grantPermission(
        @RequestBody request: GrantPermissionDto,
        @AuthenticationPrincipal jwt: Jwt,
    ): ResponseEntity<SnippetsAuthorization> {
        log.info("Granting permission for snippet ${request.snippetId} to user ${request.userId}")
        val requestingUserId = jwt.subject
        val result = permissionService.createAuthorization(request, requestingUserId)
        log.info("Permission granted successfully for snippet ${request.snippetId} to user ${request.userId}")
        return ResponseEntity.ok(result)
    }

    @GetMapping("/user/{userId}")
    fun getSnippetsForUser(
        @PathVariable userId: String,
        @AuthenticationPrincipal jwt: Jwt,
    ): ResponseEntity<List<SharedSnippetDto>> {
        log.info("Fetching permissions for user $userId")
        if (userId != jwt.subject) {
            log.debug("User ${jwt.subject} attempted to access permissions for user $userId")
            throw UnauthorizedException("No puedes ver los permisos de otro usuario.")
        }

        val permissions = permissionService.getPermissionsForUser(userId)
        log.info("Returning ${permissions.size} permissions for user $userId")
        return ResponseEntity.ok(permissions)
    }

    @GetMapping("/snippet/{snippetId}")
    fun hasAccess(
        @PathVariable snippetId: String,
        @RequestParam permission: ingsist.auth.entity.AuthorizationTypes,
        @AuthenticationPrincipal jwt: Jwt,
    ): ResponseEntity<Boolean> {
        log.info("Checking if user ${jwt.subject} has $permission access to snippet $snippetId")
        val userId = jwt.subject
        val hasAccess = permissionService.hasPermission(userId, snippetId, permission)
        log.info("User $userId has access: $hasAccess")
        return ResponseEntity.ok(hasAccess)
    }

    @DeleteMapping("/snippet/{snippetId}")
    fun deleteSnippetPermissions(
        @PathVariable snippetId: String,
        @AuthenticationPrincipal jwt: Jwt,
    ): ResponseEntity<Void> {
        log.info("Deleting all permissions for snippet $snippetId by user ${jwt.subject}")
        val requestingUserId = jwt.subject
        permissionService.deleteSnippet(snippetId, requestingUserId)
        log.info("All permissions for snippet $snippetId deleted successfully")
        return ResponseEntity.noContent().build()
    }
}
