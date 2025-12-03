package ingsist.auth.controller

import ingsist.auth.dto.AuthUsersDto
import ingsist.auth.service.Auth0ManagementService
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/users")
class UserController(
    private val auth0ManagementService: Auth0ManagementService,
) {
    @GetMapping
    fun searchUsers(
        @RequestParam email: String,
    ): ResponseEntity<List<AuthUsersDto>> {
        val users = auth0ManagementService.searchUsers(email)
        return ResponseEntity.ok(users)
    }
}
