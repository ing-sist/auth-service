package ingsist.auth.controller

import ingsist.auth.dto.AuthUsersDto
import ingsist.auth.service.Auth0ManagementService
import org.slf4j.LoggerFactory
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
    val log = LoggerFactory.getLogger(UserController::class.java)

    @GetMapping
    fun searchUsers(
        @RequestParam email: String,
    ): ResponseEntity<List<AuthUsersDto>> {
        log.info("Searching users with email: $email")
        val users = auth0ManagementService.searchUsers(email)
        log.info("Found ${users.size} user with email: $email")
        return ResponseEntity.ok(users)
    }
}
