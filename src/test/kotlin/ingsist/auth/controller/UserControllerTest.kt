package ingsist.auth.controller

import ingsist.auth.dto.AuthUsersDto
import ingsist.auth.service.Auth0ManagementService
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.Mockito.`when`
import org.mockito.junit.jupiter.MockitoExtension
import org.springframework.http.HttpStatus

@ExtendWith(MockitoExtension::class)
@DisplayName("UserController")
class UserControllerTest {
    @Mock
    private lateinit var auth0ManagementService: Auth0ManagementService

    @InjectMocks
    private lateinit var controller: UserController

    @Test
    @DisplayName("should return 200 OK with list of users")
    fun `returns ok with users list`() {
        val email = "test@example.com"
        val expectedUsers = listOf(AuthUsersDto("1", "test@example.com"))
        `when`(auth0ManagementService.searchUsers(email)).thenReturn(expectedUsers)

        val response = controller.searchUsers(email)

        assertEquals(HttpStatus.OK, response.statusCode)
        assertEquals(expectedUsers, response.body)
    }
}
