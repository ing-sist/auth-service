package ingsist.auth.exceptions

import ingsist.auth.dto.ApiError
import jakarta.servlet.http.HttpServletRequest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.Mock
import org.mockito.Mockito.`when`
import org.mockito.junit.jupiter.MockitoExtension
import org.springframework.http.HttpStatus

@ExtendWith(MockitoExtension::class)
@DisplayName("GlobalExceptionHandler")
class GlobalExceptionHandlerTest {
    private lateinit var handler: GlobalExceptionHandler

    @Mock
    private lateinit var request: HttpServletRequest

    companion object {
        const val TEST_PATH = "/test/path"
        const val SNIPPETS_PATH = "/snippets/snippet-123/permissions"
        const val USERS_PATH = "/users/user-123/permissions"
    }

    @BeforeEach
    fun setUp() {
        handler = GlobalExceptionHandler()
    }

    @Nested
    @DisplayName("handleUnauthorized")
    inner class UnauthorizedExceptionHandler {
        @Test
        @DisplayName("should return 403 FORBIDDEN with correct error details")
        fun `returns forbidden status`() {
            // Given
            val errorMessage = "User does not have permission"
            val exception = UnauthorizedException(errorMessage)
            givenRequestPath(TEST_PATH)

            // When
            val response = handler.handleUnauthorized(exception, request)

            // Then
            assertEquals(HttpStatus.FORBIDDEN, response.statusCode)
            assertApiError(response.body, errorMessage, "FORBIDDEN", TEST_PATH)
        }

        @Test
        @DisplayName("should include request URI in error response")
        fun `includes request uri`() {
            val exception = UnauthorizedException("Access denied")
            givenRequestPath(SNIPPETS_PATH)

            val response = handler.handleUnauthorized(exception, request)

            assertEquals(SNIPPETS_PATH, response.body?.path)
        }

        @Test
        @DisplayName("should handle exception with detailed message")
        fun `handles detailed message`() {
            val detailedMessage = "User user-123 does not have WRITE permission on snippet snippet-456"
            val exception = UnauthorizedException(detailedMessage)
            givenRequestPath(TEST_PATH)

            val response = handler.handleUnauthorized(exception, request)

            assertEquals(detailedMessage, response.body?.message)
        }
    }

    @Nested
    @DisplayName("handlePermissionNotFound")
    inner class PermissionNotFoundExceptionHandler {
        @Test
        @DisplayName("should return 404 NOT_FOUND with correct error details")
        fun `returns not found status`() {
            val errorMessage = "Permission not found"
            val exception = PermissionNotFoundException(errorMessage)
            givenRequestPath(TEST_PATH)

            val response = handler.handlePermissionNotFound(exception, request)

            assertEquals(HttpStatus.NOT_FOUND, response.statusCode)
            assertApiError(response.body, errorMessage, "PERMISSION_NOT_FOUND", TEST_PATH)
        }

        @Test
        @DisplayName("should handle detailed permission not found message")
        fun `handles detailed not found message`() {
            val detailedMessage = "No permission found for user user-456 on snippet snippet-789"
            val exception = PermissionNotFoundException(detailedMessage)
            givenRequestPath(SNIPPETS_PATH)

            val response = handler.handlePermissionNotFound(exception, request)

            assertEquals(detailedMessage, response.body?.message)
            assertEquals("PERMISSION_NOT_FOUND", response.body?.code)
        }
    }

    @Nested
    @DisplayName("handlePermissionAlreadyExists")
    inner class PermissionAlreadyExistsExceptionHandler {
        @Test
        @DisplayName("should return 409 CONFLICT with correct error details")
        fun `returns conflict status`() {
            val errorMessage = "Permission already exists"
            val exception = PermissionAlreadyExistsException(errorMessage)
            givenRequestPath(TEST_PATH)

            val response = handler.handlePermissionAlreadyExists(exception, request)

            assertEquals(HttpStatus.CONFLICT, response.statusCode)
            assertApiError(response.body, errorMessage, "PERMISSION_ALREADY_EXISTS", TEST_PATH)
        }

        @Test
        @DisplayName("should handle detailed duplicate permission message")
        fun `handles detailed duplicate message`() {
            val detailedMessage = "User user-456 already has a permission on snippet snippet-123"
            val exception = PermissionAlreadyExistsException(detailedMessage)
            givenRequestPath(SNIPPETS_PATH)

            val response = handler.handlePermissionAlreadyExists(exception, request)

            assertEquals(detailedMessage, response.body?.message)
            assertEquals("PERMISSION_ALREADY_EXISTS", response.body?.code)
        }
    }

    @Nested
    @DisplayName("handleCannotRevokeLastWritePermission")
    inner class CannotRevokeLastWritePermissionExceptionHandler {
        @Test
        @DisplayName("should return 400 BAD_REQUEST with correct error details")
        fun `returns bad request status`() {
            val errorMessage = "Cannot revoke last WRITE permission"
            val exception = CannotRevokeLastWritePermissionException(errorMessage)
            givenRequestPath(TEST_PATH)

            val response = handler.handleCannotRevokeLastWritePermission(exception, request)

            assertEquals(HttpStatus.BAD_REQUEST, response.statusCode)
            assertApiError(response.body, errorMessage, "CANNOT_REVOKE_LAST_WRITE_PERMISSION", TEST_PATH)
        }

        @Test
        @DisplayName("should handle detailed last writer revocation message")
        fun `handles detailed last writer message`() {
            val detailedMessage = "Cannot revoke the last WRITE permission for snippet snippet-123"
            val exception = CannotRevokeLastWritePermissionException(detailedMessage)
            givenRequestPath(SNIPPETS_PATH)

            val response = handler.handleCannotRevokeLastWritePermission(exception, request)

            assertEquals(detailedMessage, response.body?.message)
            assertEquals("CANNOT_REVOKE_LAST_WRITE_PERMISSION", response.body?.code)
        }
    }

    @Nested
    @DisplayName("error response structure")
    inner class ErrorResponseStructure {
        @Test
        @DisplayName("should create consistent ApiError structure for all exception types")
        fun `creates consistent error structure`() {
            givenRequestPath(TEST_PATH)

            val unauthorizedResponse =
                handler.handleUnauthorized(
                    UnauthorizedException("msg1"),
                    request,
                )
            val notFoundResponse =
                handler.handlePermissionNotFound(
                    PermissionNotFoundException("msg2"),
                    request,
                )
            val conflictResponse =
                handler.handlePermissionAlreadyExists(
                    PermissionAlreadyExistsException("msg3"),
                    request,
                )
            val badRequestResponse =
                handler.handleCannotRevokeLastWritePermission(
                    CannotRevokeLastWritePermissionException("msg4"),
                    request,
                )

            // All responses should have the same path
            assertEquals(TEST_PATH, unauthorizedResponse.body?.path)
            assertEquals(TEST_PATH, notFoundResponse.body?.path)
            assertEquals(TEST_PATH, conflictResponse.body?.path)
            assertEquals(TEST_PATH, badRequestResponse.body?.path)
        }

        @Test
        @DisplayName("should handle different request paths correctly")
        fun `handles different request paths`() {
            val exception = UnauthorizedException("test")

            givenRequestPath("/api/v1/snippets")
            val response1 = handler.handleUnauthorized(exception, request)
            assertEquals("/api/v1/snippets", response1.body?.path)

            givenRequestPath("/users/permissions")
            val response2 = handler.handleUnauthorized(exception, request)
            assertEquals("/users/permissions", response2.body?.path)
        }
    }

    // Helper methods
    private fun givenRequestPath(path: String) {
        `when`(request.requestURI).thenReturn(path)
    }

    private fun assertApiError(
        error: ApiError?,
        expectedMessage: String,
        expectedCode: String,
        expectedPath: String,
    ) {
        assertEquals(expectedMessage, error?.message)
        assertEquals(expectedCode, error?.code)
        assertEquals(expectedPath, error?.path)
    }
}
