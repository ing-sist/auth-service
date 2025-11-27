package ingsist.auth.exceptions

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

@DisplayName("Auth Exceptions")
class AuthExceptionsTest {
    @Nested
    @DisplayName("UnauthorizedException")
    inner class UnauthorizedExceptionTests {
        @Test
        @DisplayName("should create exception with message")
        fun `creates with message`() {
            val message = "User does not have permission"
            val exception = UnauthorizedException(message)

            assertEquals(message, exception.message)
        }

        @Test
        @DisplayName("should be throwable")
        fun `is throwable`() {
            val exception =
                assertThrows<UnauthorizedException> {
                    throw UnauthorizedException("Access denied")
                }

            assertNotNull(exception)
            assertEquals("Access denied", exception.message)
        }

        @Test
        @DisplayName("should extend RuntimeException")
        fun `extends runtime exception`() {
            val exception = UnauthorizedException("test")

            assert(exception is RuntimeException)
        }

        @Test
        @DisplayName("should handle detailed user permission message")
        fun `handles detailed permission message`() {
            val message = "User user-123 does not have WRITE permission on snippet snippet-456"
            val exception = UnauthorizedException(message)

            assertEquals(message, exception.message)
        }
    }

    @Nested
    @DisplayName("PermissionAlreadyExistsException")
    inner class PermissionAlreadyExistsExceptionTests {
        @Test
        @DisplayName("should create exception with message")
        fun `creates with message`() {
            val message = "Permission already exists"
            val exception = PermissionAlreadyExistsException(message)

            assertEquals(message, exception.message)
        }

        @Test
        @DisplayName("should be throwable")
        fun `is throwable`() {
            val exception =
                assertThrows<PermissionAlreadyExistsException> {
                    throw PermissionAlreadyExistsException("Duplicate permission")
                }

            assertNotNull(exception)
        }

        @Test
        @DisplayName("should extend RuntimeException")
        fun `extends runtime exception`() {
            val exception = PermissionAlreadyExistsException("test")

            assert(exception is RuntimeException)
        }

        @Test
        @DisplayName("should handle detailed duplicate permission message")
        fun `handles detailed duplicate message`() {
            val message = "User user-456 already has a permission on snippet snippet-123"
            val exception = PermissionAlreadyExistsException(message)

            assertEquals(message, exception.message)
        }
    }

    @Nested
    @DisplayName("PermissionNotFoundException")
    inner class PermissionNotFoundExceptionTests {
        @Test
        @DisplayName("should create exception with message")
        fun `creates with message`() {
            val message = "Permission not found"
            val exception = PermissionNotFoundException(message)

            assertEquals(message, exception.message)
        }

        @Test
        @DisplayName("should be throwable")
        fun `is throwable`() {
            val exception =
                assertThrows<PermissionNotFoundException> {
                    throw PermissionNotFoundException("No permission exists")
                }

            assertNotNull(exception)
        }

        @Test
        @DisplayName("should extend RuntimeException")
        fun `extends runtime exception`() {
            val exception = PermissionNotFoundException("test")

            assert(exception is RuntimeException)
        }

        @Test
        @DisplayName("should handle detailed not found message")
        fun `handles detailed not found message`() {
            val message = "No permission found for user user-456 on snippet snippet-789"
            val exception = PermissionNotFoundException(message)

            assertEquals(message, exception.message)
        }
    }

    @Nested
    @DisplayName("CannotRevokeLastWritePermissionException")
    inner class CannotRevokeLastWritePermissionExceptionTests {
        @Test
        @DisplayName("should create exception with message")
        fun `creates with message`() {
            val message = "Cannot revoke last WRITE permission"
            val exception = CannotRevokeLastWritePermissionException(message)

            assertEquals(message, exception.message)
        }

        @Test
        @DisplayName("should be throwable")
        fun `is throwable`() {
            val exception =
                assertThrows<CannotRevokeLastWritePermissionException> {
                    throw CannotRevokeLastWritePermissionException("Cannot remove last writer")
                }

            assertNotNull(exception)
        }

        @Test
        @DisplayName("should extend RuntimeException")
        fun `extends runtime exception`() {
            val exception = CannotRevokeLastWritePermissionException("test")

            assert(exception is RuntimeException)
        }

        @Test
        @DisplayName("should handle detailed last writer message")
        fun `handles detailed last writer message`() {
            val message = "Cannot revoke the last WRITE permission for snippet snippet-123"
            val exception = CannotRevokeLastWritePermissionException(message)

            assertEquals(message, exception.message)
        }
    }

    @Nested
    @DisplayName("exception hierarchy")
    inner class ExceptionHierarchy {
        @Test
        @DisplayName("all exceptions should be RuntimeException subtypes")
        fun `all are runtime exceptions`() {
            val exceptions =
                listOf(
                    UnauthorizedException("test"),
                    PermissionAlreadyExistsException("test"),
                    PermissionNotFoundException("test"),
                    CannotRevokeLastWritePermissionException("test"),
                )

            exceptions.forEach { exception ->
                assert(exception is RuntimeException) {
                    "${exception::class.simpleName} should be RuntimeException"
                }
            }
        }

        @Test
        @DisplayName("all exceptions should be catchable as Exception")
        fun `catchable as exception`() {
            val exceptions =
                listOf(
                    UnauthorizedException("test"),
                    PermissionAlreadyExistsException("test"),
                    PermissionNotFoundException("test"),
                    CannotRevokeLastWritePermissionException("test"),
                    Auth0TokenException("test"),
                )

            exceptions.forEach { exception ->
                assert(exception is Exception) {
                    "${exception::class.simpleName} should be Exception"
                }
            }
        }
    }

    @Nested
    @DisplayName("Auth0TokenException")
    inner class Auth0TokenExceptionTests {
        @Test
        @DisplayName("should create exception with message")
        fun `creates with message`() {
            val message = "Could not retrieve Access Token from Auth0"
            val exception = Auth0TokenException(message)

            assertEquals(message, exception.message)
        }

        @Test
        @DisplayName("should be throwable")
        fun `is throwable`() {
            val exception =
                assertThrows<Auth0TokenException> {
                    throw Auth0TokenException("Token request failed")
                }

            assertNotNull(exception)
            assertEquals("Token request failed", exception.message)
        }

        @Test
        @DisplayName("should extend RuntimeException")
        fun `extends runtime exception`() {
            val exception = Auth0TokenException("test")

            assert(exception is RuntimeException)
        }

        @Test
        @DisplayName("should handle detailed error messages")
        fun `handles detailed error messages`() {
            val message = "Failed to retrieve M2M token: HTTP 401 Unauthorized"
            val exception = Auth0TokenException(message)

            assertEquals(message, exception.message)
        }
    }
}
