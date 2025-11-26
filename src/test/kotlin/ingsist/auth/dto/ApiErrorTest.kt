package ingsist.auth.dto

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

@DisplayName("ApiError")
class ApiErrorTest {
    companion object {
        const val MESSAGE = "Error message"
        const val CODE = "ERROR_CODE"
        const val PATH = "/api/test"
    }

    @Nested
    @DisplayName("construction")
    inner class Construction {
        @Test
        @DisplayName("should create ApiError with all fields")
        fun `creates with all fields`() {
            val error =
                ApiError(
                    message = MESSAGE,
                    code = CODE,
                    path = PATH,
                )

            assertEquals(MESSAGE, error.message)
            assertEquals(CODE, error.code)
            assertEquals(PATH, error.path)
        }

        @Test
        @DisplayName("should create ApiError with null message")
        fun `creates with null message`() {
            val error =
                ApiError(
                    message = null,
                    code = CODE,
                    path = PATH,
                )

            assertNull(error.message)
            assertEquals(CODE, error.code)
            assertEquals(PATH, error.path)
        }
    }

    @Nested
    @DisplayName("data class behavior")
    inner class DataClassBehavior {
        @Test
        @DisplayName("should be equal when fields match")
        fun `equals when fields match`() {
            val error1 = ApiError(MESSAGE, CODE, PATH)
            val error2 = ApiError(MESSAGE, CODE, PATH)

            assertEquals(error1, error2)
        }

        @Test
        @DisplayName("should not be equal when message differs")
        fun `not equals when message differs`() {
            val error1 = ApiError("message1", CODE, PATH)
            val error2 = ApiError("message2", CODE, PATH)

            assertNotEquals(error1, error2)
        }

        @Test
        @DisplayName("should not be equal when code differs")
        fun `not equals when code differs`() {
            val error1 = ApiError(MESSAGE, "CODE1", PATH)
            val error2 = ApiError(MESSAGE, "CODE2", PATH)

            assertNotEquals(error1, error2)
        }

        @Test
        @DisplayName("should not be equal when path differs")
        fun `not equals when path differs`() {
            val error1 = ApiError(MESSAGE, CODE, "/path1")
            val error2 = ApiError(MESSAGE, CODE, "/path2")

            assertNotEquals(error1, error2)
        }

        @Test
        @DisplayName("should have consistent hashCode")
        fun `consistent hashcode`() {
            val error1 = ApiError(MESSAGE, CODE, PATH)
            val error2 = ApiError(MESSAGE, CODE, PATH)

            assertEquals(error1.hashCode(), error2.hashCode())
        }

        @Test
        @DisplayName("should generate meaningful toString")
        fun `meaningful toString`() {
            val error = ApiError(MESSAGE, CODE, PATH)

            val str = error.toString()
            assert(str.contains(MESSAGE))
            assert(str.contains(CODE))
            assert(str.contains(PATH))
        }

        @Test
        @DisplayName("should support copy")
        fun `supports copy`() {
            val original = ApiError(MESSAGE, CODE, PATH)
            val copied = original.copy(code = "NEW_CODE")

            assertEquals(MESSAGE, copied.message)
            assertEquals("NEW_CODE", copied.code)
            assertEquals(PATH, copied.path)
        }
    }

    @Nested
    @DisplayName("real world error codes")
    inner class RealWorldErrorCodes {
        @Test
        @DisplayName("should create FORBIDDEN error")
        fun `creates forbidden error`() {
            val error =
                ApiError(
                    message = "User does not have permission",
                    code = "FORBIDDEN",
                    path = "/snippets/123/permissions",
                )

            assertEquals("FORBIDDEN", error.code)
        }

        @Test
        @DisplayName("should create PERMISSION_NOT_FOUND error")
        fun `creates permission not found error`() {
            val error =
                ApiError(
                    message = "No permission found",
                    code = "PERMISSION_NOT_FOUND",
                    path = "/snippets/123/permissions/user456",
                )

            assertEquals("PERMISSION_NOT_FOUND", error.code)
        }

        @Test
        @DisplayName("should create PERMISSION_ALREADY_EXISTS error")
        fun `creates permission already exists error`() {
            val error =
                ApiError(
                    message = "Permission already exists",
                    code = "PERMISSION_ALREADY_EXISTS",
                    path = "/snippets/123/permissions",
                )

            assertEquals("PERMISSION_ALREADY_EXISTS", error.code)
        }

        @Test
        @DisplayName("should create CANNOT_REVOKE_LAST_WRITE_PERMISSION error")
        fun `creates cannot revoke last write error`() {
            val error =
                ApiError(
                    message = "Cannot revoke last WRITE permission",
                    code = "CANNOT_REVOKE_LAST_WRITE_PERMISSION",
                    path = "/snippets/123/permissions/user456",
                )

            assertEquals("CANNOT_REVOKE_LAST_WRITE_PERMISSION", error.code)
        }
    }
}
