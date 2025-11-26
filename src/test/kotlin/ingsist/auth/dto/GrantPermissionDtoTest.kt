package ingsist.auth.dto

import ingsist.auth.entity.AuthorizationTypes
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

@DisplayName("GrantPermissionDto")
class GrantPermissionDtoTest {
    companion object {
        const val USER_ID = "user-123"
    }

    @Nested
    @DisplayName("construction")
    inner class Construction {
        @Test
        @DisplayName("should create DTO with READ permission")
        fun `creates with read permission`() {
            val dto =
                GrantPermissionDto(
                    userId = USER_ID,
                    permission = AuthorizationTypes.READ,
                )

            assertEquals(USER_ID, dto.userId)
            assertEquals(AuthorizationTypes.READ, dto.permission)
        }

        @Test
        @DisplayName("should create DTO with WRITE permission")
        fun `creates with write permission`() {
            val dto =
                GrantPermissionDto(
                    userId = USER_ID,
                    permission = AuthorizationTypes.WRITE,
                )

            assertEquals(USER_ID, dto.userId)
            assertEquals(AuthorizationTypes.WRITE, dto.permission)
        }
    }

    @Nested
    @DisplayName("data class behavior")
    inner class DataClassBehavior {
        @Test
        @DisplayName("should be equal when fields match")
        fun `equals when fields match`() {
            val dto1 = GrantPermissionDto(USER_ID, AuthorizationTypes.READ)
            val dto2 = GrantPermissionDto(USER_ID, AuthorizationTypes.READ)

            assertEquals(dto1, dto2)
        }

        @Test
        @DisplayName("should not be equal when userId differs")
        fun `not equals when userId differs`() {
            val dto1 = GrantPermissionDto("user-1", AuthorizationTypes.READ)
            val dto2 = GrantPermissionDto("user-2", AuthorizationTypes.READ)

            assertNotEquals(dto1, dto2)
        }

        @Test
        @DisplayName("should not be equal when permission differs")
        fun `not equals when permission differs`() {
            val dto1 = GrantPermissionDto(USER_ID, AuthorizationTypes.READ)
            val dto2 = GrantPermissionDto(USER_ID, AuthorizationTypes.WRITE)

            assertNotEquals(dto1, dto2)
        }

        @Test
        @DisplayName("should have consistent hashCode")
        fun `consistent hashcode`() {
            val dto1 = GrantPermissionDto(USER_ID, AuthorizationTypes.READ)
            val dto2 = GrantPermissionDto(USER_ID, AuthorizationTypes.READ)

            assertEquals(dto1.hashCode(), dto2.hashCode())
        }

        @Test
        @DisplayName("should generate meaningful toString")
        fun `meaningful toString`() {
            val dto = GrantPermissionDto(USER_ID, AuthorizationTypes.WRITE)

            val str = dto.toString()
            assert(str.contains(USER_ID))
            assert(str.contains("WRITE"))
        }

        @Test
        @DisplayName("should support copy")
        fun `supports copy`() {
            val original = GrantPermissionDto(USER_ID, AuthorizationTypes.READ)
            val copied = original.copy(permission = AuthorizationTypes.WRITE)

            assertEquals(USER_ID, copied.userId)
            assertEquals(AuthorizationTypes.WRITE, copied.permission)
        }
    }
}
