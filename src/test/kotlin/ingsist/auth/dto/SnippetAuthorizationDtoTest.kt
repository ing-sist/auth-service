package ingsist.auth.dto

import ingsist.auth.entity.AuthorizationTypes
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

@DisplayName("SnippetAuthorizationDto")
class SnippetAuthorizationDtoTest {
    companion object {
        const val SNIPPET_ID = "snippet-123"
        const val USER_ID = "user-456"
        const val USER_EMAIL = "user@example.com"
        const val PERMISSION_ID = "perm-789"

        fun aDto(
            id: String? = PERMISSION_ID,
            snippetId: String = SNIPPET_ID,
            userId: String = USER_ID,
            userEmail: String = USER_EMAIL,
            permission: AuthorizationTypes = AuthorizationTypes.READ,
        ) = SnippetAuthorizationDto(
            id = id,
            snippetId = snippetId,
            userId = userId,
            userEmail = userEmail,
            permission = permission,
        )
    }

    @Nested
    @DisplayName("Construction")
    inner class ConstructionTests {
        @Test
        @DisplayName("should create DTO with all fields")
        fun `creates with all fields`() {
            val dto = aDto()

            assertEquals(PERMISSION_ID, dto.id)
            assertEquals(SNIPPET_ID, dto.snippetId)
            assertEquals(USER_ID, dto.userId)
            assertEquals(USER_EMAIL, dto.userEmail)
            assertEquals(AuthorizationTypes.READ, dto.permission)
        }

        @Test
        @DisplayName("should create DTO with null id")
        fun `creates with null id`() {
            val dto = aDto(id = null)

            assertEquals(null, dto.id)
            assertEquals(SNIPPET_ID, dto.snippetId)
            assertEquals(USER_ID, dto.userId)
            assertEquals(USER_EMAIL, dto.userEmail)
        }

        @Test
        @DisplayName("should create DTO with WRITE permission")
        fun `creates with write permission`() {
            val dto = aDto(permission = AuthorizationTypes.WRITE)

            assertEquals(AuthorizationTypes.WRITE, dto.permission)
        }

        @Test
        @DisplayName("should create DTO with READ permission")
        fun `creates with read permission`() {
            val dto = aDto(permission = AuthorizationTypes.READ)

            assertEquals(AuthorizationTypes.READ, dto.permission)
        }
    }

    @Nested
    @DisplayName("Equality")
    inner class EqualityTests {
        @Test
        @DisplayName("should be equal when all fields match")
        fun `equal when fields match`() {
            val dto1 = aDto()
            val dto2 = aDto()

            assertEquals(dto1, dto2)
        }

        @Test
        @DisplayName("should not be equal when id differs")
        fun `not equal when id differs`() {
            val dto1 = aDto(id = "id-1")
            val dto2 = aDto(id = "id-2")

            assertNotEquals(dto1, dto2)
        }

        @Test
        @DisplayName("should not be equal when snippetId differs")
        fun `not equal when snippet id differs`() {
            val dto1 = aDto(snippetId = "snippet-1")
            val dto2 = aDto(snippetId = "snippet-2")

            assertNotEquals(dto1, dto2)
        }

        @Test
        @DisplayName("should not be equal when userId differs")
        fun `not equal when user id differs`() {
            val dto1 = aDto(userId = "user-1")
            val dto2 = aDto(userId = "user-2")

            assertNotEquals(dto1, dto2)
        }

        @Test
        @DisplayName("should not be equal when userEmail differs")
        fun `not equal when user email differs`() {
            val dto1 = aDto(userEmail = "user1@example.com")
            val dto2 = aDto(userEmail = "user2@example.com")

            assertNotEquals(dto1, dto2)
        }

        @Test
        @DisplayName("should not be equal when permission differs")
        fun `not equal when permission differs`() {
            val dto1 = aDto(permission = AuthorizationTypes.READ)
            val dto2 = aDto(permission = AuthorizationTypes.WRITE)

            assertNotEquals(dto1, dto2)
        }
    }

    @Nested
    @DisplayName("Field Access")
    inner class FieldAccessTests {
        @Test
        @DisplayName("should provide access to id field")
        fun `provides id access`() {
            val dto = aDto(id = "custom-id")

            assertEquals("custom-id", dto.id)
        }

        @Test
        @DisplayName("should provide access to snippetId field")
        fun `provides snippet id access`() {
            val dto = aDto(snippetId = "custom-snippet")

            assertEquals("custom-snippet", dto.snippetId)
        }

        @Test
        @DisplayName("should provide access to userId field")
        fun `provides user id access`() {
            val dto = aDto(userId = "custom-user")

            assertEquals("custom-user", dto.userId)
        }

        @Test
        @DisplayName("should provide access to userEmail field")
        fun `provides user email access`() {
            val dto = aDto(userEmail = "custom@example.com")

            assertEquals("custom@example.com", dto.userEmail)
        }

        @Test
        @DisplayName("should provide access to permission field")
        fun `provides permission access`() {
            val dto = aDto(permission = AuthorizationTypes.WRITE)

            assertEquals(AuthorizationTypes.WRITE, dto.permission)
        }
    }

    @Nested
    @DisplayName("Use Cases")
    inner class UseCasesTests {
        @Test
        @DisplayName("should represent a READ permission")
        fun `represents read permission`() {
            val dto =
                aDto(
                    id = "perm-1",
                    snippetId = "snippet-123",
                    userId = "user-456",
                    userEmail = "reader@example.com",
                    permission = AuthorizationTypes.READ,
                )

            assertEquals(AuthorizationTypes.READ, dto.permission)
            assertEquals("reader@example.com", dto.userEmail)
        }

        @Test
        @DisplayName("should represent a WRITE permission")
        fun `represents write permission`() {
            val dto =
                aDto(
                    id = "perm-2",
                    snippetId = "snippet-789",
                    userId = "owner-123",
                    userEmail = "owner@example.com",
                    permission = AuthorizationTypes.WRITE,
                )

            assertEquals(AuthorizationTypes.WRITE, dto.permission)
            assertEquals("owner@example.com", dto.userEmail)
        }

        @Test
        @DisplayName("should support listing multiple permissions")
        fun `supports listing multiple permissions`() {
            val permissions =
                listOf(
                    aDto(id = "perm-1", userId = "user-1", userEmail = "user1@example.com"),
                    aDto(id = "perm-2", userId = "user-2", userEmail = "user2@example.com"),
                    aDto(id = "perm-3", userId = "user-3", userEmail = "user3@example.com"),
                )

            assertEquals(3, permissions.size)
            assertEquals("user1@example.com", permissions[0].userEmail)
            assertEquals("user2@example.com", permissions[1].userEmail)
            assertEquals("user3@example.com", permissions[2].userEmail)
        }
    }

    @Nested
    @DisplayName("Data Class Features")
    inner class DataClassFeaturesTests {
        @Test
        @DisplayName("should support copy with modified fields")
        fun `supports copy with modifications`() {
            val original = aDto()
            val modified = original.copy(userEmail = "new@example.com")

            assertEquals(original.id, modified.id)
            assertEquals(original.snippetId, modified.snippetId)
            assertEquals(original.userId, modified.userId)
            assertEquals("new@example.com", modified.userEmail)
            assertEquals(original.permission, modified.permission)
        }

        @Test
        @DisplayName("should generate meaningful toString")
        fun `generates meaningful toString`() {
            val dto = aDto()
            val toString = dto.toString()

            assert(toString.contains("SnippetAuthorizationDto"))
            assert(toString.contains(SNIPPET_ID))
            assert(toString.contains(USER_ID))
            assert(toString.contains(USER_EMAIL))
        }
    }
}
