package ingsist.auth.entity

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

@DisplayName("SnippetsAuthorization Entity")
class SnippetsAuthorizationTest {
    companion object {
        const val SNIPPET_ID = "snippet-123"
        const val USER_ID = "user-456"
    }

    @Nested
    @DisplayName("construction")
    inner class Construction {
        @Test
        @DisplayName("should create entity with all fields")
        fun `creates with all fields`() {
            val authorization =
                SnippetsAuthorization(
                    id = "perm-1",
                    snippetId = SNIPPET_ID,
                    userId = USER_ID,
                    permission = AuthorizationTypes.WRITE,
                )

            assertEquals("perm-1", authorization.id)
            assertEquals(SNIPPET_ID, authorization.snippetId)
            assertEquals(USER_ID, authorization.userId)
            assertEquals(AuthorizationTypes.WRITE, authorization.permission)
        }

        @Test
        @DisplayName("should create entity without id (null for new entities)")
        fun `creates without id`() {
            val authorization =
                SnippetsAuthorization(
                    snippetId = SNIPPET_ID,
                    userId = USER_ID,
                    permission = AuthorizationTypes.READ,
                )

            assertNull(authorization.id)
            assertEquals(SNIPPET_ID, authorization.snippetId)
            assertEquals(USER_ID, authorization.userId)
        }

        @Test
        @DisplayName("should create entity with READ permission")
        fun `creates with read permission`() {
            val authorization =
                SnippetsAuthorization(
                    snippetId = SNIPPET_ID,
                    userId = USER_ID,
                    permission = AuthorizationTypes.READ,
                )

            assertEquals(AuthorizationTypes.READ, authorization.permission)
        }

        @Test
        @DisplayName("should create entity with WRITE permission")
        fun `creates with write permission`() {
            val authorization =
                SnippetsAuthorization(
                    snippetId = SNIPPET_ID,
                    userId = USER_ID,
                    permission = AuthorizationTypes.WRITE,
                )

            assertEquals(AuthorizationTypes.WRITE, authorization.permission)
        }
    }

    @Nested
    @DisplayName("data class behavior")
    inner class DataClassBehavior {
        @Test
        @DisplayName("should be equal when all fields match")
        fun `equals when fields match`() {
            val auth1 =
                SnippetsAuthorization(
                    id = "perm-1",
                    snippetId = SNIPPET_ID,
                    userId = USER_ID,
                    permission = AuthorizationTypes.READ,
                )
            val auth2 =
                SnippetsAuthorization(
                    id = "perm-1",
                    snippetId = SNIPPET_ID,
                    userId = USER_ID,
                    permission = AuthorizationTypes.READ,
                )

            assertEquals(auth1, auth2)
        }

        @Test
        @DisplayName("should not be equal when id differs")
        fun `not equals when id differs`() {
            val auth1 =
                SnippetsAuthorization(
                    id = "perm-1",
                    snippetId = SNIPPET_ID,
                    userId = USER_ID,
                    permission = AuthorizationTypes.READ,
                )
            val auth2 =
                SnippetsAuthorization(
                    id = "perm-2",
                    snippetId = SNIPPET_ID,
                    userId = USER_ID,
                    permission = AuthorizationTypes.READ,
                )

            assertNotEquals(auth1, auth2)
        }

        @Test
        @DisplayName("should not be equal when permission differs")
        fun `not equals when permission differs`() {
            val auth1 =
                SnippetsAuthorization(
                    id = "perm-1",
                    snippetId = SNIPPET_ID,
                    userId = USER_ID,
                    permission = AuthorizationTypes.READ,
                )
            val auth2 =
                SnippetsAuthorization(
                    id = "perm-1",
                    snippetId = SNIPPET_ID,
                    userId = USER_ID,
                    permission = AuthorizationTypes.WRITE,
                )

            assertNotEquals(auth1, auth2)
        }

        @Test
        @DisplayName("should have consistent hashCode for equal objects")
        fun `consistent hashcode`() {
            val auth1 =
                SnippetsAuthorization(
                    id = "perm-1",
                    snippetId = SNIPPET_ID,
                    userId = USER_ID,
                    permission = AuthorizationTypes.READ,
                )
            val auth2 =
                SnippetsAuthorization(
                    id = "perm-1",
                    snippetId = SNIPPET_ID,
                    userId = USER_ID,
                    permission = AuthorizationTypes.READ,
                )

            assertEquals(auth1.hashCode(), auth2.hashCode())
        }

        @Test
        @DisplayName("should generate meaningful toString")
        fun `meaningful toString`() {
            val authorization =
                SnippetsAuthorization(
                    id = "perm-1",
                    snippetId = SNIPPET_ID,
                    userId = USER_ID,
                    permission = AuthorizationTypes.WRITE,
                )

            val str = authorization.toString()
            assert(str.contains("perm-1"))
            assert(str.contains(SNIPPET_ID))
            assert(str.contains(USER_ID))
            assert(str.contains("WRITE"))
        }

        @Test
        @DisplayName("should support copy with modified fields")
        fun `supports copy`() {
            val original =
                SnippetsAuthorization(
                    id = "perm-1",
                    snippetId = SNIPPET_ID,
                    userId = USER_ID,
                    permission = AuthorizationTypes.READ,
                )

            val copied = original.copy(permission = AuthorizationTypes.WRITE)

            assertEquals("perm-1", copied.id)
            assertEquals(SNIPPET_ID, copied.snippetId)
            assertEquals(USER_ID, copied.userId)
            assertEquals(AuthorizationTypes.WRITE, copied.permission)
        }
    }

    @Nested
    @DisplayName("field mutability")
    inner class FieldMutability {
        @Test
        @DisplayName("should allow id to be modified (for JPA)")
        fun `allows id modification`() {
            val authorization =
                SnippetsAuthorization(
                    snippetId = SNIPPET_ID,
                    userId = USER_ID,
                    permission = AuthorizationTypes.READ,
                )

            authorization.id = "new-id"

            assertEquals("new-id", authorization.id)
        }
    }
}
