package ingsist.auth.entity

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

@DisplayName("AuthorizationTypes Enum")
class AuthorizationTypesTest {
    @Nested
    @DisplayName("values")
    inner class Values {
        @Test
        @DisplayName("should have WRITE type with correct value")
        fun `write type has correct value`() {
            assertEquals("WRITE", AuthorizationTypes.WRITE.value)
        }

        @Test
        @DisplayName("should have READ type with correct value")
        fun `read type has correct value`() {
            assertEquals("READ", AuthorizationTypes.READ.value)
        }

        @Test
        @DisplayName("should have exactly two authorization types")
        fun `has two types`() {
            assertEquals(2, AuthorizationTypes.entries.size)
        }

        @Test
        @DisplayName("should contain both READ and WRITE")
        fun `contains read and write`() {
            val types = AuthorizationTypes.entries
            assert(types.contains(AuthorizationTypes.READ))
            assert(types.contains(AuthorizationTypes.WRITE))
        }
    }

    @Nested
    @DisplayName("enum behavior")
    inner class EnumBehavior {
        @Test
        @DisplayName("should return correct name for WRITE")
        fun `write name is correct`() {
            assertEquals("WRITE", AuthorizationTypes.WRITE.name)
        }

        @Test
        @DisplayName("should return correct name for READ")
        fun `read name is correct`() {
            assertEquals("READ", AuthorizationTypes.READ.name)
        }

        @Test
        @DisplayName("should return correct ordinal for WRITE")
        fun `write ordinal is zero`() {
            assertEquals(0, AuthorizationTypes.WRITE.ordinal)
        }

        @Test
        @DisplayName("should return correct ordinal for READ")
        fun `read ordinal is one`() {
            assertEquals(1, AuthorizationTypes.READ.ordinal)
        }

        @Test
        @DisplayName("should be able to get value from string")
        fun `valueOf works correctly`() {
            assertEquals(AuthorizationTypes.WRITE, AuthorizationTypes.valueOf("WRITE"))
            assertEquals(AuthorizationTypes.READ, AuthorizationTypes.valueOf("READ"))
        }
    }

    @Nested
    @DisplayName("comparison")
    inner class Comparison {
        @Test
        @DisplayName("should be comparable by ordinal")
        fun `comparable by ordinal`() {
            assert(AuthorizationTypes.WRITE.ordinal < AuthorizationTypes.READ.ordinal)
        }

        @Test
        @DisplayName("should support equality check")
        fun `supports equality`() {
            val type1 = AuthorizationTypes.WRITE
            val type2 = AuthorizationTypes.WRITE
            assertEquals(type1, type2)
        }
    }
}
