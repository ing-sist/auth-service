package ingsist.auth.security

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.springframework.security.oauth2.jwt.Jwt
import java.time.Instant

@DisplayName("AudienceValidator")
class AudienceValidatorTest {
    companion object {
        const val EXPECTED_AUDIENCE = "https://snippetApi"
        const val DIFFERENT_AUDIENCE = "https://different-api"
        const val ANOTHER_AUDIENCE = "https://another-api"

        fun createJwtWithAudience(vararg audiences: String): Jwt {
            return Jwt.withTokenValue("test-token")
                .header("alg", "RS256")
                .claim("sub", "user123")
                .claim("aud", audiences.toList())
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build()
        }
    }

    @Nested
    @DisplayName("validate")
    inner class ValidateTests {
        private val validator = AudienceValidator(EXPECTED_AUDIENCE)

        @Nested
        @DisplayName("when JWT contains expected audience")
        inner class ValidAudience {
            @Test
            @DisplayName("should return success when audience matches exactly")
            fun `returns success for matching audience`() {
                // Given
                val jwt = createJwtWithAudience(EXPECTED_AUDIENCE)

                // When
                val result = validator.validate(jwt)

                // Then
                assertFalse(result.hasErrors())
            }

            @Test
            @DisplayName("should return success when expected audience is among multiple audiences")
            fun `returns success for multiple audiences including expected`() {
                val jwt = createJwtWithAudience(DIFFERENT_AUDIENCE, EXPECTED_AUDIENCE, ANOTHER_AUDIENCE)

                val result = validator.validate(jwt)

                assertFalse(result.hasErrors())
            }

            @Test
            @DisplayName("should return success when expected audience is first in list")
            fun `returns success when expected is first`() {
                val jwt = createJwtWithAudience(EXPECTED_AUDIENCE, DIFFERENT_AUDIENCE)

                val result = validator.validate(jwt)

                assertFalse(result.hasErrors())
            }

            @Test
            @DisplayName("should return success when expected audience is last in list")
            fun `returns success when expected is last`() {
                val jwt = createJwtWithAudience(DIFFERENT_AUDIENCE, ANOTHER_AUDIENCE, EXPECTED_AUDIENCE)

                val result = validator.validate(jwt)

                assertFalse(result.hasErrors())
            }
        }

        @Nested
        @DisplayName("when JWT does not contain expected audience")
        inner class InvalidAudience {
            @Test
            @DisplayName("should return failure when audience is different")
            fun `returns failure for different audience`() {
                val jwt = createJwtWithAudience(DIFFERENT_AUDIENCE)

                val result = validator.validate(jwt)

                assertTrue(result.hasErrors())
            }

            @Test
            @DisplayName("should return failure when audience list does not contain expected")
            fun `returns failure when expected not in list`() {
                val jwt = createJwtWithAudience(DIFFERENT_AUDIENCE, ANOTHER_AUDIENCE)

                val result = validator.validate(jwt)

                assertTrue(result.hasErrors())
            }

            @Test
            @DisplayName("should return error with correct message")
            fun `returns error with invalid_token description`() {
                val jwt = createJwtWithAudience(DIFFERENT_AUDIENCE)

                val result = validator.validate(jwt)

                assertTrue(result.hasErrors())
                val error = result.errors.first()
                assertTrue(error.errorCode == "invalid_token")
                assertTrue(error.description == "The required audience is missing")
            }
        }

        @Nested
        @DisplayName("edge cases")
        inner class EdgeCases {
            @Test
            @DisplayName("should handle empty audience list")
            fun `handles empty audience list`() {
                val jwt =
                    Jwt.withTokenValue("test-token")
                        .header("alg", "RS256")
                        .claim("sub", "user123")
                        .claim("aud", emptyList<String>())
                        .issuedAt(Instant.now())
                        .expiresAt(Instant.now().plusSeconds(3600))
                        .build()

                val result = validator.validate(jwt)

                assertTrue(result.hasErrors())
            }

            @Test
            @DisplayName("should be case-sensitive when matching audience")
            fun `is case sensitive`() {
                val jwt = createJwtWithAudience("HTTPS://SNIPPETAPI")

                val result = validator.validate(jwt)

                assertTrue(result.hasErrors())
            }

            @Test
            @DisplayName("should handle partial audience match as failure")
            fun `handles partial match as failure`() {
                val jwt = createJwtWithAudience("https://snippet")

                val result = validator.validate(jwt)

                assertTrue(result.hasErrors())
            }
        }
    }

    @Nested
    @DisplayName("different configurations")
    inner class DifferentConfigurations {
        @Test
        @DisplayName("should work with different expected audience values")
        fun `works with different expected audiences`() {
            val customValidator = AudienceValidator("https://custom-api")
            val jwt = createJwtWithAudience("https://custom-api")

            val result = customValidator.validate(jwt)

            assertFalse(result.hasErrors())
        }

        @Test
        @DisplayName("should work with simple audience string")
        fun `works with simple audience string`() {
            val simpleValidator = AudienceValidator("my-api")
            val jwt = createJwtWithAudience("my-api")

            val result = simpleValidator.validate(jwt)

            assertFalse(result.hasErrors())
        }
    }
}
