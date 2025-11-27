package ingsist.auth.service

import com.fasterxml.jackson.databind.ObjectMapper
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.web.client.RestClient

@DisplayName("Auth0ManagementService")
class Auth0ManagementServiceTest {
    private lateinit var mockServer: MockWebServer
    private lateinit var service: Auth0ManagementService
    private lateinit var baseUrl: String

    @BeforeEach
    fun setUp() {
        mockServer = MockWebServer()
        mockServer.start()
        baseUrl = mockServer.url("/").toString().removeSuffix("/")

        service =
            Auth0ManagementService(
                domain = baseUrl,
                clientId = "test-client-id",
                clientSecret = "test-client-secret",
                managementAudience = "$baseUrl/api/v2/",
                restClientBuilder = RestClient.builder(),
            )
    }

    @AfterEach
    fun tearDown() {
        mockServer.shutdown()
    }

    @Nested
    @DisplayName("getUserEmail")
    inner class GetUserEmailTests {
        @Nested
        @DisplayName("when both requests succeed")
        inner class SuccessfulRequests {
            @Test
            @DisplayName("should return email when user exists")
            fun `returns email successfully`() {
                // Mock token response
                mockServer.enqueue(
                    MockResponse()
                        .setBody("""{"access_token":"fake-token"}""")
                        .addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE),
                )

                // Mock user response
                mockServer.enqueue(
                    MockResponse()
                        .setBody("""{"email":"test@example.com","name":"Test User"}""")
                        .addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE),
                )

                val result = service.getUserEmail("auth0|123")

                assertEquals("test@example.com", result)
            }

            @Test
            @DisplayName("should return 'email_not_found' when email is null")
            fun `returns email_not_found when email is null`() {
                mockServer.enqueue(
                    MockResponse()
                        .setBody("""{"access_token":"fake-token"}""")
                        .addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE),
                )

                mockServer.enqueue(
                    MockResponse()
                        .setBody("""{"name":"Test User"}""")
                        .addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE),
                )

                val result = service.getUserEmail("auth0|123")

                assertEquals("email_not_found", result)
            }

            @Test
            @DisplayName("should handle different user IDs")
            fun `handles different user ids`() {
                mockServer.enqueue(
                    MockResponse()
                        .setBody("""{"access_token":"fake-token"}""")
                        .addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE),
                )

                mockServer.enqueue(
                    MockResponse()
                        .setBody("""{"email":"another@example.com"}""")
                        .addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE),
                )

                val result = service.getUserEmail("google-oauth2|987")

                assertEquals("another@example.com", result)
            }
        }

        @Nested
        @DisplayName("when requests fail")
        inner class FailedRequests {
            @Test
            @DisplayName("should return 'unknown_user' when token request fails")
            fun `returns unknown_user when token request fails`() {
                mockServer.enqueue(
                    MockResponse().setResponseCode(500),
                )

                val result = service.getUserEmail("auth0|123")

                assertEquals("unknown_user", result)
            }

            @Test
            @DisplayName("should return 'unknown_user' when user request returns 404")
            fun `returns unknown_user when user not found`() {
                mockServer.enqueue(
                    MockResponse()
                        .setBody("""{"access_token":"fake-token"}""")
                        .addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE),
                )

                mockServer.enqueue(
                    MockResponse().setResponseCode(404),
                )

                val result = service.getUserEmail("auth0|123")

                assertEquals("unknown_user", result)
            }

            @Test
            @DisplayName("should return 'unknown_user' when user request fails with 500")
            fun `returns unknown_user when user request fails`() {
                mockServer.enqueue(
                    MockResponse()
                        .setBody("""{"access_token":"fake-token"}""")
                        .addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE),
                )

                mockServer.enqueue(
                    MockResponse().setResponseCode(500),
                )

                val result = service.getUserEmail("auth0|123")

                assertEquals("unknown_user", result)
            }

            @Test
            @DisplayName("should return 'unknown_user' when response is malformed")
            fun `returns unknown_user when response is malformed`() {
                mockServer.enqueue(
                    MockResponse()
                        .setBody("""{"access_token":"fake-token"}""")
                        .addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE),
                )

                mockServer.enqueue(
                    MockResponse()
                        .setBody("""invalid{json""")
                        .addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE),
                )

                val result = service.getUserEmail("auth0|123")

                assertEquals("unknown_user", result)
            }
        }
    }

    @Nested
    @DisplayName("getManagementApiToken")
    inner class GetManagementApiTokenTests {
        @Test
        @DisplayName("should send correct token request and parse response")
        fun `sends correct request and parses token`() {
            mockServer.enqueue(
                MockResponse()
                    .setBody("""{"access_token":"correct-token-value"}""")
                    .addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE),
            )

            mockServer.enqueue(
                MockResponse()
                    .setBody("""{"email":"test@example.com"}""")
                    .addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE),
            )

            val result = service.getUserEmail("auth0|123")

            assertEquals("test@example.com", result)

            // Verify the token request
            val tokenRequest = mockServer.takeRequest()
            assert(tokenRequest.path?.contains("/oauth/token") == true)
        }
    }

    @Nested
    @DisplayName("DTOs")
    inner class DtoTests {
        @Test
        @DisplayName("Auth0TokenResponse should deserialize access_token correctly")
        fun `token response dto deserializes correctly`() {
            val json = """{"access_token":"test-token-123"}"""
            val mapper = ObjectMapper()
            val response = mapper.readValue(json, Auth0ManagementService.Auth0TokenResponse::class.java)

            assertEquals("test-token-123", response.accessToken)
        }

        @Test
        @DisplayName("Auth0UserResponse should deserialize email and name correctly")
        fun `user response dto deserializes email and name`() {
            val json = """{"email":"test@example.com","name":"Test User"}"""
            val mapper = ObjectMapper()
            val response = mapper.readValue(json, Auth0ManagementService.Auth0UserResponse::class.java)

            assertEquals("test@example.com", response.email)
            assertEquals("Test User", response.name)
        }

        @Test
        @DisplayName("Auth0UserResponse should handle null email")
        fun `user response dto handles null email`() {
            val json = """{"name":"Test User"}"""
            val mapper = ObjectMapper()
            val response = mapper.readValue(json, Auth0ManagementService.Auth0UserResponse::class.java)

            assertEquals(null, response.email)
            assertEquals("Test User", response.name)
        }

        @Test
        @DisplayName("Auth0UserResponse should handle null name")
        fun `user response dto handles null name`() {
            val json = """{"email":"test@example.com"}"""
            val mapper = ObjectMapper()
            val response = mapper.readValue(json, Auth0ManagementService.Auth0UserResponse::class.java)

            assertEquals("test@example.com", response.email)
            assertEquals(null, response.name)
        }

        @Test
        @DisplayName("Auth0UserResponse should handle empty JSON object")
        fun `user response dto handles empty json`() {
            val json = """{}"""
            val mapper = ObjectMapper()
            val response = mapper.readValue(json, Auth0ManagementService.Auth0UserResponse::class.java)

            assertEquals(null, response.email)
            assertEquals(null, response.name)
        }
    }
}
