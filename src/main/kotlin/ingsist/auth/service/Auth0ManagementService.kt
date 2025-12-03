package ingsist.auth.service

import com.fasterxml.jackson.annotation.JsonProperty
import ingsist.auth.dto.AuthUsersDto
import ingsist.auth.exceptions.Auth0TokenException
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.MediaType
import org.springframework.stereotype.Service
import org.springframework.web.client.RestClient
import org.springframework.web.client.RestClientException

@Service
class Auth0ManagementService(
    @Value("\${auth0.domain}") private val domain: String,
    @Value("\${auth0.management.client-id}") private val clientId: String,
    @Value("\${auth0.management.client-secret}") private val clientSecret: String,
    @Value("\${auth0.management.audience}") private val managementAudience: String,
    restClientBuilder: RestClient.Builder,
) {
    private val client = restClientBuilder.build()

    fun getUserEmail(userId: String): String {
        return try {
            // 1. Obtener Token para la Management API
            val token = getManagementApiToken()

            // 2. Normalizar dominio para la URL
            val authDomainUrl = if (domain.startsWith("http")) domain else "https://$domain"

            // 3. Consultar el usuario
            val userResponse =
                client.get()
                    .uri("$authDomainUrl/api/v2/users/$userId")
                    .header("Authorization", "Bearer $token")
                    .retrieve()
                    .body(Auth0UserResponse::class.java)

            userResponse?.email ?: "email_not_found"
        } catch (e: RestClientException) {
            println("Error fetching user email for ID $userId: ${e.message}")
            "unknown_user"
        } catch (e: IllegalStateException) {
            println("Error fetching user email for ID $userId: ${e.message}")
            "unknown_user"
        } catch (e: IllegalArgumentException) {
            println("Error fetching user email for ID $userId: ${e.message}")
            "unknown_user"
        }
    }

    fun searchUsers(emailFragment: String): List<AuthUsersDto> {
        return try {
            val token = getManagementApiToken()
            val authDomainUrl = if (domain.startsWith("http")) domain else "https://$domain"

            val query = "email:*$emailFragment*"

            val response =
                client.get()
                    .uri("$authDomainUrl/api/v2/users?q={q}&search_engine=v3", mapOf("q" to query))
                    .header("Authorization", "Bearer $token")
                    .retrieve()
                    .body(Array<Auth0UserResponse>::class.java)

            response?.map {
                AuthUsersDto(it.userId ?: "", it.email ?: "")
            }?.toList() ?: emptyList()
        } catch (e: RestClientException) {
            println("Error searching users: ${e.message}")
            emptyList()
        }
    }

    private fun getManagementApiToken(): String {
        val authDomainUrl = if (domain.startsWith("http")) domain else "https://$domain"

        val requestBody =
            mapOf(
                "client_id" to clientId,
                "client_secret" to clientSecret,
                "audience" to managementAudience,
                "grant_type" to "client_credentials",
            )

        val response =
            client.post()
                .uri("$authDomainUrl/oauth/token")
                .contentType(MediaType.APPLICATION_JSON)
                .body(requestBody)
                .retrieve()
                .body(Auth0TokenResponse::class.java)

        return response?.accessToken ?: throw Auth0TokenException("Could not retrieve Access Token from Auth0")
    }

    // DTOs internos para mapear la respuesta JSON con Jackson
    data class Auth0TokenResponse(
        @JsonProperty("access_token") val accessToken: String,
    )

    data class Auth0UserResponse(
        @JsonProperty("user_id") val userId: String? = null,
        val email: String? = null,
        val name: String? = null,
    )
}
