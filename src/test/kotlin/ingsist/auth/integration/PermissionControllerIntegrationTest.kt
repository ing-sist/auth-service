package ingsist.auth.integration

import com.fasterxml.jackson.databind.ObjectMapper
import ingsist.auth.dto.GrantPermissionDto
import ingsist.auth.entity.AuthorizationTypes
import ingsist.auth.entity.SnippetsAuthorization
import ingsist.auth.repository.SnippetAuthorizationRepository
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.MediaType
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

@SpringBootTest
@ActiveProfiles("test")
@AutoConfigureMockMvc
class PermissionControllerIntegrationTest {
    @Autowired
    private lateinit var mockMvc: MockMvc

    @Autowired
    private lateinit var repository: SnippetAuthorizationRepository

    @Autowired
    private lateinit var objectMapper: ObjectMapper

    @BeforeEach
    fun setup() {
        repository.deleteAll()
    }

    @Test
    fun `should grant permission to a user`() {
        val snippetId = "snippet-1"
        val targetUserId = "user-2"
        val request = GrantPermissionDto(targetUserId, AuthorizationTypes.READ, snippetId)

        mockMvc.perform(
            post("/permissions")
                .with(jwt().jwt { it.claim("sub", "owner-user") })
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.userId").value(targetUserId))
            .andExpect(jsonPath("$.permission").value("READ"))

        val saved = repository.findByUserIdAndSnippetId(targetUserId, snippetId)
        assertTrue(saved.isPresent)
        assertEquals(AuthorizationTypes.READ, saved.get().permission)
    }

    @Test
    fun `should check permission for a snippet`() {
        val snippetId = "snippet-2"
        val ownerId = "owner-user"
        val otherUserId = "other-user"

        repository.save(
            SnippetsAuthorization(
                snippetId = snippetId,
                userId = ownerId,
                permission = AuthorizationTypes.WRITE,
            ),
        )
        repository.save(
            SnippetsAuthorization(
                snippetId = snippetId,
                userId = otherUserId,
                permission = AuthorizationTypes.READ,
            ),
        )

        // Check owner has WRITE
        mockMvc.perform(
            get("/permissions/snippet/$snippetId")
                .param("permission", "WRITE")
                .with(jwt().jwt { it.claim("sub", ownerId) }),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$").value(true))

        // Check other user has READ
        mockMvc.perform(
            get("/permissions/snippet/$snippetId")
                .param("permission", "READ")
                .with(jwt().jwt { it.claim("sub", otherUserId) }),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$").value(true))

        // Check other user does NOT have WRITE
        mockMvc.perform(
            get("/permissions/snippet/$snippetId")
                .param("permission", "WRITE")
                .with(jwt().jwt { it.claim("sub", otherUserId) }),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$").value(false))
    }

    @Test
    fun `should delete snippet permissions`() {
        val snippetId = "snippet-3"
        val ownerId = "owner-user"

        repository.save(
            SnippetsAuthorization(
                snippetId = snippetId,
                userId = ownerId,
                permission = AuthorizationTypes.WRITE,
            ),
        )
        repository.save(
            SnippetsAuthorization(
                snippetId = snippetId,
                userId = "user-2",
                permission = AuthorizationTypes.READ,
            ),
        )

        mockMvc.perform(
            delete("/permissions/snippet/$snippetId")
                .with(jwt().jwt { it.claim("sub", ownerId) }),
        )
            .andExpect(status().isNoContent)

        val remaining = repository.findAllBySnippetId(snippetId)
        assertTrue(remaining.isEmpty())
    }

    @Test
    fun `should return 403 when non-owner tries to grant permission`() {
        val snippetId = "snippet-5"
        val ownerId = "owner-user"
        val intruderId = "intruder"

        repository.save(
            SnippetsAuthorization(
                snippetId = snippetId,
                userId = ownerId,
                permission = AuthorizationTypes.WRITE,
            ),
        )

        val request = GrantPermissionDto("some-user", AuthorizationTypes.READ, snippetId)

        mockMvc.perform(
            post("/permissions")
                .with(jwt().jwt { it.claim("sub", intruderId) })
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)),
        )
            .andExpect(status().isForbidden)
    }
}
