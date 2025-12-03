package ingsist.auth.repository

import ingsist.auth.entity.SnippetsAuthorization
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository
import java.util.Optional

@Repository
interface SnippetAuthorizationRepository : JpaRepository<SnippetsAuthorization, String> {
    fun findByUserIdAndSnippetId(
        userId: String,
        snippetId: String,
    ): Optional<SnippetsAuthorization>

    fun countBySnippetId(snippetId: String): Long

    fun findAllBySnippetId(snippetId: String): List<SnippetsAuthorization>

    fun findAllByUserId(userId: String): List<SnippetsAuthorization>

    fun deleteAllBySnippetId(snippetId: String)
}
