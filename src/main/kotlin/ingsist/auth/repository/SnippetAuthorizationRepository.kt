package ingsist.auth.repository

import ingsist.auth.entity.AuthorizationTypes
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

    fun countBySnippetIdAndPermission(
        snippetId: String,
        permission: AuthorizationTypes,
    ): Long

    fun countBySnippetId(snippetId: String): Long
}
