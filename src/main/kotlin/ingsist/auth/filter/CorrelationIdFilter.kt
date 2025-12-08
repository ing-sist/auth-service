package ingsist.auth.filter

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.MDC
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import java.util.UUID

@Component
class CorrelationIdFilter : OncePerRequestFilter() {
    companion object {
        private const val CORRELATION_ID_KEY = "correlation-id"
        private const val CORRELATION_ID_HEADER = "X-Correlation-Id"
    }

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain,
    ) {
        val correlationId =
            request.getHeader(CORRELATION_ID_HEADER)
                ?.takeIf { it.isNotBlank() }
                ?: UUID.randomUUID().toString()

        // lo guardamos en MDC para que lo agarren todos los logs
        MDC.put(CORRELATION_ID_KEY, correlationId)

        // opcional pero lindo: devolvérselo al cliente
        response.setHeader(CORRELATION_ID_HEADER, correlationId)

        try {
            filterChain.doFilter(request, response)
        } finally {
            MDC.remove(CORRELATION_ID_KEY)
        }
    }
}
