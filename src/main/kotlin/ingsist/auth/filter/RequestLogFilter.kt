package ingsist.auth.filter

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

@Component
class RequestLogFilter : OncePerRequestFilter() {
    private val logger = LoggerFactory.getLogger(RequestLogFilter::class.java)

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain,
    ) {
        val method = request.method
        val uri = request.requestURI
        val prefix = "$method $uri"

        try {
            filterChain.doFilter(request, response)
        } finally {
            val status = response.status
            logger.info("$prefix - $status")
        }
    }
}
