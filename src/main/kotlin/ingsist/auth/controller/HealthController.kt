package ingsist.auth.controller

import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/health")
class HealthController {
    fun healthCheck(): ResponseEntity<String> {
        return ResponseEntity.ok("Snippet Service is healthy")
    }
}
