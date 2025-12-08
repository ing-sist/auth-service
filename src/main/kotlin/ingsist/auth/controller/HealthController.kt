package ingsist.auth.controller

import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/health")
class HealthController {
    @GetMapping("/check")
    fun healthCheck(): ResponseEntity<String> {
        return ResponseEntity.ok("Snippet Service is healthy")
    }

    @GetMapping("/error")
    fun errorCheck(): ResponseEntity<String> {
        return ResponseEntity.status(500).body("Snippet Service has an error")
    }
}
