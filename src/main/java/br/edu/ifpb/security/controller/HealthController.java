package br.edu.ifpb.security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/health")
public class HealthController {
    @GetMapping
    public ResponseEntity<Map<String, String>> health() {
        Map<String, String> status = Map.of(
                "status", "UP",
                "message", "Application is healthy"
        );
        return ResponseEntity.ok(status);
    }
}
