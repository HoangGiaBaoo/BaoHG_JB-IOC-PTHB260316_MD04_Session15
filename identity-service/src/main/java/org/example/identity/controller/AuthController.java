package org.example.identity.controller;

import jakarta.validation.Valid;
import org.example.identity.dto.LoginRequest;
import org.example.identity.dto.RefreshRequest;
import org.example.identity.dto.TokenResponse;
import org.example.identity.exception.InvalidAccessTokenException;
import org.example.identity.service.AuthService;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final String BEARER_PREFIX = "Bearer ";

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public TokenResponse login(@Valid @RequestBody LoginRequest request) {
        return authService.login(request);
    }

    @PostMapping("/refresh")
    public TokenResponse refresh(@Valid @RequestBody RefreshRequest request) {
        return authService.refresh(request.refreshToken());
    }

    @PostMapping("/logout")
    public Map<String, String> logout(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        if (authorization == null || !authorization.startsWith(BEARER_PREFIX)) {
            throw new InvalidAccessTokenException("Thieu header Authorization: Bearer <token>");
        }
        authService.logout(authorization.substring(BEARER_PREFIX.length()));
        return Map.of("message", "Dang xuat thanh cong");
    }
}
