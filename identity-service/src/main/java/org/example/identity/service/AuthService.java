package org.example.identity.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.example.identity.dto.LoginRequest;
import org.example.identity.dto.TokenResponse;
import org.example.identity.entity.RefreshToken;
import org.example.identity.entity.User;
import org.example.identity.exception.InvalidAccessTokenException;
import org.example.identity.repository.UserRepository;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final TokenBlacklistService tokenBlacklistService;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService,
                       RefreshTokenService refreshTokenService, TokenBlacklistService tokenBlacklistService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.tokenBlacklistService = tokenBlacklistService;
    }

    /** Bai 1: so khop mat khau voi ban bam BCrypt, cap cap Access + Refresh token. */
    public TokenResponse login(LoginRequest request) {
        User user = userRepository.findByUsername(request.username())
                .filter(u -> passwordEncoder.matches(request.password(), u.getPassword()))
                .orElseThrow(() -> new BadCredentialsException("Sai ten dang nhap hoac mat khau"));
        return issueTokens(user);
    }

    /** Bai 4: doi refresh token cu lay cap token moi (rotation). */
    public TokenResponse refresh(String refreshToken) {
        User user = refreshTokenService.consume(refreshToken);
        return issueTokens(user);
    }

    /** Bai 5: dua jti cua access token vao blacklist tren Redis, dong thoi thu hoi cac refresh token. */
    @Transactional
    public void logout(String accessToken) {
        Claims claims;
        try {
            claims = jwtService.parseClaims(accessToken);
        } catch (JwtException | IllegalArgumentException ex) {
            throw new InvalidAccessTokenException("Access token khong hop le hoac da het han");
        }

        long ttlMillis = claims.getExpiration().getTime() - System.currentTimeMillis();
        if (ttlMillis > 0) {
            tokenBlacklistService.revoke(claims.getId(), Duration.ofMillis(ttlMillis));
        }
        userRepository.findByUsername(claims.getSubject()).ifPresent(refreshTokenService::deleteAllOf);
    }

    private TokenResponse issueTokens(User user) {
        String accessToken = jwtService.generateAccessToken(user);
        RefreshToken refreshToken = refreshTokenService.create(user);
        return new TokenResponse(accessToken, refreshToken.getToken(), "Bearer",
                jwtService.getAccessTokenExpirationSeconds());
    }
}
