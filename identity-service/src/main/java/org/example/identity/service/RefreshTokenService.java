package org.example.identity.service;

import org.example.identity.config.JwtProperties;
import org.example.identity.entity.RefreshToken;
import org.example.identity.entity.User;
import org.example.identity.exception.InvalidRefreshTokenException;
import org.example.identity.repository.RefreshTokenRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

@Service
public class RefreshTokenService {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtProperties properties;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository, JwtProperties properties) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.properties = properties;
    }

    /** Sinh chuoi ngau nhien (song 7 ngay) va luu vao bang refresh_tokens. */
    @Transactional
    public RefreshToken create(User user) {
        byte[] bytes = new byte[64];
        RANDOM.nextBytes(bytes);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes));
        refreshToken.setUser(user);
        refreshToken.setExpiryDate(Instant.now().plus(properties.refreshTokenExpiration()));
        return refreshTokenRepository.save(refreshToken);
    }

    /**
     * Kiem tra refresh token va "tieu thu" no (Token Rotation):
     * ban ghi cu bi xoa han nen khong the dung lai lan thu hai.
     * noRollbackFor: token het han van phai bi xoa khoi DB du co nem exception.
     */
    @Transactional(noRollbackFor = InvalidRefreshTokenException.class)
    public User consume(String token) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new InvalidRefreshTokenException("Refresh token khong ton tai hoac da bi thu hoi"));

        refreshTokenRepository.delete(refreshToken);

        if (refreshToken.getExpiryDate().isBefore(Instant.now())) {
            throw new InvalidRefreshTokenException("Refresh token da het han, vui long dang nhap lai");
        }
        return refreshToken.getUser();
    }

    @Transactional
    public void deleteAllOf(User user) {
        refreshTokenRepository.deleteAllByUser(user);
    }
}
