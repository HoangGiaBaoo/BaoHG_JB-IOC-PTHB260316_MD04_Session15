package org.example.identity.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.example.identity.config.JwtProperties;
import org.example.identity.entity.User;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Service
public class JwtService {

    private final JwtProperties properties;
    private final Key signingKey;

    public JwtService(JwtProperties properties) {
        this.properties = properties;
        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(properties.secret()));
    }

    /**
     * Access token HS256, song 15 phut.
     * Claims: sub (username), jti (UUID duy nhat), permissions (Bai 6), role (Bai 1-3).
     */
    public String generateAccessToken(User user) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + properties.accessTokenExpiration().toMillis());
        List<String> permissions = user.getPermissions().stream().sorted().toList();

        return Jwts.builder()
                .setSubject(user.getUsername())
                .setId(UUID.randomUUID().toString())
                .claim("role", user.getRole().name())
                .claim("permissions", permissions)
                .setIssuedAt(now)
                .setExpiration(expiry)
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();
    }

    /** Verify chu ky + han su dung, nem JwtException neu khong hop le. */
    public Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public long getAccessTokenExpirationSeconds() {
        return properties.accessTokenExpiration().toSeconds();
    }
}
