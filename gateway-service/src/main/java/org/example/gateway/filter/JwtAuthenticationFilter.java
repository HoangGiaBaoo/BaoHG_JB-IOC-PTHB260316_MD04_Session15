package org.example.gateway.filter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.List;

/**
 * "Tram gac bien phong": verify JWT cho moi request toi /api/courses/**.
 * - Bai 2: sai chu ky / het han -> 401; hop le -> gan X-User-Role
 * - Bai 5: kiem tra jti trong Redis blacklist -> 401 neu da logout
 * - Bai 6: serialize claim permissions thanh JSON -> header X-User-Permissions
 */
@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    public static final String HEADER_USER_NAME = "X-User-Name";
    public static final String HEADER_USER_ROLE = "X-User-Role";
    public static final String HEADER_USER_PERMISSIONS = "X-User-Permissions";

    private static final String PROTECTED_PATH = "/api/courses";
    private static final String BEARER_PREFIX = "Bearer ";
    /** Trung voi TokenBlacklistService.KEY_PREFIX ben Identity-Service */
    private static final String BLACKLIST_PREFIX = "blacklist:";

    private final Key signingKey;
    private final ReactiveStringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;

    public JwtAuthenticationFilter(@Value("${jwt.secret}") String secret,
                                   ReactiveStringRedisTemplate redisTemplate,
                                   ObjectMapper objectMapper) {
        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
        this.redisTemplate = redisTemplate;
        this.objectMapper = objectMapper;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();
        if (!path.equals(PROTECTED_PATH) && !path.startsWith(PROTECTED_PATH + "/")) {
            return chain.filter(exchange);
        }

        String authorization = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authorization == null || !authorization.startsWith(BEARER_PREFIX)) {
            return unauthorized(exchange, "Thieu Access Token");
        }

        Claims claims;
        try {
            claims = Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(authorization.substring(BEARER_PREFIX.length()))
                    .getBody();
        } catch (ExpiredJwtException ex) {
            return unauthorized(exchange, "Access Token da het han");
        } catch (JwtException | IllegalArgumentException ex) {
            return unauthorized(exchange, "Access Token khong hop le");
        }

        String jti = claims.getId();
        if (jti == null) {
            return unauthorized(exchange, "Access Token thieu jti");
        }

        // Bai 5: chu ky hop le -> hoi Redis xem jti co nam trong blacklist khong
        return redisTemplate.hasKey(BLACKLIST_PREFIX + jti)
                .flatMap(revoked -> {
                    if (Boolean.TRUE.equals(revoked)) {
                        return unauthorized(exchange, "Access Token da bi thu hoi (dang xuat)");
                    }
                    return chain.filter(withUserHeaders(exchange, claims));
                });
    }

    private ServerWebExchange withUserHeaders(ServerWebExchange exchange, Claims claims) {
        String role = claims.get("role", String.class);
        List<?> permissions = claims.get("permissions", List.class);

        ServerHttpRequest mutated = exchange.getRequest().mutate()
                .headers(headers -> {
                    // Xoa header client tu gui len de tranh gia mao quyen
                    headers.remove(HEADER_USER_NAME);
                    headers.remove(HEADER_USER_ROLE);
                    headers.remove(HEADER_USER_PERMISSIONS);

                    headers.set(HEADER_USER_NAME, claims.getSubject());
                    if (role != null) {
                        headers.set(HEADER_USER_ROLE, role);
                    }
                    headers.set(HEADER_USER_PERMISSIONS, toJson(permissions == null ? List.of() : permissions));
                })
                .build();
        return exchange.mutate().request(mutated).build();
    }

    private String toJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("Khong the serialize permissions", ex);
        }
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        String body = "{\"status\":401,\"error\":\"Unauthorized\",\"message\":\"" + message + "\"}";
        DataBuffer buffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
