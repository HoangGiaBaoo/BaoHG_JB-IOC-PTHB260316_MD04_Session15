package org.example.identity.service;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
public class TokenBlacklistService {

    /** Gateway dung chung prefix nay de tra cuu. */
    public static final String KEY_PREFIX = "blacklist:";

    private final StringRedisTemplate redisTemplate;

    public TokenBlacklistService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /** Luu jti voi value "revoked", TTL = thoi gian song con lai cua access token. */
    public void revoke(String jti, Duration ttl) {
        redisTemplate.opsForValue().set(KEY_PREFIX + jti, "revoked", ttl);
    }
}
