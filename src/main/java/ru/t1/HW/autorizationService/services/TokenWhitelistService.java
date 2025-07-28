package ru.t1.HW.autorizationService.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.concurrent.TimeUnit;

@Service
public class TokenWhitelistService {

    private final RedisTemplate<String, String> redisTemplate;

    @Autowired
    public TokenWhitelistService(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    private static final String WHITELIST_PREFIX = "jwt:whitelist:";

    /**
     * Добавляет JWT в белый список с истечением срока действия равным оставшемуся времени жизни токена
     */
    public void whitelistAddToken(String token, Date expirationDate) {
        long now = System.currentTimeMillis();
        long expireAt = expirationDate.getTime();
        long ttl = expireAt - now;
        if (ttl > 0) {
            redisTemplate.opsForValue().set(WHITELIST_PREFIX + token, "true", ttl, TimeUnit.MILLISECONDS);
        }
    }

    public void blockedToken(String token)
    {
        redisTemplate.delete(WHITELIST_PREFIX + token);
    }

    /**
     * Проверяет, находится ли токен в черном списке
     */
    public boolean isTokenWhitelisted(String token) {
        String value = redisTemplate.opsForValue().get(WHITELIST_PREFIX + token);
        return value != null;
    }
}