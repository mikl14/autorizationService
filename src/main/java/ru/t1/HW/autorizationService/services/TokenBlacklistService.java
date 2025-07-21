package ru.t1.HW.autorizationService.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.concurrent.TimeUnit;

@Service
public class TokenBlacklistService {

        private final RedisTemplate<String, String> redisTemplate;

        @Autowired
        public TokenBlacklistService(RedisTemplate<String, String> redisTemplate) {
            this.redisTemplate = redisTemplate;
        }

        private static final String BLACKLIST_PREFIX = "jwt:blacklist:";

        /**
         * Добавляет JWT в черный список с истечением срока действия равным оставшемуся времени жизни токена
         */
        public void blacklistToken(String token, Date expirationDate) {
            long now = System.currentTimeMillis();
            long expireAt = expirationDate.getTime();
            long ttl = expireAt - now;
            if (ttl > 0) {
                redisTemplate.opsForValue().set(BLACKLIST_PREFIX + token, "true", ttl, TimeUnit.MILLISECONDS);
            }
        }

        /**
         * Проверяет, находится ли токен в черном списке
         */
        public boolean isTokenBlacklisted(String token) {
            String value = redisTemplate.opsForValue().get(BLACKLIST_PREFIX + token);
            return value != null;
        }
}