package ru.t1.HW.autorizationService.security;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

/**
 * <b>JwtUtils</b> - содержит методы для работы с jwt токенами
 */
@Component
public class JwtUtils {
    @Value("${jwt.secret}")
    private String jwtSecret;
    private final long jwtExpirationMs = 60000; // 5 минут

    @Getter
    private Key key;

    @PostConstruct
    public void init() {
        this.key = key = Keys.hmacShaKeyFor(jwtSecret.getBytes());
    }

    public String generateJwtToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public String getUsernameFromJwtToken(String token) {
        return Jwts.parserBuilder().setSigningKey(key).build()
                .parseClaimsJws(token)
                .getBody().getSubject();
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(authToken);
            return true;
        } catch (JwtException e) {
            return false;
        }
    }

    public Date getExpirationFromToken(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(key) // ваш секретный ключ
                    .build()
                    .parseClaimsJws(token)
                    .getBody()
                    .getExpiration();
        } catch (JwtException e) {
            return null;
        }
    }
}
