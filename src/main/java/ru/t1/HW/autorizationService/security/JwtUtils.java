package ru.t1.HW.autorizationService.security;

import lombok.Getter;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.JoseException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.security.Key;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.util.Date;

/**
 * <b>JwtUtils</b> - содержит методы для работы с jwt токенами
 */
@Component
public class JwtUtils {
    @Value("${jwt.secret}")
    private String jwtSecret;
    private final long jwtExpirationMs = 300000; // 5 минут

    @Getter
    private Key key;


    @PostConstruct
    public void init() throws NoSuchAlgorithmException {
        this.key = new SecretKeySpec(jwtSecret.getBytes(), "AES");
    }

    public String generateJwtToken(String username) throws JoseException {
        JwtClaims claims = new JwtClaims();
        claims.setSubject(username);
        claims.setIssuedAtToNow();
        claims.setExpirationTimeMinutesInTheFuture(jwtExpirationMs / 60000.0f);
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.DIRECT);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_GCM);
        jwe.setPayload(claims.toJson());
        jwe.setKey(key);
        return jwe.getCompactSerialization();
    }

    public String getUsernameFromJwtToken(String token) throws JoseException, InvalidJwtException, MalformedClaimException {
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setCompactSerialization(token);
        jwe.setKey(key);

        String decryptedPayload = jwe.getPayload();

        JwtClaims claims = JwtClaims.parse(decryptedPayload);
        return claims.getSubject();
    }

    private JwtClaims getJwtClaimsFromJwe(String authToken)
    {
        try {
            JsonWebEncryption jwe = new JsonWebEncryption();
            jwe.setCompactSerialization(authToken);
            jwe.setKey(key);

            String payload = jwe.getPayload();
            return JwtClaims.parse(payload);
        } catch (InvalidJwtException e) {
            throw new RuntimeException(e);
        } catch (JoseException e) {
            throw new RuntimeException(e);
        }

    }

    public boolean validateJwtToken(String authToken) {
        try {
            JwtClaims claims = getJwtClaimsFromJwe(authToken);
            if (claims.getExpirationTime() != null && claims.getExpirationTime().isBefore(NumericDate.now())) {
                return false;
            }

            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public Date getExpirationFromToken(String token) {
        try {
            JwtClaims claims = getJwtClaimsFromJwe(token);
            NumericDate expiration = claims.getExpirationTime();
            if (expiration == null) {
                return null; // или выберите другое поведение при отсутствии exp
            }
            return new Date(expiration.getValue() * 1000L);
        } catch (MalformedClaimException e) {
            throw new RuntimeException(e);
        }
    }
}
