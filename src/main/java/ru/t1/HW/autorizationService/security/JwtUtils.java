package ru.t1.HW.autorizationService.security;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.JoseException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

/**
 * <b>JwtUtils</b> - содержит методы для работы с jwt токенами
 */
@Component
public class JwtUtils {
    @Value("${secret.signing}")
    private String secretSigning;
    @Value("${secret.signing}")
    private String secretEncryption;
    private final long jwtExpirationMs = 300000; // 5 минут

    @Getter
    private Key keySigning, keyEncryption;

    @PostConstruct
    public void init() throws NoSuchAlgorithmException {
        this.keySigning = new SecretKeySpec(secretSigning.getBytes(), "AES");
        this.keyEncryption = new SecretKeySpec(secretEncryption.getBytes(), "AES");
    }

    public String generateJwtToken(String username) throws JoseException {
        JwtClaims claims = new JwtClaims();
        claims.setSubject(username);
        claims.setIssuedAtToNow();
        claims.setExpirationTimeMinutesInTheFuture(jwtExpirationMs / 60000.0f);

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());

        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        jws.setKey(keySigning); // секретный ключ для подписи (javax.crypto.SecretKey или byte[])

        String jwsCompact = jws.getCompactSerialization();

        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.DIRECT);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_GCM);
        jwe.setPayload(jwsCompact); // payload - подписанный токен
        jwe.setKey(keyEncryption); // ключ для шифрования (SecretKey или byte[])

        return jwe.getCompactSerialization();
    }

    public String getUsernameFromJwtToken(String token) throws JoseException, InvalidJwtException, MalformedClaimException {
        JwtClaims claims = getJwtClaimsFromJwe(token);
        return claims.getSubject();
    }

    private JwtClaims getJwtClaimsFromJwe(String authToken) {
        try {
            JsonWebEncryption jwe = new JsonWebEncryption();
            jwe.setCompactSerialization(authToken);
            jwe.setKey(keyEncryption);
            String jwsCompact = jwe.getPayload();

            JsonWebSignature jws = new JsonWebSignature();
            jws.setCompactSerialization(jwsCompact);
            jws.setKey(keySigning);
            if (!jws.verifySignature()) {
                throw new RuntimeException("Invalid JWS signature");
            }

            return JwtClaims.parse(jws.getPayload());

        } catch (InvalidJwtException | JoseException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean validateJwtToken(String authToken) {
        try {
            JwtClaims claims = getJwtClaimsFromJwe(authToken);
            return claims.getExpirationTime() == null || !claims.getExpirationTime().isBefore(NumericDate.now());
        } catch (MalformedClaimException e) {
            throw new RuntimeException(e);
        }
    }

    public Date getExpirationFromToken(String token) {
        try {
            JwtClaims claims = getJwtClaimsFromJwe(token);
            NumericDate expiration = claims.getExpirationTime();
            if (expiration == null) {
                return null;
            }
            return new Date(expiration.getValue() * 1000L);
        } catch (MalformedClaimException e) {
            throw new RuntimeException(e);
        }
    }
}
