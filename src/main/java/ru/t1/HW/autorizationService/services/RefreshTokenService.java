package ru.t1.HW.autorizationService.services;

import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import ru.t1.HW.autorizationService.entities.RefreshToken;
import ru.t1.HW.autorizationService.entities.User;
import ru.t1.HW.autorizationService.repositories.RefreshTokenRepository;

import java.time.Instant;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;

@Service
@Transactional
public class RefreshTokenService {

    @Value("${app.jwtRefreshExpirationMs}")
    private Long refreshTokenDurationMs;

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserService userService;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository, UserService userService) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userService = userService;
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    /**
     * <b>createRefreshToken</b> - создает refreshToken
     * @param username
     * @return
     * @throws UsernameNotFoundException
     */
    public RefreshToken createRefreshToken(String username) throws UsernameNotFoundException {
        RefreshToken refreshToken = new RefreshToken();
        User user = userService.getUserByUsername(username);
        refreshToken.setUser(user);
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken = refreshTokenRepository.save(refreshToken);
        return refreshToken;
    }

    /**
     * <b>verifyExpiration</b> - валидирует refreshToken
     * @param token
     * @return
     */
    public RefreshToken verifyExpiration(RefreshToken token) throws RuntimeException{
        if (token.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.delete(token);
            throw new RuntimeException("Refresh token expired. Please login again.");
        }
        return token;
    }


    public void deleteByUsername(String username) throws UsernameNotFoundException {
        User user = userService.getUserByUsername(username);
        refreshTokenRepository.deleteByUser(user);
        refreshTokenRepository.flush();
    }

    /**
     * <b>updateRefreshToken</b> - обновляет refresh токен, вызывается после использования токена для его замены.
     * @param requestRefreshToken
     * @return
     * @throws NoSuchElementException
     */

    public RefreshToken updateRefreshToken(String requestRefreshToken) throws NoSuchElementException {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(requestRefreshToken).orElseThrow();
        deleteByUsername(refreshToken.getUser().getUsername());
        return createRefreshToken(refreshToken.getUser().getUsername());
    }

    /**
     * <b>getOrCreateRefreshToken</b> - проверяет существует ли токен и возвращает его если он существует, или возвращает новый
     * @param username
     * @return
     * @throws UsernameNotFoundException
     */
    public RefreshToken getOrCreateRefreshToken(String username) throws UsernameNotFoundException {
        User user = userService.getUserByUsername(username);

        Optional<RefreshToken> existingTokenOpt = refreshTokenRepository.findByUser(user);

        if (existingTokenOpt.isPresent()) {
            RefreshToken existingToken = existingTokenOpt.get();
            if (existingToken.getExpiryDate().isAfter(Instant.now())) {
                return existingToken;
            } else {
                refreshTokenRepository.delete(existingToken);
            }
        }

        RefreshToken newToken = new RefreshToken();
        newToken.setUser(user);
        newToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
        newToken.setToken(UUID.randomUUID().toString());
        return refreshTokenRepository.save(newToken);
    }
}
