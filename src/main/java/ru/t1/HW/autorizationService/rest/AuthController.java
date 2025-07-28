package ru.t1.HW.autorizationService.rest;

import jakarta.servlet.http.HttpServletResponse;
import org.jose4j.lang.JoseException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import ru.t1.HW.autorizationService.entities.RefreshToken;
import ru.t1.HW.autorizationService.entities.User;
import ru.t1.HW.autorizationService.rest.dto.AuthRequest;
import ru.t1.HW.autorizationService.rest.dto.AuthResponse;
import ru.t1.HW.autorizationService.rest.dto.RegisterRequest;
import ru.t1.HW.autorizationService.rest.dto.TokenRefreshRequest;
import ru.t1.HW.autorizationService.security.JwtUtils;
import ru.t1.HW.autorizationService.services.RefreshTokenService;
import ru.t1.HW.autorizationService.services.TokenWhitelistService;
import ru.t1.HW.autorizationService.services.UserService;

import java.util.Date;
import java.util.Set;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;

    private final TokenWhitelistService tokenWhitelistService;

    public AuthController(AuthenticationManager authenticationManager, JwtUtils jwtUtils, UserService userService, PasswordEncoder passwordEncoder, RefreshTokenService refreshTokenService, TokenWhitelistService tokenWhitelistService) {
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.refreshTokenService = refreshTokenService;
        this.tokenWhitelistService = tokenWhitelistService;
    }

    @PostMapping("/index")
    public ResponseEntity<?> index() {
        return ResponseEntity.ok("Это сообщение для простых работяг!");
    }

    @PostMapping("/premium")
    public ResponseEntity<?> premium() {
        return ResponseEntity.ok("Это сообщение для зажиточных!");
    }

    @PostMapping("/admin")
    public ResponseEntity<?> admin() {
        return ResponseEntity.ok("Это сообщение только для админов!");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest request, HttpServletResponse response) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
            String jwt = jwtUtils.generateJwtToken(request.getUsername());
            Date expirationDate = jwtUtils.getExpirationFromToken(jwt);
            if (expirationDate == null) {
                return ResponseEntity.badRequest().body("Невалидный токен");
            }
            tokenWhitelistService.whitelistAddToken(jwt, expirationDate);
            RefreshToken refreshToken = refreshTokenService.getOrCreateRefreshToken(request.getUsername());
            return ResponseEntity.ok(new AuthResponse(jwt, refreshToken.getToken()));
        } catch (Exception e) {
            System.out.print(e);
        }
        return ResponseEntity.internalServerError().body("error on login");
    }

    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshToken(@RequestBody TokenRefreshRequest request) {
        String requestRefreshToken = request.getRefreshToken();

        return refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    String token = null;
                    try {
                        token = jwtUtils.generateJwtToken(user.getUsername());
                    } catch (JoseException e) {
                        return ResponseEntity.internalServerError().body("error on create token");
                    }
                    Date expirationDate = jwtUtils.getExpirationFromToken(token);
                    if (expirationDate == null) {
                        return ResponseEntity.badRequest().body("Невалидный токен");
                    }
                    tokenWhitelistService.whitelistAddToken(token, expirationDate);
                    return ResponseEntity.ok(new AuthResponse(token, refreshTokenService.updateRefreshToken(requestRefreshToken).getToken()));
                })
                .orElse(ResponseEntity.status(HttpStatus.FORBIDDEN).build());
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody RegisterRequest registerRequest) {
        try {
            userService.loadUserByUsername(registerRequest.getUsername());
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body("Ошибка: Username уже занят");
        } catch (UsernameNotFoundException ex) {
            if (userService.getUserByEmail(registerRequest.getEmail()) != null) {
                return ResponseEntity
                        .status(HttpStatus.BAD_REQUEST)
                        .body("Ошибка: Email уже зарегистрирован");
            }
            User user = new User();
            user.setUsername(registerRequest.getUsername());
            user.setEmail(registerRequest.getEmail());
            user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
            user.setRoles(Set.of(registerRequest.getRole()));
            userService.saveUser(user);
            return ResponseEntity.ok("Пользователь успешно зарегистрирован");
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);

            Date expirationDate = jwtUtils.getExpirationFromToken(token);
            if (expirationDate == null) {
                return ResponseEntity.badRequest().body("Невалидный токен");
            }

            tokenWhitelistService.blockedToken(token);
            return ResponseEntity.ok("Токен успешно отозван");
        }
        return ResponseEntity.badRequest().body("Отсутствует токен для отзыва");
    }
}