package ru.t1.HW.autorizationService.rest;

import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.t1.HW.autorizationService.entities.Role;
import ru.t1.HW.autorizationService.entities.User;
import ru.t1.HW.autorizationService.security.JwtUtils;
import ru.t1.HW.autorizationService.services.UserService;

import java.util.Set;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    public AuthController(AuthenticationManager authenticationManager, JwtUtils jwtUtils, UserService userService, PasswordEncoder passwordEncoder) {
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
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
    public ResponseEntity<?> login(@RequestBody AuthRequest request) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
            String jwt = jwtUtils.generateJwtToken(request.getUsername());

            return ResponseEntity.ok(new AuthResponse(jwt));
        } catch (Exception e) {
            System.out.print(e);
        }
        return null;
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody RegisterRequest registerRequest) {
        try {
            userService.loadUserByUsername(registerRequest.getUsername());
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body("Ошибка: Username уже занят");
        } catch (UsernameNotFoundException ex) {
            if (userService.loadUserByEmail(registerRequest.getEmail()) != null) {
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
}


@Getter
@Setter
class AuthRequest {
    private String username;
    private String password;
}

@Getter
@Setter
class AuthResponse {
    private String token;
    public AuthResponse(String token) {
        this.token = token;
    }
}

@Getter
@Setter
class RegisterRequest {
    private String username;
    private String email;
    private String password;
    private Role role;
}

