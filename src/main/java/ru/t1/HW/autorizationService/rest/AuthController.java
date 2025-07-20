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
import org.springframework.web.bind.annotation.*;
import ru.t1.HW.autorizationService.entities.User;
import ru.t1.HW.autorizationService.repositories.UserRepository;
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

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest request) {
        try{
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
            String jwt = jwtUtils.generateJwtToken(request.getUsername());

            return ResponseEntity.ok(new AuthResponse(jwt));
        }
        catch (Exception e)
        {
            System.out.print(e);
        }
        return null;
    }

    @PostMapping("/index")
    public ResponseEntity<?> index() {
        return  ResponseEntity.ok("Вы реально крутые!");
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody RegisterRequest registerRequest) {
        // Проверка уникальности username

        try {
            userService.loadUserByUsername(registerRequest.getUsername());
            // Если пользователь найден, значит username уже занят
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body("Ошибка: Username уже занят");
        } catch (UsernameNotFoundException ex) {
            // Проверка уникальности email
            if (userService.getUserByEmail(registerRequest.getEmail()) != null) {
                return ResponseEntity
                        .status(HttpStatus.BAD_REQUEST)
                        .body("Ошибка: Email уже зарегистрирован");
            }
            // Создаём пользователя
            User user = new User();
            user.setUsername(registerRequest.getUsername());
            user.setEmail(registerRequest.getEmail());

            // Хэшируем пароль
            user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));

            // Назначаем роли по умолчанию, например "guest"
            user.setRoles(Set.of("guest"));

            // Сохраняем в базу
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
    // getters/setters
}

@Getter
@Setter
class AuthResponse {
    private String token;
    public AuthResponse(String token) { this.token = token; }
    // getter
}

@Getter
@Setter
class RegisterRequest {
    private String username;
    private String email;
    private String password;
}

