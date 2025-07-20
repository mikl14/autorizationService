package ru.t1.HW.autorizationService.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import ru.t1.HW.autorizationService.services.UserService;

import java.io.IOException;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtils jwtUtils;
    private final UserService userService;

    public JwtAuthFilter(JwtUtils jwtUtils, UserService userService) {
        this.jwtUtils = jwtUtils;
        this.userService = userService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String servletPath = request.getServletPath();
        // Пропускаем без проверки токена эндпоинты регистрации и логина

        if (servletPath.equals("/api/auth/register") || servletPath.equals("/api/auth/login")) {
            filterChain.doFilter(request, response);
            return;
        }

        String header = request.getHeader("Authorization");
        String token = null;
        String username = request.getHeader("username");


        // Ожидаем header "Authorization: Bearer <токен>"
        if (header != null && header.startsWith("Bearer ")) {
            token = header.substring(7);
            if (jwtUtils.validateJwtToken(token)) {
                username = jwtUtils.getUsernameFromJwtToken(token);
            }
        }



        Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();

        if (username != null && (currentAuth == null || !currentAuth.isAuthenticated() || currentAuth instanceof AnonymousAuthenticationToken)) {
            UserDetails userDetails = userService.getUserByUserName(username);
            if (userDetails != null) {
                try {
                    UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities()
                    );
                    auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(auth);
                }
                catch (Exception e)
                {
                    System.out.print(e);
                }
            }
        }


        filterChain.doFilter(request, response);
    }
}
