package ru.t1.HW.autorizationService.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.JoseException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import ru.t1.HW.autorizationService.services.TokenWhitelistService;
import ru.t1.HW.autorizationService.services.UserService;

import java.io.IOException;

/**
 * <b>JwtUtils</b> - содержит логику аунтификации по токену, пропускает без проверки на токен запросы на регистрацию и вход
 */
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtils jwtUtils;
    private final UserService userService;
    private final TokenWhitelistService tokenBlacklistService;

    public JwtAuthFilter(JwtUtils jwtUtils, UserService userService, TokenWhitelistService tokenBlacklistService) {
        this.jwtUtils = jwtUtils;
        this.userService = userService;
        this.tokenBlacklistService = tokenBlacklistService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String servletPath = request.getServletPath();
        if (servletPath.equals("/api/auth/register") || servletPath.equals("/api/auth/login") || servletPath.equals("/api/auth/refreshtoken")) {
            filterChain.doFilter(request, response); // тут пропускаем всех без проверки токена
            return;
        }

        String header = request.getHeader("Authorization");
        String token = null;
        String username = null;

        if (header != null && header.startsWith("Bearer ")) {
            token = header.substring(7);
            if (jwtUtils.validateJwtToken(token)) {
                try {
                    username = jwtUtils.getUsernameFromJwtToken(token);
                } catch (JoseException | InvalidJwtException | MalformedClaimException e) {
                    throw new RuntimeException(e);
                }
            }

            if (!tokenBlacklistService.isTokenWhitelisted(token)) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Token is blocked");
                return;
            }
        }

        Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();
        if (username != null && (currentAuth == null || !currentAuth.isAuthenticated() || currentAuth instanceof AnonymousAuthenticationToken)) {
            UserDetails userDetails = userService.loadUserByUsername(username);
            if (userDetails != null) {
                try {
                    UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities()
                    );
                    auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(auth);
                } catch (Exception e) {
                    System.out.print(e);
                }
            }
        }
        filterChain.doFilter(request, response);
    }
}
