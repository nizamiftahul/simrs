package com.nizamiftahul.simrs.auth.security;

import com.nizamiftahul.simrs.shared.CurrentUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.UUID;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;

    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring("Bearer ".length());
            try {
                Jws<Claims> jws = jwtTokenProvider.parseAndValidate(token);
                Claims claims = jws.getPayload();
                UUID userId = UUID.fromString(claims.getSubject());
                String username = claims.get("username", String.class);
                String role = claims.get("role", String.class);

                CurrentUser currentUser = new CurrentUser(userId, username, role);
                var authentication = new UsernamePasswordAuthenticationToken(
                        currentUser, null, List.of(new SimpleGrantedAuthority("ROLE_" + role)));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (Exception ex) {
                // invalid/expired token: leave SecurityContext empty, let it 401 downstream
            }
        }
        filterChain.doFilter(request, response);
    }
}
