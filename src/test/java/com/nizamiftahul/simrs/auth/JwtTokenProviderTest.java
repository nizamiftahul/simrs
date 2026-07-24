package com.nizamiftahul.simrs.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nizamiftahul.simrs.auth.config.JwtProperties;
import com.nizamiftahul.simrs.auth.entity.Role;
import com.nizamiftahul.simrs.auth.entity.User;
import com.nizamiftahul.simrs.auth.security.JwtTokenProvider;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;

class JwtTokenProviderTest {

    private static final String SECRET = "test-secret-key-with-at-least-32-bytes!!";

    private JwtProperties properties() {
        JwtProperties properties = new JwtProperties();
        properties.setSecret(SECRET);
        properties.setAccessTokenTtlMinutes(15);
        properties.setIssuer("simrs");
        return properties;
    }

    @Test
    void generateAndParseAccessToken_roundTrip() {
        JwtTokenProvider provider = new JwtTokenProvider(properties());
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setUsername("admin");
        user.setRole(Role.ADMIN);

        String token = provider.generateAccessToken(user);
        Jws<Claims> jws = provider.parseAndValidate(token);

        assertThat(jws.getPayload().getSubject()).isEqualTo(user.getId().toString());
        assertThat(jws.getPayload().get("username", String.class)).isEqualTo("admin");
        assertThat(jws.getPayload().get("role", String.class)).isEqualTo("ADMIN");
    }

    @Test
    void expiredToken_throwsOnParse() {
        JwtTokenProvider provider = new JwtTokenProvider(properties());
        SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));

        String expiredToken = Jwts.builder()
                .subject(UUID.randomUUID().toString())
                .issuedAt(Date.from(Instant.now().minus(20, ChronoUnit.MINUTES)))
                .expiration(Date.from(Instant.now().minus(5, ChronoUnit.MINUTES)))
                .signWith(key, Jwts.SIG.HS256)
                .compact();

        assertThatThrownBy(() -> provider.parseAndValidate(expiredToken))
                .isInstanceOf(io.jsonwebtoken.ExpiredJwtException.class);
    }
}
