package com.nizamiftahul.simrs.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.nizamiftahul.simrs.auth.config.JwtProperties;
import com.nizamiftahul.simrs.auth.entity.RefreshToken;
import com.nizamiftahul.simrs.auth.exception.InvalidRefreshTokenException;
import com.nizamiftahul.simrs.auth.repository.RefreshTokenRepository;
import com.nizamiftahul.simrs.auth.service.RefreshTokenService;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Captor
    private ArgumentCaptor<RefreshToken> refreshTokenCaptor;

    private RefreshTokenService refreshTokenService;

    @BeforeEach
    void setUp() {
        JwtProperties properties = new JwtProperties();
        properties.setRefreshTokenTtlDays(7);
        refreshTokenService = new RefreshTokenService(refreshTokenRepository, properties);
    }

    @Test
    void issue_storesHashedTokenAndReturnsRawToken() {
        String rawToken = refreshTokenService.issue(UUID.randomUUID());

        verify(refreshTokenRepository).save(refreshTokenCaptor.capture());
        RefreshToken saved = refreshTokenCaptor.getValue();

        assertThat(saved.getTokenHash()).isNotEqualTo(rawToken);
        assertThat(saved.getTokenHash()).hasSize(64);
        assertThat(rawToken).isNotBlank();
    }

    @Test
    void rotate_revokesOldTokenAndReturnsNewOne() {
        UUID userId = UUID.randomUUID();
        RefreshToken existing = new RefreshToken();
        existing.setUserId(userId);
        existing.setTokenHash("irrelevant-since-mocked");
        existing.setExpiresAt(Instant.now().plus(1, ChronoUnit.DAYS));
        existing.setRevoked(false);

        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.of(existing));

        RefreshTokenService.RotationResult result = refreshTokenService.rotate("raw-token");

        assertThat(existing.isRevoked()).isTrue();
        assertThat(result.userId()).isEqualTo(userId);
        assertThat(result.rawToken()).isNotBlank();
    }

    @Test
    void rotate_unknownToken_throwsInvalidRefreshTokenException() {
        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> refreshTokenService.rotate("unknown"))
                .isInstanceOf(InvalidRefreshTokenException.class);
    }

    @Test
    void rotate_revokedToken_throwsInvalidRefreshTokenException() {
        RefreshToken existing = new RefreshToken();
        existing.setUserId(UUID.randomUUID());
        existing.setExpiresAt(Instant.now().plus(1, ChronoUnit.DAYS));
        existing.setRevoked(true);
        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.of(existing));

        assertThatThrownBy(() -> refreshTokenService.rotate("revoked"))
                .isInstanceOf(InvalidRefreshTokenException.class);
    }

    @Test
    void rotate_expiredToken_throwsInvalidRefreshTokenException() {
        RefreshToken existing = new RefreshToken();
        existing.setUserId(UUID.randomUUID());
        existing.setExpiresAt(Instant.now().minus(1, ChronoUnit.DAYS));
        existing.setRevoked(false);
        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.of(existing));

        assertThatThrownBy(() -> refreshTokenService.rotate("expired"))
                .isInstanceOf(InvalidRefreshTokenException.class);
    }
}
