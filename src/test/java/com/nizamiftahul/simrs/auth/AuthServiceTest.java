package com.nizamiftahul.simrs.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

import com.nizamiftahul.simrs.auth.config.JwtProperties;
import com.nizamiftahul.simrs.auth.entity.Role;
import com.nizamiftahul.simrs.auth.entity.User;
import com.nizamiftahul.simrs.auth.exception.InvalidCredentialsException;
import com.nizamiftahul.simrs.auth.repository.UserRepository;
import com.nizamiftahul.simrs.auth.security.JwtTokenProvider;
import com.nizamiftahul.simrs.auth.service.AuthService;
import com.nizamiftahul.simrs.auth.service.RefreshTokenService;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private UserRepository userRepository;

    @Mock
    private JwtTokenProvider jwtTokenProvider;

    @Mock
    private RefreshTokenService refreshTokenService;

    private AuthService authService;

    @BeforeEach
    void setUp() {
        JwtProperties properties = new JwtProperties();
        properties.setAccessTokenTtlMinutes(15);
        authService = new AuthService(authenticationManager, userRepository, jwtTokenProvider, refreshTokenService, properties);
    }

    @Test
    void login_happyPath_returnsLoginResult() {
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setUsername("admin");
        user.setRole(Role.ADMIN);

        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(user));
        when(jwtTokenProvider.generateAccessToken(user)).thenReturn("access-token");
        when(refreshTokenService.issue(user.getId())).thenReturn("refresh-token");

        AuthService.LoginResult result = authService.login("admin", "ChangeMe123!");

        assertThat(result.accessToken()).isEqualTo("access-token");
        assertThat(result.refreshToken()).isEqualTo("refresh-token");
        assertThat(result.username()).isEqualTo("admin");
        assertThat(result.role()).isEqualTo("ADMIN");
        assertThat(result.expiresIn()).isEqualTo(900);
    }

    @Test
    void login_authenticationFails_throwsInvalidCredentialsException() {
        doThrow(new BadCredentialsException("bad"))
                .when(authenticationManager)
                .authenticate(any());

        assertThatThrownBy(() -> authService.login("admin", "wrong"))
                .isInstanceOf(InvalidCredentialsException.class);
    }
}
