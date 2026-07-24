package com.nizamiftahul.simrs.auth.service;

import com.nizamiftahul.simrs.auth.config.JwtProperties;
import com.nizamiftahul.simrs.auth.entity.User;
import com.nizamiftahul.simrs.auth.exception.InvalidCredentialsException;
import com.nizamiftahul.simrs.auth.repository.UserRepository;
import com.nizamiftahul.simrs.auth.security.JwtTokenProvider;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final JwtProperties jwtProperties;

    public AuthService(AuthenticationManager authenticationManager, UserRepository userRepository,
            JwtTokenProvider jwtTokenProvider, RefreshTokenService refreshTokenService, JwtProperties jwtProperties) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.jwtTokenProvider = jwtTokenProvider;
        this.refreshTokenService = refreshTokenService;
        this.jwtProperties = jwtProperties;
    }

    public LoginResult login(String username, String password) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (AuthenticationException ex) {
            throw new InvalidCredentialsException("Username atau password salah");
        }

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new InvalidCredentialsException("Username atau password salah"));

        String accessToken = jwtTokenProvider.generateAccessToken(user);
        String refreshToken = refreshTokenService.issue(user.getId());
        int expiresIn = jwtProperties.getAccessTokenTtlMinutes() * 60;

        return new LoginResult(accessToken, refreshToken, user.getUsername(), user.getRole().name(), expiresIn);
    }

    public RefreshResult refresh(String rawRefreshToken) {
        RefreshTokenService.RotationResult rotationResult = refreshTokenService.rotate(rawRefreshToken);
        User user = userRepository.findById(rotationResult.userId())
                .orElseThrow(() -> new InvalidCredentialsException("Username atau password salah"));

        String accessToken = jwtTokenProvider.generateAccessToken(user);
        int expiresIn = jwtProperties.getAccessTokenTtlMinutes() * 60;

        return new RefreshResult(accessToken, rotationResult.rawToken(), expiresIn);
    }

    public void logout(String rawRefreshToken) {
        if (rawRefreshToken != null) {
            refreshTokenService.revoke(rawRefreshToken);
        }
    }

    public record LoginResult(String accessToken, String refreshToken, String username, String role, int expiresIn) {
    }

    public record RefreshResult(String accessToken, String refreshToken, int expiresIn) {
    }
}
