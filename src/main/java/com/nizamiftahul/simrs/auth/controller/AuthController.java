package com.nizamiftahul.simrs.auth.controller;

import com.nizamiftahul.simrs.auth.dto.LoginRequest;
import com.nizamiftahul.simrs.auth.dto.LoginResponse;
import com.nizamiftahul.simrs.auth.dto.RefreshResponse;
import com.nizamiftahul.simrs.auth.exception.InvalidRefreshTokenException;
import com.nizamiftahul.simrs.auth.service.AuthService;
import com.nizamiftahul.simrs.auth.service.CookieUtil;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final CookieUtil cookieUtil;

    public AuthController(AuthService authService, CookieUtil cookieUtil) {
        this.authService = authService;
        this.cookieUtil = cookieUtil;
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        AuthService.LoginResult result = authService.login(request.username(), request.password());
        ResponseCookie cookie = cookieUtil.buildRefreshCookie(result.refreshToken());
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(new LoginResponse(result.accessToken(), "Bearer", result.expiresIn(), result.username(), result.role()));
    }

    @PostMapping("/refresh")
    public ResponseEntity<RefreshResponse> refresh(@CookieValue(name = "refreshToken", required = false) String refreshToken) {
        if (refreshToken == null) {
            throw new InvalidRefreshTokenException("Refresh token tidak ada");
        }
        AuthService.RefreshResult result = authService.refresh(refreshToken);
        ResponseCookie cookie = cookieUtil.buildRefreshCookie(result.refreshToken());
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(new RefreshResponse(result.accessToken(), "Bearer", result.expiresIn()));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@CookieValue(name = "refreshToken", required = false) String refreshToken) {
        authService.logout(refreshToken);
        ResponseCookie cookie = cookieUtil.clearRefreshCookie();
        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .build();
    }
}
