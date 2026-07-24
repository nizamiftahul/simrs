package com.nizamiftahul.simrs.auth.dto;

public record LoginResponse(String accessToken, String tokenType, int expiresIn, String username, String role) {
}
