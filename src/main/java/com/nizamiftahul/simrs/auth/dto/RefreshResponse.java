package com.nizamiftahul.simrs.auth.dto;

public record RefreshResponse(String accessToken, String tokenType, int expiresIn) {
}
