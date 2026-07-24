package com.nizamiftahul.simrs.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "simrs.security.jwt")
public class JwtProperties {

    private String secret;
    private int accessTokenTtlMinutes = 15;
    private int refreshTokenTtlDays = 7;
    private String issuer = "simrs";

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public int getAccessTokenTtlMinutes() {
        return accessTokenTtlMinutes;
    }

    public void setAccessTokenTtlMinutes(int accessTokenTtlMinutes) {
        this.accessTokenTtlMinutes = accessTokenTtlMinutes;
    }

    public int getRefreshTokenTtlDays() {
        return refreshTokenTtlDays;
    }

    public void setRefreshTokenTtlDays(int refreshTokenTtlDays) {
        this.refreshTokenTtlDays = refreshTokenTtlDays;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }
}
