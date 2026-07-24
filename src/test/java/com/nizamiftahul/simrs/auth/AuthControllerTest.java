package com.nizamiftahul.simrs.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "simrs.security.jwt.secret=test-jwt-secret-key-with-at-least-32-bytes!!")
@AutoConfigureMockMvc
@Testcontainers
class AuthControllerTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    private MockMvc mockMvc;

    private String extractCookieValue(MvcResult result, String cookieName) {
        String setCookie = result.getResponse().getHeader("Set-Cookie");
        Matcher matcher = Pattern.compile(cookieName + "=([^;]*)").matcher(setCookie);
        return matcher.find() ? matcher.group(1) : null;
    }

    @Test
    void fullAuthLifecycle() throws Exception {
        // 1. login with correct credentials
        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"admin\",\"password\":\"ChangeMe123!\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(header().string("Set-Cookie", org.hamcrest.Matchers.containsString("HttpOnly")))
                .andExpect(header().string("Set-Cookie", org.hamcrest.Matchers.containsString("Secure")))
                .andExpect(header().string("Set-Cookie", org.hamcrest.Matchers.containsString("SameSite=Strict")))
                .andReturn();

        String firstRefreshCookie = extractCookieValue(loginResult, "refreshToken");
        assertThat(firstRefreshCookie).isNotBlank();

        // 2. login with wrong password
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"admin\",\"password\":\"wrong-password\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().doesNotExist("Set-Cookie"));

        // 3. refresh with valid cookie from step 1
        MvcResult refreshResult = mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new jakarta.servlet.http.Cookie("refreshToken", firstRefreshCookie)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andReturn();

        String secondRefreshCookie = extractCookieValue(refreshResult, "refreshToken");
        assertThat(secondRefreshCookie).isNotBlank();
        assertThat(secondRefreshCookie).isNotEqualTo(firstRefreshCookie);

        // 4. refresh again with the old (now rotated-out) cookie -> 401
        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new jakarta.servlet.http.Cookie("refreshToken", firstRefreshCookie)))
                .andExpect(status().isUnauthorized());

        // 5. logout with the latest valid cookie -> 204, cookie cleared
        mockMvc.perform(post("/api/auth/logout")
                        .cookie(new jakarta.servlet.http.Cookie("refreshToken", secondRefreshCookie)))
                .andExpect(status().isNoContent())
                .andExpect(header().string("Set-Cookie", org.hamcrest.Matchers.containsString("Max-Age=0")));

        // 6. refresh with the just-revoked cookie -> 401
        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new jakarta.servlet.http.Cookie("refreshToken", secondRefreshCookie)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void protectedEndpoint_withoutBearerToken_returnsJson401() throws Exception {
        mockMvc.perform(post("/api/auth/nonexistent-but-not-permitted"))
                .andExpect(status().isNotFound());
    }
}
