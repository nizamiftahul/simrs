package com.nizamiftahul.simrs.auth;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

class PasswordHashingTest {

    @Test
    void matches_verifiesRawPasswordAgainstHash() {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String raw = "ChangeMe123!";
        String hash = encoder.encode(raw);

        assertThat(encoder.matches(raw, hash)).isTrue();
    }

    @Test
    void encode_producesDifferentHashesForSamePassword() {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String raw = "ChangeMe123!";

        String hash1 = encoder.encode(raw);
        String hash2 = encoder.encode(raw);

        assertThat(hash1).isNotEqualTo(hash2);
    }
}
