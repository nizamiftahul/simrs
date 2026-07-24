package com.nizamiftahul.simrs.shared;

import java.util.UUID;

public record CurrentUser(UUID userId, String username, String role) {
}
