package com.meta.springauth2.auth.domain;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

@Getter
@RequiredArgsConstructor
public enum UserRole implements GrantedAuthority {
    ROLE_USER("ROLE_USER", "일반사용자"),
    ROLE_ADMIN("ROLE_ADMIN", "관리자");

    private final String authority;
    private final String description;

    @Override
    public String getAuthority() {
        return this.authority;
    }
}
