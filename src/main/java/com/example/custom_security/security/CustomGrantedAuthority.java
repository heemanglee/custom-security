package com.example.custom_security.security;

import lombok.ToString;
import org.springframework.security.core.GrantedAuthority;

@ToString
public class CustomGrantedAuthority implements GrantedAuthority {

    private final String role;

    public CustomGrantedAuthority(String role) {
        this.role = role;
    }

    @Override
    public String getAuthority() {
        return role;
    }
}
