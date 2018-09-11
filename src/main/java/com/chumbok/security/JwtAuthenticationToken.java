package com.chumbok.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * JwtAuthenticationToken
 */
public class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private final String principal;

    /**
     * Creates a token with the auth http header
     */
    public JwtAuthenticationToken(String principal, Collection<GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.setAuthenticated(isAuthenticated());
    }

    @Override
    public String getCredentials() {
        return "";
    }

    @Override
    public String getPrincipal() {
        return principal;
    }

    @Override
    public boolean isAuthenticated() {
        return true;
    }
}
