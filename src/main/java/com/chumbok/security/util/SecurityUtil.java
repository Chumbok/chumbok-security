package com.chumbok.security.util;

import com.chumbok.security.JwtAuthenticationToken;
import lombok.Getter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collection;
import java.util.Optional;

/**
 * SecurityUtil
 */
public class SecurityUtil {

    /**
     * Returns security context.
     *
     * @return
     */
    public SecurityContext getSecurityContext() {
        return SecurityContextHolder.getContext();
    }

    /**
     * Returns new instance of JwtAuthenticationToken from principle and authorities.
     *
     * @param principal
     * @param authorities
     * @return
     */
    public JwtAuthenticationToken newInstance(String principal, Collection<GrantedAuthority> authorities) {
        return new JwtAuthenticationToken(principal, authorities);
    }

    /**
     * Returns Authentication from security context.
     *
     * @return
     */
    public Authentication getAuthentication() {
        return getSecurityContext().getAuthentication();
    }

    /**
     * Returns logged in user's principle and authorities.
     *
     * @return
     */
    public Optional<AuthenticatedUser> getAuthenticatedUser() {
        AuthenticatedUser authenticatedUser = null;
        try {
            authenticatedUser = new AuthenticatedUser(getAuthentication());
        } catch (Exception ex) {
        }
        return Optional.ofNullable(authenticatedUser);
    }

    @Getter
    static class AuthenticatedUser {

        private final String org;
        private final String tenant;
        private final String username;
        private final Collection<? extends GrantedAuthority> authorities;

        public AuthenticatedUser(Authentication authentication) {

            if (authentication == null || !authentication.isAuthenticated()) {
                throw new RuntimeException("Authentication must not be null.");
            }

            String[] orgTenantUsername = ((String) authentication.getPrincipal())
                    .split(String.valueOf(Character.LINE_SEPARATOR));

            if (orgTenantUsername == null || orgTenantUsername.length != 3) {
                throw new RuntimeException("Org, Tenant and Username must be present in Authentication.");
            }

            this.org = orgTenantUsername[0];
            this.tenant = orgTenantUsername[1];
            this.username = orgTenantUsername[2];
            this.authorities = authentication.getAuthorities();
        }
    }


}
