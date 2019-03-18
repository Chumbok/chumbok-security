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
 * SecurityUtil provides logged in user's information and generate jwt tokens.
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

    /**
     * Return optional logged in user's username
     * @return
     */
    public Optional<String> findAuthenticatedUsername() {
        Optional<AuthenticatedUser> authenticatedUser = getAuthenticatedUser();
        if (authenticatedUser.isPresent() && authenticatedUser.get().getUsername() != null) {
            return Optional.of(authenticatedUser.get().getUsername());
        }
        return Optional.empty();
    }

    /**
     * Return logged in user's username
     * @return
     */
    public String getAuthenticatedUsername() {
        Optional<AuthenticatedUser> authenticatedUser = getAuthenticatedUser();
        if (!authenticatedUser.isPresent() || authenticatedUser.get().getUsername() == null) {
            throw new IllegalStateException("Security Context does not have user.");
        }
        return authenticatedUser.get().getUsername();
    }

    /**
     * Return a boolean to signal if user is logged in.
     */
    public boolean isLoggedIn() {
        return getAuthenticatedUser().isPresent()? true : false;
    }

    @Getter
    public static class AuthenticatedUser {

        private final String org;
        private final String tenant;
        private final String username;
        private final Collection<? extends GrantedAuthority> authorities;

        public AuthenticatedUser(String org, String tenant, String username,
                                 Collection<? extends GrantedAuthority> authorities) {
            this.org = org;
            this.tenant = tenant;
            this.username = username;
            this.authorities = authorities;
        }

        private AuthenticatedUser(Authentication authentication) {

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
