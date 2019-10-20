package com.chumbok.security.properties;

import lombok.Data;

/**
 * Data class to read security properties from application yaml.
 */
@Data
public class SecurityProperties {

    /**
     * Flag to enable Chumbok Security.
     */
    private boolean enable;

    /**
     * JWT access token signing key.
     */
    private String tokenSigningPublicKeyPath;

    /**
     * assertOrgWith is a String which going to be validated with access token org.
     */
    private String assertOrgWith;

    /**
     * Flag to check Tenant.
     */
    private boolean assertTenant;

    /**
     * assertTenantWith is a String which going to be validated with access token tenant.
     */
    private String assertTenantWith;

    /**
     * Flag to disable CSRF.
     */
    private boolean disableCsrf;

    /**
     * Comma separated paths that needed to be ignored in CSRF filter.
     */
    private String ignoredCsrfPaths;

    /**
     * Flag to disable CORS.
     */
    private boolean disableCors;

}
