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

}
