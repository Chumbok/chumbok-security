package com.chumbok.security.config;

import com.chumbok.security.properties.SecurityProperties;
import com.chumbok.security.util.AuthTokenParser;
import com.chumbok.security.util.EncryptionKeyUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@EnableWebSecurity
@ConditionalOnProperty(name = "com.chumbok.security.enable", havingValue = "true", matchIfMissing = false)
public class ChumbokSecurityConfig extends AbstractSecurityConfig {

    private EncryptionKeyUtil encryptionKeyUtil;
    private SecurityProperties securityProperties;

    /**
     * Construct security config with encryptionKeyUtil and securityProperties.
     *
     * @param encryptionKeyUtil
     * @param securityProperties
     */
    public ChumbokSecurityConfig(EncryptionKeyUtil encryptionKeyUtil, SecurityProperties securityProperties) {
        setSecurityProperties(securityProperties);
        this.encryptionKeyUtil = encryptionKeyUtil;
        this.securityProperties = securityProperties;
    }

    /**
     * Create AuthTokenParser bean.
     *
     * @return
     */
    @Bean
    public AuthTokenParser authTokenParser() {
        return new AuthTokenParser(encryptionKeyUtil.loadPublicKey(securityProperties.getTokenSigningPublicKeyPath()));
    }

    /**
     * Set AuthTokenParser to super class so that auth token can be consumed.
     *
     * @param authTokenParser
     */
    @Autowired
    @Override
    protected void setAuthTokenParser(AuthTokenParser authTokenParser) {
        super.setAuthTokenParser(authTokenParser);
    }


    /**
     * Set SecurityProperties to super class so that auth token can be consumed.
     *
     * @param securityProperties
     */
    @Autowired
    @Override
    protected void setSecurityProperties(SecurityProperties securityProperties) {
        super.setSecurityProperties(securityProperties);
    }

}