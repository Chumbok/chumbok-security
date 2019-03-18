package com.chumbok.security.config;

import com.chumbok.security.properties.SecurityProperties;
import com.chumbok.security.util.AuthTokenParser;
import com.chumbok.security.util.EncryptionKeyUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import java.io.File;
import java.io.IOException;

@EnableWebSecurity
public class SecurityConfig extends AbstractSecurityConfig {

    @Bean(name = "authenticationManager")
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public AuthTokenParser authTokenParser() throws IOException {
        ClassLoader classLoader = getClass().getClassLoader();
        File resource = new File(classLoader.getResource("public_key.der").getFile());
        EncryptionKeyUtil encryptionKeyUtil = new EncryptionKeyUtil();
        return new AuthTokenParser(encryptionKeyUtil.loadPublicKey(resource.toPath().toString()));
    }

    @Autowired
    @Override
    protected void setAuthTokenParser(AuthTokenParser authTokenParser) {
        super.setAuthTokenParser(authTokenParser);
    }

    @Bean
    public SecurityProperties securityProperties() {
        SecurityProperties securityProperties = new SecurityProperties();
        securityProperties.setEnable(true);
        securityProperties.setAssertOrgWith("Chumbok");
        securityProperties.setAssertTenant(true);
        securityProperties.setAssertTenantWith("Chumbok");
        return securityProperties;
    }

    @Autowired
    @Override
    protected void setSecurityProperties(SecurityProperties securityProperties) {
        super.setSecurityProperties(securityProperties);
    }
}
