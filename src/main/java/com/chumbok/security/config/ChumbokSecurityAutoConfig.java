package com.chumbok.security.config;

import com.chumbok.security.properties.SecurityProperties;
import com.chumbok.security.util.EncryptionKeyUtil;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConditionalOnProperty(name = "com.chumbok.security.enable", havingValue = "true", matchIfMissing = false)
public class ChumbokSecurityAutoConfig {

    @Bean
    public EncryptionKeyUtil encryptionKeyUtil() {
        return new EncryptionKeyUtil();
    }

    @Bean
    @ConfigurationProperties("com.chumbok.security")
    public SecurityProperties serviceProps() { return new SecurityProperties(); }
}