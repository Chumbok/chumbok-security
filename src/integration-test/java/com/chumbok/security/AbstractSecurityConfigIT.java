package com.chumbok.security;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;

import javax.servlet.http.Cookie;
import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = AbstractSecurityConfigIT.Application.class)
@AutoConfigureMockMvc
@ActiveProfiles("it")
public class AbstractSecurityConfigIT {

    /**
     * JWT auth token created with private_key.der
     */
    private final String AUTH_TOKEN = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbkBjaHVtYm9rLmNvbSIsImRvbWFpbiI6ImNodW1ib2siLCJzY29wZXMiOlsiUk9MRV9TVVBFUkFETUlOIl0sImlzcyI6IkNodW1ib2siLCJpYXQiOjE1MzY2MTMwNDAsImV4cCI6MTk1MzY2MTMwNDB9.BjqrMJTEAuoaw2laeiNqVYdgtgf4_WJlmK-vh7Lq70G04-QztW0bYGsptUatKxnfVWsEr0I6726xo__9L9yvBN4d7pd3N7v0LKu05mfhY6-WMkg0N-VM_4BpZ7Y-sgb-07_pEfVi8wVj3iER0IHPXJOvo9xL1gXmsjox0dTveW_qndd4yLtZ7Aq4b9Kfrw3nGnjujoK3URf2fuahlHlaMoJFh7tVrHKQ3D3QjdFdNBvtXMGzuBnIcc943HIxjXBzS3C92j5scMT7wLoefVABGhQbPXmmfzcw2ASJAOCg2BJy-ArA3jCM4Y1dTEAlKpwC-ssIbMH5EuKNFK4Zxly9mw";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private FilterChainProxy springSecurityFilterChain;

    @Before
    public void setup() throws Exception {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(springSecurityFilterChain)
                .build();
    }

    @Test
    public void shouldReturn403OnMissingAuthorizationHeaderOrCookie() throws Exception {

        mockMvc.perform(get("/"))
                .andExpect(status().isForbidden())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8_VALUE))
                .andExpect(jsonPath("$.code").value("FORBIDDEN_REQUEST"))
                .andExpect(jsonPath("$.message").value("Permission denied for the resource."))
                .andDo(print());
    }

    @Test
    public void shouldReturn200OnValidAuthorizationHeader() throws Exception {

        mockMvc.perform(get("/").header("Authorization", "Bearer+" + AUTH_TOKEN))
                .andExpect(status().isOk())
                .andDo(print());
    }

    @Test
    public void shouldReturn200OnValidAuthorizationCookie() throws Exception {

        mockMvc.perform(get("/").cookie(new Cookie("Authorization", AUTH_TOKEN)))
                .andExpect(status().isOk())
                .andDo(print());

    }

    @Test
    public void shouldReturnAuthenticationInfoOnValidSecurityContext() throws Exception {

        mockMvc.perform(get("/authentication")
                .cookie(new Cookie("Authorization", "Bearer+" + AUTH_TOKEN)))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8_VALUE))
                .andExpect(jsonPath("$.principle").value("chumbok13admin@chumbok.com"))
                .andExpect(jsonPath("$.isAuthenticated").value("true"))
                .andExpect(jsonPath("$.authorities").value("[ROLE_SUPERADMIN]"))
                .andDo(print());


    }

    @EnableWebSecurity
    static class SecurityConfig extends AbstractSecurityConfig {

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
    }

    @SpringBootApplication
    @RestController
    static class Application {

        @RequestMapping("/")
        public void ping() {
        }

        @RequestMapping("/authentication")
        public Map<String, String> authentication() {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Map<String, String> authMap = new HashMap<>();
            authMap.put("principle", (String) authentication.getPrincipal());
            authMap.put("isAuthenticated", String.valueOf(authentication.isAuthenticated()));
            authMap.put("authorities", authentication.getAuthorities().toString());
            return authMap;
        }
    }

}
