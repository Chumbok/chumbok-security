package com.chumbok.security.config;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
@PropertySource("classpath:application.yml")
@RestController
public class Application {

    @GetMapping("/")
    public void ping() {
    }

    @PostMapping("/")
    public void postSomething() {
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
