package com.flex.security_spring_boot_256.providers;

import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class SecurityDetailsProvider {

    private List<String> types;
    private static String key;

    public String setKey(String secretKey) {
        return key = secretKey;
    }

    public List<String> setUserTypes(List<String> userTypes) {
        return this.types = userTypes;
    }

    public List<String> getUserTypes() {
        return types;
    }

    public static String getEncodeKey() {
        return key;
    }
}
