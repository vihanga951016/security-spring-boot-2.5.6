package com.flex.security_spring_boot_256;

public class AuthorizationException extends Exception {

    public AuthorizationException(String message) {
        super(message);
    }

    public AuthorizationException(Exception ex) {
        super(ex);
    }
}
