package com.github.base.security.keycloak.exception;

public class InvalidKeycloakResponseException extends RuntimeException {

    public InvalidKeycloakResponseException() {
        super();
    }

    public InvalidKeycloakResponseException(String message) {
        super(message);
    }

    public InvalidKeycloakResponseException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidKeycloakResponseException(Throwable cause) {
        super(cause);
    }

    protected InvalidKeycloakResponseException(String message, Throwable cause,
        boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
