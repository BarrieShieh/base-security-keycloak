package com.bosch.inst.base.security.keycloak.exception;

public class FailedRequestKeycloakException extends RuntimeException {

    public FailedRequestKeycloakException() {
        super();
    }

    public FailedRequestKeycloakException(String message) {
        super(message);
    }

    public FailedRequestKeycloakException(String message, Throwable cause) {
        super(message, cause);
    }

    public FailedRequestKeycloakException(Throwable cause) {
        super(cause);
    }

    protected FailedRequestKeycloakException(String message, Throwable cause,
        boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
