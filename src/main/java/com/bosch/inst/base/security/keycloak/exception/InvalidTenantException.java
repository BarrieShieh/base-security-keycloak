package com.bosch.inst.base.security.keycloak.exception;

public class InvalidTenantException extends RuntimeException {

    public InvalidTenantException() {
        super();
    }

    public InvalidTenantException(String message) {
        super(message);
    }

    public InvalidTenantException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidTenantException(Throwable cause) {
        super(cause);
    }

    protected InvalidTenantException(String message, Throwable cause, boolean enableSuppression,
        boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
