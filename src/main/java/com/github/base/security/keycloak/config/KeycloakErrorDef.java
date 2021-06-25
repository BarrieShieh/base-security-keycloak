package com.github.base.security.keycloak.config;

import com.bosch.inst.base.rest.entity.BaseErrorDef;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum KeycloakErrorDef implements BaseErrorDef {
    HTTP_CLIENT_ERROR_EXCEPTION(10001, "HttpClient Error Exception"),
    INVALID_TENANT_EXCEPTION(10002, "Invalid Tenant Exception"),
    INVALID_KEYCLOAK_RESPONSE_EXCEPTION(10003, "Invalid Keycloak Response Exception"),
    FAILED_REQUEST_KEYCLOAK_EXCEPTION(10004, "Failed Request Keycloak Exception"),
    ;

    private final int value;
    private final String reasonPhrase;
}
