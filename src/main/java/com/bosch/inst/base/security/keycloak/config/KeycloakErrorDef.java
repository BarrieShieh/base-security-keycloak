package com.bosch.inst.base.security.keycloak.config;

import com.bosch.inst.base.rest.entity.BaseErrorDef;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum KeycloakErrorDef implements BaseErrorDef {
    HTTP_CLIENT_ERROR_EXCEPTION(10001, "HttpClient Error Exception"),
    ;

    private final int value;
    private final String reasonPhrase;
}
