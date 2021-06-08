package com.bosch.inst.base.security.keycloak.config;

import com.bosch.inst.base.rest.entity.ApiError;
import javax.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

/**
 * The ControllerAdviser is the standard advisor to be aware of errors and treat them accordingly.
 */
@Slf4j
@ControllerAdvice
@Order // Let the project specific advisers get a chance to step in
public class KeycloakAdviser extends ResponseEntityExceptionHandler {

    @ResponseBody
    @ExceptionHandler(HttpClientErrorException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    ResponseEntity<Object> invalidLicenseExceptionHandler(HttpServletRequest request,
        HttpClientErrorException ex) {
        log.warn(KeycloakErrorDef.HTTP_CLIENT_ERROR_EXCEPTION.getReasonPhrase(), ex);
        ApiError apiError = new ApiError(KeycloakErrorDef.HTTP_CLIENT_ERROR_EXCEPTION, request, ex);
        return new ResponseEntity<>(apiError, HttpStatus.UNAUTHORIZED);
    }

}
