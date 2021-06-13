package com.bosch.inst.base.security.keycloak.filter;

import com.bosch.inst.base.security.keycloak.cookie.AuthorizationCookieHandler;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

public class CustomLogoutHandler implements LogoutHandler {

  private final AuthorizationCookieHandler authorizationCookieHandler;

  public CustomLogoutHandler(AuthorizationCookieHandler authorizationCookieHandler) {
    this.authorizationCookieHandler = authorizationCookieHandler;
  }

  @Override
  public void logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
      Authentication authentication) {
    authorizationCookieHandler.deleteAuthenticationCookie(httpServletRequest, httpServletResponse);
    authorizationCookieHandler.deleteRealmCookie(httpServletRequest, httpServletResponse);
  }
}
