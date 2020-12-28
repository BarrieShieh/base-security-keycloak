package com.bosch.inst.base.security.keycloak.filter;

import static org.springframework.http.HttpStatus.valueOf;

import com.bosch.inst.base.security.keycloak.auth.HttpProperties;
import com.bosch.inst.base.security.keycloak.cookie.AuthorizationCookieHandler;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Import;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
@Slf4j
@EnableConfigurationProperties({
    HttpProperties.class
})
@Import({
    AuthorizationCookieHandler.class
})
public class RefreshLoginCookieFilter extends OncePerRequestFilter {

  @Autowired
  private HttpServletRequest request;

  @Autowired
  private HttpServletResponse response;

  @Autowired
  private HttpProperties httpProperties;

  @Autowired
  private AuthorizationCookieHandler authorizationCookieHandler;

  private void refreshAuthorizationCookie() {
    Cookie loginCookie = authorizationCookieHandler.getAuthorizationCookie(request);
    if (loginCookie != null) {
      log.debug(
          "Processed request with response HTTP status {} - will add fresh authorization cookie",
          response.getStatus());
//      authorizationCookieHandler.setAuthenticationCookie();
    } else {
      log.debug(
          "Processed request with response HTTP status {} - will NOT add fresh authorization cookie "
              + "since the request was made with basic auth, not with a login cookie",
          response.getStatus());
    }
  }

  private void refreshTenantCookie(HttpServletRequest request,
      HttpServletResponse response) {
    Cookie loginCookie = authorizationCookieHandler.getTenantCookie(request);
    if (loginCookie != null) {
      // TODO: Fix debug messages
      log.debug("Processed request with response HTTP status {} - will add fresh tenant cookie",
          response.getStatus());
      authorizationCookieHandler
          .setTenantCookie(loginCookie.getValue());
    } else {
      log.debug("Processed request with response HTTP status {} - will NOT add fresh tenant cookie "
              + "since the request was made with basic auth, not with a login cookie",
          response.getStatus());
    }
  }

  @Override
  protected void doFilterInternal(HttpServletRequest httpServletRequest,
      HttpServletResponse httpServletResponse, FilterChain filterChain)
      throws ServletException, IOException {
    if (!matchWhiteList(httpServletRequest.getServletPath())) {
      if (valueOf(httpServletResponse.getStatus()).is2xxSuccessful()) {
        // Check whether the request contains the login cookie.
        // If not do nothing - we do not want to return a authentication cookie
        // if a REST call has been made with basic auth since this is the job of the LoginController
        this.refreshAuthorizationCookie();
        this.refreshTenantCookie(httpServletRequest, httpServletResponse);

      } else {
        log.debug(
            "Processed request with response HTTP status {} - will NOT add fresh authorization cookie",
            httpServletResponse.getStatus());
      }
    }
    filterChain.doFilter(httpServletRequest, httpServletResponse);
  }

  private boolean matchWhiteList(String path) {
    for (String pattern : httpProperties.getWhitelist()) {
      if (new AntPathMatcher().match(pattern, path)) {
        return true;
      }
    }
    return false;
  }


}
