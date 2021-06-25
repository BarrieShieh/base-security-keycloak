package com.github.base.security.keycloak.servlet;

import static com.github.base.security.keycloak.adapter.BaseAdapter.ROOT_REALM_NAME;

import com.github.base.security.keycloak.adapter.BaseAdapter;
import com.github.base.security.keycloak.adapter.UserAdapter;
import com.github.base.security.keycloak.auth.HttpProperties;
import com.github.base.security.keycloak.cookie.AuthorizationCookieHandler;
import com.github.base.security.keycloak.filter.CorsFilter;
import com.github.base.security.keycloak.filter.EnforceSecureLoginFilter;
import com.github.base.security.keycloak.filter.RefreshLoginCookieFilter;
import com.github.base.security.keycloak.filter.XRequestedHeaderFilter;
import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(jsr250Enabled = true)
@EnableConfigurationProperties({
    HttpProperties.class
})
@Import({
    RefreshLoginCookieFilter.class,
    AuthorizationCookieHandler.class
})
public class SecurityConfiguration extends KeycloakWebSecurityConfigurerAdapter {

  @Autowired
  private HttpProperties httpProperties;

  @Autowired
  private AuthorizationCookieHandler authorizationCookieHandler;

  @Value("${identity-provider.config.path}")
  private String configPath;

  @Override
  public void configure(WebSecurity web) throws Exception {
    web.ignoring()
        .antMatchers(httpProperties.getWhitelist()
            .toArray(new String[httpProperties.getWhitelist().size()]));
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    super.configure(http);

    http.authorizeRequests()
//        .antMatchers("/actuator/**").hasAnyAuthority("ACTUATOR")
//        .antMatchers("/actuator/**").hasAnyAuthority("ROLE_ACTUATOR")
        .anyRequest().permitAll();

    // Don't use sessions for stateless REST interfaces
    http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

    http.addFilterBefore(new CorsFilter(), UsernamePasswordAuthenticationFilter.class);

    if (!httpProperties.isEnable()) {
      http.addFilterBefore(new EnforceSecureLoginFilter(),
          UsernamePasswordAuthenticationFilter.class);
    }

//        http.addFilterBefore(getTokenAuthFilter("/**"), UsernamePasswordAuthenticationFilter.class);
//        http.addFilterBefore(getCookieAuthFilter("/**"), UsernamePasswordAuthenticationFilter.class);
    http.addFilterBefore(new XRequestedHeaderFilter(httpProperties),
        UsernamePasswordAuthenticationFilter.class);

//    http.logout()
//        .addLogoutHandler(new CustomLogoutHandler(authorizationCookieHandler))
//        .deleteCookies(httpProperties.getCookie().getName())
//        .deleteCookies(BaseAdapter.REALM_COOKIE_NAME)
//        .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler(HttpStatus.OK));

    // Return the 'WWW-Authenticate: Basic' header in case of missing credentials
    http.httpBasic();

    // Hint:
    // We disable csrf since we are running stateless REST services.
    // Instead of the Synchronized Token Pattern we check for the presence of a custom request header.
    // -> Only JavaScript can be used to add a custom header, and only within its origin.
    // -> See https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet
    // Section 'Protecting REST Services: Use of Custom Request Headers'
    http.csrf().disable();
  }

  @Autowired
  public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
    KeycloakAuthenticationProvider keycloakAuthenticationProvider = keycloakAuthenticationProvider();
    keycloakAuthenticationProvider.setGrantedAuthoritiesMapper(new SimpleAuthorityMapper());
    auth.authenticationProvider(keycloakAuthenticationProvider);
  }

  @Bean
  @Override
  protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
    return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
  }

//  @Bean
//  public KeycloakConfigResolver KeycloakConfigResolver() {
//    return new KeycloakSpringBootConfigResolver();
//  }

  /**
   * Overrides default keycloak config resolver behaviour (/WEB-INF/keycloak.json) by a simple
   * mechanism.
   * <p>
   * This example loads other-keycloak.json when the parameter use.other is set to true, e.g.:
   * {@code ./gradlew bootRun -Duse.other=true}
   *
   * @return keycloak config resolver
   */
  @Bean
  public KeycloakConfigResolver keycloakConfigResolver() {
    return request -> {
//        String uri = facade.getRelativePath();
      String realm = BaseAdapter.getRealm(request);
      return new UserAdapter(null != realm ? realm : ROOT_REALM_NAME, configPath).getRealmInfo();

//        if ("/login".equals(uri)) {
////          return new KeycloakSpringBootConfigResolver().resolve(facade);
//          String tenant = facade.getCookie(TENANT_HEADER_NAME).getValue();
//          if (null != facade.getHeader(TENANT_HEADER_NAME)) {
//            tenant = facade.getCookie(TENANT_COOKIE_NAME).getValue();
//          }
//          return keycloakService.getRealmInfo(tenant);
//        } else {
//          String tenant = facade.getCookie(TENANT_HEADER_NAME).getValue();
//          return keycloakService.getRealmInfo(tenant);
//        }
    };
  }


}
