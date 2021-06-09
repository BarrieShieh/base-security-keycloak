package com.bosch.inst.base.security.keycloak.service.impl;

import static graphql.Assert.assertTrue;
import static org.springframework.test.util.AssertionErrors.assertEquals;

import com.bosch.inst.base.security.keycloak.auth.Credentials;
import com.bosch.inst.base.security.keycloak.exception.FailedRequestKeycloakException;
import com.bosch.inst.base.security.keycloak.exception.InvalidKeycloakResponseException;
import com.bosch.inst.base.security.keycloak.exception.InvalidTenantException;
import com.bosch.inst.base.security.keycloak.service.IKeycloakService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response;
import lombok.extern.slf4j.Slf4j;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RealmsResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

@Service
@Slf4j
public class KeycloakService implements IKeycloakService {

  public static final String TENANT_HEADER_NAME = "x-tenant";
  public static final String TENANT_COOKIE_NAME = "TENANT";
  public static final String ACCESS_TOKEN_COOKIE_NAME = "TOKEN";
  public static final String REFRESH_TOKEN_COOKIE_NAME = "REFRESH_TOKEN";
  public static final String ROOT_TENANT_NAME = "master";

  @Autowired
  private HttpServletRequest request;

  @Override
  public Keycloak getKeycloakInstance() {
    String realm = getTenant(request);
    KeycloakDeployment deployment = getRealmInfo(realm);
    String authServerUrl = deployment.getAuthServerBaseUrl();

    KeycloakAuthenticationToken token = (KeycloakAuthenticationToken) request.getUserPrincipal();
    KeycloakPrincipal principal = (KeycloakPrincipal) token.getPrincipal();
    KeycloakSecurityContext session = principal.getKeycloakSecurityContext();
    Keycloak keycloak = KeycloakBuilder.builder()
        .serverUrl(authServerUrl)
        .realm(realm)
        .authorization(session.getTokenString())
        .resteasyClient(new ResteasyClientBuilder().connectionPoolSize(20).build())
        .build();
    return keycloak;
  }

  @Override
  public AccessTokenResponse getAccessToken(Credentials credentials) {
    String realm = getTenant(request);
    KeycloakDeployment deployment = getRealmInfo(realm);
    String authServerUrl = deployment.getAuthServerBaseUrl();

    // data for token request
    MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
    params.add("grant_type", "password");
//    params.add("client_id", deployment.getResourceName());
    params.add("username", credentials.getUsername());
    params.add("password", credentials.getPassword());

    // construct token request (including authorization for client(
    RequestEntity<MultiValueMap<String, String>> authRequest = null;
    try {
      authRequest = RequestEntity
          .post(new URI(authServerUrl +
              "/realms/" + realm + "/protocol/openid-connect/token"))
          .contentType(MediaType.APPLICATION_FORM_URLENCODED)
          .accept(MediaType.APPLICATION_JSON)
          .header("Authorization",
              httpBasicAuthorization(deployment.getResourceName(),
                  deployment.getResourceCredentials().get("secret").toString()))
          .body(params);
    } catch (URISyntaxException e) {
      throw new FailedRequestKeycloakException("Request keycloak failed", e);
    }

    // execute request and test for success
    RestTemplate restTemplate = new RestTemplate();
    ResponseEntity<String> response = restTemplate.exchange(authRequest, String.class);
    assertEquals("", HttpStatus.OK, response.getStatusCode());
    assertTrue(response.getHeaders().getContentType().isCompatibleWith(MediaType.APPLICATION_JSON));

    // extract access token (JWT) from response

    ObjectMapper objectMapper = new ObjectMapper();

    AccessTokenResponse tokenResponse = null;
    try {
      tokenResponse = objectMapper.readValue(response.getBody(), AccessTokenResponse.class);
    } catch (JsonProcessingException e) {
      throw new InvalidKeycloakResponseException("Invalid Keycloak response!", e);
    }

    return tokenResponse;
  }

  @Override
  public AccessTokenResponse refreshAccessToken() {
    String realm = getTenant(request);
    String refreshToken = getCookie(request, REFRESH_TOKEN_COOKIE_NAME);

    KeycloakDeployment deployment = getRealmInfo(realm);
    String authServerUrl = deployment.getAuthServerBaseUrl();

    // data for token request
    MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
    params.add("grant_type", "refresh_token");
//    params.add("client_id", deployment.getResourceName());

    params.add("refresh_token", refreshToken);
    // construct token request (including authorization for client(
    RequestEntity<MultiValueMap<String, String>> authRequest = null;
    try {
      authRequest = RequestEntity
          .post(new URI(authServerUrl +
              "/realms/" + realm + "/protocol/openid-connect/token"))
          .contentType(MediaType.APPLICATION_FORM_URLENCODED)
          .accept(MediaType.APPLICATION_JSON)
          .header("Authorization",
              httpBasicAuthorization(deployment.getResourceName(),
                  deployment.getResourceCredentials().get("secret").toString()))
          .body(params);
    } catch (URISyntaxException e) {
      throw new FailedRequestKeycloakException("Request keycloak failed", e);
    }

    // execute request and test for success
    RestTemplate restTemplate = new RestTemplate();
    ResponseEntity<String> response = restTemplate.exchange(authRequest, String.class);
    assertEquals("", HttpStatus.OK, response.getStatusCode());
    assertTrue(response.getHeaders().getContentType().isCompatibleWith(MediaType.APPLICATION_JSON));

    // extract access token (JWT) from response

    ObjectMapper objectMapper = new ObjectMapper();

    AccessTokenResponse tokenResponse = null;
    try {
      tokenResponse = objectMapper
          .readValue(response.getBody(), AccessTokenResponse.class);
    } catch (JsonProcessingException e) {
      throw new InvalidKeycloakResponseException("Invalid Keycloak response!", e);
    }

    return tokenResponse;
  }


  @Override
  public List<RealmRepresentation> getRealms() {
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmsResource realmResources = keycloakInstance.realms();
    return realmResources.findAll();
  }

  @Override
  public UserRepresentation getLoginUser() {
    String realm = getTenant(request);
    KeycloakAuthenticationToken token = (KeycloakAuthenticationToken) request.getUserPrincipal();
    KeycloakPrincipal principal = (KeycloakPrincipal) token.getPrincipal();
    UserRepresentation user = getUserById(principal.getName());
    List<String> realmRoles = this.getRealmLevelRolesByUserId(principal.getName()).stream()
        .map(r -> r.getName()).collect(
            Collectors.toList());
    user.setRealmRoles(realmRoles);

    Map<String, List<RoleRepresentation>> roles = this
        .getClientLevelRolesByUserId(principal.getName());

    Map<String, List<String>> clientsRoles = new HashMap<>();
    for (Map.Entry<String, List<RoleRepresentation>> entry : roles.entrySet()) {
      String mapKey = entry.getKey();
      List<String> mapValue = entry.getValue().stream().map(r -> r.getName())
          .collect(Collectors.toList());
      clientsRoles.put(mapKey, mapValue);
    }

    user.setClientRoles(clientsRoles);

//    String client = deployment.realm(realm).clients().findAll().get(0).getClientId();
//    user.setClientRoles(new HashMap<String, List<String>>() {
//      {
//        put(client, clientsRoles);
//      }
//    });
    return user;
  }

  @Override
  public UserRepresentation selfRegistration(UserRepresentation user) {
    String realm = getTenant(request);

    Keycloak keycloakInstance = getKeycloakInstance();
    user.setEnabled(true);

//    CredentialRepresentation credential = new CredentialRepresentation();
//    credential.setType(CredentialRepresentation.PASSWORD);
//    credential.setValue(password);
//
//    user.setCredentials(Arrays.asList(credential));
    Response response = keycloakInstance.realm(realm).users().create(user);
    log.info("Response |  Status: {} | Status Info: {}", response.getStatus(),
        response.getStatusInfo());
    String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
    List<RoleRepresentation> roleRepresentations = new ArrayList<>();

    for (String role : user.getRealmRoles()) {
      roleRepresentations.add(keycloakInstance.realm(realm).roles().get(role).toRepresentation());
    }

    setRoles(userId, roleRepresentations);
    setGroups(userId, user.getGroups());
    sendVerifyEmail(userId);

    return keycloakInstance.realm(realm).users().get(userId).toRepresentation();
  }

  @Override
  public void sendVerifyEmail(String userId) {
    String realm = getTenant(request);
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    UserResource userResource = realmResource.users().get(userId);

    userResource.sendVerifyEmail();
  }

  @Override
  public void resetPasswordEmail(String username) {
    String realm = getTenant(request);
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    List<UserRepresentation> users = realmResource.users().search(username);
    if (users.size() == 1) {
      realmResource.users().get(users.get(0).getId())
          .executeActionsEmail(Arrays.asList("UPDATE_PASSWORD"));
    }
  }

  @Override
  public void setRoles(String userId, List<RoleRepresentation> roles) {
    String realm = getTenant(request);
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    UserResource userResource = realmResource.users().get(userId);
    // Assign realm-role role1 to user
    userResource.roles().realmLevel().add(roles);
  }

  @Override
  public void setGroups(String userId, List<String> groupIds) {
    String realm = getTenant(request);
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    UserResource userResource = realmResource.users().get(userId);

    for (String groupId : groupIds) {
      userResource.joinGroup(groupId);
    }
  }

  @Override
  public UserRepresentation getUserById(String userId) {
    String realm = getTenant(request);
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    return realmResource.users().get(userId).toRepresentation();
  }

  @Override
  public List<UserRepresentation> getUserByUsername(String username) {
    String realm = getTenant(request);
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    return realmResource.users().search(username);
  }

  @Override
  public List<UserRepresentation> getUsers() {
    String realm = getTenant(request);
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    return realmResource.users().list();
  }

  @Override
  public GroupRepresentation getGroupById(String groupId) {
    String realm = getTenant(request);
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    return realmResource.groups().group(groupId).toRepresentation();
  }

  @Override
  public List<GroupRepresentation> getGroupsByUserId(String userId) {
    String realm = getTenant(request);
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    return realmResource.users().get(userId).groups();
  }

  @Override
  public List<GroupRepresentation> getGroups() {
    String realm = getTenant(request);
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    return realmResource.groups().groups();
  }

  @Override
  public List<UserRepresentation> getGroupUserMembers(String groupId) {
    String realm = getTenant(request);
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);

    return realmResource.groups().group(groupId).members();
  }

  @Override
  public List<RoleRepresentation> getRealmLevelRolesByUserId(String userId) {
    String realm = getTenant(request);
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    return realmResource.users().get(userId).roles().realmLevel().listAll();
  }

  @Override
  public Map<String, List<RoleRepresentation>> getClientLevelRolesByUserId(String userId) {
    String realm = getTenant(request);
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);

    List<ClientRepresentation> clients = keycloakInstance.realm(realm).clients().findAll();

    Map<String, List<RoleRepresentation>> map = new HashMap<>();

    for (ClientRepresentation client : clients) {
      List<RoleRepresentation> roles = realmResource.users().get(userId).roles()
          .clientLevel(client.getId()).listAll();
      map.put(client.getClientId(), roles);
    }

    return map;
  }

  @Override
  public List<RoleRepresentation> getAllRolesByUserId(String userId) {
    String realm = getTenant(request);
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    return realmResource.users().get(userId).roles().getAll().getRealmMappings();
  }

  @Override
  public List<String> getRoleNamesByLoginUser() {
    String realm = getTenant(request);
    KeycloakAuthenticationToken token = (KeycloakAuthenticationToken) request.getUserPrincipal();
    KeycloakPrincipal principal = (KeycloakPrincipal) token.getPrincipal();

    KeycloakDeployment deployment = getRealmInfo(realm);

    String clientId = deployment.getResourceName();
    Set<String> set = principal.getKeycloakSecurityContext().getToken().getResourceAccess(clientId)
        .getRoles();
    return new ArrayList<>(set);
  }

  @Override
  public RoleRepresentation getRoleByName(String roleName) {
    String realm = getTenant(request);
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    return realmResource.roles().get(roleName).toRepresentation();
  }

  @Override
  public List<RoleRepresentation> getRoles() {
    String realm = getTenant(request);
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    return realmResource.roles().list();
  }

  @Override
  public List<UserRepresentation> getRoleUserMembers(String roleName) {
    String realm = getTenant(request);
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);

    return new ArrayList<>(realmResource.roles().get(roleName).getRoleUserMembers());
  }

  @Override
  public List<GroupRepresentation> getRoleGroupMembers(String roleName) {
    String realm = getTenant(request);
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);

    return new ArrayList<>(realmResource.roles().get(roleName).getRoleGroupMembers());
  }

  @Override
  public KeycloakDeployment getRealmInfo(String tenant) {
    if (null == tenant) {
      throw new InvalidTenantException("Tenant is null!");
    }
    KeycloakDeployment keycloakDeployment;

    String path = "/keycloak/" + tenant + ".json";
    InputStream configInputStream = getClass().getResourceAsStream(path);

    if (configInputStream == null) {
      throw new InvalidTenantException("Could not load Keycloak deployment info: " + path);
    } else {
      keycloakDeployment = KeycloakDeploymentBuilder.build(configInputStream);
    }

    return keycloakDeployment;
  }

  @Override
  public String getTenant(HttpFacade.Request facade) {
    String tenant = null;
    if (null != facade.getCookie(TENANT_COOKIE_NAME)) {
      tenant = facade.getCookie(TENANT_COOKIE_NAME).getValue();
    }
    if (null != facade.getHeader(TENANT_HEADER_NAME)) {
      tenant = facade.getHeader(TENANT_HEADER_NAME);
    }
    return tenant;
  }

  @Override
  public String getTenant(HttpServletRequest httpServletRequest) {
    String tenant = null;
    if (null != getCookie(httpServletRequest, TENANT_COOKIE_NAME)) {
      tenant = getCookie(httpServletRequest, TENANT_COOKIE_NAME);
    }
    if (null != httpServletRequest.getHeader(TENANT_HEADER_NAME)) {
      tenant = httpServletRequest.getHeader(TENANT_HEADER_NAME);
    }
    return tenant;
  }

  @Override
  public String getCookie(HttpServletRequest httpServletRequest, String key) {
    Cookie[] cookies = request.getCookies();

    if (cookies != null) {
      for (Cookie cookie : cookies) {
        if (cookie.getName().equals(key)) {
          //do something
          //value can be retrieved using #cookie.getValue()
          return cookie.getValue();
        }
      }
    }

    return null;
  }

  private String httpBasicAuthorization(String username, String password) {
    return "Basic " + Base64.getEncoder().encodeToString((username + ":" + password).getBytes());
  }
}
