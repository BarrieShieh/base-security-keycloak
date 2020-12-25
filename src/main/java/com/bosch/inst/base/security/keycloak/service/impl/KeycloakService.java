package com.bosch.inst.base.security.keycloak.service.impl;

import com.bosch.inst.base.security.keycloak.service.IKeycloakService;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response;
import lombok.extern.slf4j.Slf4j;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class KeycloakService implements IKeycloakService {

  public static String cookieTenantKey = "TENANT";

  @Autowired
  private HttpServletRequest request;

  @Override
  public Keycloak getKeycloakInstance() {
    String realm = readCookie(cookieTenantKey).get();
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
  public UserRepresentation getLoginUser() {
    String realm = readCookie(cookieTenantKey).get();
    KeycloakAuthenticationToken token = (KeycloakAuthenticationToken) request.getUserPrincipal();
    KeycloakPrincipal principal = (KeycloakPrincipal) token.getPrincipal();
    return getUserById(principal.getName());
  }

  @Override
  public UserRepresentation selfRegistration(UserRepresentation user) {
    String realm = readCookie(cookieTenantKey).get();

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
    String realm = readCookie(cookieTenantKey).get();
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    UserResource userResource = realmResource.users().get(userId);

    userResource.sendVerifyEmail();
  }

  @Override
  public void resetPasswordEmail(String username) {
    String realm = readCookie(cookieTenantKey).get();
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
    String realm = readCookie(cookieTenantKey).get();
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    UserResource userResource = realmResource.users().get(userId);
    // Assign realm-role role1 to user
    userResource.roles().realmLevel().add(roles);
  }

  @Override
  public void setGroups(String userId, List<String> groupIds) {
    String realm = readCookie(cookieTenantKey).get();
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    UserResource userResource = realmResource.users().get(userId);

    for (String groupId : groupIds) {
      userResource.joinGroup(groupId);
    }
  }

  @Override
  public UserRepresentation getUserById(String userId) {
    String realm = readCookie(cookieTenantKey).get();
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    return realmResource.users().get(userId).toRepresentation();
  }

  @Override
  public List<UserRepresentation> getUserByUsername(String username) {
    String realm = readCookie(cookieTenantKey).get();
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    return realmResource.users().search(username);
  }

  @Override
  public List<UserRepresentation> getUsers() {
    String realm = readCookie(cookieTenantKey).get();
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    return realmResource.users().list();
  }

  @Override
  public GroupRepresentation getGroupById(String groupId) {
    String realm = readCookie(cookieTenantKey).get();
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    return realmResource.groups().group(groupId).toRepresentation();
  }

  @Override
  public List<GroupRepresentation> getGroupsByUserId(String userId) {
    String realm = readCookie(cookieTenantKey).get();
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    return realmResource.users().get(userId).groups();
  }

  @Override
  public List<GroupRepresentation> getGroups() {
    String realm = readCookie(cookieTenantKey).get();
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    return realmResource.groups().groups();
  }

  @Override
  public List<UserRepresentation> getGroupUserMembers(String groupId) {
    String realm = readCookie(cookieTenantKey).get();
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);

    return realmResource.groups().group(groupId).members();
  }

  @Override
  public List<RoleRepresentation> getRolesByUserId(String userId) {
    String realm = readCookie(cookieTenantKey).get();
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    return realmResource.users().get(userId).roles().realmLevel().listAll();
  }

  @Override
  public RoleRepresentation getRoleByName(String roleName) {
    String realm = readCookie(cookieTenantKey).get();
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    return realmResource.roles().get(roleName).toRepresentation();
  }

  @Override
  public List<RoleRepresentation> getRoles() {
    String realm = readCookie(cookieTenantKey).get();
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);
    return realmResource.roles().list();
  }

  @Override
  public List<UserRepresentation> getRoleUserMembers(String roleName) {
    String realm = readCookie(cookieTenantKey).get();
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);

    return new ArrayList<>(realmResource.roles().get(roleName).getRoleUserMembers());
  }

  @Override
  public List<GroupRepresentation> getRoleGroupMembers(String roleName) {
    String realm = readCookie(cookieTenantKey).get();
    Keycloak keycloakInstance = getKeycloakInstance();
    RealmResource realmResource = keycloakInstance.realm(realm);

    return new ArrayList<>(realmResource.roles().get(roleName).getRoleGroupMembers());
  }

  @Override
  public KeycloakDeployment getRealmInfo(String tenant) {
    KeycloakDeployment keycloakDeployment;

    String path = "/keycloak/" + tenant + ".json";
    InputStream configInputStream = getClass().getResourceAsStream(path);

    if (configInputStream == null) {
      throw new RuntimeException("Could not load Keycloak deployment info: " + path);
    } else {
      keycloakDeployment = KeycloakDeploymentBuilder.build(configInputStream);
    }

    return keycloakDeployment;
  }

  private Optional<String> readCookie(String key) {
    return Arrays.stream(request.getCookies())
        .filter(c -> key.equals(c.getName()))
        .map(Cookie::getValue)
        .findAny();
  }
}
