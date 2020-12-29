package com.bosch.inst.base.security.keycloak.service;

import com.bosch.inst.base.security.keycloak.auth.Credentials;
import com.fasterxml.jackson.core.JsonProcessingException;
import java.net.URISyntaxException;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

public interface IKeycloakService {


  Keycloak getKeycloakInstance();


  AccessTokenResponse getAccessToken(Credentials credentials);

  AccessTokenResponse refreshAccessToken()
      throws URISyntaxException, JsonProcessingException;

  UserRepresentation getLoginUser();

  UserRepresentation selfRegistration(UserRepresentation user);

  void sendVerifyEmail(String userId);

  void resetPasswordEmail(String username);

  void setRoles(String userId, List<RoleRepresentation> roles);

  void setGroups(String userId, List<String> groupIds);

  UserRepresentation getUserById(String userId);

  List<UserRepresentation> getUserByUsername(String username);

  List<UserRepresentation> getUsers();

  GroupRepresentation getGroupById(String groupId);

  List<GroupRepresentation> getGroupsByUserId(String userId);

  List<GroupRepresentation> getGroups();

  List<UserRepresentation> getGroupUserMembers(String groupId);

  List<RoleRepresentation> getRolesByUserId(String userId);

  RoleRepresentation getRoleByName(String roleName);

  List<RoleRepresentation> getRoles();

  List<UserRepresentation> getRoleUserMembers(String roleName);

  List<GroupRepresentation> getRoleGroupMembers(String roleName);

  KeycloakDeployment getRealmInfo(String tenant);

  String getTenant(HttpFacade.Request facade);

  String getTenant(HttpServletRequest httpServletRequest);

  String getCookie(HttpServletRequest httpServletRequest, String key);
}
