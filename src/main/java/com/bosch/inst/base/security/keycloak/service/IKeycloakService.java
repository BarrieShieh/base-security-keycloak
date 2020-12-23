package com.bosch.inst.base.security.keycloak.service;

import java.util.List;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

public interface IKeycloakService {

  Keycloak getKeycloakInstance();

  UserRepresentation selfRegistration(String realm, String userName, String firstName,
      String lastName,
      String email,
      String password, List<String> roles, List<String> groupIds);

  void sendVerifyEmail(String realm, String userId);

  void resetPasswordEmail(String realm, String userId);

  void setRoles(String realm, String userId, List<RoleRepresentation> roles);

  void setGroups(String realm, String userId, List<String> groupIds);

  UserRepresentation getUserById(String realm, String userId);

  List<UserRepresentation> getUserByUsername(String realm, String username);

  List<UserRepresentation> getUsers(String realm);

  GroupRepresentation getGroupById(String realm, String groupId);

  List<GroupRepresentation> getGroups(String realm);

  List<UserRepresentation> getGroupMembers(String realm, String groupId);

  RoleRepresentation getRoleByName(String realm, String roleName);

  List<RoleRepresentation> getRoles(String realm);
}
