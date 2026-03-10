import 'keycloak_token.dart';

/// Realm role access.
typedef KeycloakRoles = KeycloakRolesData;

/// Resource-level role access mapping.
typedef KeycloakResourceAccess = Map<String, KeycloakRolesData>;
