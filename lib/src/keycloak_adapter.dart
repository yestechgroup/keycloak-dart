import 'keycloak_login_options.dart';

/// Interface for platform-specific adapters.
///
/// Implement this to provide custom login/logout behavior
/// for different platforms (browser, mobile, etc.).
abstract class KeycloakAdapter {
  Future<void> login([KeycloakLoginOptions? options]);
  Future<void> logout([KeycloakLogoutOptions? options]);
  Future<void> register([KeycloakRegisterOptions? options]);
  Future<void> accountManagement();
  String redirectUri([KeycloakRedirectUriOptions? options]);
}
