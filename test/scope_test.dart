import 'package:keycloak_dart/keycloak_dart.dart';
import 'package:test/test.dart';

void main() {
  const authServerUrl = 'http://localhost:8080';
  const realm = 'test-realm';
  const clientId = 'test-client';
  const appUrl = 'http://localhost:3000';

  test('uses scopes passed during initialization', () async {
    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ),);
    await keycloak.init(KeycloakInitOptions(
      redirectUri: appUrl,
      scope: 'openid profile email phone',
    ),);

    final loginUrlString = await keycloak.createLoginUrl();
    final loginUrl = Uri.parse(loginUrlString);

    expect(
      loginUrl.queryParameters['scope'],
      'openid profile email phone',
    );
  });

  test('uses scopes passed during login (overrides init scope)', () async {
    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ),);
    await keycloak.init(KeycloakInitOptions(
      redirectUri: appUrl,
      scope: 'openid profile',
    ),);

    final loginUrlString = await keycloak.createLoginUrl(
      KeycloakLoginOptions(scope: 'openid profile email phone'),
    );
    final loginUrl = Uri.parse(loginUrlString);

    expect(
      loginUrl.queryParameters['scope'],
      'openid profile email phone',
    );
  });
}
