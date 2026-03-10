import 'package:keycloak_dart/keycloak_dart.dart';
import 'package:test/test.dart';

void main() {
  const authServerUrl = 'http://localhost:8080';
  const realm = 'test-realm';
  const clientId = 'test-client';
  const appUrl = 'http://localhost:3000';

  test('configures silent SSO redirect URI', () async {
    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ));
    await keycloak.init(KeycloakInitOptions(
      redirectUri: appUrl,
      silentCheckSsoRedirectUri: '$appUrl/silent-check-sso.html',
    ));

    expect(
      keycloak.silentCheckSsoRedirectUri,
      '$appUrl/silent-check-sso.html',
    );
  });

  test('configures silent SSO with login iframe disabled', () async {
    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ));
    await keycloak.init(KeycloakInitOptions(
      redirectUri: appUrl,
      silentCheckSsoRedirectUri: '$appUrl/silent-check-sso.html',
      checkLoginIframe: false,
    ));

    expect(
      keycloak.silentCheckSsoRedirectUri,
      '$appUrl/silent-check-sso.html',
    );
  });

  test('configures silent SSO with fallback disabled', () async {
    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ));
    await keycloak.init(KeycloakInitOptions(
      redirectUri: appUrl,
      silentCheckSsoRedirectUri: '$appUrl/silent-check-sso.html',
      silentCheckSsoFallback: false,
    ));

    expect(keycloak.silentCheckSsoFallback, isFalse);
    expect(
      keycloak.silentCheckSsoRedirectUri,
      '$appUrl/silent-check-sso.html',
    );
  });
}
