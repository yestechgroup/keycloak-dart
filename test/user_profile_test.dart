import 'package:keycloak_dart/keycloak_dart.dart';
import 'package:test/test.dart';

void main() {
  const authServerUrl = 'http://localhost:8080';
  const realm = 'test-realm';
  const clientId = 'test-client';
  const appUrl = 'http://localhost:3000';

  test('throws loading user profile when not authenticated', () async {
    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ));
    await keycloak.init(KeycloakInitOptions(redirectUri: appUrl));

    expect(
      () => keycloak.loadUserProfile(),
      throwsA(isA<StateError>().having(
        (e) => e.message,
        'message',
        contains('token is not set'),
      )),
    );
  });

  test('throws loading user profile using a generic OpenID provider', () async {
    final keycloak = Keycloak(GenericOidcConfig(
      clientId: clientId,
      oidcProvider: OpenIdProviderMetadata(
        authorizationEndpoint:
            '$authServerUrl/realms/$realm/protocol/openid-connect/auth',
        tokenEndpoint:
            '$authServerUrl/realms/$realm/protocol/openid-connect/token',
        endSessionEndpoint:
            '$authServerUrl/realms/$realm/protocol/openid-connect/logout',
      ),
    ));
    await keycloak.init();

    // Even with a token, it should fail because there's no realm URL
    keycloak.token = 'test-token';

    expect(
      () => keycloak.loadUserProfile(),
      throwsA(isA<StateError>().having(
        (e) => e.message,
        'message',
        contains('generic OIDC provider'),
      )),
    );
  });
}
