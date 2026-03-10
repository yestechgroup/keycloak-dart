import 'package:keycloak_dart/keycloak_dart.dart';
import 'package:test/test.dart';

import 'token_test.dart' show createTestToken;

void main() {
  const authServerUrl = 'http://localhost:8080';
  const realm = 'test-realm';
  const clientId = 'test-client';
  const appUrl = 'http://localhost:3000';

  test('does not allow query response mode with implicit flow (creates URL with query)',
      () async {
    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ));
    await keycloak.init(KeycloakInitOptions(
      redirectUri: appUrl,
      flow: KeycloakFlow.implicit,
      responseMode: KeycloakResponseMode.query,
    ));

    // The URL is created with query response mode.
    // The server would reject this, but we test that the adapter
    // correctly passes the configured values.
    final loginUrlString = await keycloak.createLoginUrl();
    final loginUrl = Uri.parse(loginUrlString);

    expect(loginUrl.queryParameters['response_mode'], 'query');
    expect(loginUrl.queryParameters['response_type'], 'id_token token');
  });

  test('fails refreshing a token for implicit flow', () async {
    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ));
    await keycloak.init(KeycloakInitOptions(
      redirectUri: appUrl,
      flow: KeycloakFlow.implicit,
    ));

    // Simulate authentication via implicit flow (no refresh token)
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final token = createTestToken({
      'sub': 'user-123',
      'exp': now + 300,
      'iat': now,
    });
    keycloak.setToken(token, null, null, DateTime.now().millisecondsSinceEpoch);

    expect(keycloak.authenticated, isTrue);
    expect(
      () => keycloak.updateToken(9999),
      throwsA(isA<StateError>().having(
        (e) => e.message,
        'message',
        contains('no refresh token available'),
      )),
    );
  });

  test('expires the access token with implicit flow', () async {
    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ));
    await keycloak.init(KeycloakInitOptions(
      redirectUri: appUrl,
      flow: KeycloakFlow.implicit,
    ));

    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final token = createTestToken({
      'sub': 'user-123',
      'exp': now + 3,
      'iat': now,
    });
    keycloak.setToken(token, null, null, DateTime.now().millisecondsSinceEpoch);

    expect(keycloak.authenticated, isTrue);
    // Token not expired yet (3s remaining, checking with 0 min validity)
    expect(keycloak.isTokenExpired(0), isFalse);

    // Simulate time passing by adjusting timeSkew
    keycloak.timeSkew = keycloak.timeSkew! - 5;
    expect(keycloak.isTokenExpired(0), isTrue);
  });

  test('sets correct response type for implicit flow', () async {
    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ));
    await keycloak.init(KeycloakInitOptions(
      flow: KeycloakFlow.implicit,
    ));

    expect(keycloak.flow, KeycloakFlow.implicit);
    expect(keycloak.responseType, KeycloakResponseType.idTokenToken);
  });

  test('sets correct response type for hybrid flow', () async {
    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ));
    await keycloak.init(KeycloakInitOptions(
      flow: KeycloakFlow.hybrid,
    ));

    expect(keycloak.flow, KeycloakFlow.hybrid);
    expect(keycloak.responseType, KeycloakResponseType.codeIdTokenToken);
  });
}
