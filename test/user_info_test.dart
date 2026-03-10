import 'package:keycloak_dart/keycloak_dart.dart';
import 'package:test/test.dart';

void main() {
  const authServerUrl = 'http://localhost:8080';
  const realm = 'test-realm';
  const clientId = 'test-client';
  const appUrl = 'http://localhost:3000';

  test('throws loading user info when not authenticated', () async {
    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ));
    await keycloak.init(KeycloakInitOptions(redirectUri: appUrl));

    expect(
      () => keycloak.loadUserInfo(),
      throwsA(isA<StateError>().having(
        (e) => e.message,
        'message',
        contains('token is not set'),
      )),
    );
  });
}
