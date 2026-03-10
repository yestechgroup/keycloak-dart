import 'package:keycloak_dart/keycloak_dart.dart';
import 'package:test/test.dart';

void main() {
  const authServerUrl = 'http://localhost:8080';
  const realm = 'test-realm';
  const clientId = 'test-client';

  test('throws when initializing multiple times', () async {
    final keycloak = Keycloak(KeycloakServerConfig(
      url: authServerUrl,
      realm: realm,
      clientId: clientId,
    ));
    await keycloak.init();

    expect(
      () => keycloak.init(),
      throwsA(isA<StateError>().having(
        (e) => e.message,
        'message',
        contains('can only be initialized once'),
      )),
    );
  });
}
