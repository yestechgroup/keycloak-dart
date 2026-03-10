import 'package:keycloak_dart/keycloak_dart.dart';
import 'package:test/test.dart';

void main() {
  test('creates KeycloakRedirectUriOptions with redirect URI', () {
    const options = KeycloakRedirectUriOptions(
      redirectUri: 'http://localhost:3000/callback',
    );

    expect(options.redirectUri, 'http://localhost:3000/callback');
  });

  test('creates KeycloakRedirectUriOptions without redirect URI', () {
    const options = KeycloakRedirectUriOptions();

    expect(options.redirectUri, isNull);
  });
}
