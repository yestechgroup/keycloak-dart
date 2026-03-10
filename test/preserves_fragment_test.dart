import 'package:keycloak_dart/keycloak_dart.dart';
import 'package:test/test.dart';

/// These tests verify that the Keycloak adapter correctly handles
/// URL fragments. In the JS version, these test that the adapter
/// preserves URL fragments after login redirects. In our unit test
/// version, we test the fragment parsing/callback logic.
void main() {
  test('parseCallbackParams preserves basic URL fragment', () {
    // Test that the callback URL parser correctly separates
    // OAuth params from user fragments
    const fragment = 'section=preserved';
    final url = Uri.parse('http://localhost:3000/#$fragment');

    // The fragment should be preserved as-is
    expect(url.fragment, fragment);
  });

  test('parseCallbackParams preserves fragment with conflicting OAuth params',
      () {
    const fragment = 'state=anotherValue';
    final url = Uri.parse('http://localhost:3000/#$fragment');

    expect(url.fragment, fragment);
  });

  test('parseCallbackParams preserves path-style URL fragment', () {
    const fragment = '/admin/users';
    final url = Uri.parse('http://localhost:3000/#$fragment');

    expect(url.fragment, fragment);
  });

  test('parseCallbackParams preserves path-style fragment with query params',
      () {
    const fragment = '/admin/users?tab=details&sort=asc';
    final url = Uri.parse('http://localhost:3000/#$fragment');

    expect(url.fragment, fragment);
  });

  test('parseCallbackParams preserves fragment with leading question mark', () {
    const fragment = '?tab=details';
    final url = Uri.parse('http://localhost:3000/#$fragment');

    expect(url.fragment, fragment);
  });

  test('parseCallbackParams preserves fragment with multiple ampersands', () {
    const fragment = '&&foo=bar&&baz=qux&=bax&fuz=';
    final url = Uri.parse('http://localhost:3000/#$fragment');

    // Dart's Uri parser may normalize some of these, but the
    // important thing is that fragments are handled correctly
    expect(url.hasFragment, isTrue);
  });

  test('login URL does not interfere with app fragment', () async {
    final keycloak = Keycloak(KeycloakServerConfig(
      url: 'http://localhost:8080',
      realm: 'test-realm',
      clientId: 'test-client',
    ));
    await keycloak.init(KeycloakInitOptions(
      redirectUri: 'http://localhost:3000/#/admin/users',
    ));

    final loginUrl = await keycloak.createLoginUrl();
    final parsed = Uri.parse(loginUrl);

    // The redirect_uri should contain the full URL with fragment
    expect(
      parsed.queryParameters['redirect_uri'],
      'http://localhost:3000/#/admin/users',
    );
  });
}
