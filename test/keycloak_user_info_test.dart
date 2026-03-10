import 'package:keycloak_dart/keycloak_dart.dart';
import 'package:test/test.dart';

void main() {
  test('creates KeycloakUserInfo from JSON', () {
    final userInfo = KeycloakUserInfo.fromJson({
      'sub': 'user-123',
      'email': 'test@example.com',
      'name': 'Test User',
      'preferred_username': 'testuser',
    });

    expect(userInfo.sub, 'user-123');
    expect(userInfo['email'], 'test@example.com');
    expect(userInfo['name'], 'Test User');
    expect(userInfo['preferred_username'], 'testuser');
  });

  test('provides access to all claims via operator[]', () {
    final userInfo = KeycloakUserInfo.fromJson({
      'sub': 'user-456',
      'custom_claim': 'custom_value',
    });

    expect(userInfo['sub'], 'user-456');
    expect(userInfo['custom_claim'], 'custom_value');
    expect(userInfo['nonexistent'], isNull);
  });

  test('creates KeycloakUserInfo from constructor', () {
    const userInfo = KeycloakUserInfo(sub: 'user-789');

    expect(userInfo.sub, 'user-789');
    expect(userInfo.claims, isEmpty);
  });
}
