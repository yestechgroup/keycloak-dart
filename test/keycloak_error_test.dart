import 'package:keycloak_dart/keycloak_dart.dart';
import 'package:test/test.dart';

void main() {
  test('creates KeycloakError from constructor', () {
    const error = KeycloakError(
      error: 'invalid_grant',
      errorDescription: 'Session not active',
    );

    expect(error.error, 'invalid_grant');
    expect(error.errorDescription, 'Session not active');
  });

  test('creates KeycloakError from JSON', () {
    final error = KeycloakError.fromJson({
      'error': 'unauthorized_client',
      'error_description': 'Client is not authorized',
    });

    expect(error.error, 'unauthorized_client');
    expect(error.errorDescription, 'Client is not authorized');
  });

  test('serializes KeycloakError to JSON', () {
    const error = KeycloakError(
      error: 'invalid_scope',
      errorDescription: 'Requested scope is invalid',
    );

    final json = error.toJson();
    expect(json['error'], 'invalid_scope');
    expect(json['error_description'], 'Requested scope is invalid');
  });

  test('toString includes error details', () {
    const error = KeycloakError(
      error: 'access_denied',
      errorDescription: 'Access denied',
    );

    expect(error.toString(), contains('access_denied'));
    expect(error.toString(), contains('Access denied'));
  });
}
