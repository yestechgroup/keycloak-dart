import 'package:keycloak_dart/keycloak_dart.dart';
import 'package:test/test.dart';

void main() {
  test('creates NetworkError with message', () {
    const error = NetworkError('Connection failed');

    expect(error.message, 'Connection failed');
    expect(error.statusCode, isNull);
    expect(error.responseBody, isNull);
  });

  test('creates NetworkError with status code and body', () {
    const error = NetworkError(
      'Server error',
      statusCode: 500,
      responseBody: '{"error":"internal"}',
    );

    expect(error.message, 'Server error');
    expect(error.statusCode, 500);
    expect(error.responseBody, '{"error":"internal"}');
  });

  test('toString includes message', () {
    const error = NetworkError('Timeout');

    expect(error.toString(), 'NetworkError: Timeout');
  });

  test('NetworkError is an Exception', () {
    const error = NetworkError('Test');

    expect(error, isA<Exception>());
  });
}
