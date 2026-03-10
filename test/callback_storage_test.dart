import 'package:keycloak_dart/keycloak_dart.dart';
import 'package:test/test.dart';

void main() {
  test('InMemoryCallbackStorage stores and retrieves state', () {
    final storage = InMemoryCallbackStorage();

    const state = CallbackState(
      state: 'test-state',
      nonce: 'test-nonce',
      redirectUri: 'http://localhost:3000',
    );

    storage.add(state);

    final result = storage.get('test-state');
    expect(result, isNotNull);
    expect(result!.state, 'test-state');
    expect(result.nonce, 'test-nonce');
    expect(result.redirectUri, 'http://localhost:3000');
  });

  test('InMemoryCallbackStorage returns null for unknown state', () {
    final storage = InMemoryCallbackStorage();
    expect(storage.get('unknown'), isNull);
  });

  test('InMemoryCallbackStorage returns null for null state', () {
    final storage = InMemoryCallbackStorage();
    expect(storage.get(null), isNull);
  });

  test('InMemoryCallbackStorage removes state after retrieval', () {
    final storage = InMemoryCallbackStorage();

    const state = CallbackState(
      state: 'test-state',
      nonce: 'test-nonce',
      redirectUri: 'http://localhost:3000',
    );

    storage.add(state);

    // First get removes it
    expect(storage.get('test-state'), isNotNull);
    // Second get returns null
    expect(storage.get('test-state'), isNull);
  });

  test('InMemoryCallbackStorage expires entries after TTL', () async {
    final storage = InMemoryCallbackStorage(
      ttl: const Duration(milliseconds: 50),
    );

    const state = CallbackState(
      state: 'expiring-state',
      nonce: 'test-nonce',
      redirectUri: 'http://localhost:3000',
    );

    storage.add(state);

    // Should be available immediately
    // Don't consume it — add again
    storage.add(state);

    // Wait for expiry
    await Future<void>.delayed(const Duration(milliseconds: 100));

    expect(storage.get('expiring-state'), isNull);
  });

  test('InMemoryCallbackStorage stores PKCE code verifier', () {
    final storage = InMemoryCallbackStorage();

    const state = CallbackState(
      state: 'pkce-state',
      nonce: 'test-nonce',
      redirectUri: 'http://localhost:3000',
      pkceCodeVerifier: 'test-verifier-abc123',
    );

    storage.add(state);

    final result = storage.get('pkce-state');
    expect(result, isNotNull);
    expect(result!.pkceCodeVerifier, 'test-verifier-abc123');
  });

  test('InMemoryCallbackStorage stores login options', () {
    final storage = InMemoryCallbackStorage();

    const state = CallbackState(
      state: 'options-state',
      nonce: 'test-nonce',
      redirectUri: 'http://localhost:3000',
      loginOptions: KeycloakLoginOptions(scope: 'openid profile'),
      prompt: 'login',
    );

    storage.add(state);

    final result = storage.get('options-state');
    expect(result, isNotNull);
    expect(result!.loginOptions!.scope, 'openid profile');
    expect(result.prompt, 'login');
  });
}
