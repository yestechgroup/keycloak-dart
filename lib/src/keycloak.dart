import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart' as crypto_lib;
import 'package:http/http.dart' as http;

import 'keycloak_adapter.dart';
import 'keycloak_config.dart';
import 'keycloak_init_options.dart';
import 'keycloak_login_options.dart';
import 'keycloak_profile.dart';
import 'keycloak_token.dart';

/// Callback storage for managing OAuth state between redirects.
class CallbackState {
  final String state;
  final String nonce;
  final String redirectUri;
  final KeycloakLoginOptions? loginOptions;
  final String? prompt;
  final String? pkceCodeVerifier;

  const CallbackState({
    required this.state,
    required this.nonce,
    required this.redirectUri,
    this.loginOptions,
    this.prompt,
    this.pkceCodeVerifier,
  });
}

/// In-memory callback storage.
class CallbackStorage {
  final Map<String, CallbackState> _storage = {};

  void add(CallbackState state) {
    _storage[state.state] = state;
  }

  CallbackState? get(String? state) {
    if (state == null) return null;
    return _storage.remove(state);
  }
}

/// Endpoints for the Keycloak server.
class Endpoints {
  final String Function() authorize;
  final String Function() token;
  final String Function() logout;
  final String Function() checkSessionIframe;
  final String Function() register;
  final String Function() userinfo;

  const Endpoints({
    required this.authorize,
    required this.token,
    required this.logout,
    required this.checkSessionIframe,
    required this.register,
    required this.userinfo,
  });
}

/// A client for the Keycloak authentication server.
class Keycloak {
  final Object _config;
  final http.Client _httpClient;

  KeycloakAdapter? _adapter;
  bool _useNonce = true;
  CallbackStorage _callbackStorage = CallbackStorage();

  bool didInitialize = false;
  bool authenticated = false;
  bool loginRequired = false;

  KeycloakResponseMode responseMode = KeycloakResponseMode.fragment;
  KeycloakResponseType responseType = KeycloakResponseType.code;
  KeycloakFlow flow = KeycloakFlow.standard;

  int? timeSkew;
  String? redirectUri;
  String? silentCheckSsoRedirectUri;
  bool silentCheckSsoFallback = true;
  KeycloakPkceMethod? pkceMethod = KeycloakPkceMethod.s256;
  bool enablePkce = true;
  bool enableLogging = false;
  String logoutMethod = 'GET';
  String? scope;
  int messageReceiveTimeout = 10000;

  String? idToken;
  KeycloakTokenParsed? idTokenParsed;
  String? token;
  KeycloakTokenParsed? tokenParsed;
  String? refreshToken;
  KeycloakTokenParsed? refreshTokenParsed;

  String? clientId;
  String? sessionId;
  String? subject;
  String? authServerUrl;
  String? realm;

  KeycloakRolesData? realmAccess;
  Map<String, KeycloakRolesData>? resourceAccess;

  KeycloakProfile? profile;
  Map<String, dynamic>? userInfo;

  Endpoints? endpoints;

  // Callbacks
  void Function(bool authenticated)? onReady;
  void Function()? onAuthSuccess;
  void Function(Map<String, String>? errorData)? onAuthError;
  void Function()? onAuthRefreshSuccess;
  void Function()? onAuthRefreshError;
  void Function()? onTokenExpired;
  void Function()? onAuthLogout;
  void Function(String status, String? action)? onActionUpdate;

  /// Creates a new Keycloak client instance.
  ///
  /// [config] must be a [KeycloakServerConfig], [GenericOidcConfig],
  /// or a [String] URL to a JSON configuration file.
  Keycloak(
    Object config, {
    http.Client? httpClient,
  })  : _config = config,
        _httpClient = httpClient ?? http.Client() {
    if (config is String) {
      // URL to JSON config - valid
    } else if (config is KeycloakServerConfig) {
      // Valid
    } else if (config is GenericOidcConfig) {
      // Valid
    } else {
      throw ArgumentError(
        "The 'Keycloak' constructor must be provided with a "
        'KeycloakServerConfig, GenericOidcConfig, or a URL string '
        'to a JSON configuration file.',
      );
    }
  }

  /// Initialize the Keycloak adapter.
  Future<bool> init([KeycloakInitOptions? initOptions]) async {
    final options = initOptions ?? const KeycloakInitOptions();

    if (didInitialize) {
      throw StateError(
        "A 'Keycloak' instance can only be initialized once.",
      );
    }

    didInitialize = true;
    _callbackStorage = CallbackStorage();

    if (options.adapter != null) {
      _adapter = options.adapter;
    } else {
      _adapter = _DefaultAdapter(this);
    }

    _useNonce = options.useNonce;

    if (options.onLoad == KeycloakOnLoad.loginRequired) {
      loginRequired = true;
    }

    if (options.responseMode != null) {
      responseMode = options.responseMode!;
    }

    if (options.flow != null) {
      switch (options.flow!) {
        case KeycloakFlow.standard:
          responseType = KeycloakResponseType.code;
          break;
        case KeycloakFlow.implicit:
          responseType = KeycloakResponseType.idTokenToken;
          break;
        case KeycloakFlow.hybrid:
          responseType = KeycloakResponseType.codeIdTokenToken;
          break;
      }
      flow = options.flow!;
    }

    if (options.timeSkew != null) {
      timeSkew = options.timeSkew;
    }

    if (options.redirectUri != null) {
      redirectUri = options.redirectUri;
    }

    if (options.silentCheckSsoRedirectUri != null) {
      silentCheckSsoRedirectUri = options.silentCheckSsoRedirectUri;
    }

    silentCheckSsoFallback = options.silentCheckSsoFallback;

    if (options.enablePkce) {
      pkceMethod = options.pkceMethod;
    } else {
      pkceMethod = null;
    }

    enableLogging = options.enableLogging;

    if (options.logoutMethod == 'POST') {
      logoutMethod = 'POST';
    }

    if (options.scope != null) {
      scope = options.scope;
    }

    if (options.messageReceiveTimeout > 0) {
      messageReceiveTimeout = options.messageReceiveTimeout;
    }

    await _loadConfig();

    onReady?.call(authenticated);

    return authenticated;
  }

  /// Redirect to login form.
  Future<void> login([KeycloakLoginOptions? options]) async {
    if (_adapter == null) {
      throw StateError('Adapter not initialized. Call init() first.');
    }
    return _adapter!.login(options);
  }

  /// Create a login URL.
  Future<String> createLoginUrl([KeycloakLoginOptions? options]) async {
    if (endpoints == null) {
      throw StateError('Endpoints not configured. Call init() first.');
    }

    final state = _createUUID();
    final nonce = _createUUID();
    final effectiveRedirectUri =
        options?.redirectUri ?? _adapter?.redirectUri() ?? redirectUri ?? '';

    final url = options?.action == 'register'
        ? endpoints!.register()
        : endpoints!.authorize();

    String? effectiveScope = options?.scope ?? scope;
    final scopeValues =
        effectiveScope != null ? effectiveScope.split(' ') : <String>[];

    if (!scopeValues.contains('openid')) {
      scopeValues.insert(0, 'openid');
    }

    effectiveScope = scopeValues.join(' ');

    final params = <String, String>{
      'client_id': clientId!,
      'redirect_uri': effectiveRedirectUri,
      'state': state,
      'response_mode': responseMode.value,
      'response_type': responseType.value,
      'scope': effectiveScope,
    };

    if (_useNonce) {
      params['nonce'] = nonce;
    }

    if (options?.prompt != null) {
      params['prompt'] = options!.prompt!;
    }

    if (options?.maxAge != null) {
      params['max_age'] = options!.maxAge.toString();
    }

    if (options?.loginHint != null) {
      params['login_hint'] = options!.loginHint!;
    }

    if (options?.idpHint != null) {
      params['kc_idp_hint'] = options!.idpHint!;
    }

    if (options?.action != null && options!.action != 'register') {
      params['kc_action'] = options.action!;
    }

    if (options?.locale != null) {
      params['ui_locales'] = options!.locale!;
    }

    if (options?.acr != null) {
      params['claims'] = _buildClaimsParameter(options!.acr!);
    }

    if (options?.acrValues != null) {
      params['acr_values'] = options!.acrValues!;
    }

    String? pkceCodeVerifier;
    if (pkceMethod != null) {
      final codeVerifier = _generateCodeVerifier(96);
      final pkceChallenge =
          await _generatePkceChallenge(pkceMethod!, codeVerifier);

      pkceCodeVerifier = codeVerifier;
      params['code_challenge'] = pkceChallenge;
      params['code_challenge_method'] = pkceMethod!.value;
    }

    final updatedCallbackState = CallbackState(
      state: state,
      nonce: nonce,
      redirectUri: effectiveRedirectUri,
      loginOptions: options,
      prompt: options?.prompt,
      pkceCodeVerifier: pkceCodeVerifier,
    );

    _callbackStorage.add(updatedCallbackState);

    final uri = Uri.parse(url).replace(queryParameters: params);
    return uri.toString();
  }

  /// Redirect to logout.
  Future<void> logout([KeycloakLogoutOptions? options]) async {
    if (_adapter == null) {
      throw StateError('Adapter not initialized. Call init() first.');
    }
    return _adapter!.logout(options);
  }

  /// Create a logout URL.
  String createLogoutUrl([KeycloakLogoutOptions? options]) {
    if (endpoints == null) {
      throw StateError('Endpoints not configured. Call init() first.');
    }

    final effectiveLogoutMethod = options?.logoutMethod ?? logoutMethod;
    final url = endpoints!.logout();

    if (effectiveLogoutMethod == 'POST') {
      return url;
    }

    final effectiveRedirectUri =
        options?.redirectUri ?? _adapter?.redirectUri() ?? redirectUri ?? '';

    final params = <String, String>{
      'client_id': clientId!,
      'post_logout_redirect_uri': effectiveRedirectUri,
    };

    if (idToken != null) {
      params['id_token_hint'] = idToken!;
    }

    final uri = Uri.parse(url).replace(queryParameters: params);
    return uri.toString();
  }

  /// Redirect to registration form.
  Future<void> register([KeycloakRegisterOptions? options]) async {
    if (_adapter == null) {
      throw StateError('Adapter not initialized. Call init() first.');
    }
    return _adapter!.register(options);
  }

  /// Create a registration URL.
  Future<String> createRegisterUrl([KeycloakRegisterOptions? options]) {
    final loginOptions = options?.toLoginOptions() ??
        const KeycloakLoginOptions(action: 'register');
    return createLoginUrl(loginOptions);
  }

  /// Create an account management URL.
  String createAccountUrl([KeycloakAccountOptions? options]) {
    final realmUrl = getRealmUrl();

    if (realmUrl == null) {
      throw StateError(
        'Unable to create account URL, make sure the adapter is not '
        'configured using a generic OIDC provider.',
      );
    }

    final effectiveRedirectUri =
        options?.redirectUri ?? _adapter?.redirectUri() ?? redirectUri ?? '';

    final params = <String, String>{
      'referrer': clientId!,
      'referrer_uri': effectiveRedirectUri,
    };

    final uri = Uri.parse('$realmUrl/account').replace(queryParameters: params);
    return uri.toString();
  }

  /// Returns true if the token has the given realm role.
  bool hasRealmRole(String role) {
    return realmAccess != null && realmAccess!.roles.contains(role);
  }

  /// Returns true if the token has the given role for the resource.
  bool hasResourceRole(String role, [String? resource]) {
    if (resourceAccess == null) return false;
    final access = resourceAccess![resource ?? clientId];
    return access != null && access.roles.contains(role);
  }

  /// Load the user's profile from the account endpoint.
  Future<KeycloakProfile> loadUserProfile() async {
    final realmUrl = getRealmUrl();

    if (realmUrl == null) {
      throw StateError(
        'Unable to load user profile, make sure the adapter is not '
        'configured using a generic OIDC provider.',
      );
    }

    if (token == null) {
      throw StateError(
        'Unable to build authorization header, token is not set, '
        'make sure the user is authenticated.',
      );
    }

    final url = '$realmUrl/account';
    final response = await _httpClient.get(
      Uri.parse(url),
      headers: {
        'Accept': 'application/json',
        'Authorization': 'bearer $token',
      },
    );

    if (response.statusCode != 200) {
      throw Exception('Failed to load user profile.');
    }

    final json = jsonDecode(response.body) as Map<String, dynamic>;
    profile = KeycloakProfile.fromJson(json);
    return profile!;
  }

  /// Load user info from the userinfo endpoint.
  Future<Map<String, dynamic>> loadUserInfo() async {
    if (endpoints == null) {
      throw StateError('Endpoints not configured. Call init() first.');
    }

    if (token == null) {
      throw StateError(
        'Unable to build authorization header, token is not set, '
        'make sure the user is authenticated.',
      );
    }

    final url = endpoints!.userinfo();
    final response = await _httpClient.get(
      Uri.parse(url),
      headers: {
        'Accept': 'application/json',
        'Authorization': 'bearer $token',
      },
    );

    if (response.statusCode != 200) {
      throw Exception('Failed to load user info.');
    }

    final json = jsonDecode(response.body) as Map<String, dynamic>;
    userInfo = json;
    return json;
  }

  /// Returns true if the token has less than [minValidity] seconds
  /// left before it expires.
  bool isTokenExpired([int minValidity = 0]) {
    if (tokenParsed == null) {
      throw StateError('Not authenticated');
    }

    if (flow != KeycloakFlow.implicit && refreshToken == null) {
      throw StateError('Not authenticated');
    }

    if (timeSkew == null) {
      return true;
    }

    if (tokenParsed!.exp == null) {
      return false;
    }

    var expiresIn = tokenParsed!.exp! -
        (DateTime.now().millisecondsSinceEpoch / 1000).ceil() +
        timeSkew!;
    expiresIn -= minValidity;
    return expiresIn < 0;
  }

  /// If the token expires within [minValidity] seconds, refresh it.
  Future<bool> updateToken([int minValidity = 5]) async {
    if (refreshToken == null) {
      throw StateError(
        'Unable to update token, no refresh token available.',
      );
    }

    if (endpoints == null) {
      throw StateError('Endpoints not configured. Call init() first.');
    }

    bool shouldRefresh = false;

    if (minValidity == -1) {
      shouldRefresh = true;
    } else if (tokenParsed == null || isTokenExpired(minValidity)) {
      shouldRefresh = true;
    }

    if (!shouldRefresh) {
      return false;
    }

    final url = endpoints!.token();
    final response = await _httpClient.post(
      Uri.parse(url),
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: {
        'grant_type': 'refresh_token',
        'refresh_token': refreshToken,
        'client_id': clientId,
      },
    );

    if (response.statusCode != 200) {
      if (response.statusCode == 400) {
        clearToken();
      }
      onAuthRefreshError?.call();
      throw Exception('Failed to refresh token.');
    }

    final json = jsonDecode(response.body) as Map<String, dynamic>;
    final timeLocal = DateTime.now().millisecondsSinceEpoch;

    setToken(
      json['access_token'] as String,
      json['refresh_token'] as String?,
      json['id_token'] as String?,
      timeLocal,
    );

    onAuthRefreshSuccess?.call();
    return true;
  }

  /// Clear authentication state.
  void clearToken() {
    if (token != null) {
      setToken();
      onAuthLogout?.call();
      if (loginRequired) {
        login();
      }
    }
  }

  /// Set the token state.
  void setToken([
    String? accessToken,
    String? newRefreshToken,
    String? newIdToken,
    int? timeLocal,
  ]) {
    if (newRefreshToken != null) {
      refreshToken = newRefreshToken;
      refreshTokenParsed = decodeToken(newRefreshToken);
    } else {
      refreshToken = null;
      refreshTokenParsed = null;
    }

    if (newIdToken != null) {
      idToken = newIdToken;
      idTokenParsed = decodeToken(newIdToken);
    } else {
      idToken = null;
      idTokenParsed = null;
    }

    if (accessToken != null) {
      token = accessToken;
      tokenParsed = decodeToken(accessToken);
      sessionId = tokenParsed!.sid;
      authenticated = true;
      subject = tokenParsed!.sub;
      realmAccess = tokenParsed!.realmAccess;
      resourceAccess = tokenParsed!.resourceAccess;

      if (timeLocal != null) {
        timeSkew =
            (timeLocal / 1000).floor() - (tokenParsed!.iat ?? 0);
      }
    } else {
      token = null;
      tokenParsed = null;
      subject = null;
      realmAccess = null;
      resourceAccess = null;
      authenticated = false;
    }
  }

  /// Get the realm URL.
  String? getRealmUrl() {
    if (authServerUrl == null) return null;
    final url = _stripTrailingSlash(authServerUrl!);
    return '$url/realms/${Uri.encodeComponent(realm!)}';
  }

  /// Load configuration from the provided config object.
  Future<void> _loadConfig() async {
    if (_config is String) {
      final response = await _httpClient.get(
        Uri.parse(_config as String),
        headers: {'Accept': 'application/json'},
      );

      if (response.statusCode != 200) {
        throw Exception('Failed to load adapter configuration.');
      }

      final json = jsonDecode(response.body) as Map<String, dynamic>;
      authServerUrl = json['auth-server-url'] as String?;
      realm = json['realm'] as String?;
      clientId = json['resource'] as String?;
      _setupEndpoints();
    } else if (_config is KeycloakServerConfig) {
      final config = _config as KeycloakServerConfig;
      clientId = config.clientId;
      authServerUrl = config.url;
      realm = config.realm;
      _setupEndpoints();
    } else if (_config is GenericOidcConfig) {
      final config = _config as GenericOidcConfig;
      clientId = config.clientId;
      await _loadOidcConfig(config.oidcProvider);
    }
  }

  void _setupEndpoints() {
    final realmUrl = getRealmUrl()!;
    endpoints = Endpoints(
      authorize: () => '$realmUrl/protocol/openid-connect/auth',
      token: () => '$realmUrl/protocol/openid-connect/token',
      logout: () => '$realmUrl/protocol/openid-connect/logout',
      checkSessionIframe: () =>
          '$realmUrl/protocol/openid-connect/login-status-iframe.html',
      register: () => '$realmUrl/protocol/openid-connect/registrations',
      userinfo: () => '$realmUrl/protocol/openid-connect/userinfo',
    );
  }

  Future<void> _loadOidcConfig(Object oidcProvider) async {
    if (oidcProvider is String) {
      final url =
          '${_stripTrailingSlash(oidcProvider)}/.well-known/openid-configuration';
      final response = await _httpClient.get(
        Uri.parse(url),
        headers: {'Accept': 'application/json'},
      );

      if (response.statusCode != 200) {
        throw Exception('Failed to load OpenID configuration.');
      }

      final json = jsonDecode(response.body) as Map<String, dynamic>;
      final metadata = OpenIdProviderMetadata.fromJson(json);
      _setupOidcEndpoints(metadata);
    } else if (oidcProvider is OpenIdProviderMetadata) {
      _setupOidcEndpoints(oidcProvider);
    }
  }

  void _setupOidcEndpoints(OpenIdProviderMetadata config) {
    endpoints = Endpoints(
      authorize: () => config.authorizationEndpoint,
      token: () => config.tokenEndpoint,
      logout: () {
        if (config.endSessionEndpoint == null) {
          throw StateError('Not supported by the OIDC server');
        }
        return config.endSessionEndpoint!;
      },
      checkSessionIframe: () {
        if (config.checkSessionIframe == null) {
          throw StateError('Not supported by the OIDC server');
        }
        return config.checkSessionIframe!;
      },
      register: () {
        throw StateError(
          'Redirection to "Register user" page not supported '
          'in standard OIDC mode',
        );
      },
      userinfo: () {
        if (config.userinfoEndpoint == null) {
          throw StateError('Not supported by the OIDC server');
        }
        return config.userinfoEndpoint!;
      },
    );
  }

  // Utility functions

  static String _createUUID() {
    final random = Random.secure();
    final bytes = List<int>.generate(16, (_) => random.nextInt(256));

    // Set version 4
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    // Set variant
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    final hex = bytes
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join();

    return '${hex.substring(0, 8)}-${hex.substring(8, 12)}-'
        '${hex.substring(12, 16)}-${hex.substring(16, 20)}-'
        '${hex.substring(20)}';
  }

  static String _buildClaimsParameter(Acr requestedAcr) {
    return jsonEncode({
      'id_token': {
        'acr': requestedAcr.toJson(),
      },
    });
  }

  static String _generateCodeVerifier(int length) {
    const alphabet =
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    final random = Random.secure();
    return String.fromCharCodes(
      List.generate(
        length,
        (_) => alphabet.codeUnitAt(random.nextInt(alphabet.length)),
      ),
    );
  }

  static Future<String> _generatePkceChallenge(
    KeycloakPkceMethod method,
    String codeVerifier,
  ) async {
    if (method != KeycloakPkceMethod.s256) {
      throw ArgumentError(
        "Invalid value for 'pkceMethod', expected 'S256'.",
      );
    }

    final bytes = utf8.encode(codeVerifier);
    final digest = crypto_lib.sha256.convert(bytes);
    final encoded = base64Url.encode(digest.bytes).replaceAll('=', '');

    return encoded;
  }

  static String _stripTrailingSlash(String url) {
    return url.endsWith('/') ? url.substring(0, url.length - 1) : url;
  }
}

/// Default adapter that stores redirect URIs without performing
/// actual browser redirects (suitable for non-browser environments).
class _DefaultAdapter implements KeycloakAdapter {
  final Keycloak _keycloak;

  _DefaultAdapter(this._keycloak);

  @override
  Future<void> login([KeycloakLoginOptions? options]) async {
    // In a real browser environment, this would redirect.
    // For non-browser usage, the URL can be obtained via createLoginUrl.
  }

  @override
  Future<void> logout([KeycloakLogoutOptions? options]) async {
    // In a real browser environment, this would redirect.
  }

  @override
  Future<void> register([KeycloakRegisterOptions? options]) async {
    // In a real browser environment, this would redirect.
  }

  @override
  Future<void> accountManagement() async {
    // In a real browser environment, this would redirect.
  }

  @override
  String redirectUri([KeycloakAccountOptions? options]) {
    return options?.redirectUri ?? _keycloak.redirectUri ?? '';
  }
}
