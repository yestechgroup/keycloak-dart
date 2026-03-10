import 'dart:convert';

/// Parsed JWT token claims.
class KeycloakTokenParsed {
  final String? iss;
  final String? sub;
  final String? aud;
  final int? exp;
  final int? iat;
  final int? authTime;
  final String? nonce;
  final String? acr;
  final String? amr;
  final String? azp;
  final String? sessionState;
  final String? sid;
  final String? scope;
  final KeycloakRolesData? realmAccess;
  final Map<String, KeycloakRolesData>? resourceAccess;
  final Map<String, dynamic> raw;

  const KeycloakTokenParsed({
    this.iss,
    this.sub,
    this.aud,
    this.exp,
    this.iat,
    this.authTime,
    this.nonce,
    this.acr,
    this.amr,
    this.azp,
    this.sessionState,
    this.sid,
    this.scope,
    this.realmAccess,
    this.resourceAccess,
    this.raw = const {},
  });

  factory KeycloakTokenParsed.fromJson(Map<String, dynamic> json) {
    Map<String, KeycloakRolesData>? resourceAccess;
    if (json['resource_access'] is Map) {
      resourceAccess = {};
      (json['resource_access'] as Map<String, dynamic>).forEach((key, value) {
        if (value is Map<String, dynamic>) {
          resourceAccess![key] = KeycloakRolesData.fromJson(value);
        }
      });
    }

    return KeycloakTokenParsed(
      iss: json['iss'] as String?,
      sub: json['sub'] as String?,
      aud: json['aud'] is String ? json['aud'] as String? : null,
      exp: json['exp'] as int?,
      iat: json['iat'] as int?,
      authTime: json['auth_time'] as int?,
      nonce: json['nonce'] as String?,
      acr: json['acr'] as String?,
      amr: json['amr'] as String?,
      azp: json['azp'] as String?,
      sessionState: json['session_state'] as String?,
      sid: json['sid'] as String?,
      scope: json['scope'] as String?,
      realmAccess: json['realm_access'] is Map
          ? KeycloakRolesData.fromJson(
              json['realm_access'] as Map<String, dynamic>,
            )
          : null,
      resourceAccess: resourceAccess,
      raw: json,
    );
  }

  dynamic operator [](String key) => raw[key];
}

/// Role data container.
class KeycloakRolesData {
  final List<String> roles;

  const KeycloakRolesData({required this.roles});

  factory KeycloakRolesData.fromJson(Map<String, dynamic> json) {
    return KeycloakRolesData(
      roles: (json['roles'] as List<dynamic>).cast<String>(),
    );
  }
}

/// Decode a JWT token string into its parsed representation.
KeycloakTokenParsed decodeToken(String token) {
  final parts = token.split('.');
  if (parts.length < 2) {
    throw Exception('Unable to decode token, payload not found.');
  }

  final payload = parts[1];
  String decoded;

  try {
    decoded = _base64UrlDecode(payload);
  } catch (e) {
    throw Exception(
      'Unable to decode token, payload is not a valid Base64URL value.',
    );
  }

  try {
    final json = jsonDecode(decoded) as Map<String, dynamic>;
    return KeycloakTokenParsed.fromJson(json);
  } catch (e) {
    throw Exception(
      'Unable to decode token, payload is not a valid JSON value.',
    );
  }
}

String _base64UrlDecode(String input) {
  String output = input.replaceAll('-', '+').replaceAll('_', '/');

  switch (output.length % 4) {
    case 0:
      break;
    case 2:
      output += '==';
      break;
    case 3:
      output += '=';
      break;
    default:
      throw Exception('Input is not of the correct length.');
  }

  final bytes = base64Decode(output);
  return utf8.decode(bytes);
}
