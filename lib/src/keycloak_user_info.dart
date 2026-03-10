/// User info returned from the UserInfo endpoint.
class KeycloakUserInfo {
  /// The subject (user ID).
  final String sub;

  /// All claims from the userinfo response.
  final Map<String, dynamic> claims;

  const KeycloakUserInfo({
    required this.sub,
    this.claims = const {},
  });

  factory KeycloakUserInfo.fromJson(Map<String, dynamic> json) {
    return KeycloakUserInfo(
      sub: json['sub'] as String,
      claims: json,
    );
  }

  /// Access additional claims by key.
  dynamic operator [](String key) => claims[key];
}
