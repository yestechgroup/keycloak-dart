/// User profile information from the Keycloak account endpoint.
class KeycloakProfile {
  final String? id;
  final String? username;
  final String? email;
  final String? firstName;
  final String? lastName;
  final bool? enabled;
  final bool? emailVerified;
  final bool? totp;
  final int? createdTimestamp;
  final Map<String, dynamic>? attributes;

  const KeycloakProfile({
    this.id,
    this.username,
    this.email,
    this.firstName,
    this.lastName,
    this.enabled,
    this.emailVerified,
    this.totp,
    this.createdTimestamp,
    this.attributes,
  });

  factory KeycloakProfile.fromJson(Map<String, dynamic> json) {
    return KeycloakProfile(
      id: json['id'] as String?,
      username: json['username'] as String?,
      email: json['email'] as String?,
      firstName: json['firstName'] as String?,
      lastName: json['lastName'] as String?,
      enabled: json['enabled'] as bool?,
      emailVerified: json['emailVerified'] as bool?,
      totp: json['totp'] as bool?,
      createdTimestamp: json['createdTimestamp'] as int?,
      attributes: json['attributes'] as Map<String, dynamic>?,
    );
  }
}
