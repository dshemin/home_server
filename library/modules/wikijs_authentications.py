#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Dmitriy Shemin <me@shemindmitry.tech>
from __future__ import (absolute_import, division, print_function)
from ansible.module_utils.basic import AnsibleModule
from gql import gql, Client
from gql.transport.aiohttp import AIOHTTPTransport

__metaclass__ = type

DOCUMENTATION = r'''
---
module: wikijs_authentications

short_description: Manage API keys in WikiJS

version_added: "1.0.0"

description: Enable or disable API access to WikiJS and manage API keys.

options:
    endpoint:
        description: The WikiJS' API endpoint.
        required: true
        type: str
    auth_username:
        description: The username which will be used for authentication.
        required: true
        type: str
    auth_password:
        description: The password which will be used for authentication.
        required: true
        type: str
    strategies:
        description:
            - The list of required strategies.
            - Strategy uniqueness will be controlled with "key" property of each strategy.
            - All listed strategies will be created and all unlisted strategies will be removed except "local" strategy.
        type: list
        elements: dict
        suboptions:
            key:
                description: The unique strategy identifier.
                required: true
                type: str
            strategy_key:
                description: Kind of authentication mechanism.
                required: true
                type: str
                choices:
                    - auth0
                    - azure
                    - cas
                    - discord
                    - dropbox
                    - facebook
                    - github
                    - gitlab
                    - google
                    - keycloak
                    - ldap
                    - oauth2
                    - oidc
                    - okta
                    - rocketchat
                    - saml
                    - slack
                    - twitch
            name:
                description: The strategy name.
                required: true
                type: str
            allow_self_registration:
                description: Allow any user successfully authorized by the strategy to access the wiki.
                required: true
                type: bool
            limit_to_email_domain:
                description: A list of domains authorized to register. The user email address domain must match one of these to gain access.
                type: list
                elements: str
            assign_to_group:
                description: Automatically assign new users to these groups.
                type: list
                elements: int
            auth0_domain:
                description:
                    - Auth0 domain.
                    - Required only for "auth0" strategy.
                type: str
            auth0_client_id:
                description:
                    - Auth0 domain.
                    - Required only for "auth0" strategy.
                type: str
            auth0_client_secret:
                description:
                    - Application Client Secret.
                    - Required only for "auth0" strategy.
                type: str
            azure_ad:
                description:
                    - The metadata endpoint provided by the Microsoft Identity Portal that provides the keys and other important information at runtime.
                    - Required only for "azure" strategy.
                type: str
            azure_client_id:
                description:
                    - The client ID of your application in AAD (Azure Active Directory).
                    - Required only for "azure" strategy.
                type: str
            azure_cookie_encryption_key:
                description:
                    - Random string with 44-character length. Setting this enables workaround for Chrome's SameSite cookies.
                    - Required only for "azure" strategy.
                type: str
            cas_base_url:
                description:
                    - 'Base-URL of your WikiJS (for example: https://wiki.example.com).'
                    - Required only for "cas" strategy.
                type: str
            cas_server_url:
                description:
                    - 'Base-URL of the CAS server, including context path. (for example: https://login.company.com/cas).'
                    - Required only for "cas" strategy.
                type: str
            cas_version:
                description:
                    - The version of CAS to use.
                    - Required only for "cas" strategy.
                type: str
                default: "CAS3.0"
            cas_attr_key_email:
                description:
                    - Attribute key which contains the users email.
                    - Required only for "cas" strategy.
                type: str
                default: "email"
            cas_attr_key_username:
                description:
                    - Attribute key which contains the users display name (leave empty if there is none).
                    - Required only for "cas" strategy.
                type: str
            cas_attr_key_id:
                description:
                    - Attribute key which contains the unique identifier of a user. (if empty, username will be used).
                    - Required only for "cas" strategy.
                type: str
            discord_client_id:
                description:
                    - Application Client ID.
                    - Required only for "discord" strategy.
                type: str
            discord_client_secret:
                description:
                    - Application Client Secret.
                    - Required only for "discord" strategy.
                type: str
            discord_server_id:
                description:
                    - Optional - Your unique server identifier, such that only members are authorized.
                    - Required only for "discord" strategy.
                type: str
            dropbox_app_key:
                description:
                    - Application Client ID.
                    - Required only for "dropbox" strategy.
                type: str
            dropbox_app_secret:
                description:
                    - Application Client Secret.
                    - Required only for "dropbox" strategy.
                type: str
            facebook_app_key:
                description:
                    - Application ID.
                    - Required only for "facebook" strategy.
                type: str
            facebook_app_secret:
                description:
                    - Application Secret.
                    - Required only for "facebook" strategy.
                type: str
            github_client_id:
                description:
                    - Application Client ID.
                    - Required only for "github" strategy.
                type: str
            github_client_secret:
                description:
                    - Application Client Secret.
                    - Required only for "github" strategy.
                type: str
            github_enterprise:
                description:
                    - Enable if you're using the self-hosted GitHub Enterprise version.
                    - Required only for "github" strategy.
                type: str
            github_enterprise_domain:
                description:
                    - GitHub Enterprise Only - Domain of your installation (e.g. github.company.com).
                    - Required only for "github" strategy and when github enterprise is enabled.
                type: str
            github_enterprise_user_endpoint:
                description:
                    - GitHub Enterprise Only - Endpoint to fetch user details (e.g. https://api.github.com/user).
                    - Required only for "github" strategy and when github enterprise is enabled.
                type: str
            gitlab_client_id:
                description:
                    - Application Client ID.
                    - Required only for "gitlab" strategy.
                type: str
            gitlab_client_secret:
                description:
                    - Application Client Secret.
                    - Required only for "gitlab" strategy.
                type: str
            gitlab_base_url:
                description:
                    - For self-managed GitLab instances, define the base URL (e.g. https://gitlab.example.com). Leave default for GitLab.com SaaS (https://gitlab.com).
                    - Required only for "gitlab" strategy.
                type: str
            gitlab_authorization_url:
                description:
                    - For self-managed GitLab instances, define an alternate authorization URL (e.g. http://example.com/oauth/authorize).
                    - Required only for "gitlab" strategy.
                type: str
            gitlab_token_url:
                description:
                    - For self-managed GitLab instances, define an alternate token URL (e.g. http://example.com/oauth/token).
                    - Required only for "gitlab" strategy.
                type: str
            google_client_id:
                description:
                    - Application Client ID.
                    - Required only for "google" strategy.
                type: str
            google_client_secret:
                description:
                    - Application Client Secret.
                    - Required only for "google" strategy.
                type: str
            google_hosted_domain:
                description:
                    - (optional) Only for G Suite hosted domain.
                    - Required only for "google" strategy.
                type: str
            keycloak_host:
                description:
                    - e.g. https://your.keycloak-host.com.
                    - Required only for "keycloak" strategy.
                type: str
            keycloak_realm:
                description:
                    - The realm this application belongs to.
                    - Required only for "keycloak" strategy.
                type: str
            keycloak_client_id:
                description:
                    - Application Client ID.
                    - Required only for "keycloak" strategy.
                type: str
            keycloak_client_secret:
                description:
                    - Application Client Secret.
                    - Required only for "keycloak" strategy.
                type: str
            keycloak_authorization_endpoint:
                description:
                    - e.g. https://KEYCLOAK-HOST/auth/realms/YOUR-REALM/protocol/openid-connect/auth.
                    - Required only for "keycloak" strategy.
                type: str
            keycloak_token_endpoint:
                description:
                    - e.g. https://KEYCLOAK-HOST/auth/realms/YOUR-REALM/protocol/openid-connect/token.
                    - Required only for "keycloak" strategy.
                type: str
            keycloak_user_info_endpoint:
                description:
                    - e.g. https://KEYCLOAK-HOST/auth/realms/YOUR-REALM/protocol/openid-connect/userinfo.
                    - Required only for "keycloak" strategy.
                type: str
            keycloak_logout_from_keycloak_on_logout:
                description:
                    - Should the user be redirected to Keycloak logout mechanism upon logout.
                    - Required only for "keycloak" strategy.
                default: false
                type: bool
            keycloak_logout_endpoint:
                description:
                    - e.g. https://KEYCLOAK-HOST/auth/realms/YOUR-REALM/protocol/openid-connect/logout.
                    - Required only for "keycloak" strategy.
                type: str
            ldap_url:
                description:
                    - (e.g. ldap://serverhost:389 or ldaps://serverhost:636).
                    - Required only for "ldap" strategy.
                type: str
            ldap_admin_bind_dn:
                description:
                    - The distinguished name (dn) of the account used for binding.
                    - Required only for "ldap" strategy.
                type: str
            ldap_admin_bind_credentials:
                description:
                    - The password of the account used above for binding.
                    - Required only for "ldap" strategy.
                type: str
            ldap_search_base:
                description:
                    - The base DN from which to search for users.
                    - Required only for "ldap" strategy.
                type: str
            ldap_search_filter:
                description:
                    - The query to use to match username. {{username}} must be present and will be interpolated with the user provided username when performing the LDAP search.
                    - Required only for "ldap" strategy.
                type: str
            ldap_use_tls:
                description: Required only for "ldap" strategy.
                type: bool
                default: false
            ldap_verify_cert:
                description: Required only for "ldap" strategy.
                type: bool
                default: true
            ldap_tls_cert_path:
                description:
                    - Absolute path to the TLS certificate on the server.
                    - Required only for "ldap" strategy.
                type: str
            ldap_mapping_uid:
                description:
                    - The field storing the user unique identifier. Usually "uid" or "sAMAccountName".
                    - Required only for "ldap" strategy.
                type: str
            ldap_mapping_email:
                description:
                    - The field storing the user email. Usually "mail".
                    - Required only for "ldap" strategy.
                type: str
            ldap_mapping_name:
                description:
                    - The field storing the user display name. Usually "displayName" or "cn".
                    - Required only for "ldap" strategy.
                type: str
            ldap_mapping_avatar:
                description:
                    - The field storing the user avatar picture. Usually "jpegPhoto" or "thumbnailPhoto".
                    - Required only for "ldap" strategy.
                type: str
            ldap_map_groups:
                description:
                    - Map groups matching names from the users LDAP/Active Directory groups. Group Search Base must also be defined for this to work. Note this will remove any groups the user has that doesn't match an LDAP/Active Directory group.
                    - Required only for "ldap" strategy.
                type: bool
                default: false
            ldap_group_search_base:
                description:
                    - The base DN from which to search for groups.
                    - Required only for "ldap" strategy and when ldap_map_groups is enabled.
                type: str
            ldap_group_search_filter:
                description:
                    - LDAP search filter for groups. (member={{dn}}) will use the distinguished name of the user and will work in most cases.
                    - Required only for "ldap" strategy and when ldap_map_groups is enabled.
                type: str
            ldap_group_search_scope:
                description:
                    - How far from the Group Search Base to search for groups. sub (default) will search the entire subtree. base, will only search the Group Search Base dn. one, will search the Group Search Base dn and one additional level.
                    - Required only for "ldap" strategy and when ldap_map_groups is enabled.
                type: str
            ldap_group_dn_property:
                description:
                    - The property of user object to use in {{dn}} interpolation of Group Search Filter.
                    - Required only for "ldap" strategy and when ldap_map_groups is enabled.
                type: str
            ldap_group_mapping_name:
                description:
                    - The field that contains the name of the LDAP group to match on, usually "name" or "cn".
                    - Required only for "ldap" strategy and when ldap_map_groups is enabled.
                type: str
            oauth2_client_id:
                description:
                    - Application Client ID.
                    - Required only for "oauth2" strategy.
                type: str
            oauth2_client_secret:
                description:
                    - Application Client Secret.
                    - Required only for "oauth2" strategy.
                type: str
            oauth2_authorization_endpoint:
                description:
                    - Application Authorization Endpoint URL.
                    - Required only for "oauth2" strategy.
                type: str
            oauth2_token_endpoint:
                description:
                    - Application Token Endpoint URL.
                    - Required only for "oauth2" strategy.
                type: str
            oauth2_user_info_endpoint:
                description:
                    - User Info Endpoint URL.
                    - Required only for "oauth2" strategy.
                type: str
            oauth2_id_claim:
                description:
                    - Field containing the user ID.
                    - Required only for "oauth2" strategy.
                type: str
            oauth2_display_name_claim:
                description:
                    - Field containing user display name.
                    - Required only for "oauth2" strategy.
                type: str
            oauth2_email_claim:
                description:
                    - Field containing the user email address.
                    - Required only for "oauth2" strategy.
                type: str
            oauth2_map_groups:
                description:
                    - Map groups matching names from the groups claim value.
                    - Required only for "oauth2" strategy.
                type: bool
                default: false
            oauth2_groups_claim:
                description:
                    - Field containing the group names.
                    - Required only for "oauth2" strategy.
                type: str
            oauth2_logout_url:
                description:
                    - Logout URL on the OAuth2 provider where the user will be redirected to complete the logout process.
                    - Required only for "oauth2" strategy.
                type: str
            oauth2_scope:
                description:
                    - Application Client permission scopes.
                    - Required only for "oauth2" strategy.
                type: str
            oauth2_pass_access_token_via_get_query_to_user_info_endpoint:
                description:
                    - Pass the access token in an `access_token` parameter attached to the GET query string of the User Info Endpoint URL. Otherwise the access token will be passed in the Authorization header.
                    - Required only for "oauth2" strategy.
                type: str
            oauth2_enable_csrf:
                description:
                    - Pass a nonce state parameter during authentication to protect against CSRF attacks.
                    - Required only for "oauth2" strategy.
                type: str
            oidc_client_id:
                description:
                    - Application Client ID.
                    - Required only for "oidc" strategy.
                type: str
            oidc_client_secret:
                description:
                    - Application Client Secret.
                    - Required only for "oidc" strategy.
                type: str
            oidc_authorization_endpoint:
                description:
                    - Application Authorization Endpoint URL.
                    - Required only for "oidc" strategy.
                type: str
            oidc_token_endpoint:
                description:
                    - Application Token Endpoint URL.
                    - Required only for "oidc" strategy.
                type: str
            oidc_user_info_endpoint:
                description:
                    - User Info Endpoint URL.
                    - Required only for "oidc" strategy.
                type: str
            oidc_skip_user_profile:
                description:
                    - Skips call to the OIDC UserInfo endpoint.
                    - Required only for "oidc" strategy.
                type: str
            oidc_issuer:
                description:
                    - Issuer URL.
                    - Required only for "oidc" strategy.
                type: str
            oidc_email_claim:
                description:
                    - Field containing the email address.
                    - Required only for "oidc" strategy.
                type: str
            oidc_display_name_claim:
                description:
                    - Field containing the user display name.
                    - Required only for "oidc" strategy.
                type: str
            oidc_map_groups:
                description:
                    - Map groups matching names from the groups claim value.
                    - Required only for "oidc" strategy.
                type: bool
                default: false
            oidc_groups_claim:
                description:
                    - Field containing the group names.
                    - Required only for "oidc" strategy.
                type: str
            oidc_logout_url:
                description:
                    - Logout URL on the oidc provider where the user will be redirected to complete the logout process.
                    - Required only for "oidc" strategy.
                type: str
            okta_org_url:
                description:
                    - Okta organization URL (e.g. https://example.okta.com, https://example.oktapreview.com), found on the Developer Dashboard, in the upper right.
                    - Required only for "oidc" strategy.
                type: str
            okta_client_id:
                description:
                    - 20 chars alphanumeric string.
                    - Required only for "okta" strategy.
                type: str
            okta_client_secret:
                description:
                    - 40 chars alphanumeric string with a hyphen(s).
                    - Required only for "okta" strategy.
                type: str
            okta_idp:
                description:
                    - 20 chars alphanumeric string.
                    - Required only for "okta" strategy.
                type: str
            rocketchat_client_id:
                description:
                    - Application Client ID.
                    - Required only for "rocketchat" strategy.
                type: str
            rocketchat_client_secret:
                description:
                    - Application Client Secret.
                    - Required only for "rocketchat" strategy.
                type: str
            rocketchat_server_url:
                description:
                    - he base URL of your Rocket.chat site (e.g. https://example.rocket.chat).
                    - Required only for "rocketchat" strategy.
                type: str
            saml_entrypoint:
                description:
                    - Identity provider entrypoint (URL).
                    - Required only for "saml" strategy.
                type: str
            saml_issuer:
                description:
                    - Issuer string to supply to Identity Provider.
                    - Required only for "saml" strategy.
                type: str
            saml_audience:
                description:
                    - Expected SAML response Audience (if not provided, audience won't be verified).
                    - Required only for "saml" strategy.
                type: str
            saml_cert:
                description:
                    - Public PEM-encoded X.509 signing certificate. If the provider has multiple certificates that are valid, join them together using the | pipe symbol.
                    - Required only for "saml" strategy.
                type: str
            saml_priv_key:
                description:
                    - PEM formatted key used to sign the certificate.
                    - Required only for "saml" strategy.
                type: str
            saml_decryption_priv_key:
                description:
                    - Private key that will be used to attempt to decrypt any encrypted assertions that are received.
                    - Required only for "saml" strategy.
                type: str
            saml_signature_algorithm:
                description:
                    - Private key that will be used to attempt to decrypt any encrypted assertions that are received.
                    - Required only for "saml" strategy.
                type: str
                choices:
                    - sha1
                    - sha256
                    - sha512
            saml_digest_algorithm:
                description:
                    - Digest algorithm used to provide a digest for the signed data object.
                    - Required only for "saml" strategy.
                type: str
                choices:
                    - sha1
                    - sha256
                    - sha512
            saml_name_id_format:
                description: Required only for "saml" strategy.
                type: str
            saml_always_sign_assertion:
                description:
                    - If enabled, add WantAssertionsSigned="true" to the metadata, to specify that the IdP should always sign the assertions.
                    - Required only for "saml" strategy.
                type: bool
                default: false
            saml_accepted_clock_skew_milliseconds:
                description:
                    - Time in milliseconds of skew that is acceptable between client and server when checking OnBefore and NotOnOrAfter assertion condition validity timestamps. Setting to -1 will disable checking these conditions entirely.
                    - Required only for "saml" strategy.
                type: int
            saml_disable_requested_auth_context:
                description:
                    - If enabled, do not request a specific authentication context. This is known to help when authenticating against Active Directory (AD FS) servers.
                    - Required only for "saml" strategy.
                type: bool
                default: false
            saml_auth_context:
                description:
                    - Name identifier format to request auth context. For multiple values, join them together using the | pipe symbol.
                    - Required only for "saml" strategy.
                type: str
            saml_rac_comparison_type:
                description:
                    - Requested Authentication Context comparison type.
                    - Required only for "saml" strategy.
                type: str
                choices:
                    - exact
                    - minimum
                    - maximum
                    - better
            saml_force_initial_reauth:
                description:
                    - If enabled, the initial SAML request from the service provider specifies that the IdP should force re-authentication of the user, even if they possess a valid session.
                    - Required only for "saml" strategy.
                type: bool
                default: false
            saml_passive:
                description:
                    - If enabled, the initial SAML request from the service provider specifies that the IdP should prevent visible user interaction.
                    - Required only for "saml" strategy.
                type: bool
                default: false
            saml_provider_name:
                description:
                    - Optional human-readable name of the requester for use by the presenter's user agent or the identity provider.
                    - Required only for "saml" strategy.
                type: str
            saml_skip_request_compression:
                description:
                    - If enabled, the SAML request from the service provider won't be compressed.
                    - Required only for "saml" strategy.
                type: str
            saml_request_binding:
                description:
                    - Binding used for request authentication from IDP.
                    - Required only for "saml" strategy.
                type: str
                choices:
                    - HTTP-POST
                    - HTTP-Redirect
            saml_mapping_uid:
                description:
                    - The field storing the user unique identifier. Can be a variable name or a URI-formatted string.
                    - Required only for "saml" strategy.
                type: str
            saml_mapping_email:
                description:
                    - The field storing the user email. Can be a variable name or a URI-formatted string.
                    - Required only for "saml" strategy.
                type: str
            saml_mapping_display_name:
                description:
                    - The field storing the user display name. Can be a variable name or a URI-formatted string.
                    - Required only for "saml" strategy.
                type: str
            saml_mapping_avatar:
                description:
                    - The field storing the user avatar picture. Can be a variable name or a URI-formatted string.
                    - Required only for "saml" strategy.
                type: str
            slack_client_id:
                description:
                    - Application Client ID.
                    - Required only for "slack" strategy.
                type: str
            slack_client_secret:
                description:
                    - Application Client Secret.
                    - Required only for "slack" strategy.
                type: str
            slack_workspace_id:
                description:
                    - Your unique team (workspace) identifier.
                    - Required only for "slack" strategy.
                type: str
            twitch_client_id:
                description:
                    - Application Client ID.
                    - Required only for "twitch" strategy.
                type: str
            twitch_client_secret:
                description:
                    - Application Client Secret.
                    - Required only for "twitch" strategy.
                type: str

author:
    - Dmitry Shemin (@dshemin)
'''

EXAMPLES = r'''
# Pass in a message
- name: Test with a message
  my_namespace.my_collection.my_test:
    name: hello world

# pass in a message and have changed true
- name: Test with a message and changed output
  my_namespace.my_collection.my_test:
    name: hello world
    new: true

# fail the module
- name: Test failure of the module
  my_namespace.my_collection.my_test:
    name: fail me
'''

RETURN = r'''
# These are examples of possible return values, and in general should use other names for return values.
original_message:
    description: The original name param that was passed in.
    type: str
    returned: always
    sample: 'hello world'
message:
    description: The output message that the test module generates.
    type: str
    returned: always
    sample: 'goodbye'
'''


def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        endpoint=dict(
            type='str',
            required=True,
        ),
        auth_username=dict(
            type='str',
            required=True,
        ),
        auth_password=dict(
            type='str',
            required=True,
            no_log=True,
        ),
        strategies=dict(
            type='list',
            disposition='/strategies',
            elements='dict',
            options=dict(
                key=dict(
                    type='str',
                    required=True,
                ),
                strategyKey=dict(
                    type='str',
                    required=True,
                    choices=[
                        'auth0',
                        'azure',
                        'cas',
                        'discord',
                        'dropbox',
                        'facebook',
                        'github',
                        'gitlab',
                        'google',
                        'keycloak',
                        'ldap',
                        'oauth2',
                        'oidc',
                        'okta',
                        'rocketchat',
                        'saml',
                        'slack',
                        'twitch',
                    ],
                ),
                name=dict(
                    type='str',
                    required=True,
                ),
                allow_self_registration=dict(
                    type='bool',
                    required=True,
                    default=False,
                ),
                limit_to_email_domain=dict(
                    type='list',
                    elements='str',
                ),
                assign_to_group=dict(
                    type='list',
                    elements='int',
                ),
                auth0_domain=dict(
                    type='str',
                ),
                auth0_client_id=dict(
                    type='str',
                ),
                auth0_client_secret=dict(
                    type='str',
                ),
                azure_ad=dict(
                    type='str',
                ),
                azure_client_id=dict(
                    type='str',
                ),
                azure_cookie_encryption_key=dict(
                    type='str',
                ),
                cas_base_url=dict(
                    type='str',
                ),
                cas_server_url=dict(
                    type='str',
                ),
                cas_version=dict(
                    type='str',
                    default='CAS3.0',
                ),
                cas_attr_key_email=dict(
                    type='str',
                    default='email',
                ),
                cas_attr_key_username=dict(
                    type='str',
                ),
                cas_attr_key_id=dict(
                    type='str',
                ),
                discord_client_id=dict(
                    type='str',
                ),
                discord_client_secret=dict(
                    type='str',
                ),
                discord_server_id=dict(
                    type='str',
                ),
                dropbox_app_key=dict(
                    type='str',
                ),
                dropbox_app_secret=dict(
                    type='str',
                ),
                facebook_app_key=dict(
                    type='str',
                ),
                facebook_app_secret=dict(
                    type='str',
                ),
                github_client_id=dict(
                    type='str',
                ),
                github_client_secret=dict(
                    type='str',
                ),
                github_enterprise=dict(
                    type='str',
                ),
                github_enterprise_domain=dict(
                    type='str',
                ),
                github_enterprise_user_endpoint=dict(
                    type='str',
                ),
                gitlab_client_id=dict(
                    type='str',
                ),
                gitlab_client_secret=dict(
                    type='str',
                ),
                gitlab_base_url=dict(
                    type='str',
                ),
                gitlab_authorization_url=dict(
                    type='str',
                ),
                gitlab_token_url=dict(
                    type='str',
                ),
                google_client_id=dict(
                    type='str',
                ),
                google_client_secret=dict(
                    type='str',
                ),
                google_hosted_domain=dict(
                    type='str',
                ),
                keycloak_host=dict(
                    type='str',
                ),
                keycloak_realm=dict(
                    type='str',
                ),
                keycloak_client_id=dict(
                    type='str',
                ),
                keycloak_client_secret=dict(
                    type='str',
                ),
                keycloak_authorization_endpoint=dict(
                    type='str',
                ),
                keycloak_token_endpoint=dict(
                    type='str',
                ),
                keycloak_user_info_endpoint=dict(
                    type='str',
                ),
                keycloak_logout_from_keycloak_on_logout=dict(
                    type='bool',
                    default=False,
                ),
                keycloak_logout_endpoint=dict(
                    type='str',
                ),
                ldap_url=dict(
                    type='str',
                ),
                ldap_admin_bind_dn=dict(
                    type='str',
                ),
                ldap_admin_bind_credentials=dict(
                    type='str',
                ),
                ldap_search_base=dict(
                    type='str',
                ),
                ldap_search_filter=dict(
                    type='str',
                ),
                ldap_use_tls=dict(
                    type='bool',
                    default=False,
                ),
                ldap_verify_cert=dict(
                    type='bool',
                    default=True,
                ),
                ldap_tls_cert_path=dict(
                    type='str',
                ),
                ldap_mapping_uid=dict(
                    type='str',
                ),
                ldap_mapping_email=dict(
                    type='str',
                ),
                ldap_mapping_name=dict(
                    type='str',
                ),
                ldap_mapping_avatar=dict(
                    type='str',
                ),
                ldap_map_groups=dict(
                    type='bool',
                    default=False,
                ),
                ldap_group_search_base=dict(
                    type='str',
                ),
                ldap_group_search_filter=dict(
                    type='str',
                ),
                ldap_group_search_scope=dict(
                    type='str',
                ),
                ldap_group_dn_property=dict(
                    type='str',
                ),
                ldap_group_mapping_name=dict(
                    type='str',
                ),
                oauth2_client_id=dict(
                    type='str',
                ),
                oauth2_client_secret=dict(
                    type='str',
                ),
                oauth2_authorization_endpoint=dict(
                    type='str',
                ),
                oauth2_token_endpoint=dict(
                    type='str',
                ),
                oauth2_user_info_endpoint=dict(
                    type='str',
                ),
                oauth2_id_claim=dict(
                    type='str',
                ),
                oauth2_display_name_claim=dict(
                    type='str',
                ),
                oauth2_email_claim=dict(
                    type='str',
                ),
                oauth2_map_groups=dict(
                    type='bool',
                    default=False,
                ),
                oauth2_groups_claim=dict(
                    type='str',
                ),
                oauth2_logout_url=dict(
                    type='str',
                ),
                oauth2_scope=dict(
                    type='str',
                ),
                oauth2_pass_access_token_via_get_query_to_user_info_endpoint=dict(
                    type='str',
                ),
                oauth2_enable_csrf=dict(
                    type='str',
                ),
                oidc_client_id=dict(
                    type='str',
                ),
                oidc_client_secret=dict(
                    type='str',
                ),
                oidc_authorization_endpoint=dict(
                    type='str',
                ),
                oidc_token_endpoint=dict(
                    type='str',
                ),
                oidc_user_info_endpoint=dict(
                    type='str',
                ),
                oidc_skip_user_profile=dict(
                    type='str',
                ),
                oidc_issuer=dict(
                    type='str',
                ),
                oidc_email_claim=dict(
                    type='str',
                ),
                oidc_display_name_claim=dict(
                    type='str',
                ),
                oidc_map_groups=dict(
                    type='bool',
                    default=False,
                ),
                oidc_groups_claim=dict(
                    type='str',
                ),
                oidc_logout_url=dict(
                    type='str',
                ),
                okta_org_url=dict(
                    type='str',
                ),
                okta_client_id=dict(
                    type='str',
                ),
                okta_client_secret=dict(
                    type='str',
                ),
                okta_idp=dict(
                    type='str',
                ),
                rocketchat_client_id=dict(
                    type='str',
                ),
                rocketchat_client_secret=dict(
                    type='str',
                ),
                rocketchat_server_url=dict(
                    type='str',
                ),
                saml_entrypoint=dict(
                    type='str',
                ),
                saml_issuer=dict(
                    type='str',
                ),
                saml_audience=dict(
                    type='str',
                ),
                saml_cert=dict(
                    type='str',
                ),
                saml_priv_key=dict(
                    type='str',
                ),
                saml_decryption_priv_key=dict(
                    type='str',
                ),
                saml_signature_algorithm=dict(
                    type='str',
                    choices=['sha1', 'sha256', 'sha512'],
                ),
                saml_digest_algorithm=dict(
                    type='str',
                    choices=['sha1', 'sha256', 'sha512'],
                ),
                saml_name_id_format=dict(
                    type='str',
                ),
                saml_always_sign_assertion=dict(
                    type='bool',
                    default=False,
                ),
                saml_accepted_clock_skew_milliseconds=dict(
                    type='int'
                ),
                saml_disable_requested_auth_context=dict(
                    type='bool',
                    default=False,
                ),
                saml_auth_context=dict(
                    type='str',
                ),
                saml_rac_comparison_type=dict(
                    type='str',
                    choices=['exact', 'minimum', 'maximum', 'better']
                ),
                saml_force_initial_reauth=dict(
                    type='bool',
                    default=False,
                ),
                saml_passive=dict(
                    type='bool',
                    default=False,
                ),
                saml_provider_name=dict(
                    type='str',
                ),
                saml_skip_request_compression=dict(
                    type='str',
                ),
                saml_request_binding=dict(
                    type='str',
                    choices=['HTTP-POST', 'HTTP-Redirect'],
                ),
                saml_mapping_uid=dict(
                    type='str',
                ),
                saml_mapping_email=dict(
                    type='str',
                ),
                saml_mapping_display_name=dict(
                    type='str',
                ),
                saml_mapping_avatar=dict(
                    type='str',
                ),
                slack_client_id=dict(
                    type='str',
                ),
                slack_client_secret=dict(
                    type='str',
                ),
                slack_workspace_id=dict(
                    type='str',
                ),
                twitch_client_id=dict(
                    type='str',
                ),
                twitch_client_secret=dict(
                    type='str',
                ),
            ),
        ),
    )

    result = dict(
        changed=False,
        original_message='',
        message=''
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    if module.check_mode:
        module.exit_json(**result)

    client = setup_client(
        module.params['endpoint'],
        module.params['auth_username'],
        module.params['auth_password'],
    )

    module.exit_json(**result)


def setup_client(url: str, username: str, password: str) -> Client:
    transport = AIOHTTPTransport(url=url)

    # Create temporary client for obtaining JWT access token.
    client = Client(transport=transport, fetch_schema_from_transport=True)

    query = gql(
        """
mutation ($username: String!, $password: String!) {
  authentication {
    login(username: $username, password: $password, strategy: "local") {
      jwt
    }
  }
}
"""
    )

    variables = {
        "username": username,
        "password": password,
    }

    result = client.execute(query, variable_values=variables)
    jwt = result['authentication']['login']['jwt']

    # Create a "real" client with necessary headers.

    transport = AIOHTTPTransport(url=url, headers={
        "Authorization": 'Bearer {}'.format(jwt),
    })
    return Client(transport=transport, fetch_schema_from_transport=True)


def main():
    run_module()


if __name__ == '__main__':
    main()
