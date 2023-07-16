"""
WikiJS utils.

Hold all necessary class adn function for communicate with WikiJS API.
"""

# -*- coding: utf-8 -*-

from __future__ import annotations
import json
import copy
from gql import gql, Client as InnerClient
from gql.transport.aiohttp import AIOHTTPTransport


def class_to_dict(cls, skipped: list[str]) -> dict:
    """
    Extracts all fields form class and create a dictionary.
    """
    return {
        to_lower_camel_case(key): value
        for (key, value) in cls.__dict__.items()
        if key not in skipped
    }


def to_camel_case(s: str) -> str:
    return "".join(x.capitalize() for x in s.lower().split("_"))


def to_lower_camel_case(s: str) -> str:
    # We capitalize the first letter of each component except the first one
    # with the 'capitalize' method and join them together.
    camel_string = to_camel_case(s)
    return s[0].lower() + camel_string[1:]


def sort(s: list, key: None = None) -> list:
    tmp = copy.deepcopy(s)
    tmp.sort(key=key)
    return tmp


class DTO:
    """
    Base class for all DTOs.
    """

    def to_dict(self: DTO) -> dict:
        """
        Converts this class to dictionary.
        """
        return class_to_dict(self, [])


class KeyValuePair(DTO):
    """
    Represents some key-value pair.
    """

    key: str
    value: str

    def __init__(self, key: str, value: str) -> KeyValuePair:
        self.key = key
        self.value = value

    @classmethod
    def from_dict(cls, data: dict) -> KeyValuePair:
        """
        Create from the dict.
        This method is used for parsing response from the API.
        """
        return cls(data["key"], data["value"])


class AuthenticationStrategy(DTO):
    """
    Represents authentication strategy.
    """

    key: str
    title: str
    description: str
    use_form: str
    logo: str
    website: str

    def __init__(
        self,
        key: str,
        title: str,
        description: str,
        use_form: str,
        logo: str,
        website: str,
    ) -> AuthenticationStrategy:
        self.key = key
        self.title = title
        self.description = description
        self.use_form = use_form
        self.logo = logo
        self.website = website

    @classmethod
    def from_dict(cls, data: dict) -> AuthenticationStrategy:
        """
        Create from the dict.
        This method is used for parsing response from the API.
        """
        return cls(
            data["key"],
            data["title"],
            data["description"],
            data["useForm"],
            data["logo"],
            data["website"],
        )


class AuthenticationStrategyInput(DTO):
    """
    Represents request payload for create new authentication strategy.
    """

    auto_enroll_groups: list[int]
    config: list[KeyValuePair]
    display_name: str
    domain_whitelist: list[str]
    is_enabled: bool
    key: str
    order: int
    self_registration: bool
    strategy_key: str

    def __init__(
        self,
        auto_enroll_groups: list[int],
        config: list[KeyValuePair],
        display_name: str,
        domain_whitelist: list[str],
        is_enabled: bool,
        key: str,
        order: int,
        self_registration: bool,
        strategy_key: str,
    ) -> AuthenticationStrategyInput:
        self.auto_enroll_groups = sort(auto_enroll_groups)
        self.config = sort(config, key=lambda cfg: cfg.key)
        self.display_name = display_name
        self.domain_whitelist = sort(domain_whitelist)
        self.is_enabled = is_enabled
        self.key = key
        self.order = order
        self.self_registration = self_registration
        self.strategy_key = strategy_key

    def to_dict(self) -> dict:
        res = class_to_dict(self, ["config"])
        res["config"] = [x.to_dict() for x in self.config]
        return res

    def __eq__(self, other: AuthenticationStrategyInput) -> bool:
        return self.to_dict() == other.to_dict()

    def __ne__(self, other: AuthenticationStrategyInput) -> bool:
        return not (self == other)


def is_authentication_strategy_inputs_diff(
    left: list[AuthenticationStrategyInput],
    right: list[AuthenticationStrategyInput],
) -> bool:
    """
    Compares two list of authentications strategies inputs and returns true if they are different.
    """
    if len(left) != len(right):
        return True

    left_dict = {x.key: x for x in left}
    right_dict = {x.key: x for x in right}

    for k in left_dict:
        if k not in right_dict:
            return True

        if left_dict[k] != right_dict[k]:
            return True
    return False


class AuthenticationActiveStrategy(DTO):
    """
    Represents authentication active strategy.
    """

    auto_enroll_groups: list[int]
    display_name: str
    domain_whitelist: list[str]
    is_enabled: bool
    key: str
    order: int
    self_registration: bool
    strategy: AuthenticationStrategy
    config: list[KeyValuePair]

    def __init__(
        self,
        auto_enroll_groups: list[int],
        config: list[KeyValuePair],
        display_name: str,
        domain_whitelist: list[str],
        is_enabled: bool,
        key: str,
        order: int,
        self_registration: bool,
        strategy: AuthenticationStrategy,
    ) -> AuthenticationActiveStrategy:
        self.auto_enroll_groups = sort(auto_enroll_groups)
        self.config = sort(config, key=lambda cfg: cfg.key)
        self.display_name = display_name
        self.domain_whitelist = sort(domain_whitelist)
        self.is_enabled = is_enabled
        self.key = key
        self.order = order
        self.self_registration = self_registration
        self.strategy = strategy

    @classmethod
    def from_dict(cls, data: dict) -> AuthenticationActiveStrategy:
        """
        Create from the dict.
        This method is used for parsing response from the API.
        """
        return cls(
            data["autoEnrollGroups"],
            [KeyValuePair.from_dict(x) for x in data["config"]],
            data["displayName"],
            data["domainWhitelist"],
            data["isEnabled"],
            data["key"],
            data["order"],
            data["selfRegistration"],
            AuthenticationStrategy.from_dict(data["strategy"]),
        )

    def to_dict(self) -> dict:
        res = class_to_dict(self, ["config", "strategy"])
        res["strategy"] = self.strategy.to_dict()
        return res

    def to_authentication_strategy_input(self) -> AuthenticationStrategyInput:
        """
        Converts active strategy to strategy input.
        """
        res = AuthenticationStrategyInput(
            self.auto_enroll_groups,
            self.__convert_config(),
            self.display_name,
            self.domain_whitelist,
            self.is_enabled,
            self.key,
            self.order,
            self.self_registration,
            self.strategy.key,
        )
        return res

    def __convert_config(self) -> list[KeyValuePair]:
        return [self.__convert_key_value_pair(x) for x in self.config]

    def __convert_key_value_pair(self, kv: KeyValuePair) -> KeyValuePair:
        val = json.loads(kv.value)

        val = {"v": val["value"]}

        return KeyValuePair(kv.key, json.dumps(val))


class UpdateListOfAuthenticationError(BaseException):
    pass


class Client:
    """
    Client for WikiJS API.
    """

    __inner: InnerClient

    def __init__(self, url: str, username: str, password: str) -> Client:
        """
        Creates new authenticated WikiJS client.
        """
        jwt = self.__get_access_token(url, username, password)

        transport = AIOHTTPTransport(
            url=url,
            headers={
                "Authorization": f"Bearer {jwt}",
            },
        )

        self.__inner = InnerClient(
            transport=transport, fetch_schema_from_transport=True
        )

    def __get_access_token(self, url: str, username: str, password: str) -> str:
        """
        Obtains access token from the WikiJS.
        """
        transport = AIOHTTPTransport(url=url)

        # Create temporary client for obtaining JWT access token.
        client = InnerClient(transport=transport, fetch_schema_from_transport=True)

        query = gql(
            """
        mutation($username: String!, $password: String!) {
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
        return result["authentication"]["login"]["jwt"]

    def get_list_of_authentications(self) -> list[AuthenticationActiveStrategy]:
        """
        Get list of exists authentications.
        """
        query = gql(
            """
{
  authentication {
    activeStrategies {
      key
      strategy {
        key
        title
        description
        useForm
        logo
        website
      }
      order
      isEnabled
      displayName
      selfRegistration
      domainWhitelist
      autoEnrollGroups
      config {
        key
        value
      }
    }
  }
}
"""
        )
        data = self.__inner.execute(query)

        data = data["authentication"]["activeStrategies"]
        return [AuthenticationActiveStrategy.from_dict(x) for x in data]

    def put_list_of_authentications(
        self, strategies: list[AuthenticationStrategyInput]
    ) -> None:
        """
        Save new list of authentications.
        """
        query = gql(
            """
mutation ($strategies: [AuthenticationStrategyInput]!) {
  authentication {
    updateStrategies(strategies: $strategies) {
      responseResult {
        succeeded
        errorCode
        slug
        message
      }
    }
  }
}
"""
        )

        variables = {
            "strategies": [x.to_dict() for x in strategies],
        }

        res = self.__inner.execute(query, variable_values=variables)

        if not isinstance(res, dict):
            raise UpdateListOfAuthenticationError("Unhandled type of response")

        res = res["authentication"]["updateStrategies"]["responseResult"]
        if not res["succeeded"]:
            raise UpdateListOfAuthenticationError(res["message"])
        return
