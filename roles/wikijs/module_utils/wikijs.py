import json
from gql import gql, Client as InnerClient
from gql.transport.aiohttp import AIOHTTPTransport


def class_to_dict(cls, skipped: list[str]) -> dict:
    return dict(
        (key, value)
        for (key, value) in cls.__dict__.items()
        if key not in skipped
    )


class AuthenticationStrategy:
    """
    Represent authentication strategy.
    """
    key: str
    title: str
    description: str
    use_form: str
    logo: str
    website: str

    def __init__(self, data: dict) -> None:
        self.key = data["key"]
        self.title = data["title"]
        self.description = data["description"]
        self.use_form = data["useForm"]
        self.logo = data["logo"]
        self.website = data["website"]

    def to_dict(self) -> dict:
        return class_to_dict(self, [])


class AuthenticationActiveStrategy:
    """
    Represent authentication active strategy.
    """
    key: str
    strategy: AuthenticationStrategy
    order: int
    is_enabled: bool
    display_name: str
    self_registration: bool
    domain_whitelist: list[str]
    auto_enroll_groups: list[int]

    def __init__(self, data: dict) -> None:
        self.key = data["key"]
        self.strategy = AuthenticationStrategy(data["strategy"])
        self.order = data["order"]
        self.is_enabled = data["isEnabled"]
        self.display_name = data["displayName"]
        self.self_registration = data["selfRegistration"]
        self.domain_whitelist = data["domainWhitelist"]
        self.auto_enroll_groups = data["autoEnrollGroups"]

    def to_dict(self) -> dict:
        res = class_to_dict(self, ["strategy"])
        res["strategy"] = self.strategy.to_dict()
        return res


class Client:
    __inner: InnerClient

    def __init__(self, url: str, username: str, password: str) -> None:
        """
        Creates new authenticated WikiJS client.
        """
        jwt = self.__get_access_token(url, username, password)

        transport = AIOHTTPTransport(url=url, headers={
            "Authorization": f"Bearer {jwt}",
        })

        self.__inner = InnerClient(transport=transport,
                                   fetch_schema_from_transport=True)

    def __get_access_token(self, url: str, username: str, password: str) -> str:
        """
        Obtain access token from the WikiJS.
        """
        transport = AIOHTTPTransport(url=url)

        # Create temporary client for obtaining JWT access token.
        client = InnerClient(transport=transport,
                             fetch_schema_from_transport=True)

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
        return result['authentication']['login']['jwt']

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
    }
  }
}
"""
        )
        data = self.__inner.execute(query)

        result = []
        for raw in data["authentication"]["activeStrategies"]:
            result.append(AuthenticationActiveStrategy(raw))
        return result
