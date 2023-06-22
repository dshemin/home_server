from gql import gql, Client
from gql.transport.aiohttp import AIOHTTPTransport


class WikiJSClient:
    __url: str
    __inner: Client

    def __init__(self, url: str, username: str, password: str) -> None:
        """
        Creates new authenticated WikiJS client.
        """
        jwt = self.__get_access_token(url, username, password)

        transport = AIOHTTPTransport(url=url, headers={
            "Authorization": f"Bearer {jwt}",
        })

        self.__url = url
        self.__inner = Client(transport=transport,
                              fetch_schema_from_transport=True)

    def __get_access_token(self, url: str, username: str, password: str) -> str:
        """
        Obtain access token from the WikiJS.
        """
        transport = AIOHTTPTransport(url=url)

        # Create temporary client for obtaining JWT access token.
        client = Client(transport=transport, fetch_schema_from_transport=True)

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
