The client can be instatiated with either a username and password, a base64-encoded [HTTP Basic Access Authentication](https://en.wikipedia.org/wiki/Basic_access_authentication) credential string, or Harbor JSON credentials file.

### Username and password

Username and password (titled `secret` to conform with Harbor naming schemes) can be used by instantiating the client with the `username` and `secret` parameters. This is the most straight forward method of authenticating.

```py title="user_pw.py"
from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)
```

### Basic access authentication aredentials

In place of `username` and `secret`, a Base64-encoded [HTTP Basic Access Authentication](https://en.wikipedia.org/wiki/Basic_access_authentication) credentials string can be used to authenticate.
This string is simply `username:secret` encoded to Base64, and as such provides no stronger security than username and password authentication; it only obscures the text.

```py title="base64_credentials.py"
from harborapi import HarborAsyncClient

client = HarborAsyncClient(
    url="https://your-harbor-instance.com/api/v2.0",
    credentials="base64_string_here",
)
```

### Credentials file

When [creating Robot accounts](https://goharbor.io/docs/1.10/working-with-projects/project-configuration/create-robot-accounts/), the robot account's credentials can be exported as a JSON file. The `credentials_file` parameter takes an argument specifying the path to such a file.


```py title="credentials_file.py"
from harborapi import HarborAsyncClient

client = HarborAsyncClient(
    url="https://your-harbor-instance.com/api/v2.0",
    credentials_file="/path/to/file.json",
)
```

See [Creating Privileged Robot Accounts](creating-system-robot.md) for information about how to create Robot accounts with extended privileges using `harborapi`.
