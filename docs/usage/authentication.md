The client can be instatiated with either a username and password, a base64-encoded [HTTP Basic Access Authentication Token](https://en.wikipedia.org/wiki/Basic_access_authentication), or a Harbor JSON credentials file.

### Username and password

Username and password (titled `secret` to conform with Harbor naming schemes) can be used by instantiating the client with the `username` and `secret` parameters. This is the most straight forward method of authenticating.

```py
from harborapi import HarborAsyncClient

client = HarborAsyncClient(
    url="https://your-harbor-instance.com/api/v2.0",
    username="username",
    secret="secret"
)
```

In order to avoid hard-coding secrets in your application, you might want to consider using environment variables to store the username and password:

```py
import os
from harborapi import HarborAsyncClient

client = HarborAsyncClient(
    url="https://your-harbor-instance.com/api/v2.0",
    username=os.environ["HARBOR_USERNAME"],
    secret=os.environ["HARBOR_PASSWORD"]
)
```

### Basic access authentication aredentials

In place of `username` and `secret`, a Base64-encoded [HTTP Basic Access Authentication](https://en.wikipedia.org/wiki/Basic_access_authentication) credentials string can be used to authenticate.
This string is simply `username:secret` encoded to Base64, and as such is not any more secure than username and password authentication; it only obscures the text.

```py
from harborapi import HarborAsyncClient

client = HarborAsyncClient(
    url="https://your-harbor-instance.com/api/v2.0",
    basicauth="base64_basicauth_here",
)
```

Again, it might be pertinent to store this in your environment variables:

```py
import os
from harborapi import HarborAsyncClient

client = HarborAsyncClient(
    url="https://your-harbor-instance.com/api/v2.0",
    basicauth=os.environ["HARBOR_BASICAUTH"],
)
```

### Credentials file

When [creating Robot accounts](https://goharbor.io/docs/1.10/working-with-projects/project-configuration/create-robot-accounts/), the robot account's credentials can be exported as a JSON file. The `credentials_file` parameter takes an argument specifying the path to such a file.


```py
from harborapi import HarborAsyncClient

client = HarborAsyncClient(
    url="https://your-harbor-instance.com/api/v2.0",
    credentials_file="/path/to/file.json", # can also be Path object
)
```

For simple project-level robot accounts, using the _Robot Accounts_ tab in the web interface for a project should be sufficient. However, if you require a Robot account with privileges that go beyond the ones offered in the Web UI, such as controlling user groups and replication, managing multiple projects, starting scans, or managing the system configuration, you will need to create a system-level Robot account through the API. See [Creating Privileged Robot Accounts](creating-system-robot.md) for information about how to create system-level Robot accounts with such extended privileges using `harborapi`.
