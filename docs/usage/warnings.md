# Warnings

By default, the warnings are emitted and displayed when deprecated code is called, as well as other situations where user code is _probably_ incorrect, but . This can be disabled in your application permanently by adding the following snippet to your code:

```py
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning, module="harborapi")
```

Or if you want to just disable it temporarily:

```py
import warnings

with warnings.catch_warnings():
    warnings.filterwarnings("ignore", category=DeprecationWarning, module="harborapi")
    # Your code here
```
