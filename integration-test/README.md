# Integration test (python)

The integration test is written in python, using the `pytest` module.

## Configuration

The test identity must be registered at the ubirch console / thing API in advance.

`config.json`:

```json
{
  "host": "<base URL of the UPP-signer instance under test>",
  "staticAuth": "<static auth token>",
  "testDevice": {
    "uuid": "<test identity UUID>",
    "password": "<test identity password>"
  },
  "env": "<ubirch backend environment>"
}
```

## Run integration test

  ```shell
  python3 -m venv venv && \
  . venv/bin/activate && \
  pip install -r requirements.txt && \
  pytest -v
  ```
