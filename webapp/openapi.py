"""Hand-written OpenAPI 3.0 spec + Swagger UI page for /admin/api/*.

FastAPI would generate this for free, but Starlette was chosen over it to
avoid adding a dependency for a handful of admin routes (see webapp/asgi.py).
Swagger UI is loaded from a CDN rather than bundled, matching the "no
separate frontend build step" constraint the rest of webapp/ follows.

Not documented here: /mcp/* -- that's raw MCP JSON-RPC over streamable HTTP,
not a REST surface, so it isn't Swagger-shaped.
"""

from __future__ import annotations

OPENAPI_SPEC = {
    "openapi": "3.0.3",
    "info": {
        "title": "MCP M365 Admin API",
        "version": "1.0.0",
        "description": (
            "Manage per-agent client secrets for the /mcp surface. Protected by "
            "Easy Auth (Entra SSO) -- sign in via /admin in this browser first, "
            "then 'Try it out' below reuses that session cookie automatically."
        ),
    },
    "paths": {
        "/admin/api/secrets": {
            "get": {
                "summary": "List client secrets",
                "responses": {
                    "200": {
                        "description": "OK",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {"$ref": "#/components/schemas/SecretRecord"},
                                }
                            }
                        },
                    }
                },
            },
            "post": {
                "summary": "Create a client secret",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {"schema": {"$ref": "#/components/schemas/CreateSecretRequest"}}
                    },
                },
                "responses": {
                    "200": {
                        "description": "Created -- the token is shown only once, here and nowhere else",
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/CreateSecretResponse"}}
                        },
                    },
                    "400": {"description": "label is required"},
                },
            },
        },
        "/admin/api/secrets/{key_id}/revoke": {
            "post": {
                "summary": "Revoke a client secret",
                "parameters": [
                    {"name": "key_id", "in": "path", "required": True, "schema": {"type": "string"}}
                ],
                "responses": {"200": {"description": "OK"}},
            }
        },
        "/admin/api/tools": {
            "get": {
                "summary": "List every tool name available to scope a secret to",
                "responses": {
                    "200": {
                        "description": "OK",
                        "content": {
                            "application/json": {"schema": {"type": "array", "items": {"type": "string"}}}
                        },
                    }
                },
            }
        },
    },
    "components": {
        "schemas": {
            "SecretRecord": {
                "type": "object",
                "properties": {
                    "key_id": {"type": "string"},
                    "label": {"type": "string"},
                    "created_at": {"type": "string", "format": "date-time"},
                    "created_by": {"type": "string"},
                    "revoked": {"type": "boolean"},
                    "revoked_at": {"type": "string", "nullable": True},
                    "last_used_at": {"type": "string", "nullable": True},
                    "scopes": {
                        "type": "string",
                        "description": "JSON-encoded list of allowed tool names; \"[]\" means unrestricted",
                    },
                },
            },
            "CreateSecretRequest": {
                "type": "object",
                "required": ["label"],
                "properties": {
                    "label": {"type": "string", "example": "helpdesk-agent"},
                    "scopes": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Tool names to restrict this secret to. Empty/omitted = unrestricted.",
                        "example": [],
                    },
                },
            },
            "CreateSecretResponse": {
                "type": "object",
                "properties": {
                    "token": {"type": "string", "description": "Plaintext bearer token, shown only once"},
                    "record": {"$ref": "#/components/schemas/SecretRecord"},
                },
            },
        }
    },
}

SWAGGER_UI_HTML = """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>MCP M365 Admin API</title>
  <link rel="icon" type="image/png" href="/admin/static/favicon.png">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.onload = () => {
      SwaggerUIBundle({
        url: "/admin/openapi.json",
        dom_id: "#swagger-ui",
        presets: [SwaggerUIBundle.presets.apis],
      });
    };
  </script>
</body>
</html>
"""
