
# GPT MCP Proxy

A REST API server that provides HTTP access to Multiple Command Protocol (MCP) tools. This server acts as a bridge between HTTP clients and MCP-compliant tool servers, allowing tools to be discovered and executed via REST endpoints.
This is very useful for integrating MCP tools with custom GPT through Actions.

## Features

- List available MCP servers and their tools
- Get detailed information about specific tools
- Execute tools with custom parameters
- OpenAPI 3.1.0 specification
- Automatic public HTTPS exposure via ngrok

## Prerequisites

- Go 1.20 or later
- ngrok account and authtoken
- MCP-compliant tools

## Configuration

The server requires the following environment variables:

```bash
NGROK_AUTH_TOKEN=your_ngrok_auth_token
NGROK_DOMAIN=your_ngrok_domain
MCP_CONFIG_FILE=/path/to/mcp_settings.json  # Optional, defaults to mcp_settings.json
```

### Configuration File Format

Create an `mcp_settings.json` file with your MCP server configurations:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/Users/username/Desktop",
        "/path/to/other/allowed/dir"
      ]
    }
  }
}
```

## API Endpoints

- `GET /openapi.json` - OpenAPI specification
- `GET /mcp/servers` - List all servers and their tools
- `GET /mcp/{serverName}` - Get server details
- `GET /mcp/{serverName}/tools/{toolName}` - Get tool details
- `POST /mcp/{serverName}/tools/{toolName}/execute` - Execute a tool

## Usage

1. Set up environment variables
2. Prepare configuration file
3. Run the server:

```bash
go run main.go
```

## Development

To build from source:

```bash
git clone https://github.com/wricardo/mcp-http-server.git
cd mcp-http-server
go build
```

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
