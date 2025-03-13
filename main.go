// Package main provides an HTTP server for MCP (sulti-Tool Coordination Protocol) tools
// It exposes REST endpoints that allow listing, describing, and executing MCP tools
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/go-openapi/spec"
	"github.com/gorilla/mux"
	mcpclient "github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
	"golang.ngrok.com/ngrok"
	"golang.ngrok.com/ngrok/config"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func main() {
	// Check for required environment variables
	ngrokToken := os.Getenv("NGROK_AUTH_TOKEN")
	ngrokDomain := os.Getenv("NGROK_DOMAIN")
	if ngrokToken == "" || ngrokDomain == "" {
		log.Fatal("NGROK_AUTH_TOKEN and NGROK_DOMAIN environment variables must be set")
	}
	fmt.Println("Using ngrok domain:", ngrokDomain)
	fmt.Println("Using ngrok auth token:", ngrokToken)

	// Get config file path from environment or use default
	configFile := os.Getenv("MCP_CONFIG_FILE")
	if configFile == "" {
		log.Println("MCP_CONFIG_FILE not set, using default path")
		configFile = "mcp_settings.json"
	}

	// Load configuration from file
	cfg, err := LoadConfig(configFile)
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	// Initialize MCP servers registry and clients
	mcpServers = make(map[string]MCPServerInfo)
	clients = make(map[string]mcpclient.MCPClient)

	// Register MCP servers from config
	for name, serverConfig := range cfg.MCPServers {
		if serverConfig.Disabled {
			continue
		}
		mcpServers[name] = MCPServerInfo{
			Name:    name,
			Command: serverConfig.Command,
			Env:     convertMapToSlice(serverConfig.Env),
			Args:    serverConfig.Args,
		}
	}

	// Initialize MCP clients for each server
	for name, info := range mcpServers {
		client, err := mcpclient.NewStdioMCPClient(info.Command, info.Env, info.Args...)
		if err != nil {
			log.Fatalf("Error initializing MCP client for %s: %v", name, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_, err = client.Initialize(ctx, mcp.InitializeRequest{})
		if err != nil {
			log.Fatalf("Error initializing MCP client for %s: %v", name, err)
		}
		log.Printf("Successfully initialized MCP client for %s", name)
		clients[name] = client
	}

	// Set up HTTP routes using Gorilla Mux
	router := mux.NewRouter()
	router.HandleFunc("/", handleIndex).Methods("GET")
	router.HandleFunc("/openapi.json", handleOpenAPISpec).Methods("GET")
	router.HandleFunc("/instructions.txt", handleInstructions).Methods("GET")
	router.HandleFunc("/servers", listServersToolsHandler(mcpServers)).Methods("GET")
	router.HandleFunc("/{serverName}", describeServerHandler).Methods("GET")
	router.HandleFunc("/{serverName}/{toolName}", getToolDetailsHandler).Methods("GET")
	router.HandleFunc("/{serverName}/{toolName}", executeToolHandler).Methods("POST")

	// Start the server using ngrok for public exposure
	ctx := context.Background()
	listener, err := ngrok.Listen(ctx,
		config.HTTPEndpoint(config.WithDomain(ngrokDomain)),
		ngrok.WithAuthtokenFromEnv(),
	)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("MCP HTTP server is running at https://%s", ngrokDomain)
	err = http.Serve(listener, h2c.NewHandler(router, &http2.Server{}))
	if err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

// MCPServerInfo represents a registered MCP server configuration
type MCPServerInfo struct {
	Name    string   `json:"name"`
	Command string   `json:"command"`
	Env     []string `json:"env"`
	Args    []string `json:"args"`
}

// Global registry of MCP servers
var mcpServers map[string]MCPServerInfo

// Global map of initialized MCP clients
var clients map[string]mcpclient.MCPClient

// ToolExecutionRequest represents the payload for executing a tool
type ToolExecutionRequest struct {
	InputData string                 `json:"input_data"`
	Config    map[string]interface{} `json:"config"`
}

// describeServerHandler queries the MCP server for the details of the server and its tools
func describeServerHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serverName := vars["serverName"]

	client, ok := clients[serverName]
	if !ok {
		http.Error(w, fmt.Sprintf("MCP client not found for server: %s", serverName), http.StatusNotFound)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	listReq := mcp.ListToolsRequest{}
	listResp, err := client.ListTools(ctx, listReq)
	if err != nil {
		http.Error(w, "Error listing tools: "+err.Error(), http.StatusInternalServerError)
		return
	}

	serverInfo, ok := mcpServers[serverName]
	if !ok {
		http.Error(w, "Server info not found", http.StatusInternalServerError)
		return
	}

	// Define server description structure for response
	type ServerDescription struct {
		Server MCPServerInfo `json:"server"`
		Tools  []mcp.Tool    `json:"tools"`
	}

	serverDescription := ServerDescription{
		Server: serverInfo,
		Tools:  listResp.Tools,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(serverDescription)
}

// getToolDetailsHandler returns details for a specified tool
func getToolDetailsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serverName := vars["serverName"]
	toolName := vars["toolName"]

	client, ok := clients[serverName]
	if !ok {
		http.Error(w, fmt.Sprintf("MCP client not found for server: %s", serverName), http.StatusNotFound)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	listReq := mcp.ListToolsRequest{}
	listResp, err := client.ListTools(ctx, listReq)
	if err != nil {
		http.Error(w, "Error listing tools: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var found *mcp.Tool
	for _, tool := range listResp.Tools {
		if tool.Name == toolName {
			found = &tool
			break
		}
	}

	if found == nil {
		http.Error(w, fmt.Sprintf("Tool %s not found", toolName), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(found)
}

// executeToolHandler invokes a tool on the MCP server synchronously
func executeToolHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serverName := vars["serverName"]
	toolName := vars["toolName"]

	client, ok := clients[serverName]
	if !ok {
		http.Error(w, fmt.Sprintf("MCP client not found for server: %s", serverName), http.StatusNotFound)
		return
	}

	var args map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&args); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Use a longer timeout for tool execution
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// Build the tool call request
	callReq := mcp.CallToolRequest{
		Request: mcp.Request{
			Method: "tools/call",
		},
	}

	callReq.Params.Name = toolName
	callReq.Params.Arguments = args

	log.Printf("Tool name: %s\n", toolName)
	encoded, err := json.Marshal(args)
	if err != nil {
		log.Printf("Error encoding args: %v\n", err)
	}
	log.Printf("Args: %s\n", string(encoded))

	result, err := client.CallTool(ctx, callReq)
	// log the the request and result. Pretty.
	if err != nil {
		log.Printf("error: %v\n", err)
	}
	log.Printf("error: %v\n", err)
	if result != nil {
		if result.IsError {
			log.Println("response is an error.")

		}
		log.Println("Response:")
		for _, content := range result.Content {
			casted := content.(mcp.TextContent)
			fmt.Println(casted.Text)
		}
	}

	if err != nil {
		errorMsg := fmt.Sprintf("Error executing tool %s: %v", toolName, err)
		http.Error(w, errorMsg, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// convertMapToSlice converts a map of environment variables to a slice of strings in "key=value" format
func convertMapToSlice(envMap map[string]string) []string {
	var env []string
	for k, v := range envMap {
		env = append(env, k+"="+v)
	}
	return env
}

// listServersToolsHandler returns a handler function that lists all registered servers and their tools
func listServersToolsHandler(mcpServers map[string]MCPServerInfo) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Define structure for server tools response
		type ServerTools struct {
			Server MCPServerInfo `json:"server"`
			Tools  []mcp.Tool    `json:"tools"`
		}
		var serverToolsList []ServerTools

		for _, server := range mcpServers {
			client, ok := clients[server.Name]
			if !ok {
				continue
			}

			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()

			listReq := mcp.ListToolsRequest{}
			listResp, err := client.ListTools(ctx, listReq)
			if err != nil {
				log.Printf("Error listing tools for %s: %v", server.Name, err)
				continue
			}

			serverToolsList = append(serverToolsList, ServerTools{
				Server: server,
				Tools:  listResp.Tools,
			})
		}

		json.NewEncoder(w).Encode(serverToolsList)
	}
}

// handleOpenAPISpec generates and returns an OpenAPI specification for the server's endpoints
func handleOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	// Get the domain from environment
	domain := os.Getenv("NGROK_DOMAIN")
	if domain == "" {
		http.Error(w, "NGROK_DOMAIN environment variable not set", http.StatusInternalServerError)
		return
	}

	// Build the schema for MCPServerInfo
	mcpServerInfoSchema := spec.Schema{
		SchemaProps: spec.SchemaProps{
			Type: []string{"object"},
			Properties: map[string]spec.Schema{
				"name":    {SchemaProps: spec.SchemaProps{Type: []string{"string"}, Description: "Name of the MCP server"}},
				"command": {SchemaProps: spec.SchemaProps{Type: []string{"string"}, Description: "Command to start the MCP server"}},
				"env": {
					SchemaProps: spec.SchemaProps{
						Type: []string{"array"},
						Items: &spec.SchemaOrArray{
							Schema: &spec.Schema{SchemaProps: spec.SchemaProps{Type: []string{"string"}}},
						},
						Description: "Environment variables for the MCP server",
					},
				},
				"args": {
					SchemaProps: spec.SchemaProps{
						Type: []string{"array"},
						Items: &spec.SchemaOrArray{
							Schema: &spec.Schema{SchemaProps: spec.SchemaProps{Type: []string{"string"}}},
						},
						Description: "Command-line arguments for the MCP server",
					},
				},
			},
			Required: []string{"name", "command", "env", "args"},
		},
	}

	// Build the schema for a Tool
	toolSchema := spec.Schema{
		SchemaProps: spec.SchemaProps{
			Type: []string{"object"},
			Properties: map[string]spec.Schema{
				"name":    {SchemaProps: spec.SchemaProps{Type: []string{"string"}, Description: "Name of the tool"}},
				"command": {SchemaProps: spec.SchemaProps{Type: []string{"string"}, Description: "Command to execute the tool"}},
				"env": {
					SchemaProps: spec.SchemaProps{
						Type: []string{"array"},
						Items: &spec.SchemaOrArray{
							Schema: &spec.Schema{SchemaProps: spec.SchemaProps{Type: []string{"string"}}},
						},
						Description: "Environment variables for the tool",
					},
				},
				"args": {
					SchemaProps: spec.SchemaProps{
						Type: []string{"array"},
						Items: &spec.SchemaOrArray{
							Schema: &spec.Schema{SchemaProps: spec.SchemaProps{Type: []string{"string"}}},
						},
						Description: "Command-line arguments for the tool",
					},
				},
			},
			Description:          "Details of a tool. Additional properties may be included.",
			AdditionalProperties: &spec.SchemaOrBool{Allows: true},
		},
	}

	// ServerTools: an object with "server" and "tools"
	serverToolsSchema := spec.Schema{
		SchemaProps: spec.SchemaProps{
			Type: []string{"object"},
			Properties: map[string]spec.Schema{
				"server": mcpServerInfoSchema,
				"tools": {
					SchemaProps: spec.SchemaProps{
						Type: []string{"array"},
						Items: &spec.SchemaOrArray{
							Schema: &toolSchema,
						},
						Description: "List of tools available on this server",
					},
				},
			},
		},
	}

	// For simplicity, let ServerDescription have the same schema as ServerTools
	serverDescriptionSchema := serverToolsSchema

	// ExecuteToolResponse: an arbitrary JSON object
	executeToolResponseSchema := spec.Schema{
		SchemaProps: spec.SchemaProps{
			Type:                 []string{"object"},
			AdditionalProperties: &spec.SchemaOrBool{Allows: true},
			Description:          "Arbitrary JSON object representing the result of tool execution",
		},
	}

	// Build the Swagger spec document
	swaggerSpec := &spec.Swagger{
		VendorExtensible: spec.VendorExtensible{
			Extensions: spec.Extensions{
				"x-servers": []map[string]string{
					{"url": "https://" + domain},
				},
			},
		},
		SwaggerProps: spec.SwaggerProps{
			Swagger: "3.1.0",
			Info: &spec.Info{
				InfoProps: spec.InfoProps{
					Title:       "MCP Tools API",
					Description: "API for interacting with MCP servers to list tools, retrieve tool details, execute tools, and list registered servers.",
					Version:     "v1.0.0",
				},
			},
			Schemes: []string{"https"},
			Paths: &spec.Paths{
				Paths: map[string]spec.PathItem{
					"/servers": {
						PathItemProps: spec.PathItemProps{
							Get: &spec.Operation{
								VendorExtensible: spec.VendorExtensible{
									Extensions: spec.Extensions{
										"x-openai-inconsequential": "false",
									},
								},
								OperationProps: spec.OperationProps{
									ID:          "list_servers-tools",
									Summary:     "List registered servers with tools",
									Description: "Returns a list of registered MCP servers along with their available tools.",
									Produces:    []string{"application/json"},
									Responses: &spec.Responses{
										ResponsesProps: spec.ResponsesProps{
											StatusCodeResponses: map[int]spec.Response{
												200: {
													ResponseProps: spec.ResponseProps{
														Description: "List of registered servers with tools",
														Schema: &spec.Schema{
															SchemaProps: spec.SchemaProps{
																Type: spec.StringOrArray{"array"},
																Items: &spec.SchemaOrArray{
																	Schema: &spec.Schema{
																		SchemaProps: spec.SchemaProps{
																			Ref: spec.MustCreateRef("#/definitions/ServerTools"),
																		},
																	},
																},
															},
														},
													},
												},
											},
											Default: &spec.Response{
												ResponseProps: spec.ResponseProps{
													Description: "Error listing servers",
												},
											},
										},
									},
								},
							},
						},
					},
					"/instructions.txt": {
						PathItemProps: spec.PathItemProps{
							Get: &spec.Operation{
								VendorExtensible: spec.VendorExtensible{
									Extensions: spec.Extensions{
										"x-openai-inconsequential": "false",
									},
								},
								OperationProps: spec.OperationProps{
									ID:          "get_instructions",
									Summary:     "Get instructions",
									Description: "Returns a plain text description of all servers and their tools, with detailed usage instructions.",
									Produces:    []string{"text/plain"},
									Responses: &spec.Responses{
										ResponsesProps: spec.ResponsesProps{
											StatusCodeResponses: map[int]spec.Response{
												200: {
													ResponseProps: spec.ResponseProps{
														Description: "Plain text instructions",
														Schema: &spec.Schema{
															SchemaProps: spec.SchemaProps{
																Type: []string{"string"},
															},
														},
													},
												},
											},
											Default: &spec.Response{
												ResponseProps: spec.ResponseProps{
													Description: "Error generating instructions",
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			Definitions: map[string]spec.Schema{
				"MCPServerInfo":       mcpServerInfoSchema,
				"Tool":                toolSchema,
				"ServerTools":         serverToolsSchema,
				"ServerDescription":   serverDescriptionSchema,
				"ExecuteToolResponse": executeToolResponseSchema,
			},
		},
	}

	// Dynamically add paths per registered MCP server and its tools
	for _, server := range mcpServers {
		// Define path for describing the server
		swaggerSpec.Paths.Paths["/"+server.Name] = spec.PathItem{
			PathItemProps: spec.PathItemProps{
				Get: &spec.Operation{
					VendorExtensible: spec.VendorExtensible{
						Extensions: spec.Extensions{
							"x-openai-inconsequential": "false",
						},
					},
					OperationProps: spec.OperationProps{
						ID:          "describe_" + server.Name,
						Summary:     "Return details for MCP server " + server.Name,
						Description: "Returns details for " + server.Name + " and its tools.",
						Produces:    []string{"application/json"},
						Responses: &spec.Responses{
							ResponsesProps: spec.ResponsesProps{
								StatusCodeResponses: map[int]spec.Response{
									200: {
										ResponseProps: spec.ResponseProps{
											Description: "Server details",
											Schema: &spec.Schema{
												SchemaProps: spec.SchemaProps{
													Ref: spec.MustCreateRef("#/definitions/ServerDescription"),
												},
											},
										},
									},
								},
								Default: &spec.Response{
									ResponseProps: spec.ResponseProps{
										Description: "Error listing tools",
									},
								},
							},
						},
					},
				},
			},
		}

		client, ok := clients[server.Name]
		if !ok {
			http.Error(w, fmt.Sprintf("MCP client not found for server: %s", server.Name), http.StatusNotFound)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		listReq := mcp.ListToolsRequest{}
		listResp, err := client.ListTools(ctx, listReq)
		if err != nil {
			http.Error(w, "Error listing tools: "+err.Error(), http.StatusInternalServerError)
			return
		}

		for _, tool := range listResp.Tools {
			// IGNORE THIS TO SAVE THE NUMBER OF ENDPOINTS there is a limit on custom gpt to 30 endpoints
			if false {
				// Define path for tool details
				swaggerSpec.Paths.Paths["/"+server.Name+"/"+tool.Name] = spec.PathItem{
					PathItemProps: spec.PathItemProps{
						Get: &spec.Operation{
							VendorExtensible: spec.VendorExtensible{
								Extensions: spec.Extensions{
									"x-openai-inconsequential": "false",
								},
							},
							OperationProps: spec.OperationProps{
								ID:          "help_" + server.Name + "_" + tool.Name,
								Summary:     "Get details for " + tool.Name,
								Description: "Returns details for " + tool.Name + ".",
								Produces:    []string{"application/json"},
								Responses: &spec.Responses{
									ResponsesProps: spec.ResponsesProps{
										StatusCodeResponses: map[int]spec.Response{
											200: {
												ResponseProps: spec.ResponseProps{
													Description: "Tool details",
													Schema: &spec.Schema{
														SchemaProps: spec.SchemaProps{
															Ref: spec.MustCreateRef("#/definitions/Tool"),
														},
													},
												},
											},
										},
										Default: &spec.Response{
											ResponseProps: spec.ResponseProps{
												Description: "Error getting tool details",
											},
										},
									},
								},
							},
						},
					},
				}
			}

			// Define path for tool execution
			swaggerSpec.Paths.Paths["/"+server.Name+"/"+tool.Name] = spec.PathItem{
				PathItemProps: spec.PathItemProps{
					Post: &spec.Operation{
						VendorExtensible: spec.VendorExtensible{
							Extensions: spec.Extensions{
								"x-openai-inconsequential": "false",
							},
						},
						OperationProps: spec.OperationProps{
							ID:          server.Name + "_" + tool.Name,
							Summary:     "Execute tool " + tool.Name,
							Description: "Execute tool " + tool.Name + " with the provided parameters",
							Produces:    []string{"application/json"},
							Consumes:    []string{"application/json"},
							Parameters: func() []spec.Parameter {
								if tool.InputSchema.Properties == nil {
									return nil
								}
								return []spec.Parameter{
									{
										ParamProps: spec.ParamProps{
											Name:        "body",
											In:          "body",
											Description: "Input parameters for " + tool.Name,
											Required:    true,
											Schema: &spec.Schema{
												SchemaProps: spec.SchemaProps{
													Type:                 []string{"object"},
													AdditionalProperties: &spec.SchemaOrBool{Allows: true},
													Properties: func() spec.SchemaProperties {
														properties := make(spec.SchemaProperties)
														for name, param := range tool.InputSchema.Properties {
															properties[name] = spec.Schema{
																SchemaProps: getSchemaProps(name, param, 0),
															}
														}
														return properties
													}(),
												},
											},
										},
									},
								}
							}(),
							Responses: &spec.Responses{
								ResponsesProps: spec.ResponsesProps{
									StatusCodeResponses: map[int]spec.Response{
										200: {
											ResponseProps: spec.ResponseProps{
												Description: "Tool execution result",
												Schema: &spec.Schema{
													SchemaProps: spec.SchemaProps{
														Ref: spec.MustCreateRef("#/definitions/ExecuteToolResponse"),
													},
												},
											},
										},
									},
									Default: &spec.Response{
										ResponseProps: spec.ResponseProps{
											Description: "Error executing tool",
										},
									},
								},
							},
						},
					},
				},
			}
		}
	}

	// Marshal the spec into indented JSON
	b, err := json.MarshalIndent(swaggerSpec, "", "  ")
	if err != nil {
		http.Error(w, "Error generating spec: "+err.Error(), http.StatusInternalServerError)
		return
	}
	b = bytes.Replace(b, []byte("\"x-servers\""), []byte("\"servers\""), 1)

	// Convert the JSON into a map to modify it
	var specMap map[string]interface{}
	if err := json.Unmarshal(b, &specMap); err != nil {
		http.Error(w, "Error processing spec: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Convert parameters to requestBody for OpenAPI 3.x compliance
	paths, ok := specMap["paths"].(map[string]interface{})
	if ok {
		// Loop over all paths
		for _, pathItem := range paths {
			pathMap, ok := pathItem.(map[string]interface{})
			if !ok {
				continue
			}
			// Loop over all operations (get, post, etc.)
			for _, op := range pathMap {
				opMap, ok := op.(map[string]interface{})
				if !ok {
					continue
				}
				// Look for parameters
				if params, exists := opMap["parameters"]; exists {
					paramArray, ok := params.([]interface{})
					if !ok {
						continue
					}
					for i, param := range paramArray {
						paramMap, ok := param.(map[string]interface{})
						if !ok {
							continue
						}
						// Find the body parameter
						if in, exists := paramMap["in"]; exists && in == "body" {
							// Create a requestBody field
							opMap["requestBody"] = map[string]interface{}{
								"description": paramMap["description"],
								"required":    paramMap["required"],
								"content": map[string]interface{}{
									"application/json": map[string]interface{}{
										"schema": paramMap["schema"],
									},
								},
							}
							// Remove the body parameter from the parameters array
							paramArray = append(paramArray[:i], paramArray[i+1:]...)
							break // Assuming only one body parameter exists
						}
					}
					if len(paramArray) > 0 {
						opMap["parameters"] = paramArray
					} else {
						delete(opMap, "parameters")
					}
				}
			}
		}
	}

	// Marshal the modified spec back into JSON
	b, err = json.MarshalIndent(specMap, "", "  ")
	if err != nil {
		http.Error(w, "Error generating final spec: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

// getTypeParam extracts the type from a parameter
func getTypeParam(param interface{}) string {
	paramMap, ok := param.(string)
	if ok {
		return paramMap
	}
	if mm, ok := param.(map[string]interface{}); ok {
		if mm == nil {
			return "object"
		}
		if type_, ok := mm["type"]; ok {
			ss, ok := type_.(string)
			if ok {
				return ss
			}
		}
		return "object"
	}

	spew.Dump(param)
	log.Printf("Unrecognized parameter type: %T", param)
	return "object" // Default to object for unknown types
}

// Maximum recursion depth for schema processing
const maxSchemaDepth = 10

// getSchemaProps recursively builds schema properties for OpenAPI spec
func getSchemaProps(name string, param any, depth int) spec.SchemaProps {
	if depth > maxSchemaDepth {
		log.Printf("Warning: Schema depth exceeded for %s, limiting recursion", name)
		res := spec.SchemaProps{
			Type:  []string{"object"},
			Title: name,
		}
		res.Properties = make(map[string]spec.Schema)
		if m, ok := param.(map[string]any); ok {
			for k, v := range m {
				res.Properties[k] = spec.Schema{
					SchemaProps: getSchemaProps(k, v, depth+1),
				}
			}
		}
		return res
	}

	type_ := getTypeParam(param)
	res := spec.SchemaProps{
		Type:  []string{type_},
		Title: name,
	}

	if type_ == "object" {
		res.Properties = make(map[string]spec.Schema)
		if m, ok := param.(map[string]any); ok {
			for k, v := range m {
				res.Properties[k] = spec.Schema{
					SchemaProps: getSchemaProps(k, v, depth+1),
				}
			}
		}
	} else if type_ == "array" {
		if paramMap, ok := param.(map[string]interface{}); ok {
			if itemsVal, ok := paramMap["items"]; ok {
				res.Items = &spec.SchemaOrArray{
					Schema: &spec.Schema{
						SchemaProps: getSchemaProps(name+"_items", itemsVal, depth+1),
					},
				}
			}
		}
	}

	return res
}

// handleInstructions generates a plain text description of all servers and their tools
func handleInstructions(w http.ResponseWriter, r *http.Request) {
	var sb strings.Builder
	sb.WriteString("# Instructions\n")
	sb.WriteString("You are a helpful assistant that help the user accomplish tasks by leveraging tools to help acomplish the task, learn something, answer questions, plan, create any document.\n")
	sb.WriteString("Use the tools to obtain the information you need or ask the user. Try to approach the task step by step.\n")

	sb.WriteString("# MCP Tools Available\n\n")
	sb.WriteString("These are the available MCP tools to be called through the api:\n\n")

	// Loop through all registered servers
	for serverName, serverInfo := range mcpServers {
		sb.WriteString(fmt.Sprintf("## Server: %s\n", serverName))
		sb.WriteString(fmt.Sprintf("Command: %s\n", serverInfo.Command))

		// Get the client for this server
		client, ok := clients[serverName]
		if !ok {
			sb.WriteString("Error: Client not available for this server\n\n")
			continue
		}

		// List the tools for this server
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		listReq := mcp.ListToolsRequest{}
		listResp, err := client.ListTools(ctx, listReq)
		if err != nil {
			sb.WriteString(fmt.Sprintf("Error listing tools: %v\n\n", err))
			continue
		}

		sb.WriteString(fmt.Sprintf("\nAvailable tools (%d):\n\n", len(listResp.Tools)))

		// Loop through all tools for this server
		for _, tool := range listResp.Tools {
			sb.WriteString(fmt.Sprintf("### Tool: %s\n", tool.Name))
			sb.WriteString(fmt.Sprintf("Description: %s\n", tool.Description))

			// Add details about input schema if available
			if tool.InputSchema.Properties != nil && len(tool.InputSchema.Properties) > 0 {
				sb.WriteString("\nInput Parameters:\n")
				for paramName, paramDetails := range tool.InputSchema.Properties {
					paramType := getTypeParam(paramDetails)
					sb.WriteString(fmt.Sprintf("- %s (%s)\n", paramName, paramType))
				}
			}
			sb.WriteString("\n")
		}
		sb.WriteString("\n---\n\n")
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(sb.String()))
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`open /openapi.json to get the openapi spec to configure your custom GPT`))
}
