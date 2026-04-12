from typing import List, Dict, Any

def get_terminal_tool_definition() -> Dict[str, Any]:
    return {
        "name": "run_terminal_command",
        "description": "Execute a safe shell command on the local machine (e.g., using curl, nmap, python). Returns the stdout, stderr, and exit code. Use this to send web requests or scan targets.",
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The shell command to execute."
                },
                "timeout": {
                    "type": "integer",
                    "description": "Optional timeout in seconds (default is 60).",
                    "default": 60
                }
            },
            "required": ["command"]
        }
    }

def get_browser_tool_definitions() -> List[Dict[str, Any]]:
    return [
        {
            "name": "browser_navigate",
            "description": "Navigate the browser to a specific URL and wait for it to load.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The full URL to navigate to (e.g., http://target.com/login)."
                    }
                },
                "required": ["url"]
            }
        },
        {
            "name": "browser_get_dom",
            "description": "Get the current HTML DOM of the page.",
            "input_schema": {
                "type": "object",
                "properties": {}
            }
        },
        {
            "name": "browser_click",
            "description": "Click an element on the page using a CSS selector.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "selector": {
                        "type": "string",
                        "description": "The CSS selector to click."
                    }
                },
                "required": ["selector"]
            }
        },
        {
            "name": "browser_fill",
            "description": "Fill an input field on the page using a CSS selector.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "selector": {
                        "type": "string",
                        "description": "The CSS selector of the input field."
                    },
                    "text": {
                        "type": "string",
                        "description": "The text to type into the field."
                    }
                },
                "required": ["selector", "text"]
            }
        }
    ]
