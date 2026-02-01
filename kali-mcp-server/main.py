from typing import Any
import os
import sys
import logging
from mcp.server.fastmcp import FastMCP

# Configure logging to stderr so it doesn't interfere with stdio MCP transport
logging.basicConfig(stream=sys.stderr, level=logging.INFO)

KALI_COMMAND_SERVER = os.getenv("KALI_COMMAND_SERVER", "http://localhost:8080")
USER_AGENT = "kali-mcp-server/1.0"

mcp = FastMCP("kali")

async def make_request(endpoint: str, data: dict[str, Any] = None) -> dict[str, Any] | None:
    "Make a request to the Kali Command Server"
    import httpx  # Import inside function to avoid event loop conflicts
    url = f'{KALI_COMMAND_SERVER}/{endpoint}'
    headers = {"User-Agent": USER_AGENT}
    async with httpx.AsyncClient() as client:
        response = None
        if data:
            logging.info(f'Post {url} with {data=}')
            response = await client.post(url, json=data, headers=headers)
        else:
            logging.info(f'Get {url}')
            response = await client.get(url, headers=headers)
        response.raise_for_status()
        return response.json()

@mcp.tool()
async def health() -> str:
    """Check if the Kali Command Server is reachable."""
    res = await make_request("health")
    if res is None:
        return "Error: Kali Command Server is not reachable"
    return str(res)

@mcp.tool()
async def port_scan(targets: str, ports: str = "1-1000", fast: bool = True) -> str:
    """
    Scan specific ports on the target host.

    Args:
        targets: Target IP addresses or hostnames (comma-separated). Examples: '192.168.1.1', '192.168.1.1,192.168.1.2', 'scanme.nmap.org', '10.0.0.0/24'
        ports: Port, ports or range of ports to scan, e.g. '22,80,443' or '1-1000'
        fast: Use fast scan mode (-T4)

    Returns:
        List of open ports and services
    """
    logging.info(f'{targets=}, {ports=}, {fast=}')
    try:
        data = {"targets": targets}
        if ports:
            data["ports"] = ports
        if fast:
            data["options"] = "-T4"
        res = await make_request("nmap", data)
        if res.get("success"):
            return res.get("output", "")
        else:
            error = res.get("error", "Unknown error")
            return f"Scan failed: {error}"
    except Exception as e:
        logging.error(f"Error during port scan: {e}")
        return f"Error: {str(e)}"

def main():
    logging.info("Starting kali-mcp-server.")

    # Initialize and run the server
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()