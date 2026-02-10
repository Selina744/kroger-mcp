"""Kroger MCP Server — product search, store lookup, and cart management."""

import sys

import requests
from mcp.server.fastmcp import FastMCP

from auth import AuthManager, BASE_URL

mcp = FastMCP("kroger")
auth = AuthManager()


def _app_headers():
    """Headers for app-level API calls (product/store search)."""
    return {
        "Authorization": f"Bearer {auth.get_app_token()}",
        "Accept": "application/json",
    }


def _user_headers():
    """Headers for user-level API calls (cart). Raises if not authorized."""
    token = auth.get_user_token()
    if not token:
        auth_url = auth.generate_authorize_url()
        raise RuntimeError(
            f"Not authorized. Please authorize first.\n\n"
            f"Option 1: Run `python auth.py` with your credentials to authorize interactively.\n\n"
            f"Option 2: Visit this URL, then give me the code from the redirect:\n{auth_url}"
        )
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }


@mcp.tool()
def find_stores(zip_code: str, radius_miles: int = 10, limit: int = 5) -> str:
    """Find Kroger stores near a ZIP code.

    Args:
        zip_code: US ZIP code to search near
        radius_miles: Search radius in miles (default 10)
        limit: Maximum number of stores to return (default 5)
    """
    resp = requests.get(
        f"{BASE_URL}/locations",
        headers=_app_headers(),
        params={
            "filter.zipCode.near": zip_code,
            "filter.radiusInMiles": radius_miles,
            "filter.limit": limit,
        },
    )
    resp.raise_for_status()
    data = resp.json().get("data", [])

    if not data:
        return f"No Kroger stores found near {zip_code} within {radius_miles} miles."

    results = []
    for store in data:
        name = store.get("name", "Unknown")
        location_id = store.get("locationId", "N/A")
        address = store.get("address", {})
        addr_line = address.get("addressLine1", "")
        city = address.get("city", "")
        state = address.get("state", "")
        zipcode = address.get("zipCode", "")
        results.append(
            f"- {name} (ID: {location_id})\n  {addr_line}, {city}, {state} {zipcode}"
        )

    return f"Found {len(data)} store(s) near {zip_code}:\n\n" + "\n".join(results)


@mcp.tool()
def search_products(query: str, location_id: str, limit: int = 10) -> str:
    """Search for products at a specific Kroger store.

    Args:
        query: Search term (e.g. "organic milk")
        location_id: Kroger store location ID (from find_stores)
        limit: Maximum number of results (default 10)
    """
    resp = requests.get(
        f"{BASE_URL}/products",
        headers=_app_headers(),
        params={
            "filter.term": query,
            "filter.locationId": location_id,
            "filter.limit": limit,
        },
    )
    resp.raise_for_status()
    data = resp.json().get("data", [])

    if not data:
        return f"No products found for '{query}' at location {location_id}."

    results = []
    for product in data:
        product_id = product.get("productId", "N/A")
        description = product.get("description", "No description")
        brand = product.get("brand", "Unknown brand")

        # Extract price info if available
        items = product.get("items", [{}])
        price_info = ""
        if items:
            price = items[0].get("price", {})
            regular = price.get("regular")
            promo = price.get("promo")
            if promo and promo > 0:
                price_info = f" — ${promo:.2f} (sale, reg ${regular:.2f})"
            elif regular and regular > 0:
                price_info = f" — ${regular:.2f}"

        # Extract size info
        size = items[0].get("size", "") if items else ""
        size_str = f" [{size}]" if size else ""

        results.append(
            f"- {description} ({brand}){size_str}{price_info}\n  Product ID: {product_id}"
        )

    return f"Found {len(data)} product(s) for '{query}':\n\n" + "\n".join(results)


@mcp.tool()
def get_product(product_id: str, location_id: str) -> str:
    """Get detailed information about a specific product.

    Args:
        product_id: Kroger product ID
        location_id: Kroger store location ID for pricing/availability
    """
    resp = requests.get(
        f"{BASE_URL}/products/{product_id}",
        headers=_app_headers(),
        params={"filter.locationId": location_id},
    )
    resp.raise_for_status()
    product = resp.json().get("data", {})

    if not product:
        return f"Product {product_id} not found."

    description = product.get("description", "No description")
    brand = product.get("brand", "Unknown brand")
    categories = " > ".join(product.get("categories", []))

    items = product.get("items", [{}])
    item = items[0] if items else {}
    size = item.get("size", "N/A")
    price = item.get("price", {})
    regular = price.get("regular")
    promo = price.get("promo")

    fulfillment = item.get("fulfillment", {})
    in_store = fulfillment.get("inStore", False)
    ship_to_home = fulfillment.get("shipToHome", False)
    delivery = fulfillment.get("delivery", False)

    lines = [
        f"Product: {description}",
        f"Brand: {brand}",
        f"Size: {size}",
        f"Category: {categories}" if categories else None,
        f"Regular Price: ${regular:.2f}" if regular else None,
        f"Sale Price: ${promo:.2f}" if promo and promo > 0 else None,
        f"Available: In-store={'Yes' if in_store else 'No'}, "
        f"Delivery={'Yes' if delivery else 'No'}, "
        f"Ship-to-home={'Yes' if ship_to_home else 'No'}",
        f"Product ID: {product.get('productId', product_id)}",
    ]
    return "\n".join(line for line in lines if line is not None)


@mcp.tool()
def add_to_cart(product_id: str, quantity: int = 1) -> str:
    """Add a product to the user's Kroger cart. Requires user authorization.

    If not yet authorized, returns instructions for how to authorize.

    Args:
        product_id: Kroger product ID to add
        quantity: Number of items to add (default 1)
    """
    try:
        headers = _user_headers()
    except RuntimeError as e:
        return str(e)

    resp = requests.put(
        f"{BASE_URL}/cart/add",
        headers=headers,
        json={
            "items": [
                {
                    "upc": product_id,
                    "quantity": quantity,
                }
            ]
        },
    )

    if resp.status_code == 204 or resp.status_code == 200:
        return f"Added {quantity}x product {product_id} to your Kroger cart."
    else:
        return f"Failed to add to cart (HTTP {resp.status_code}): {resp.text}"


@mcp.tool()
def submit_auth_code(code: str) -> str:
    """Submit a Kroger OAuth authorization code to complete the login flow.

    Use this when the user has visited the Kroger authorization URL and received
    a code (from the browser redirect URL's ?code= parameter).

    Args:
        code: The authorization code from the Kroger OAuth redirect
    """
    try:
        auth.exchange_code_for_token(code)
        return "Authorization successful! You can now use add_to_cart."
    except Exception as e:
        return f"Authorization failed: {e}"


if __name__ == "__main__":
    mcp.run()
