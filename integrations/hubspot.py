import json
import secrets
import base64
import hashlib
import asyncio
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse
import httpx
import requests
from integrations.integration_item import IntegrationItem
from redis_client import add_key_value_redis, get_value_redis, delete_key_redis

CLIENT_ID = "23486d8b-e156-4631-abd7-867141cbc419"
CLIENT_SECRET = 'c776a3a4-3819-4d50-a5da-04e084555ddc'
REDIRECT_URI = 'http://localhost:8000/integrations/hubspot/oauth2callback'
AUTHORIZATION_URL = f'https://app.hubspot.com/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope=contacts%20content%20crm.objects.contacts.read'

# Encoded client ID and secret
encoded_client_id_secret = base64.b64encode(f'{CLIENT_ID}:{CLIENT_SECRET}'.encode()).decode()

async def authorize_hubspot(user_id, org_id):
    """Initiates the OAuth authorization flow for HubSpot."""
    state_data = {
        'state': secrets.token_urlsafe(32),
        'user_id': user_id,
        'org_id': org_id
    }
    encoded_state = base64.urlsafe_b64encode(json.dumps(state_data).encode('utf-8')).decode('utf-8')

    auth_url = f'{AUTHORIZATION_URL}&state={encoded_state}'
    await add_key_value_redis(f'hubspot_state:{org_id}:{user_id}', json.dumps(state_data), expire=600)
    return auth_url

async def oauth2callback_hubspot(request: Request):
    """Handles the OAuth2 callback for HubSpot."""
    if request.query_params.get('error'):
        raise HTTPException(status_code=400, detail=request.query_params.get('error_description'))

    code = request.query_params.get('code')
    encoded_state = request.query_params.get('state')
    state_data = json.loads(base64.urlsafe_b64decode(encoded_state).decode('utf-8'))

    user_id = state_data.get('user_id')
    org_id = state_data.get('org_id')

    saved_state = await get_value_redis(f'hubspot_state:{org_id}:{user_id}')
    if not saved_state or state_data.get('state') != json.loads(saved_state).get('state'):
        raise HTTPException(status_code=400, detail='State mismatch.')

    async with httpx.AsyncClient() as client:
        response = await client.post(
            'https://api.hubapi.com/oauth/v1/token',
            data={
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': REDIRECT_URI,
                'client_id': CLIENT_ID,
                'client_secret': CLIENT_SECRET,
            },
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )

    if response.status_code != 200:
        raise HTTPException(status_code=400, detail='Failed to fetch access token.')

    await add_key_value_redis(f'hubspot_credentials:{org_id}:{user_id}', json.dumps(response.json()), expire=3600)
    await delete_key_redis(f'hubspot_state:{org_id}:{user_id}')

    close_window_script = """
    <html>
        <script>
            window.close();
        </script>
    </html>
    """
    return HTMLResponse(content=close_window_script)

async def get_hubspot_credentials(user_id, org_id):
    """Fetches HubSpot OAuth credentials from Redis."""
    credentials = await get_value_redis(f'hubspot_credentials:{org_id}:{user_id}')
    if not credentials:
        raise HTTPException(status_code=400, detail='No HubSpot credentials found.')

    await delete_key_redis(f'hubspot_credentials:{org_id}:{user_id}')
    return json.loads(credentials)

async def create_integration_item_metadata_object(response_json, item_type, parent_id=None, parent_name=None):
    """Creates an IntegrationItem metadata object from HubSpot's response."""
    return IntegrationItem(
        id=response_json.get('id', None) + '_' + item_type,
        name=response_json.get('properties', {}).get('name', 'Unnamed Item'),
        type=item_type,
        parent_id=parent_id,
        parent_path_or_name=parent_name,
        creation_time=response_json.get('createdAt', None),
        last_modified_time=response_json.get('updatedAt', None),
    )

async def get_items_hubspot(credentials):
    """Fetches HubSpot objects (e.g., contacts, companies) as IntegrationItem objects."""
    access_token = credentials.get('access_token')
    url = 'https://api.hubapi.com/crm/v3/objects/contacts'

    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        raise HTTPException(status_code=400, detail='Failed to fetch items from HubSpot.')

    items = response.json().get('results', [])
    integration_items = []

    for item in items:
        # Await the async call to create integration items
        integration_item = await create_integration_item_metadata_object(item, 'Contact')
        integration_items.append(integration_item)

    return integration_items
