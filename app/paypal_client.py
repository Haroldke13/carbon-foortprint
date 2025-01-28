
import requests
import json
from flask_wtf.csrf import CSRFProtect

from config import require_env

csrf = CSRFProtect()


def get_access_token(username, password):
    
    url = 'https://api-m.sandbox.paypal.com/v1/oauth2/Token'
    data = {'grant_type': 'client_credentials'}
    response = requests.post(url, data=data, auth=(username, password))
    if response.status_code == 200:
        return json.loads(response.text)['access_token']
    else:
        raise Exception('Error getting access token: {}'.format(response.text))

def create_order(access_token, data_orders):
    """
    Create a new order on PayPal

    Args:
        access_token (str): PayPal API access token
        data_orders (dict): Order data

    Returns:
        str: Order ID

    """
    url_orders = 'https://api-m.sandbox.paypal.com/v1/checkout/orders'
    response_orders = requests.post(url_orders, json=data_orders, headers={'Authorization': 'Bearer {}'.format(access_token)})
    if response_orders.status_code == 201:
        return json.loads(response_orders.text)['id']
    else:
        raise Exception('Error creating order: {}'.format(response_orders.text))

def capture_payment(access_token, order_id):
    """
    Capture a payment for an existing order

    Args:
        access_token (str): PayPal API access token
        order_id (str): Order ID

    Returns:
        str: Payment capture response

    E
    """
    url_capture = 'https://api-m.sandbox.paypal.com/v1/checkout/orders/{}/capture'.format(order_id)
    response_capture = requests.post(url_capture, headers={'Authorization': 'Bearer {}'.format(access_token)})
    if response_capture.status_code == 201:
        return response_capture.text
    else:
        raise Exception('Error capturing payment: {}'.format(response_capture.text))

# Example usage - credentials come from the environment, never from source.
username = require_env('PAYPAL_CLIENT_ID')
password = require_env('PAYPAL_CLIENT_SECRET')
