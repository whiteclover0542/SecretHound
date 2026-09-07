import stripe

STRIPE_SECRET_KEY = "sk_live_51NxK2mQ7vRp8ZtY3wB6cH0j"
STRIPE_PUBLISHABLE_KEY = "pk_live_51NxK2mQ7vRp8ZtY3wB6cH0j"

stripe.api_key = STRIPE_SECRET_KEY


def create_charge(amount, currency="krw"):
    return stripe.Charge.create(amount=amount, currency=currency)


def refund(charge_id):
    return stripe.Refund.create(charge=charge_id)
