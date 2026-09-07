SHOPIFY_ACCESS_TOKEN = "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"
STRIPE_TEST_KEY = "sk_test_51NxK2mQ7vRp8ZtY3wB6cH0j"

OAUTH = {
  client_id: "my-app-prod",
  client_secret: "9mNxP4wZ8sT1yB6cH0jL5dF9gA3eU7iO",
}

def checkout_url(cart_id)
  "https://shop.example.com/checkout/#{cart_id}"
end
