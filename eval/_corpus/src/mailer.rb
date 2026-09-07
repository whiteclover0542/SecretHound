require "sendgrid-ruby"

SENDGRID_API_KEY = "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"
FROM_ADDRESS = "noreply@example.com"

def send_welcome(to)
  mail = SendGrid::Mail.new
  mail.from = SendGrid::Email.new(email: FROM_ADDRESS)
  mail.subject = "환영합니다"
  SendGrid::API.new(api_key: SENDGRID_API_KEY).client.mail._("send").post(request_body: mail.to_json)
end
