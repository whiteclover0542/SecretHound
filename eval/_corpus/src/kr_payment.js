const TOSS_SECRET_KEY = "live_sk_bkpCzqoKWTjlm4wXeopfnHHVDdI8";
const TOSS_CLIENT_KEY = "live_ck_S7vKJPa38ssrYxgzSmcLP8xBc8VM";

const kakaoRestApiKey = "b3014ebdecd51b716b42c6f5ab6852e7";
const KAKAO_JAVASCRIPT_KEY = "81ec574512831b6c85025f0bff773ad9";

const portone = {
  imp_key: "586151715046736815277109",
  imp_secret: "lmf2xMQYtzTLUNPo4RnIqLCTuohxVvEeUs4V0vhaylNgTcjEjflmtyGp7GI7u5jJajD5xOn2CqjJuHUSoyuVaUb9YetE7vMM",
  merchant_uid: "imp12345678",
};

async function confirmPayment(paymentKey, orderId, amount) {
  return fetch("https://api.tosspayments.com/v1/payments/confirm", {
    method: "POST",
    headers: { Authorization: "Basic " + btoa(TOSS_SECRET_KEY + ":") },
    body: JSON.stringify({ paymentKey, orderId, amount }),
  });
}
