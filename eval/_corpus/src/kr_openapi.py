import requests

FORECAST_URL = "http://apis.data.go.kr/1360000/VilageFcstInfoService_2.0/getVilageFcst"
SERVICE_KEY = "FyTqy7SGbx9oB03zC01IYkf1jJ%2FwHgkpyUKUElTRRScozuCIMe7O6M8U0zqPe2xf%2BApT2GZpMq4qAeqcM2JmdA%3D%3D"


def fetch_forecast(nx, ny):
    params = {"serviceKey": SERVICE_KEY, "numOfRows": 10, "dataType": "JSON", "nx": nx, "ny": ny}
    return requests.get(FORECAST_URL, params=params).json()


def search_blog(query):
    headers = {
        "X-Naver-Client-Id": "mKDBW49r3LooWPUEMTDM",
        "X-Naver-Client-Secret": "fkGrokoLPb",
    }
    return requests.get(
        "https://openapi.naver.com/v1/search/blog.json",
        params={"query": query},
        headers=headers,
    ).json()


# 포털 발급 화면 표기 그대로 옮긴 이름. serviceKey 라는 단어가 등장하지 않는다.
PUBLIC_DATA_DECODING_KEY = "FyTqy7SGbx9oB03zC01IYkf1jJ/wHgkpyUKUElTRRScozuCIMe7O6M8U0zqPe2xf+ApT2GZpMq4qAeqcM2JmdA=="
