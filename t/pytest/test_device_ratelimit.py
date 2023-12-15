import requests
import random
import string
import time
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

global_device_rate_limit_server_host = "http://122.9.7.176:8200"
global_device_id = None


def login_and_get_device_id(user_id):
    response = requests.get(global_device_rate_limit_server_host + "/ajax/login?userId=" + str(user_id))
    assert response.status_code == 200, "device_rate_limit_server invalid!"
    data = response.json()
    assert data["deviceId"], "deviceId required!"
    global global_device_id
    global_device_id = data["deviceId"]
    return global_device_id


def random_chars(min_nums, max_nums):
    if min_nums < 1:
        min_nums = 1

    if max_nums < min_nums:
        max_nums = min_nums

    if min_nums != max_nums:
        return ''.join(random.sample(string.ascii_letters + string.digits, random.randint(min_nums, max_nums)))
    else:
        return ''.join(random.sample(string.ascii_letters + string.digits, min_nums))


def visit_ajax_api(api_type=None, command=None):
    if api_type is None:
        api_type = "n" + random_chars(3, 7)

    if command is None:
        command = random_chars(4, 8)

    api = api_type + "/" + command

    if global_device_id is not None and 'guest' != api_type:
        headers = {
            'x-device-id': str(global_device_id)
        }
        print(datetime.now().strftime("%Y/%m/%d %H:%M:%S") + " " + global_device_rate_limit_server_host + "/ajax/" + api + " with deviceId:" + str(
            global_device_id))
        return requests.get(global_device_rate_limit_server_host + "/ajax/" + api, headers=headers)
    else:
        print(datetime.now().strftime("%Y/%m/%d %H:%M:%S") + " " + global_device_rate_limit_server_host + "/ajax/" + api)
        return requests.get(global_device_rate_limit_server_host + "/ajax/" + api)


def visit_guest_api():
    response = visit_ajax_api("guest")
    assert response.status_code == 200, "guest api failed"
    data = response.json()
    print("visit guest api[", data["uri"], "] success")


# guest api no limit
def test_guest_api_limit():
    print(datetime.now().strftime("%Y/%m/%d %H:%M:%S") + " test_guest_api_limit")

    response = visit_ajax_api('guest')
    assert response.status_code == 200

    with ThreadPoolExecutor(max_workers=5) as executor:
        responses = executor.map(visit_ajax_api, ["guest" for _ in range(100)])
        for response in responses:
            assert response.status_code == 200


# every api 4r/10s for the whole website
def test_global_io_limit():
    print(datetime.now().strftime("%Y/%m/%d %H:%M:%S") + " test_global_io_limit")
    user_id = random.randint(100, 999)
    login_and_get_device_id(user_id)

    threads = [
        threading.Thread(target=visit_ajax_api, args=('io', 'readFile')),
        threading.Thread(target=visit_ajax_api, args=('io', 'readFile')),
        threading.Thread(target=visit_ajax_api, args=('io', 'readFile')),
        threading.Thread(target=visit_ajax_api, args=('io', 'readFile'))
    ]
    for thread in threads:
        thread.start()

    time.sleep(0.1)
    response = visit_ajax_api('io', "readFile")
    assert response.status_code == 503, "global_current_uri limit failed"

    time.sleep(10)
    response = visit_ajax_api('io', "readFile")
    assert response.status_code == 200


# every api 1r/1s for single device
def test_device_key_api_limit():
    print(datetime.now().strftime("%Y/%m/%d %H:%M:%S") + " test_device_key_api_limit")
    user_id = random.randint(100, 999)
    login_and_get_device_id(user_id)

    response = visit_ajax_api('key', 'getCaseList')
    assert response.status_code == 200
    time.sleep(0.1)
    response = visit_ajax_api('key', 'getCaseList')
    assert response.status_code == 429
    time.sleep(1)
    response = visit_ajax_api('key', 'getCaseList')
    assert response.status_code == 200


# every normal api 1r/3s and all api(except guest/login api) 40r/10s for single device
def test_device_normal_api_limit():
    print(datetime.now().strftime("%Y/%m/%d %H:%M:%S") + " test_device_normal_api_limit")
    time.sleep(15)
    counter = 0
    user_id = random.randint(100, 999)
    login_and_get_device_id(user_id)
    response = visit_ajax_api("admin", 'getUserList')
    counter = counter + 1
    assert response.status_code == 200
    time.sleep(0.1)
    response = visit_ajax_api("admin", 'getUserList')
    assert response.status_code == 429
    time.sleep(3)
    response = visit_ajax_api("admin", 'getUserList')
    counter = counter + 1
    assert response.status_code == 200

    with ThreadPoolExecutor(max_workers=5) as executor:
        responses = executor.map(visit_ajax_api, [None for _ in range(38)])
        for response in responses:
            counter = counter + 1
            assert response.status_code == 200
    time.sleep(1)
    response = visit_ajax_api()
    counter = counter + 1
    print("current counter: " + str(counter))
    assert response.status_code == 429, "test device_total_uris failed"

    time.sleep(10)
    response = visit_ajax_api()
    assert response.status_code == 200, "test device_total_uris failed"
