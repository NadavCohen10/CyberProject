import requests
import threading
import os

# Configuration
URL = "http://127.0.0.1:8000/upload"
# We use /bin/ls because it's a valid binary that the model can actually parse
FILE_TO_UPLOAD = "/bin/ls" 

def send_request(request_no):
    try:
        with open(FILE_TO_UPLOAD, 'rb') as f:
            files = {'file': (f"test_file_{request_no}", f, 'application/octet-stream')}
            response = requests.post(URL, files=files)
            
            if response.status_code == 200:
                data = response.json()
                print(f"[Request {request_no}] Success! Task ID: {data['task_id']}")
            else:
                print(f"[Request {request_no}] Failed with status: {response.status_code}")
    except Exception as e:
        print(f"[Request {request_no}] Error: {str(e)}")

# Create 10 threads to simulate 10 concurrent users
threads = []
print(f"[*] Starting stress test: Sending 10 concurrent requests to {URL}...")

for i in range(1, 11):
    t = threading.Thread(target=send_request, args=(i,))
    threads.append(t)
    t.start()

# Wait for all threads to finish
for t in threads:
    t.join()

print("[*] Stress test script finished sending requests.")