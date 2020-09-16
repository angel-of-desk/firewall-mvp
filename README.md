# firewall-mvp

Lightweight MVP for flask-postgress firewall API


### Build

```bash
docker-compose up --build
```

### Testing the API

In a separate terminal run the following curl commands:

```bash
curl -X PUT http://localhost:5000/killroute/192.168.1.1
```
Adds `192.168.1.1` to the postgres database

```bash
curl -X DELETE http://localhost:5000/killroute/192.168.1.1
```
Deletes `192.168.1.1` from the database

```bash
curl http://localhost:5000/getallroutes
```
Returns a JSON object with a list of all IP addresses in the database

