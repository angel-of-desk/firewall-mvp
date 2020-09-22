# firewall-mvp

Lightweight MVP for flask-postgress firewall API


## Build

From `firewall` directory

```bash
docker-compose up --build
```

## Testing the API

In a separate terminal run the following curl commands:


Adds `192.168.1.1` to the postgres database

```bash
curl -X DELETE http://localhost:5000/killroute/192.168.1.1
```
Deletes `192.168.1.1` from the database

```bash
curl http://localhost:5000/getallroutes
```
Returns a JSON object with a list of all IP addresses in the database


## JSON Schema

### Read

```bash
curl -X POST http://localhost:5000/rules --header "Content-Type: application/json" --data @test_read_ip.json
```

`test_read_ip.json` contains:
```
{
	"action": "read",
	"type": "ip"
}
```

A succesful read response:
```
{
  "body": [
    {
      "dns": ".piratebay.org",
      "id": 1,
      "name": "Wow such trust",
      "trusted": "true",
      "type": "dns"
    },
    {
      "dns": ".google.com",
      "id": 2,
      "name": "Good DNS",
      "trusted": "true",
      "type": "dns"
    }
  ],
  "error": null,
  "name": "Request Successful",
  "status": 200
}
```

### Create, Update, & Delete Requests

For any of these actions, the `action` key can be set to any either `create`, `update`, or `delete` followed by 
one or more elements in the `rules` array. In this example the request is creating 4 new rules.

```
{
  "action": "create",
  "rules": [
    {
      "type": "ip",
      "trusted": "false",
      "name": "Bad IP",
      "ip": "192.168.1.1" 

    },
    {
      "type": "ip",
      "trusted": "false",
      "name": "Suspect IP",
      "ip": "192.168.1.2" 

    },
    {
      "type": "dns",
      "trusted": "true",
      "name": "Wow such trust",
      "dns": ".piratebay.org"
    },
    {
      "type": "dns",
      "trusted": "true",
      "name": "Good DNS",
      "dns": ".google.com"
    }
  ]
}
```

A succesful response will include the same elements provided in `rules` array of the request, with additional information.
In the event of a `create` request, the parameter `id` will be added to each element.
```
{
  "body": [
    {
      "id": 1,
      "ip": "192.168.1.1",
      "name": "Bad IP",
      "trusted": "false",
      "type": "ip"
    },
    {
      "id": 2,
      "ip": "192.168.1.2",
      "name": "Suspect IP",
      "trusted": "false",
      "type": "ip"
    },
    {
      "dns": ".piratebay.org",
      "id": 1,
      "name": "Wow such trust",
      "trusted": "true",
      "type": "dns"
    },
    {
      "dns": ".google.com",
      "id": 2,
      "name": "Good DNS",
      "trusted": "true",
      "type": "dns"
    }
  ],
  "error": null,
  "name": "Request Successful",
  "status": 200
}
```

If a request generates an error, the `body` array will be null, and the `error` field will have a message.
In this example we see the response for trying to delete elements that don't exist:
```
{
  "body": null,
  "error": "Attempt to delete rule with invalid id",
  "name": "Rule Does Not Exist",
  "status": 400
}
```
