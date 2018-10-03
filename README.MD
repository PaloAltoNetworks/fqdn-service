# FQDN Service Serverless Application
Serverless Application to turn a list of FQDN entries into a dynamic IPv4/IPv6 feed.

## Overview

Cloud embracement by many companies are driving adoption of Content Delivery providers as well as Global Server Load Balancing technologies. In many occasions the DNS service is at the very bottom layer of the stack of these technology providing FQDN to A Record mapping with too many entries or with a TTL too small to be tracked in L4 security policies.

Using L7 security policies is the right solution to the problem. But, if for any reason, you need a WEB API that provides you with a feed of IPv4 and IPv6 values bound to a set of FQDN entries then this serverless application might be a good fit.

## Installation

Just deploy the Serverless Application from the [AWS Serverless Repo](https://serverlessrepo.aws.amazon.com/#/applications/arn:aws:serverlessrepo:us-east-1:298629197879:applications~fqdnService) or create a _CloudFormation Stack_ using the template [sam_template.yaml](https://github.com/PaloAltoNetworks/fqdn-service/blob/master/sam_template.yaml)

## Configuration

The following resources will be created into your AWS Account once the FQDN Service Application is deployed:
- AWS API Gateway named **fqndServiceGw**
- AWS Lambda named **fqdnServiceLamdba**
- AWS DynamoDB table named **fqdnservice-fqndServiceTable-{ID}**
- AWS IAM Role named **fqdnservice-fqdnServiceLamdbaRole-{ID}**

In the AWS Console navigate to Services > API GW > fqdnServiceGw > Stages > prod > Stage Variables and change the default secret value (*"defaultSecret"*) for something meaningful to you.

### FQDN Service Configuration File

The configuration must be provided as a JSON document with a free schema. Inside the JSON document you must provide *fqdn templates* conforming with the following schema:

`{ "fqdn": "{full qualified domain name i.e www.paloaltonetworks.com}" }`

At runtime, any *fqdn template* in the configuration file will be replaced with and object featuring IPv4 and IPv6 arrays provided by a DNS resolver.

Example Configuration File:

```json
{
    "UPF": { "fqdn": "www.upf.edu" },
    "UB": { "fqdn": "www.ub.es" }
}
```

Example FQDN Service Sesponse:
```json
{
  "UPF": {
    "ipv4": [
      "104.24.39.14",
      "104.24.38.14"
    ],
    "ipv6": [
      "2400:cb00:2048:1::6818:270e",
      "2400:cb00:2048:1::6818:260e"
    ]
  },
  "UB": {
    "ipv4": [
      "161.116.100.2"
    ]
  }
}
```

### Publishing the configuration file

The FQDN Service provides a `/config` entry point that can be used to _POST_ a new configuration file at any moment.

In the AWS Console navigate to Services > API GW > fqdnServiceGw > Stages > prod to take note of the _Invoke URL_ value for your instance.

Then use `curl` (or any other tool you feel comfortable with) to _POST_ your configuration file.

Example:
```console
foo$ curl --data-binary '{ "PANW": { "fqdn": "www.paloaltonetworks.com" } }' "{Invoke URL}/config?key={secret}"
```

If everything goes right, the configuration file will be echoed in the response. Otherwise, the error will be returned.

Example response:
```console
{"PANW":{"fqdn":"www.paloaltonetworks.com"}}
```

## Formating the output

By default, the FQDN Service returns the list of IPv4 addresses known to have been resolved in the last 24 hours by the list of *fqdn templates* in the configuration file in a `plain/text` format.

Example:
```console
foo$ curl {Invoke URL}
104.24.39.14
104.24.38.14
161.116.100.2
```

If you want the list of IPv6 records instead, then just add the `v=ipv6` url parameter.

Example:
```console
foo$ curl {Invoke URL}?v=ipv6
2400:cb00:2048:1::6818:270e
2400:cb00:2048:1::6818:260e
```

And, finally, if you want to get the original JSON configuration file transformed then use the `v=json` url parameter.

Example:
```console
foo$ curl {Invoke URL}?v=json
{"UPF":{"ipv4":["104.24.39.14","104.24.38.14"],"ipv6":["2400:cb00:2048:1::6818:270e","2400:cb00:2048:1::6818:260e"]},"UB":{"ipv4":["161.116.100.2"]}}
```

## Spanning your response

The FQDN Service is backed by a DynamoDB table that stores all known resolutions (both IPv4 and IPv6) for a given fqdn alongside a `valid until` value computed as the current time plus the ttl value returned by the DNS resolver.

You can use the `span={seconds}` url paramter to change the default 24 hour span.

Example:
```console
foo$ curl "{Invoke URL}?v=json&span=60"
{"UPF":{"ipv4":["104.24.39.14","104.24.38.14"],"ipv6":["2400:cb00:2048:1::6818:270e","2400:cb00:2048:1::6818:260e"]},"UB":{"ipv4":["161.116.100.2"]}}
```

## Using multiple stages

You can create additional stages in the AWS API GW to implement many virtual FQDN services.

If you do so then take into account that:

1. remember to add the stage variables `dbtable` and `secret`
2. `POST` a new configuration file for the new stage.

You can (in fact you're encouraged to) use the same DynamoDB table by the many stages you decide to deploy. If you choose to use a different table than the one already deployed then remember to create it using the DynameDB console and to modify the IAM rome `fqdnServiceLamdbaRole-{ID}` to allow the fqdn service lambda perform operation onto the new table.
