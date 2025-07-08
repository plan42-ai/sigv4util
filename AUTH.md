# 0. Background

Generally, we utilize JWT based authentication for service-to-service communication where ever possible.
However, there are 2 services that require SigV4 authentication: The Tokenizer and the Metadata service. This is because
the Tokenizer is what generates JWT tokens, and the Metadata service is a dependency of the Tokenizer. 

To be able to effectively bootstrap everything, we need the tokenizer and it's dependencies to be able to authenticate
to each other before we can start generating JWT tokens.

We use sigv4 for this.

All AWS Compute (or at least all the compute we use) has built-in support for AWS IAM roles. That is, whether running on
EC2, EKS, or Lambda, the AWS control plane has the ability to automatically assume a defined IAM role and provide the
assume-role-credentials transparently to the workload. This is generally done to enable code running in AWS to
interact with other AWS services (access S3 buckets, DDB tables, SQS queues, etc). It also provides compute workloads
with dynamic, short-lived credentials that are rotated automatically.

Typically, services are deployed such that each service has a unique associated IAM role that has the IAM permissions
that service needs to operate.

This means it's possible to use the identity of the IAM role (i.e. `arn:aws:iam::123456789012:role/MyServiceRole`) as
the identity of the associated service.

By having the Tokenizer support SIGV4 authentication, it's possible for other services to boot up, access their automated
assume role credentials, and then call the Tokenizer to exchange them for a JWT token. That JWT token can then be used
to for all subsequent service-to-service communication.

When supporting Identity Federation, we can even use such tokens to authenticate to external services such as Github.

We make the Medata Service also support Sigv4 to avoid circular dependencies. 

## 1. How does Sigv4 work?

For details, please see the [AWS Documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html).

In essence, Sigv4 uses the AWS_SECRET_ACCESS_KEY to implement an HMAC-SHA256 signature of an HTTP request to an AWS
service. The AWS_SECRET_ACCESS_KEY is always kept secret, and is only accessible to the client calling a service and AWS.
When AWS receives a signed request, it can verify that the sender of an HTTP request is in possession of the AWS_SECRET_ACCESS_KEY
associated with a given AWS_ACCESS_KEY_ID. AWS will lookup the associated AWS_SECRET_ACCESS_KEY given an AWS_ACCESS_KEY_ID,
and then use it to create a HMAC-SHA256 signature of the request it received. If that signature matches the signature
provided by the caller then AWS can prove that someone in possession of the AWS_SECRET_ACCESS_KEY created the HTTP
request it received.

The Sigv4 algorithm is carefully constructed to prevent both spoofing and replay attacks. If someone were to intercept
a Sigv4 signed request the only thing they would be able to do with it is re-transmit that exact same request to AWS.
Any attempt to modify the request, or to attach the signature to a different request would result in a signature
mismatch.

Also, the signatures have embedded timestamps and are only valid for a short period of time. So, even if the exact
intercepted was replayed io AWS, it is only valid for a maximum 5 minutes.

Thus, Sigv4 provides a mechanism for AWS customers to authenticate to AWS services securely, without requiring a shared
PKI.

## 2. But how can we use Sigv4 to authenticate to our own services?

Our services don't have access to the caller's AWS_SECRET_ACCESS_KEY value. Only the caller and AWS have access to it.
This means we can't just run Sigv4 on our requests and validate them in our services.

API Gateway does have the ability to validate Sigv4 signatures for custom API requests, but it does not work with
private APIs.

However, there is a simple workaround. AWS provides the sts:GetCallerIdentity API that implements Sigv4 authentication
and simply returns back the identity of the caller that made the request. 

If a caller crafts a request to the sts:GetCallerIdentity API, signs it with Sigv4 auth, then attaches it to a request
to our service, we can then forward the sts request to AWS, and use the response to authenticate the caller.

This allows a client to authenticate to our service using Sigv4, and us to verify they possess an AWS_SECRET_ACCESS_KEY
associated with an AWS IAM Principal (IAM User, IAM Assume Role Session, or AWS Root Account credentials), without
requiring us to have possession of the AWS_SECRET_ACCESS_KEY.

This does require us to trust AWS, as it's possible GetCallerIdentity could lie to us, but we have to trust AWS, and
specifically Sigv4 auth to run any code in AWS, so this trust is reasonable

## 3. Preventing Replay Attacks

One issue with using a Sigv4 signed request as an authentication token is that it re-introduces the possibility of
replay attacks. If an attacker has access to a Sigv4 signed request, they could attach it to a different request to one
of our services and successfully authenticate. Similarly if one of our services were to be compromised, they could
extract the Sigv4 signed request from a legitimate request use it to impersonate the caller to another service.

That would be bad. To prevent replays and impersonation, we need to cryptographically bind the Sigv4 signed request to
the request it's attached to. The simplest way to do that is to construct a hash of the "outer" request the "inner"
Sigv4 request is attached to, and embed that hash as a custom header in the call to sts:GetCallerIdentity. This will
include the header in the data cryptographically verified by STS when it validates the Sigv4 signature.

If we combine that with a check in our service that extracts the hash from the "inner request", recalculates the hash of
the "outer request" (minus the missing Authentication header), and compares the two, we now have cryptographic proof
that the holder of the AWS_SECRET_ACCESS_KEY used to sign the Sigv4 request also processed the "outer request".

Using this technique, we can get the benefits of Sigv4 authentication, without the risk of replay attacks, and without
needing access to the AWS_SECRET_ACCESS_KEY.

## 4. Scheme

We implement this with 2 headers attached to each request to our service:

1. Authorization
2. X-EventHorizon-SignedHeaders

The first header, Authorization, must contain a valid HTTP/1.1 request encoding a Sigv4 signed request to the
sts:GetCallerIdentity API. The request should be encoded as a JSON string.  The encoded HTTP request must include the
header `X-EventHorizon-Request-Hash` that contains the SHA256 hash of the "canonical request" form of the "outer"
HTTP request. See [here](https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html) for documentation
on how to construct a canonical request.

The second header, `X-EventHorizon-SignedHeaders`, must contain a `;` separated list of headers that were included
when computing the outer request's hash. The list must include its self (`X-EventHorizon-SignedHeaders`).

The `X-EventHorizon-SignedHeaders` header is necessary because L7 load balancers and proxies (like ALB and API Gatway)
will often inject headers that were not present in the original request. For example the `X-Forwarded-For` header is commonly
injected by proxies. We need to exclude such injected headers when computing the hash of the outer request, hence
why we include the list of headers to include in the signature.

As described in the README.md, this library provides go code for both the client and server side of this scheme.



