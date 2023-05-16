[![Actions Status](https://github.com/levigo/url-crypto-kit/workflows/Continuous%20Delivery/badge.svg)](https://github.com/levigo/url-crypto-kit/actions)
[![Generic badge](https://img.shields.io/badge/current%20version-2.0.5-1abc9c.svg)](https://github.com/levigo/url-crypto-kit/tree/v2.0.5)

# URL cryptography functionality to be used in conjunction with the Spring&trade; Framework 

## Features
- Pre-signed-URL generation and verification
- URL encryption and decryption
- integration with the Spring Framework
- integration with Spring Security
- Activation and configuration through Spring-Boot autoconfiguration

## PSU
P(re) S(igned) U(RL) is a mechanism which enables an authenticated user to create a URL with a built-in authentication 
for a single endpoint.  
The PSU will enable anyone to use the requested endpoint, this URL is created for, without any additional 
authentication.   
This can be useful for services that can not perform the necessary authentication or simply don't have the required 
access rights.  
A user can only create a PSU for an endpoint he is authenticated for.  
The Access rights of a PSU are equivalent to the user who have created it.  
PSU are always time limited and will expire after a defined time. If the link is expired it will not provide any 
authentication.

## Usage
### Maven dependency
```xml
<dependency>
    <groupId>com.neverpile</groupId>
    <artifactId>url-crypto-kit</artifactId>
    <version>2.0.5</version>
</dependency>
```
### Example configuration
application.properties:  
```properties
neverpile.url-crypto.shared-secret.enabled=true
neverpile.url-crypto.shared-secret.secret-key=Not#So%Secret
neverpile.url-crypto.pathPatterns=/**
neverpile.url-crypto.psuEnabledPathPatterns=/path/to/static/data/**
```
__neverpile.url-crypto.shared-secret.enabled=true__  
Enable the CryptoKit with a shard secret implementation.  
This is the only implementation as of now.  
__neverpile.url-crypto.shared-secret.secret-key=Not#So%Secret__  
Choose a secret key for the encryption.  
If omitted, a random secret key will be generated on startup.  
Please don't copy the example key.  
__neverpile.url-crypto.pathPatterns=/**__  
Allows you to define one or multiple URL patterns where the PSU mechanism should be activated on.  
All URL paths which do not match any of the defined paths will not be considered for encryption.  
/&ast;&ast; will allow PSU to be enabled on all paths.  
__neverpile.url-crypto.psuEnabledPathPatterns=/path/to/static/data/**__  
All paths defined here should also match a pattern in the global pathPatterns property.  
Paths defined here allow the generation of PSU with the url parameter method described in the following section.  

### Enable a handler method:
In any Spring RestController or similar:  
```JAVA
@RestController
@RequestMapping("/controller/path")
public class ExampleResource {
  
  @GetMapping("/example/path/{id}")
  @PreSignedUrlEnabled
  public @ResponseBody ResponseEntity<Resource> getData(@PathVariable String id) {
    return ResponseEntity.ok().build();
  }
  
}
```
With the `@PreSignedUrlEnabled` Annotation a single Endpoint will be registered for use with PSU.  
Any Spring handler Method can be annotated. The annotated method must handle a path that is included in the previously 
described `pathPatterns`.  

### Generating a PSU
If you have activated the PSU functionality on an endpoint by annotating it with `@PreSignedUrlEnabled` or by defining 
it in the application property `psuEnabledPathPatterns`, you can add a PSU parameter to the URL.  
__example request:__  
```http request
https://myhost:1337/controller/path/example/path/42?X-NPE-PSU-Duration=PT1H
```
`X-NPE-PSU-Duration` has to be the parameter key and the value can be any duration as text.  
The formats accepted are based on the ISO-8601 duration format `PnDTnHnMn.nS`.  
The request with the added PSU parameter has to be authenticated, because the current user authentication will be used 
in the resulting PSU.  
The endpoint will return a PSU as plain text and will not execute its own functionality.  
__example result:__  
```http request
https://myhost:1337/controller/path/example/path/42?X-NPE-PSU-Expires=20221121223924&X-NPE-PSU-Signature=cfa1dd7db3e67208fc59abd6b78fc7d70b422ad7ccef97b7680bef4299c3d404&X-NPE-PSU-Credential=FiQXra5CW9kEHVV6wkVazKBw2FmLXmQ7pDQiCKkWxZWtdXjrEPdUM8bAVj5gLrVs
```

The result link includes a date which indicates how long this link is valid for and the encrypted authentication info.  
If this link is used by any user or application the user gains access rights corresponding to the user who created the 
link.  
Any endpoint with enabled PSU can be used as normal without the PSU URL parameter.  

## License
This library is provided "as is" under the "three-clause BSD license". See [LICENSE.md](./LICENSE.md).
