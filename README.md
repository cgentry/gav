gav
===

Golang Access Verification

Similar to AWS hmac signing, this will sign and verify requests using: 
1. A shared secret
2. A user id
3. Content-MD5 (if it exists)
4. Content-Type
5. Date/time stamp
6. The request

If there is a body text, there must be a Content-MD5 header value set. This is compared to one created on the server to ensure validity.

The Date/time stamp can either be a header field 'Timestamp' or the 'Date' header value. I recommend that every program set the 'Timestamp' value
instead of using the 'Date' field. This should be formatted in GMT and in standard HTTP header Date format.

The request is the path, the parameters and any fragments. The code "recreates" it when running and it looks like:
      /path/request?parm=value&anotherParm=value#fragment

Your code must either use the routines in this library (if using GO) or recreate the exact way the key is generated.
