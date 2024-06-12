# Samsung Pay Codec

Go module to decrypt Samsung Pay tokens as received from the SDK.

> [!NOTE]  
> This is not an official Samsung project.

Although the code is tested with decent coverage, the project is provided without guarantees. It has not been production-battled and only been used for illustration. Feedback is needed.

The module contains 2 main interfaces:

-	**KeyProvider**: returns the private key when given the key ID. The module contains 2 implementations of this interface:
    - _Filesystem key provider_: which reads the PKCS8 PEM files from the specified root directory

    - _Static key provider_: which takes a list of keys in the constructor

-	**Decryptor**: decrypts the payload using the key it receives from the key provider. The module contains only the JWE decryptor using RSA keys.

## Mechanism

The merchant or their respective PSP (payment service provider) must first generate key pair and a CSR (certificate signing request) with the key. They, then, create a Service on the Samsung Pay Developers portal and upload the CSR generated earlier. During a transaction, Samsung Pay server generates a short-lived TLS certificate using the CSR and signs it with Samsung private key. The signed certificate is then sent to the device to encrypt the token using the embedded public key (after validating the certificate chain, but this is done by on-device Samsung Pay facilities for you). The encrypted token is then given to the merchant/PSP (service ID owner). The service ID owner is expected to decrypt the token using the private key of the CSR.

### In-App Payments Verification

How does Samsung Pay know the app requesting payments is not spoofed?

When the in-app service profile is created on the Samsung Pay Developers portal, the developer receives a service ID which they ought to use with the Samsung Pay SDK when requesting the payment. What if the service ID falls into the hands of fraudsters or hackers?

The service ID is not a secret. It is an identifier. When creating the service profile, the developer enters the application/package ID and is instructed to upload the production APK of their app. When the merchant app interacts with the Samsung Pay SDK, Samsung Wallet app checks the caller app package ID and verifies its signature matches the signature of the APK uploaded by the developer on the portal. Therefore, a rogue app that is side-loaded on the phone cannot pass the verification checks of the Samsung Wallet. The mechanism proves to Samsung Pay the caller app has access to the Samsung Pay Developer portal and to have access to the signed APK of the merchant.

### Web Checkout Verification

How does Samsung Pay know the website requesting payments is not spoofed? What if a rogue network admin deploys a DNS server within the network that serves a phishing site on the payment page known to host Samsung Pay payment flow?

When creating the service profile, the developer enters the authorized service domain names (FQDN) that will host the Samsung Pay JS SDK. When loaded the SDK checks the page is hosted on HTTPS and that the host name is configured by the developers as an authorized domain name for Samsung Pay operations. This proves to Samsung Pay that the site developer has control over the DNS and the service profile access.
