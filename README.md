# StrongMapIntuneImplementer
Sync AADJ devices to dummy objects in AD and use 3x Strong Mapping methods.

I used this script as a base as it seemed to be the most capable base script to use.
https://blog.keithng.com.au/2023/04/04/aadj-nps-radius/

The only attributes on the object that matter are the entries in AltSecurityIdentities. This will create all three strong types per MS documentation.
https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16

X509IssuerSerialNumber
X509SKI
X509SHA1PublicKey

Let me know if there are issues with it. Worked in my env.
Also requires your DC, CA, NPS, and Intune Certificate Connectors to be configured properly. See my other scripts about how to do that.
