# Building a WebAuthn Click Farm — Are CAPTCHAs Obsolete?
Checkout the releted blog post: https://betterappsec.com/building-a-webauthn-click-farm-are-captchas-obsolete-bfab07bb798c?source=friends_link&sk=f7a2c54a4b70dc71a861e04d0793cb6b

### Demo
Visit https://cloudflarechallenge.com/ and run the following in the developer tools console:
```js
let script = document.createElement('script');
script.type = 'text/javascript';
script.src = 'https://webauthn.bored.engineer/script.js';
(document.getElementsByTagName('head')[0]||document.getElementsByTagName('body')[0]).appendChild(script);
```
