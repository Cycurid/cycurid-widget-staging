# cycurid-widget-js

cycurid-widget-js is CycurID's solution to authentication and onboarding through the power of a Reusable Digital Identity Token. Users register with CycurID to create a Reusable Encrypted Zero-Knowledge Identity Token that they present to your company's onboarding or authentication platform, letting them seamlessly and instantly connect.

## Installation

Use the package manager [npm](https://www.npmjs.com/) to install cycurid-widget-js.

```bash
npm install cycurid-widget-js
```

## Usage

### Import
IMPORT IN REACT:
```javascript
import { immeOauth, immeLogout } from "cycurid-widget-js";
```

### Supported methods

#### immeOauth
This is the main function to use for authentication. Invoking this function will do the whole login flow and generate an access token, refresh token and access token expiry date. The token is then used to fetch the specified scope after successful login and verification by the user.
```javascript
import { immeOauth } from 'cycurid-widget-js';

const config = {
  action: '<YOUR_ACTION>',
  client_id: '<YOUR_CLIENT_ID>',
  client_secret: '<YOUR_CLIENT_SECRET>',
  origin_url: '<YOUR_ORIGIN_URL>',
  scopes: ['<YOUR_SCOPES_ARRAY>'],
};

const onSuccess = (userInfo, token) => {<YOUR_ONSUCCESS_FUNCTION>}
const onFailure = (token) => {<YOUR_ONFAILURE_FUNCTION>}

const result = await immeOauth(config,onSuccess,onFailure);
```
#### immeLogout
This function will revoke the OAuth token.
```javascript
import { immeLogout } from 'cycurid-widget-js';

const logout = await immeLogout(token, client_id, client_secret);
```

### config
This is your configuration object for the client. The config is passed into each of the methods with optional overrides.

- **action** - This specifies the objective that you want the user to accomplish currently, we support 'login' and 'register'. 
- **client_id** - The ID provided to you from [CycurID Portal Website](https://portal.cycurid.com/) see [Account Creation](#account-creation) for more details.
- **client_secret** - The Secret provided to you from [CycurID Portal Website](https://portal.cycurid.com/) see [Account Creation](#account-creation) for more details.
- **origin_url** - This is the URL that the request is initially used to initiate the OAuth process. This URL needs to match the provided URL associated with the client account. The widget response will be sent to this address.
-  **scopes** -  An array of what user information you want to be returned.
```javascript
[reference_uuid, email, phone, first_name, last_name, middle_name, dob, sex, nationality, address, address1, address2, city, state, zip, country, passport_number, passport_exp, passport_issuing, passport_issuing_country]
```
### Demo Repository and Site
[Imme Demo Website Github](https://github.com/Cycurid/Demo-Website)

[Imme Live Demo Website](https://imme-demo-website.vercel.app/)


## Account Creation
*An Cycurid Account is required to use this package*

To create an account, navigate to [CycurID Portal Website](https://portal.cycurid.com/) and click Create An Account to start verifying users' identity with CycurID. 

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
MIT License

Copyright (c) 2022 CycurID

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
