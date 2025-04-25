# goTenna v1 and goTenna Mesh Vulnerabilities

## CVE-2025-32881
[Description]  
An issue was discovered on goTenna v1 devices with app 5.5.3 and firmware 0.25.5. By default, the GID is the user's phone number unless they specifically opt out. A phone number is very sensitive information because it can be tied back to individuals. The app does not encrypt the GID in messages.

[Additional Information]  
This has been discovered and reported to the goTenna (company/vendor) in 2017 and 2018. Our work on their latest hardware version - goTenna Pro with CISA resulted in following ICS advisory - ICSA-24-270-04. When the ICS advisory was released, the vendor fixed the goTenna Pro vulnerabilities. The vendor at the same time discontinued their entire civilian market including goTenna v1 and goTenna Mesh devices.

[VulnerabilityType Other]  
Cleartext Transmission of Sensitive Information CWE-319

[Vendor of Product]  
goTenna

[Affected Product Code Base]  
goTenna (v1) - goTenna App version 5.5.3, goTenna (v1) firmware version 0.25.5

[Affected Component]  
goTenna App and associated goTenna v1 device

[Attack Vectors]  
CVSS 3 /AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N

[Has vendor confirmed or acknowledged the vulnerability?]  
true

[Discoverer]  
Dale Wooden, Tim Kuester, Erwin Karincic

[Reference]  
https://gotenna.com

---

## CVE-2025-32882
[Description]  
An issue was discovered on goTenna v1 devices with app 5.5.3 and firmware 0.25.5. The app uses a custom implementation of encryption without any additional integrity checking mechanisms. This leaves messages malleable to an attacker that can access the message.

[Additional Information]  
This has been discovered and reported to the goTenna (company/vendor) in 2017 and 2018. Our work on their latest hardware version - goTenna Pro with CISA resulted in following ICS advisory - ICSA-24-270-04. When the ICS advisory was released, the vendor fixed the goTenna Pro vulnerabilities. The vendor at the same time discontinued their entire civilian market including goTenna v1 and goTenna Mesh devices.

[VulnerabilityType Other]  
Missing Support for Integrity Check CWE-353

[Vendor of Product]  
goTenna

[Affected Product Code Base]  
goTenna (v1) - goTenna App version 5.5.3, goTenna (v1) firmware version 0.25.5

[Affected Component]  
goTenna App and associated goTenna v1 device

[Attack Vectors]  
CVSS 3 /AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N

[Has vendor confirmed or acknowledged the vulnerability?]  
true

[Discoverer]  
Dale Wooden, Tim Kuester, Erwin Karincic

[Reference]  
https://gotenna.com

---

## CVE-2025-32883
[Description]  
An issue was discovered on goTenna Mesh devices with app 5.5.3 and firmware 1.1.12. The app there makes it possible to inject any custom message (into existing mesh networks) with any GID and Callsign via a software defined radio. This can be exploited if the device is being used in an unencrypted environment or if the cryptography has already been compromised.

[Additional Information]  
This has been discovered and reported to the goTenna (company/vendor) in 2017 and 2018. Our work on their latest hardware version - goTenna Pro with CISA resulted in following ICS advisory - ICSA-24-270-04. When the ICS advisory was released, the vendor fixed the goTenna Pro vulnerabilities. The vendor at the same time discontinued their entire civilian market including goTenna v1 and goTenna Mesh devices.

[VulnerabilityType Other]  
Weak Authentication CWE-1390

[Vendor of Product]  
goTenna

[Affected Product Code Base]  
goTenna Mesh - goTenna App version 5.5.3, goTenna Mesh firmware version 1.1.12

[Affected Component]  
goTenna App and associated goTenna Mesh device

[Attack Vectors]  
CVSS 3 /AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

[Has vendor confirmed or acknowledged the vulnerability?]  
true

[Discoverer]  
Clayton Smith, Erwin Karincic

[Reference]  
https://gotenna.com

---

## CVE-2025-32884
[Description]  
An issue was discovered on goTenna Mesh devices with app 5.5.3 and firmware 1.1.12. By default, a GID is the user's phone number unless they specifically opt out. A phone number is very sensitive information because it can be tied back to individuals. The app does not encrypt the GID in messages.

[Additional Information]  
This has been discovered and reported to the goTenna (company/vendor) in 2017 and 2018. Our work on their latest hardware version - goTenna Pro with CISA resulted in following ICS advisory - ICSA-24-270-04. When the ICS advisory was released, the vendor fixed the goTenna Pro vulnerabilities. The vendor at the same time discontinued their entire civilian market including goTenna v1 and goTenna Mesh devices.

[VulnerabilityType Other]  
Cleartext Transmission of Sensitive Information CWE-319

[Vendor of Product]  
goTenna

[Affected Product Code Base]  
goTenna Mesh - goTenna App version 5.5.3, goTenna Mesh firmware version 1.1.12

[Affected Component]  
goTenna App and associated goTenna Mesh device

[Attack Vectors]  
CVSS 3 /AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N

[Has vendor confirmed or acknowledged the vulnerability?]  
true

[Discoverer]  
Clayton Smith, Erwin Karincic

[Reference]  
https://gotenna.com

---

## CVE-2025-32885
[Description]  
An issue was discovered on goTenna v1 devices with app 5.5.3 and firmware 0.25.5. The app there makes it possible to inject any custom message (into existing v1 networks) with any GID and Callsign via a software defined radio. This can be exploited if the device is being used in an unencrypted environment or if the cryptography has already been compromised.

[Additional Information]  
This has been discovered and reported to the goTenna (company/vendor) in 2017 and 2018. Our work on their latest hardware version - goTenna Pro with CISA resulted in following ICS advisory - ICSA-24-270-04. When the ICS advisory was released, the vendor fixed the goTenna Pro vulnerabilities. The vendor at the same time discontinued their entire civilian market including goTenna v1 and goTenna Mesh devices.

[VulnerabilityType Other]  
Weak Authentication CWE-1390

[Vendor of Product]  
goTenna

[Affected Product Code Base]  
goTenna (v1) - goTenna App version 5.5.3, goTenna (v1) firmware version 0.25.5

[Affected Component]  
goTenna App and associated goTenna v1 device

[Attack Vectors]  
CVSS 3 /AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

[Has vendor confirmed or acknowledged the vulnerability?]  
true

[Discoverer]  
Dale Wooden, Tim Kuester, Erwin Karincic

[Reference]  
https://gotenna.com

---

## CVE-2025-32886
[Description]  
An issue was discovered on goTenna v1 devices with app 5.5.3 and firmware 0.25.5. All packets sent over RF are also sent over UART with USB Shell, allowing someone with local access to gain information about the protocol and intercept sensitive data.

[Additional Information]  
This has been discovered and reported to the goTenna (company/vendor) in 2017 and 2018. Our work on their latest hardware version - goTenna Pro with CISA resulted in following ICS advisory - ICSA-24-270-04. When the ICS advisory was released, the vendor fixed the goTenna Pro vulnerabilities. The vendor at the same time discontinued their entire civilian market including goTenna v1 and goTenna Mesh devices.

[VulnerabilityType Other]  
CWE-923: Improper Restriction of Communication Channel to Intended Endpoints

[Vendor of Product]  
goTenna

[Affected Product Code Base]  
goTenna (v1) - goTenna (v1) firmware version 0.25.5

[Affected Component]  
goTenna v1 device

[Attack Vectors]  
CVSS 3 /AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N

[Has vendor confirmed or acknowledged the vulnerability?]  
true

[Discoverer]  
Dale Wooden, Tim Kuester, Erwin Karincic

[Reference]  
https://gotenna.com

---

## CVE-2025-32887
[Description]  
An issue was discovered on goTenna v1 devices with app 5.5.3 and firmware 0.25.5. A command channel includes the next hop, which can be intercepted and used to break frequency hopping.

[Additional Information]  
This has been discovered and reported to the goTenna (company/vendor) in 2017 and 2018. Our work on their latest hardware version - goTenna Pro with CISA resulted in following ICS advisory - ICSA-24-270-04. When the ICS advisory was released, the vendor fixed the goTenna Pro vulnerabilities. The vendor at the same time discontinued their entire civilian market including goTenna v1 and goTenna Mesh devices.

[VulnerabilityType Other]  
CWE-319: Cleartext Transmission of Sensitive Information

[Vendor of Product]  
goTenna

[Affected Product Code Base]  
goTenna (v1) - goTenna App version 5.5.3, goTenna (v1) firmware version 0.25.5

[Affected Component]  
goTenna App and associated goTenna v1 device

[Attack Vectors]  
CVSS 3 /AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H

[Has vendor confirmed or acknowledged the vulnerability?]  
true

[Discoverer]  
Dale Wooden, Tim Kuester, Erwin Karincic

[Reference]  
https://gotenna.com

---

## CVE-2025-32888
[Description]  
An issue was discovered on goTenna Mesh devices with app 5.5.3 and firmware 1.1.12. The verification token used for sending SMS through a goTenna server is hardcoded in the app.

[Additional Information]  
This has been discovered and reported to the goTenna (company/vendor) in 2017 and 2018. Our work on their latest hardware version - goTenna Pro with CISA resulted in following ICS advisory - ICSA-24-270-04. When the ICS advisory was released, the vendor fixed the goTenna Pro vulnerabilities. The vendor at the same time discontinued their entire civilian market including goTenna v1 and goTenna Mesh devices.

[VulnerabilityType Other]  
CWE-798: Use of Hard-coded Credentials

[Vendor of Product]  
goTenna

[Affected Product Code Base]  
goTenna Mesh - goTenna App version 5.5.3, goTenna Mesh firmware version 1.1.12

[Affected Component]  
goTenna App and associated goTenna Mesh device

[Attack Vectors]  
CVSS 3 /AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H

[Has vendor confirmed or acknowledged the vulnerability?]  
true

[Discoverer]  
Clayton Smith, Erwin Karincic

[Reference]  
https://gotenna.com

---

## CVE-2025-32889
[Description]  
An issue was discovered on goTenna v1 devices with app 5.5.3 and firmware 0.25.5. The verification token used for sending SMS through a goTenna server is hardcoded in the app.

[Additional Information]  
This has been discovered and reported to the goTenna (company/vendor) in 2017 and 2018. Our work on their latest hardware version - goTenna Pro with CISA resulted in following ICS advisory - ICSA-24-270-04. When the ICS advisory was released, the vendor fixed the goTenna Pro vulnerabilities. The vendor at the same time discontinued their entire civilian market including goTenna v1 and goTenna Mesh devices.

[VulnerabilityType Other]  
CWE-798: Use of Hard-coded Credentials

[Vendor of Product]  
goTenna

[Affected Product Code Base]  
goTenna (v1) - goTenna App version 5.5.3, goTenna (v1) firmware version 0.25.5

[Affected Component]  
goTenna App and associated goTenna v1 device

[Attack Vectors]  
CVSS 3 /AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H

[Has vendor confirmed or acknowledged the vulnerability?]  
true

[Discoverer]  
Clayton Smith, Erwin Karincic

[Reference]  
https://gotenna.com

---

## CVE-2025-32890
[Description]  
An issue was discovered on goTenna Mesh devices with app 5.5.3 and firmware 1.1.12. It uses a custom implementation of encryption without any additional integrity checking mechanisms. This leaves messages malleable to an attacker that can access the message.

[Additional Information]  
This has been discovered and reported to the goTenna (company/vendor) in 2017 and 2018. Our work on their latest hardware version - goTenna Pro with CISA resulted in following ICS advisory - ICSA-24-270-04. When the ICS advisory was released, the vendor fixed the goTenna Pro vulnerabilities. The vendor at the same time discontinued their entire civilian market including goTenna v1 and goTenna Mesh devices.

[VulnerabilityType Other]  
Missing Support for Integrity Check CWE-353

[Vendor of Product]  
goTenna

[Affected Product Code Base]  
goTenna Mesh - goTenna App version 5.5.3, goTenna Mesh firmware version 1.1.12

[Affected Component]  
goTenna App and associated goTenna Mesh device

[Attack Vectors]  
CVSS 3 /AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N

[Has vendor confirmed or acknowledged the vulnerability?]  
true

[Discoverer]  
Clayton Smith, Erwin Karincic

[Reference]  
https://gotenna.com

---

