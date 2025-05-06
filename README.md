# goTenna v1 and goTenna Mesh Vulnerabilities

# goTenna v1 Vulnerabilities

The inception of goTenna was catalyzed by the communication breakdowns experienced during Hurricane Sandy in 2012, which incapacitated a significant portion of cell towers and internet services across the East Coast. Recognizing the critical need for resilient communication tools in disaster scenarios, siblings Daniela and Jorge Perdomo founded goTenna in 2013. Their mission was to develop a device that could facilitate direct communication between smartphones without relying on existing infrastructure. This led to the release of the original goTenna V1 in 2014—a compact, lightweight device that paired with smartphones via Bluetooth, enabling users to send text messages and share GPS locations over MURS radio frequencies. Designed for off-grid use, the v1 offered a range of up to 4 miles in open environments and proved invaluable for outdoor enthusiasts and emergency responders alike.

<p align="center">
  <img src="https://github.com/user-attachments/assets/b4958525-cfcc-42b6-b7af-9fda729b191e" alt="goTenna v1">
</p>

Several security issues described below were identified in goTenna v1 described below. The vendor discontinued goTenna v1 support in 2024.

## [CVE-2025-32881](https://www.cve.org/CVERecord?id=CVE-2025-32881)
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
CVSS Score 4.6 - CVSS:3.1/AC:L/AV:A/A:N/C:L/I:N/PR:N/S:U/UI:N

[Has vendor confirmed or acknowledged the vulnerability?]  
true

[Discoverer]  
Dale Wooden, Tim Kuester, Erwin Karincic

[Reference]  
https://gotenna.com

---

## [CVE-2025-32882](https://www.cve.org/CVERecord?id=CVE-2025-32882)
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
CVSS Score 5.3 - CVSS:3.1/AC:H/AV:A/A:N/C:N/I:H/PR:N/S:U/UI:N

[Has vendor confirmed or acknowledged the vulnerability?]  
true

[Discoverer]  
Dale Wooden, Tim Kuester, Erwin Karincic

[Reference]  
https://gotenna.com

---



## [CVE-2025-32885](https://www.cve.org/CVERecord?id=CVE-2025-32885)
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
CVSS Score 6.5 - CVSS:3.1/AC:L/AV:A/A:N/C:H/I:N/PR:N/S:U/UI:N

[Has vendor confirmed or acknowledged the vulnerability?]  
true

[Discoverer]  
Dale Wooden, Tim Kuester, Erwin Karincic

[Reference]  
https://gotenna.com

---

## [CVE-2025-32886](https://www.cve.org/CVERecord?id=CVE-2025-32886)
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
CVSS Score 4.0 - CVSS:3.1/AC:L/AV:L/A:N/C:L/I:N/PR:N/S:U/UI:N

[Has vendor confirmed or acknowledged the vulnerability?]  
true

[Discoverer]  
Dale Wooden, Tim Kuester, Erwin Karincic

[Reference]  
https://gotenna.com

---

## [CVE-2025-32887](https://www.cve.org/CVERecord?id=CVE-2025-32887)
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
CVSS Score 7.1 - CVSS:3.1/AC:L/AV:A/A:H/C:L/I:N/PR:N/S:U/UI:N

[Has vendor confirmed or acknowledged the vulnerability?]  
true

[Discoverer]  
Dale Wooden, Tim Kuester, Erwin Karincic

[Reference]  
https://gotenna.com

---


## [CVE-2025-32889](https://www.cve.org/CVERecord?id=CVE-2025-32889)
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
CVSS Score 7.3 - CVSS:3.1/AC:L/AV:L/A:H/C:L/I:L/PR:N/S:U/UI:N

[Has vendor confirmed or acknowledged the vulnerability?]  
true

[Discoverer]  
Clayton Smith, Erwin Karincic

[Reference]  
https://gotenna.com

---

# goTenna Mesh Vulnerabilities

Building upon the foundation laid by the V1, goTenna introduced the Mesh in 2016, marking a significant advancement in off-grid communication technology. Unlike its predecessor, the goTenna Mesh utilized mesh networking capabilities, allowing messages to hop between multiple devices to extend range and reliability. Operating on UHF frequencies, the Mesh enabled decentralized, peer-to-peer communication without the need for cell towers, Wi-Fi, or satellites. This innovation not only enhanced connectivity in remote areas but also provided a scalable solution for group communications during large events or emergencies. The Mesh's ability to relay messages through other devices in the network ensured that users could maintain contact even when separated by considerable distances or challenging terrains. 

<p align="center">
  <img src="https://github.com/user-attachments/assets/c1a511ff-3ad1-431d-a6f7-3df37d1db826" alt="goTenna Mesh">
</p>

Several security issues described below were identified in goTenna Mesh described below. The vendor discontinued goTenna Mesh support in 2024.

## [CVE-2025-32883](https://www.cve.org/CVERecord?id=CVE-2025-32883)
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
CVSS Score 6.5 - CVSS:3.1/AC:L/AV:A/A:N/C:H/I:N/PR:N/S:U/UI:N

[Has vendor confirmed or acknowledged the vulnerability?]  
true

[Discoverer]  
Clayton Smith, Erwin Karincic

[Reference]  
https://gotenna.com

---

## [CVE-2025-32884](https://www.cve.org/CVERecord?id=CVE-2025-32884)
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
CVSS Score 4.3 - CVSS:3.1/AC:L/AV:A/A:N/C:L/I:N/PR:N/S:U/UI:N

[Has vendor confirmed or acknowledged the vulnerability?]  
true

[Discoverer]  
Clayton Smith, Erwin Karincic

[Reference]  
https://gotenna.com

---

## [CVE-2025-32888](https://www.cve.org/CVERecord?id=CVE-2025-32888)
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
CVSS Score 7.3 - CVSS:3.1/AC:L/AV:L/A:H/C:L/I:L/PR:N/S:U/UI:N

[Has vendor confirmed or acknowledged the vulnerability?]  
true

[Discoverer]  
Clayton Smith, Erwin Karincic

[Reference]  
https://gotenna.com

---

## [CVE-2025-32890](https://www.cve.org/CVERecord?id=CVE-2025-32890)
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
CVSS Score 5.3 - CVSS:3.1/AC:H/AV:A/A:N/C:N/I:H/PR:N/S:U/UI:N

[Has vendor confirmed or acknowledged the vulnerability?]  
true

[Discoverer]  
Clayton Smith, Erwin Karincic

[Reference]  
https://gotenna.com

---
