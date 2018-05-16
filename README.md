# Volatility Dashlane Parser (vdp)
### Volatility Plugin to parse Dashlane-Generated passwords from memory dumps.
Tested on Volatility 2.6 and Windows 10 datasets.

Dashlane is a password manager and digital wallet with over seven million users. It’s rated as “Best Overall” by Tom’s Guide, “Editor’s Choice” by PC Mag, and is lauded by Tech Radar, CSO Online and others. Dashlane features AES-256 encryption, Two-Factor Authentication, automatic logins, and compatibility across multiple devices, depending on your license. 

Dashlane's AES-256 encryption only applies to passwords that are stored on their servers. Dashlane published a whitepaper, [Dashlane Security White Paper December 2017](https://www.dashlane.com/download/Dashlane_SecurityWhitePaper_December2017.pdf), which states, 
> Once the user has input his Master Password locally in Dashlane and his user’s data has been deciphered, data is loaded in memory.

This data includes passwords, credit card numbers, receipts, PayPal information, and secure notes, which allows a user to store unformatted text of their choice. 

While there are a multitude of data categories to parse, this version of Dashlane-Parser only collects Dashlane-generated passwords. 

## Dashlane data stored in memory is mostly uniform. For example:
```
<KWGeneratedPassword><KWDataItem key="AuthId"><![CDATA[{F54313B1-CD02-4CE4-870F-D72DE20F14A8}]]></KWDataItem><KWDataItem key="Domain"><![CDATA[google.com]]></KWDataItem><KWDataItem key="GeneratedDate"><![CDATA[1524374582]]></KWDataItem><KWDataItem key="Id"><![CDATA[{B7F7E6FA-3148-4035-85CD-DEDA2868E4B4}]]></KWDataItem><KWDataItem key="LastBackupTime"><![CDATA[1524374675]]></KWDataItem><KWDataItem key="Password"><![CDATA[EpiRCYiE9NyU]]>
```

## From this data we can discern:
Key              | Value
-----------------|----------
AuthId           | {F54313B1-CD02-4CE4-870F-D72DE20F14A8}
Domain           | google.com
GeneratedDate    | 1524374582 (Unix Epoch Time- Sunday, April 22, 2018 5:23:02 AM GMT)
Id               | {B7F7E6FA-3148-4035-85CD-DEDA2868E4B4}
Last Backup Time | 1524374675 (Unix Epoch Time- Sunday, April 22, 2018 5:24:35 AM GMT)
Password         | EpiRCYiE9NyU


The data length from “KWGeneratedPassword” to the “AuthId” value is consistent, and the AuthId and Id UUIDs are of consistent length. The Domain value can vary in length, as can the Password. However, the password’s default length is 12. The mostly structured data, along with their use of brackets allows for easy data parsing. However, corrupted data missing the ending bracket would be collected until an end bracket was found. To prevent this overflow of useless data, the data length is capped for each category.
