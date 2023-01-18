
### General Information

- The content has blank `codeblocks` to capture log outputs.
- The [Abstract] section will contain information about target, its services/protocols, any credentials found and flags.
- The [Initial Setup] section has variables to be set. Setting initial variables and exporting in all working tabs is important for commands in all sections.
- The [Port Forwarding] section is required if target has to be accessed via tunneling or port forwarding.
- The [Enumeration] section is broken up according to protocols, and is highly important to gain initial foothold and gather as much information/hints for the target. The section contains `general methodologies` for all protocols, along with various tips and useful information.
- The [Exploitation] section has useful hints/tips useful for `privilege escalation`.
- The [Privilege Escalation] section has logs to be gathered in assisting `privilege escalation`.
- The [Post Exploitation] section is intended to capture required command outputs, loots and hashes once `root` privilege is obtained.


### Disclaimer

- The content is only one of many methodologies available for OSCP and general pentesting. Feel free to edit or provide feedback.
- The content is gathered from various sources and my own experiences. Special thanks to [S1ren](https://www.youtube.com/playlist?list=PLJrSyRNlZ2EeqkJa12Tu-Ezun9kXvHufN), [Kashz Jewels](https://kashz.gitbook.io/kashz-jewels/) and [Carlos Polop](https://book.hacktricks.xyz/) for their methodologies.


### Instruction

- Replace `ATTACKERIP` and `TARGETIP` with actual values.
- Delete the sections if not required. This will tidy up the raw report and allows room to focus on actual methodologies to try.
- The [Initial Setup] is where the gathering starts. Setting up 3-4 tabs for the target is much beneficial.
- Once `masscan` and `nmap` scan is completed, retain the required sections under [Enumeration] and remove other sections.
- Remove any informational content and retain only the actual command and its log for final report.


### Report Generation

Refer to `Reporting` for steps to generate PDF report from `md` files using `pandoc` and `latex`.
