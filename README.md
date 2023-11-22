# Sentinel

[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](https://wazuh.com/community/join-us-on-slack/)
[![Email](https://img.shields.io/badge/email-join-blue.svg)](https://groups.google.com/forum/#!forum/wazuh)
[![Documentation](https://img.shields.io/badge/docs-view-green.svg)](https://documentation.wazuh.com)
[![Documentation](https://img.shields.io/badge/web-view-green.svg)](https://wazuh.com)
[![Coverity](https://scan.coverity.com/projects/10992/badge.svg)](https://scan.coverity.com/projects/wazuh-wazuh)
[![Twitter](https://img.shields.io/twitter/follow/wazuh?style=social)](https://twitter.com/wazuh)
[![YouTube](https://img.shields.io/youtube/views/peTSzcAueEc?style=social)](https://www.youtube.com/watch?v=peTSzcAueEc)


Sentinel is a proprietary cybersecurity platform meticulously engineered for advanced threat prevention, detection, and response. With a focus on safeguarding workloads, Sentinel offers robust protection across diverse environments, including on-premises, virtualized, containerized, and cloud-based infrastructures.

Comprising an intricate framework, the Sentinel solution encompasses an intelligent endpoint security agent strategically deployed across monitored systems. This agent seamlessly collaborates with a centralized management server, efficiently collecting and analyzing data to fortify your security posture.

Moreover, Sentinel boasts seamless integration with the Elastic Stack, enhancing its capabilities by providing a sophisticated search engine and data visualization tool. This integration empowers users with a comprehensive means to navigate and interpret security alerts effectively, ensuring a proactive and insightful approach to cybersecurity management.

## Sentinel capabilities

A concise overview detailing the various applications of Sentinel, our cutting-edge cybersecurity solution.

**Intrusion detection**

Sentinel's vigilant agents conduct thorough scans across monitored systems, meticulously identifying malware, rootkits, and suspicious anomalies. Leveraging a signature-based approach, the server component employs a regular expression engine to scrutinize log data for potential indicators of compromise.

**Log data analysis**

Sentinel's agents proficiently read and forward operating system and application logs to a central manager for meticulous rule-based analysis and secure storage. The rules implemented by Sentinel enhance awareness of system errors, misconfigurations, potential malicious activities, policy violations, and other security and operational concerns.

**File integrity monitoring**

Monitoring the file system, Sentinel adeptly identifies changes in file content, permissions, ownership, and attributes. This capability, complemented by threat intelligence integration, aids in the identification of potential threats or compromised hosts, aligning with regulatory compliance standards like PCI DSS.

**Vulnerability detection**

Sentinel agents dynamically pull software inventory data, correlating it with continuously updated CVE databases to identify vulnerabilities. This automated vulnerability assessment empowers organizations to proactively address weaknesses in critical assets before exploitation.

**Configuration assessment**

Sentinel diligently monitors system and application configurations, ensuring alignment with security policies, standards, and hardening guides. Customizable configuration checks provide tailored alignment with organizational requirements, offering recommendations, references, and regulatory compliance mappings.

**Incident response**

Providing out-of-the-box active responses, Sentinel executes countermeasures to address active threats, including blocking system access from threat sources based on predefined criteria. Additionally, Sentinel facilitates remote command execution, aiding in live forensics and incident response tasks.

**Regulatory compliance**

Sentinel furnishes essential security controls to support compliance with industry standards and regulations. Widely employed in payment processing and financial institutions for PCI DSS (Payment Card Industry Data Security Standard) compliance, Sentinel's interface offers comprehensive reports and dashboards for various regulatory frameworks (e.g. GPG13 or GDPR).

**Cloud security**

Sentinel excels in monitoring cloud infrastructure at an API level, integrating with major cloud providers like Amazon AWS, Azure, and Google Cloud. Rules assessing cloud environment configurations assist in identifying vulnerabilities, bolstering overall cloud security.

**Containers security**

Providing unparalleled visibility into Docker hosts and containers, Sentinel monitors behavior, detects threats, vulnerabilities, and anomalies. Native integration with the Docker engine enables monitoring of images, volumes, network settings, and running containers, ensuring robust security for containerized environments. Sentinel's lightweight and multi-platform agents are widely adopted for monitoring cloud environments at the instance level.

## WUI

The Sentinel WUI provides a powerful user interface for data visualization and analysis. This interface can also be used to manage Sentinel configuration and to monitor its status.

**Modules overview**

![Modules overview](https://github.com/wazuh/wazuh-dashboard-plugins/raw/master/screenshots/app.png)

**Security events**

![Overview](https://github.com/wazuh/wazuh-dashboard-plugins/blob/master/screenshots/app2.png)

**Integrity monitoring**

![Overview](https://github.com/wazuh/wazuh-dashboard-plugins/blob/master/screenshots/app3.png)

**Vulnerability detection**

![Overview](https://github.com/wazuh/wazuh-dashboard-plugins/blob/master/screenshots/app4.png)

**Regulatory compliance**

![Overview](https://github.com/wazuh/wazuh-dashboard-plugins/blob/master/screenshots/app5.png)

**Agents overview**

![Overview](https://github.com/wazuh/wazuh-dashboard-plugins/blob/master/screenshots/app6.png)

**Agent summary**

![Overview](https://github.com/wazuh/wazuh-dashboard-plugins/blob/master/screenshots/app7.png)

## Orchestration

Here you can find all the automation tools maintained by the Wazuh team.

* [Sentinel AWS CloudFormation](https://github.com/wazuh/wazuh-cloudformation)

* [Docker containers](https://github.com/wazuh/wazuh-docker)

* [Sentinel Ansible](https://github.com/wazuh/wazuh-ansible)

* [Sentinel Chef](https://github.com/wazuh/wazuh-chef)

* [Sentinel Puppet](https://github.com/wazuh/wazuh-puppet)

* [Sentinel Kubernetes](https://github.com/wazuh/wazuh-kubernetes)

* [Sentinel Bosh](https://github.com/wazuh/wazuh-bosh)

* [Sentinel Salt](https://github.com/wazuh/wazuh-salt)

## Branches

* `master` branch contains the latest code, be aware of possible bugs on this branch.
* `stable` branch on correspond to the last Wazuh stable version.

## Software and libraries used

|Software|Version|Author|License|
|---|---|---|---|
|[bzip2](https://github.com/libarchive/bzip2)|1.0.8|Julian Seward|BSD License|
|[cJSON](https://github.com/DaveGamble/cJSON)|1.7.12|Dave Gamble|MIT License|
|[cPython](https://github.com/python/cpython)|3.9.9|Guido van Rossum|Python Software Foundation License version 2|
|[cURL](https://github.com/curl/curl)|7.88.1|Daniel Stenberg|MIT License|
|[GoogleTest](https://github.com/google/googletest)|1.11.0|Google Inc.|3-Clause "New" BSD License|
|[jemalloc](https://github.com/jemalloc/jemalloc)|5.2.1|Jason Evans|2-Clause "Simplified" BSD License|
|[libarchive](https://github.com/libarchive/libarchive)|3.5.1|Tim Kientzle|3-Clause "New" BSD License|
|[libdb](https://github.com/yasuhirokimura/db18)|18.1.40|Oracle Corporation|Affero GPL v3|
|[libffi](https://github.com/libffi/libffi)|3.2.1|Anthony Green|MIT License|
|[libpcre2](https://github.com/PCRE2Project/pcre2)|10.34|Philip Hazel|BSD License|
|[libplist](https://github.com/libimobiledevice/libplist)|2.2.0|Aaron Burghardt et al.|GNU Lesser General Public License version 2.1|
|[libYAML](https://github.com/yaml/libyaml)|0.1.7|Kirill Simonov|MIT License|
|[Linux Audit userspace](https://github.com/linux-audit/audit-userspace)|2.8.4|Rik Faith|LGPL (copyleft)|
|[msgpack](https://github.com/msgpack/msgpack-c)|3.1.1|Sadayuki Furuhashi|Boost Software License version 1.0|
|[nlohmann](https://github.com/nlohmann/json)|3.7.3|Niels Lohmann|MIT License|
|[OpenSSL](https://github.com/openssl/openssl)|1.1.1t|OpenSSL Software Foundation|Apache 2.0 License|
|[pacman](https://gitlab.archlinux.org/pacman/pacman)|5.2.2|Judd Vinet|GNU Public License version 2 (copyleft)|
|[popt](https://github.com/rpm-software-management/popt)|1.16|Jeff Johnson & Erik Troan|MIT License|
|[procps](https://gitlab.com/procps-ng/procps)|2.8.3|Brian Edmonds et al.|LGPL (copyleft)|
|[rpm](https://github.com/rpm-software-management/rpm)|4.16.1.3|Marc Ewing & Erik Troan|GNU Public License version 2 (copyleft)|
|[sqlite](https://github.com/sqlite/sqlite)|3.36.0|D. Richard Hipp|Public Domain (no restrictions)|
|[zlib](https://github.com/madler/zlib)|1.2.11|Jean-loup Gailly & Mark Adler|zlib/libpng License|

* [PyPi packages](framework/requirements.txt)

## Documentation

* [Full documentation](http://documentation.wazuh.com)
* [Sentinel installation guide](https://documentation.wazuh.com/current/installation-guide/index.html)

## Get involved

Become part of the [Nexix Security Lab's community](https://nexixsecuritylabs.com/) to learn from other users, participate in discussions, talk to our developers and contribute to the project.

If you want to contribute to our project please don’t hesitate to make pull-requests, submit issues or send commits, we will review all your questions.

You can also join our [Discord community channel](https://wazuh.com/community/join-us-on-slack/) and [mailing list](https://groups.google.com/d/forum/wazuh) by sending an email to [wazuh+subscribe@googlegroups.com](mailto:wazuh+subscribe@googlegroups.com), to ask questions and participate in discussions.

Stay up to date on news, releases, engineering articles and more.

* [Nexix Security Labs website](http://nexixsecuritylabs.com)
* [Linkedin](https://www.linkedin.com/company/wazuh)
* [YouTube](https://www.youtube.com/c/wazuhsecurity)
* [Twitter](https://twitter.com/wazuh)
* [Nexix Security Labs blog](https://nexixsecuritylabs.com/blog/)
* [Discord announcements channel](https://wazuh.com/community/join-us-on-slack/)

## Authors

Nexix Security Labs Copyright (C) 2023 Nexix Security Labs Inc.

Based on the OSSEC project started by Daniel Cid.
