# arp-lab-tool

A simple ARP network experiment tool developed by a junior high school student (for legal learning purposes only). 一个由初中生开发的简易ARP网络实验工具（仅用于合法学习用途）。

\## 项目说明 | Project Description

\### 中文

大家好，我是一名初中生，出于对计算机网络知识的兴趣，开发了这个ARP网络实验工具。

⚠️ 重要说明：

1\. 本工具\*\*并非\*\*市面上的arpspoof工具，仅用于个人学习和受控环境下的网络实验（如本地虚拟机、家庭局域网）；

2\. 所有功能仅围绕ARP协议学习设计，严禁用于未授权的网络环境，使用前请确保符合当地法律法规；

3\. 由于本人编程经验有限，代码可能存在很多不足，非常欢迎各位前辈、同学提出改进建议，我的邮箱是：shaojunzhen@outlook.com。



\### English

Hello everyone, I am a junior high school student who developed this ARP network experiment tool out of interest in computer network knowledge.

⚠️ Important Notes:

1\. This tool is \*\*not\*\* the arpspoof tool available on the market, and is only used for personal learning and network experiments in controlled environments (such as local virtual machines, home LANs);

2\. All functions are designed only for learning the ARP protocol, and it is strictly prohibited to use them in unauthorized network environments. Please ensure compliance with local laws and regulations before use;

3\. Due to my limited programming experience, there may be many deficiencies in the code. I warmly welcome seniors and classmates to put forward improvement suggestions. My email is: shaojunzhen@outlook.com.



\## 功能列表 | Feature List

\### 中文

\- 局域网在线设备扫描与类型识别（区分手机/电脑/路由器）；

\- 简单的流量嗅探与数据包捕获（保存为PCAP格式，可通过Wireshark查看）；

\- ARP缓存恢复（用于实验后还原网络环境）；

\- 多版本适配：支持Python2/Python3，提供中英双语界面。



\### English

\- LAN online device scanning and type identification (distinguish mobile phones/computers/routers);

\- Simple traffic sniffing and packet capture (saved in PCAP format, viewable via Wireshark);

\- ARP cache restoration (used to restore the network environment after experiments);

\- Multi-version adaptation: supports Python2/Python3, provides Chinese and English interfaces.



\## 运行要求 | Running Requirements

\### 中文

1\. 安装依赖：Python2需执行 `pip install scapy`，Python3需执行 `pip3 install scapy`；

2\. 必须以管理员/root权限运行（网络抓包需要对应权限）；

3\. 支持系统：Linux/Windows（Windows需手动开启IP转发，具体见脚本内提示）。



\### English

1\. Install dependencies: execute `pip install scapy` for Python2, `pip3 install scapy` for Python3;

2\. Must run with administrator/root privileges (network packet capture requires corresponding permissions);

3\. Supported systems: Linux/Windows (Windows needs to manually enable IP forwarding, see prompts in the script for details).



\## 免责声明 | Disclaimer

\### 中文

本工具仅用于合法的网络学习和实验场景，作者（初中生）不对任何违规使用行为承担责任。

使用本工具即表示您已了解并遵守上述声明，请勿用于任何违法违规的网络活动。



\### English

This tool is only used for legal network learning and experimental scenarios, and the author (a junior high school student) is not responsible for any illegal use.

Using this tool means you have understood and complied with the above statement, and do not use it for any illegal network activities.

