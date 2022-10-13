## 目录

*   [**侦察**](#侦察)

    *   [**主动情报收集**](#主动情报收集)

    *   [**被动情报收集**](#被动情报收集)

    *   [**构架**](#构架)

*   [**武器化**](#武器化)

*   [投递](#投递)

    *   [**网络钓鱼**](#网络钓鱼)

    *   [水坑攻击](#水坑攻击)

*   [**命令与控制**](#命令与控制)

    *   [远程访问工具](#远程访问工具)

    *   [**细分**](#细分)

*   [**横向运动**](#横向运动)

*   [**建立立足点**](#建立立足点)

*   [**提升权限**](#提升权限)

    *   [**域升级**](#域升级)

    *   [**本地升级**](#本地升级)

*   [**数据泄露**](#数据泄露)

*   [**杂项**](#杂项)

    *   [**对手仿真**](#对手仿真)

    *   [**无线网络**](#无线网络)

    *   [**嵌入式和外围设备黑客**](#嵌入式和外围设备黑客)

    *   [**团队沟通软件**](#团队沟通软件)

    *   [**日志聚合**](#日志聚合)

    *   [**C# 攻击性框架**](#c-攻击性框架)

    *   [**实验室**](#实验室)

    *   [**脚本**](#脚本)

*   [**参考**](#参考)

## **侦察**

### **主动情报收集**

*   **EyeWitness** 旨在截取网站截图，提供一些服务器标头信息，并在可能的情况下识别默认凭据。 [https://github.com/ChrisTruncer/EyeWitness](https://link.zhihu.com/?target=https://github.com/ChrisTruncer/EyeWitness "https://github.com/ChrisTruncer/EyeWitness")

*   **AWSBucketDump** 是一种快速枚举 AWS S3 存储桶以查找战利品的工具。 [https://github.com/jordanpotti/AWSBucketDump](https://link.zhihu.com/?target=https://github.com/jordanpotti/AWSBucketDump "https://github.com/jordanpotti/AWSBucketDump")

*   **AQUATONE** 是一套用于对域名进行侦察的工具。 [https://github.com/michenriksen/aquatone](https://link.zhihu.com/?target=https://github.com/michenriksen/aquatone "https://github.com/michenriksen/aquatone")

*   **spoofcheck** 检查域是否可以被欺骗的程序。该程序会检查 SPF 和 DMARC 记录中是否存在允许欺骗的弱配置。 [https://github.com/BishopFox/spoofcheck](https://link.zhihu.com/?target=https://github.com/BishopFox/spoofcheck "https://github.com/BishopFox/spoofcheck")

*   **Nmap** 用于发现计算机网络上的主机和服务，从而构建网络的“地图”。 [https://github.com/nmap/nmap](https://link.zhihu.com/?target=https://github.com/nmap/nmap "https://github.com/nmap/nmap")

*   **dnsrecon** 一个工具 DNS 枚举脚本。 [https://github.com/darkoperator/dnsrecon](https://link.zhihu.com/?target=https://github.com/darkoperator/dnsrecon "https://github.com/darkoperator/dnsrecon")

*   **dirsearch** 是一个简单的命令行工具，旨在暴力破解网站中的目录和文件。 [https://github.com/maurosoria/dirsearch](https://link.zhihu.com/?target=https://github.com/maurosoria/dirsearch "https://github.com/maurosoria/dirsearch")

*   **Sn1per** 自动渗透测试侦察扫描仪。 [https://github.com/1N3/Sn1per](https://link.zhihu.com/?target=https://github.com/1N3/Sn1per "https://github.com/1N3/Sn1per")

### **被动情报收集**

*   **Social Mapper** OSINT 社交媒体映射工具，获取名称和图像列表（或 LinkedIn 公司名称），并在多个社交媒体网站上执行大规模的自动目标搜索。不受 API 限制，因为它使用 Selenium 检测浏览器。输出报告以帮助关联跨站点的目标。 [https://github.com/SpiderLabs/social\_mapper](https://link.zhihu.com/?target=https://github.com/SpiderLabs/social_mapper "https://github.com/SpiderLabs/social_mapper")

*   **skiptracer** OSINT 抓取框架，利用 PII 付费专区网站的一些基本 python 网络抓取（BeautifulSoup）来编译关于拉面预算目标的被动信息。 [https://github.com/xillwillx/skiptracer](https://link.zhihu.com/?target=https://github.com/xillwillx/skiptracer "https://github.com/xillwillx/skiptracer")

*   **FOCA** （收集档案的指纹组织）是一种主要用于在其扫描的文档中查找元数据和隐藏信息的工具。 [https://github.com/ElevenPaths/FOCA](https://link.zhihu.com/?target=https://github.com/ElevenPaths/FOCA "https://github.com/ElevenPaths/FOCA")

*   **theHarvester** 是一个从不同公共来源收集子域名、电子邮件地址、虚拟主机、开放端口/横幅和员工姓名的工具。 [https://github.com/laramies/theHarvester](https://link.zhihu.com/?target=https://github.com/laramies/theHarvester "https://github.com/laramies/theHarvester")

*   **Metagoofil** 是一种用于提取目标网站中可用的公共文档（pdf、doc、xls、ppt 等）元数据的工具。 [https://github.com/laramies/metagoofil](https://link.zhihu.com/?target=https://github.com/laramies/metagoofil "https://github.com/laramies/metagoofil")

*   **SimplyEmail** 电子邮件侦察变得快速而简单，并有一个可以构建的框架。 [https://github.com/killswitch-GUI/SimplyEmail](https://link.zhihu.com/?target=https://github.com/killswitch-GUI/SimplyEmail "https://github.com/killswitch-GUI/SimplyEmail")

*   **truffleHog** 通过 git 存储库搜索秘密，深入挖掘提交历史和分支。 [https://github.com/dxa4481/truffleHog](https://link.zhihu.com/?target=https://github.com/dxa4481/truffleHog "https://github.com/dxa4481/truffleHog")

*   **Just-Metadata** 是一种收集和分析有关 IP 地址的元数据的工具。它试图在大型数据集中找到系统之间的关系。 [https://github.com/ChrisTruncer/Just-Metadata](https://link.zhihu.com/?target=https://github.com/ChrisTruncer/Just-Metadata "https://github.com/ChrisTruncer/Just-Metadata")

*   **Typofinder** 显示 IP 地址所在国家/地区的域名拼写错误查找器。 [https://github.com/nccgroup/typofinder](https://link.zhihu.com/?target=https://github.com/nccgroup/typofinder "https://github.com/nccgroup/typofinder")

*   **pwnedOrNot** 是一个 python 脚本，它检查电子邮件帐户是否在数据泄露中受到损害，如果电子邮件帐户受到损害，它会继续查找受损害帐户的密码。 [https://github.com/thewhiteh4t/pwnedOrNot](https://link.zhihu.com/?target=https://github.com/thewhiteh4t/pwnedOrNot "https://github.com/thewhiteh4t/pwnedOrNot")

*   **GitHarvester** 这个工具用于从 GitHub 收集信息，例如 google dork。 [https://github.com/metac0rtex/GitHarvester](https://link.zhihu.com/?target=https://github.com/metac0rtex/GitHarvester "https://github.com/metac0rtex/GitHarvester")

*   **pwndb** 是一个 python 命令行工具，用于使用同名的 Onion 服务搜索泄露的凭据。 [https://github.com/davidtavarez/pwndb/](https://link.zhihu.com/?target=https://github.com/davidtavarez/pwndb/ "https://github.com/davidtavarez/pwndb/")

*   **LinkedInt** LinkedIn 侦察工具。 [https://github.com/vysecurity/LinkedInt](https://link.zhihu.com/?target=https://github.com/vysecurity/LinkedInt "https://github.com/vysecurity/LinkedInt")

*   **CrossLinked** LinkedIn 枚举工具，通过搜索引擎抓取从组织中提取有效员工姓名。 [https://github.com/m8r0wn/CrossLinked](https://link.zhihu.com/?target=https://github.com/m8r0wn/CrossLinked "https://github.com/m8r0wn/CrossLinked")

*   **findomain** 是一个快速的域枚举工具，它使用证书透明度日志和一系列 API。 [https://github.com/Edu4rdSHL/findomain](https://link.zhihu.com/?target=https://github.com/Edu4rdSHL/findomain "https://github.com/Edu4rdSHL/findomain")

### **构架**

*   **Maltego** 是一个独特的平台，旨在为组织拥有和运营的环境提供清晰的威胁图片。 [https://www.paterva.com/web7/downloads.php](https://link.zhihu.com/?target=https://www.paterva.com/web7/downloads.php "https://www.paterva.com/web7/downloads.php")

*   **SpiderFoot** 开源足迹和情报收集工具。 [https://github.com/smicallef/spiderfoot](https://link.zhihu.com/?target=https://github.com/smicallef/spiderfoot "https://github.com/smicallef/spiderfoot")

*   **datasploit** 是一个开源情报框架，用于对公司、人员、电话号码、比特币地址等执行各种侦察技术，聚合所有原始数据，并提供多种格式的数据。 [https://github.com/DataSploit/datasploit](https://link.zhihu.com/?target=https://github.com/DataSploit/datasploit "https://github.com/DataSploit/datasploit")

*   **Recon-ng** 是一个用 Python 编写的全功能 Web 侦察框架。 [https://bitbucket.org/LaNMaSteR53/recon-ng](https://link.zhihu.com/?target=https://bitbucket.org/LaNMaSteR53/recon-ng "https://bitbucket.org/LaNMaSteR53/recon-ng")

## **武器化**

*   **针对 CVE-2018-20250 的WinRAR 远程代码执行** 概念证明漏洞利用。 [https://github.com/WyAtu/CVE-2018-20250](https://link.zhihu.com/?target=https://github.com/WyAtu/CVE-2018-20250 "https://github.com/WyAtu/CVE-2018-20250")

*   CVE-2017-8570 的复合名字概念证明漏洞利用 **。**[https://github.com/rxwx/CVE-2017-8570](https://link.zhihu.com/?target=https://github.com/rxwx/CVE-2017-8570 "https://github.com/rxwx/CVE-2017-8570")

*   **Exploit toolkit CVE-2017-8759** 是一个方便的 python 脚本，它为渗透测试人员和安全研究人员提供了一种快速有效的方法来测试 Microsoft .NET Framework RCE。 [https://github.com/bhdresh/CVE-2017-8759](https://link.zhihu.com/?target=https://github.com/bhdresh/CVE-2017-8759 "https://github.com/bhdresh/CVE-2017-8759")

*   **CVE-2017-11882 漏洞利用最多** 接受超过 17k 字节长的命令/代码。 [https://github.com/unamer/CVE-2017-11882](https://link.zhihu.com/?target=https://github.com/unamer/CVE-2017-11882 "https://github.com/unamer/CVE-2017-11882")

*   **Adobe Flash 漏洞利用** CVE-2018-4878。 [https://github.com/anbai-inc/CVE-2018-4878](https://link.zhihu.com/?target=https://github.com/anbai-inc/CVE-2018-4878 "https://github.com/anbai-inc/CVE-2018-4878")

*   **Exploit toolkit CVE-2017-0199** 是一个方便的 python 脚本，它为渗透测试人员和安全研究人员提供了一种快速有效的方法来测试 Microsoft Office RCE。 [https://github.com/bhdresh/CVE-2017-0199](https://link.zhihu.com/?target=https://github.com/bhdresh/CVE-2017-0199 "https://github.com/bhdresh/CVE-2017-0199")

*   **demiguise** 是 RedTeams 的 HTA 加密工具。 [https://github.com/nccgroup/demiguise](https://link.zhihu.com/?target=https://github.com/nccgroup/demiguise "https://github.com/nccgroup/demiguise")

*   **Office-DDE-Payloads** 脚本和模板的集合，用于生成嵌入了 DDE、无宏命令执行技术的 Office 文档。 [https://github.com/0xdeadbeefJERKY/Office-DDE-Payloads](https://link.zhihu.com/?target=https://github.com/0xdeadbeefJERKY/Office-DDE-Payloads "https://github.com/0xdeadbeefJERKY/Office-DDE-Payloads")

*   **用于对手模拟的CACTUSTORCH** 有效载荷生成。 [https://github.com/mdsecactivebreach/CACTUSTORCH](https://link.zhihu.com/?target=https://github.com/mdsecactivebreach/CACTUSTORCH "https://github.com/mdsecactivebreach/CACTUSTORCH")

*   **SharpShooter** 是一个有效载荷创建框架，用于检索和执行任意 CSharp 源代码。 [https://github.com/mdsecactivebreach/SharpShooter](https://link.zhihu.com/?target=https://github.com/mdsecactivebreach/SharpShooter "https://github.com/mdsecactivebreach/SharpShooter")

*   **Don't kill my cat** 是一种生成混淆 shellcode 的工具，该 shellcode 存储在多语言图像中。该图像是 100% 有效的，也是 100% 有效的 shellcode。 [https://github.com/Mr-Un1k0d3r/DKMC](https://link.zhihu.com/?target=https://github.com/Mr-Un1k0d3r/DKMC "https://github.com/Mr-Un1k0d3r/DKMC")

*   **恶意宏生成器实用** 程序 用于生成混淆宏的简单实用程序设计，其中还包括 AV / Sandboxes 转义机制。 [https://github.com/Mr-Un1k0d3r/MaliciousMacroGenerator](https://link.zhihu.com/?target=https://github.com/Mr-Un1k0d3r/MaliciousMacroGenerator "https://github.com/Mr-Un1k0d3r/MaliciousMacroGenerator")

*   **SCT 混淆器** Cobalt Strike SCT 有效载荷混淆器。 [https://github.com/Mr-Un1k0d3r/SCT-obfuscator](https://link.zhihu.com/?target=https://github.com/Mr-Un1k0d3r/SCT-obfuscator "https://github.com/Mr-Un1k0d3r/SCT-obfuscator")

*   **调用混淆** PowerShell 混淆器。 [https://github.com/danielbohannon/Invoke-Obfuscation](https://link.zhihu.com/?target=https://github.com/danielbohannon/Invoke-Obfuscation "https://github.com/danielbohannon/Invoke-Obfuscation")

*   **Invoke-CradleCrafter** PowerShell 远程下载摇篮生成器和混淆器。 [https://github.com/danielbohannon/Invoke-CradleCrafter](https://link.zhihu.com/?target=https://github.com/danielbohannon/Invoke-CradleCrafter "https://github.com/danielbohannon/Invoke-CradleCrafter")

*   **Invoke-DOSfuscation** cmd.exe 命令混淆生成器和检测测试工具。 [https://github.com/danielbohannon/Invoke-DOSfuscation](https://link.zhihu.com/?target=https://github.com/danielbohannon/Invoke-DOSfuscation "https://github.com/danielbohannon/Invoke-DOSfuscation")

*   **morphHTA** 变形钴打击的邪恶.HTA。 [https://github.com/vysec/morphHTA](https://link.zhihu.com/?target=https://github.com/vysec/morphHTA "https://github.com/vysec/morphHTA")

*   **Unicorn** 是一个简单的工具，用于使用 PowerShell 降级攻击并将 shellcode 直接注入内存。 [https://github.com/trustedsec/unicorn](https://link.zhihu.com/?target=https://github.com/trustedsec/unicorn "https://github.com/trustedsec/unicorn")

*   **Shellter** 是一个动态的 shellcode 注入工具，也是有史以来第一个真正的动态 PE 感染器。 [https://www.shellterproject.com/](https://link.zhihu.com/?target=https://www.shellterproject.com/ "https://www.shellterproject.com/")

*   **EmbedInHTML** 嵌入和隐藏 HTML 文件中的任何文件。 [https://github.com/Arno0x/EmbedInHTML](https://link.zhihu.com/?target=https://github.com/Arno0x/EmbedInHTML "https://github.com/Arno0x/EmbedInHTML")

*   **SigThief** 窃取签名并一次制作一个无效签名。 [https://github.com/secretsquirrel/SigThief](https://link.zhihu.com/?target=https://github.com/secretsquirrel/SigThief "https://github.com/secretsquirrel/SigThief")

*   **Veil** 是一种旨在生成绕过常见反病毒解决方案的 metasploit 有效负载的工具。 [https://github.com/Veil-Framework/Veil](https://link.zhihu.com/?target=https://github.com/Veil-Framework/Veil "https://github.com/Veil-Framework/Veil")

*   **CheckPlease** 沙盒规避模块，用 PowerShell、Python、Go、Ruby、C、C#、Perl 和 Rust 编写。 [https://github.com/Arvanaghi/CheckPlease](https://link.zhihu.com/?target=https://github.com/Arvanaghi/CheckPlease "https://github.com/Arvanaghi/CheckPlease")

*   **Invoke-PSImage** 是一种将 PowerShell 脚本嵌入到 PNG 文件的像素中并生成要执行的 oneliner 的工具。 [https://github.com/peewpw/Invoke-PSImage](https://link.zhihu.com/?target=https://github.com/peewpw/Invoke-PSImage "https://github.com/peewpw/Invoke-PSImage")

*   **LuckyStrike** 一个基于 PowerShell 的实用程序，用于创建恶意 Office 宏文档。仅用于测试或教育目的。 [https://github.com/curi0usJack/luckystrike](https://link.zhihu.com/?target=https://github.com/curi0usJack/luckystrike "https://github.com/curi0usJack/luckystrike")

*   **ClickOnceGenerator** 用于红队的快速恶意 ClickOnceGenerator。默认应用程序是一个简单的 WebBrowser 小部件，它指向您选择的网站。 [https://github.com/Mr-Un1k0d3r/ClickOnceGenerator](https://link.zhihu.com/?target=https://github.com/Mr-Un1k0d3r/ClickOnceGenerator "https://github.com/Mr-Un1k0d3r/ClickOnceGenerator")

*   **macro\_pack** 是 @EmericNasi 的一个工具，用于自动混淆和生成 MS Office 文档、VB 脚本和其他格式，用于渗透测试、演示和社会工程评估。 [https://github.com/sevagas/macro\_pack](https://link.zhihu.com/?target=https://github.com/sevagas/macro_pack "https://github.com/sevagas/macro_pack")

*   **StarFighters** 基于 JavaScript 和 VBScript 的 Empire Launcher。 [https://github.com/Cn33liz/StarFighters](https://link.zhihu.com/?target=https://github.com/Cn33liz/StarFighters "https://github.com/Cn33liz/StarFighters")

*   **nps\_payload** 此脚本将生成有效负载，用于避免基本的入侵检测。它利用了来自几个不同来源的公开展示的技术。 [https://github.com/trustedsec/nps\_payload](https://link.zhihu.com/?target=https://github.com/trustedsec/nps_payload "https://github.com/trustedsec/nps_payload")

*   **SocialEngineeringPayloads** 一组用于凭据盗窃和鱼叉式网络钓鱼攻击的社会工程技巧和有效负载。 [https://github.com/bhdresh/SocialEngineeringPayloads](https://link.zhihu.com/?target=https://github.com/bhdresh/SocialEngineeringPayloads "https://github.com/bhdresh/SocialEngineeringPayloads")

*   **Social-Engineer Toolkit** 是一个为社会工程设计的开源渗透测试框架。 [https://github.com/trustedsec/social-engineer-toolkit](https://link.zhihu.com/?target=https://github.com/trustedsec/social-engineer-toolkit "https://github.com/trustedsec/social-engineer-toolkit")

*   **Phishery** 是一个简单的启用 SSL 的 HTTP 服务器，其主要目的是通过基本身份验证来钓鱼凭据。 [https://github.com/ryhanson/phishery](https://link.zhihu.com/?target=https://github.com/ryhanson/phishery "https://github.com/ryhanson/phishery")

*   **PowerShdll** 使用 rundll32 运行 PowerShell。绕过软件限制。 [https://github.com/p3nt4/PowerShdll](https://link.zhihu.com/?target=https://github.com/p3nt4/PowerShdll "https://github.com/p3nt4/PowerShdll")

*   **Ultimate AppLocker ByPass List** 此存储库的目标是记录绕过 AppLocker 的最常用技术。 [https://github.com/api0cradle/UltimateAppLockerByPassList](https://link.zhihu.com/?target=https://github.com/api0cradle/UltimateAppLockerByPassList "https://github.com/api0cradle/UltimateAppLockerByPassList")

*   **Ruler** 是一个允许您通过 MAPI/HTTP 或 RPC/HTTP 协议远程与 Exchange 服务器交互的工具。 [https://github.com/sensepost/ruler](https://link.zhihu.com/?target=https://github.com/sensepost/ruler "https://github.com/sensepost/ruler")

*   **Generate-Macro** 是一个独立的 PowerShell 脚本，它将生成具有指定负载和持久性方法的恶意 Microsoft Office 文档。 [https://github.com/enigma0x3/Generate-Macro](https://link.zhihu.com/?target=https://github.com/enigma0x3/Generate-Macro "https://github.com/enigma0x3/Generate-Macro")

*   **恶意宏 MSBuild 生成器** 生成恶意宏并通过 MSBuild 应用程序白名单绕过执行 Powershell 或 Shellcode。 [https://github.com/infosecn1nja/MaliciousMacroMSBuild](https://link.zhihu.com/?target=https://github.com/infosecn1nja/MaliciousMacroMSBuild "https://github.com/infosecn1nja/MaliciousMacroMSBuild")

*   **Meta Twin** 被设计为文件资源克隆器。元数据，包括数字签名，从一个文件中提取并注入到另一个文件中。 [https://github.com/threatexpress/metatwin](https://link.zhihu.com/?target=https://github.com/threatexpress/metatwin "https://github.com/threatexpress/metatwin")

*   **WePWNise** 生成独立于架构的 VBA 代码，用于 Office 文档或模板，并自动绕过应用程序控制和漏洞利用缓解软件。 [https://github.com/mwrlabs/wePWNise](https://link.zhihu.com/?target=https://github.com/mwrlabs/wePWNise "https://github.com/mwrlabs/wePWNise")

*   **DotNetToJScript** 一种用于创建 JScript 文件的工具，该文件从内存中加载 .NET v2 程序集。 [https://github.com/tyranid/DotNetToJScript](https://link.zhihu.com/?target=https://github.com/tyranid/DotNetToJScript "https://github.com/tyranid/DotNetToJScript")

*   **PSAmsi** 是一种用于审核和破坏 AMSI 签名的工具。 [https://github.com/cobbr/PSAmsi](https://link.zhihu.com/?target=https://github.com/cobbr/PSAmsi "https://github.com/cobbr/PSAmsi")

*   **反射 DLL 注入** 是一种库注入技术，其中采用反射编程的概念将库从内存加载到主机进程中。 [https://github.com/stephenfewer/ReflectiveDLLInjection](https://link.zhihu.com/?target=https://github.com/stephenfewer/ReflectiveDLLInjection "https://github.com/stephenfewer/ReflectiveDLLInjection")

*   **ps1encode** 用于生成和编码基于 powershell 的 metasploit 有效负载。 [https://github.com/CroweCybersecurity/ps1encode](https://link.zhihu.com/?target=https://github.com/CroweCybersecurity/ps1encode "https://github.com/CroweCybersecurity/ps1encode")

*   **更糟糕的 PDF** 会将正常的 PDF 文件变成恶意的。用于从 Windows 机器窃取 Net-NTLM 哈希。 [https://github.com/3gstudent/Worse-PDF](https://link.zhihu.com/?target=https://github.com/3gstudent/Worse-PDF "https://github.com/3gstudent/Worse-PDF")

*   **SpookFlare** 对绕过安全措施有不同的看法，它让您有机会绕过客户端检测和网络端检测的端点对策。 [https://github.com/hlldz/SpookFlare](https://link.zhihu.com/?target=https://github.com/hlldz/SpookFlare "https://github.com/hlldz/SpookFlare")

*   **GreatSCT** 是一个生成应用程序白名单绕过的开源项目。该工具适用于红队和蓝队。 [https://github.com/GreatSCT/GreatSCT](https://link.zhihu.com/?target=https://github.com/GreatSCT/GreatSCT "https://github.com/GreatSCT/GreatSCT")

*   **nps** 在没有 powershell 的情况下运行 powershell。 [https://github.com/Ben0xA/nps](https://link.zhihu.com/?target=https://github.com/Ben0xA/nps "https://github.com/Ben0xA/nps")

*   **Meterpreter\_Paranoid\_Mode.sh** 允许用户通过检查它所连接的处理程序的证书来保护 Meterpreter 的分阶段/无阶段连接。 [https://github.com/r00t-3xp10it/Meterpreter\_Paranoid\_Mode-SSL](https://link.zhihu.com/?target=https://github.com/r00t-3xp10it/Meterpreter_Paranoid_Mode-SSL "https://github.com/r00t-3xp10it/Meterpreter_Paranoid_Mode-SSL")

*   **后门工厂 (BDF)** 是使用用户所需的 shellcode 修补可执行二进制文件，并继续正常执行预修补状态。 [https://github.com/secretsquirrel/the-backdoor-factory](https://link.zhihu.com/?target=https://github.com/secretsquirrel/the-backdoor-factory "https://github.com/secretsquirrel/the-backdoor-factory")

*   **MacroShop** 一组脚本，以帮助通过 Office 宏交付有效负载。 [https://github.com/khr0x40sh/MacroShop](https://link.zhihu.com/?target=https://github.com/khr0x40sh/MacroShop "https://github.com/khr0x40sh/MacroShop")

*   **UnmanagedPowerShell** 从非托管进程执行 PowerShell。 [https://github.com/leechristensen/UnmanagedPowerShell](https://link.zhihu.com/?target=https://github.com/leechristensen/UnmanagedPowerShell "https://github.com/leechristensen/UnmanagedPowerShell")

*   **evil-ssdp** 欺骗 SSDP 回复网络上 NTLM 哈希的网络钓鱼。创建一个虚假的 UPNP 设备，诱骗用户访问恶意网络钓鱼页面。 [https://gitlab.com/initstring/evil-ssdp](https://link.zhihu.com/?target=https://gitlab.com/initstring/evil-ssdp "https://gitlab.com/initstring/evil-ssdp")

*   **用于制作环境键控有效载荷的Ebowla** 框架。 [https://github.com/Genetic-Malware/Ebowla](https://link.zhihu.com/?target=https://github.com/Genetic-Malware/Ebowla "https://github.com/Genetic-Malware/Ebowla")

*   **make-pdf-embedded** 一个工具，用于创建带有嵌入文件的 PDF 文档。 [https://github.com/DidierStevens/DidierStevensSuite/blob/master/make-pdf-embedded.py](https://link.zhihu.com/?target=https://github.com/DidierStevens/DidierStevensSuite/blob/master/make-pdf-embedded.py "https://github.com/DidierStevens/DidierStevensSuite/blob/master/make-pdf-embedded.py")

*   **avet** (AntiVirusEvasionTool) 的目标是具有使用不同规避技术的可执行文件的 Windows 机器。 [https://github.com/govolution/avet](https://link.zhihu.com/?target=https://github.com/govolution/avet "https://github.com/govolution/avet")

*   **EvilClippy** 用于创建恶意 MS Office 文档的跨平台助手。可以隐藏 VBA 宏、践踏 VBA 代码（通过 P-Code）和混淆宏分析工具。在 Linux、OSX 和 Windows 上运行。 [https://github.com/outflanknl/EvilClippy](https://link.zhihu.com/?target=https://github.com/outflanknl/EvilClippy "https://github.com/outflanknl/EvilClippy")

*   **CallObfuscator** 混淆来自静态分析工具和调试器的 windows api。 [https://github.com/d35ha/CallObfuscator](https://link.zhihu.com/?target=https://github.com/d35ha/CallObfuscator "https://github.com/d35ha/CallObfuscator")

*   **Donut** 是一个 shellcode 生成工具，可以从 .NET 程序集创建与位置无关的 shellcode 有效负载。此 shellcode 可用于将程序集注入任意 Windows 进程。 [https://github.com/TheWover/donut](https://link.zhihu.com/?target=https://github.com/TheWover/donut "https://github.com/TheWover/donut")

## 投递

### **网络钓鱼**

*   **King Phisher** 是一种通过模拟现实世界的网络钓鱼攻击来测试和提高用户意识的工具。 [https://github.com/securestate/king-phisher](https://link.zhihu.com/?target=https://github.com/securestate/king-phisher "https://github.com/securestate/king-phisher")

*   **FiercePhish** 是一个成熟的网络钓鱼框架，用于管理所有网络钓鱼活动。它允许您跟踪单独的网络钓鱼活动、安排电子邮件发送等等。 [https://github.com/Raikia/FiercePhish](https://link.zhihu.com/?target=https://github.com/Raikia/FiercePhish "https://github.com/Raikia/FiercePhish")

*   **ReelPhish** 是一种实时双因素网络钓鱼工具。 [https://github.com/fireeye/ReelPhish/](https://link.zhihu.com/?target=https://github.com/fireeye/ReelPhish/ "https://github.com/fireeye/ReelPhish/")

*   **Gophish** 是一个为企业和渗透测试人员设计的开源网络钓鱼工具包。它提供了快速轻松地设置和执行网络钓鱼活动和安全意识培训的能力。 [https://github.com/gophish/gophish](https://link.zhihu.com/?target=https://github.com/gophish/gophish "https://github.com/gophish/gophish")

*   **CredSniper** 是一个使用 Python 微框架 Flask 和 Jinja2 模板编写的网络钓鱼框架，支持捕获 2FA 令牌。 [https://github.com/ustayready/CredSniper](https://link.zhihu.com/?target=https://github.com/ustayready/CredSniper "https://github.com/ustayready/CredSniper")

*   **PwnAuth** 一个用于启动和管理 OAuth 滥用活动的 Web 应用程序框架。 [https://github.com/fireeye/PwnAuth](https://link.zhihu.com/?target=https://github.com/fireeye/PwnAuth "https://github.com/fireeye/PwnAuth")

*   **网络钓鱼狂热** Ruby on Rails 网络钓鱼框架。 [https://github.com/pentestgeek/phishing-frenzy](https://link.zhihu.com/?target=https://github.com/pentestgeek/phishing-frenzy "https://github.com/pentestgeek/phishing-frenzy")

*   **网络钓鱼** 借口 用于攻击性网络钓鱼活动的借口库。 [https://github.com/L4bF0x/PhishingPretexts](https://link.zhihu.com/?target=https://github.com/L4bF0x/PhishingPretexts "https://github.com/L4bF0x/PhishingPretexts")

*   **Modlishka** 是一个灵活而强大的反向代理，它将使您的道德网络钓鱼活动更上一层楼。 [https://github.com/drk1wi/Modlishka](https://link.zhihu.com/?target=https://github.com/drk1wi/Modlishka "https://github.com/drk1wi/Modlishka")

*   **Evilginx2** 是一个中间人攻击框架，用于任何 Web 服务的网络钓鱼凭证和会话 cookie。 [https://github.com/kgretzky/evilginx2](https://link.zhihu.com/?target=https://github.com/kgretzky/evilginx2 "https://github.com/kgretzky/evilginx2")

### 水坑攻击

*   **BeEF** 是浏览器开发框架的缩写。它是一款专注于网络浏览器的渗透测试工具。 [https://github.com/beefproject/beef](https://link.zhihu.com/?target=https://github.com/beefproject/beef "https://github.com/beefproject/beef")

## **命令与控制**

### 远程访问工具

*   **Cobalt Strike** 是用于对抗模拟和红队作战的软件。 [https://cobaltstrike.com/](https://link.zhihu.com/?target=https://cobaltstrike.com/ "https://cobaltstrike.com/")

*   **Empire** 是一个后开发框架，包括一个纯 PowerShell2.0 Windows 代理和一个纯 Python 2.6/2.7 Linux/OS X 代理。 [https://github.com/EmpireProject/Empire](https://link.zhihu.com/?target=https://github.com/EmpireProject/Empire "https://github.com/EmpireProject/Empire")

*   **Metasploit Framework** 是一个计算机安全项目，它提供有关安全漏洞的信息并帮助进行渗透测试和 IDS 签名开发。 [https://github.com/rapid7/metasploit-framework](https://link.zhihu.com/?target=https://github.com/rapid7/metasploit-framework "https://github.com/rapid7/metasploit-framework")

*   **SILENTTRINITY** 由 Python、IronPython、C#/.NET 提供支持的后利用代理。 [https://github.com/byt3bl33d3r/SILENTTRINITY](https://link.zhihu.com/?target=https://github.com/byt3bl33d3r/SILENTTRINITY "https://github.com/byt3bl33d3r/SILENTTRINITY") [\_](https://link.zhihu.com/?target=https://github.com/byt3bl33d3r/SILENTTRINITY "_") [\_](https://link.zhihu.com/?target=https://github.com/byt3bl33d3r/SILENTTRINITY "_")

*   **Pupy** 是一个开源、跨平台（Windows、Linux、OSX、Android）的远程管理和后期开发工具，主要用 python 编写。 [https://github.com/n1nj4sec/pupy](https://link.zhihu.com/?target=https://github.com/n1nj4sec/pupy "https://github.com/n1nj4sec/pupy")

*   **Koadic** 或 COM 命令与控制，是一种 Windows 后利用 rootkit，类似于其他渗透测试工具，如 Meterpreter 和 Powershell Empire。 [https://github.com/zerosum0x0/koadic](https://link.zhihu.com/?target=https://github.com/zerosum0x0/koadic "https://github.com/zerosum0x0/koadic")

*   **PoshC2** 是一个完全用 PowerShell 编写的代理感知 C2 框架，可帮助渗透测试人员进行红队、后利用和横向移动。 [https://github.com/nettitude/PoshC2\_Python](https://link.zhihu.com/?target=https://github.com/nettitude/PoshC2_Python "https://github.com/nettitude/PoshC2_Python")

*   **Gcat** 一个隐蔽的基于 Python 的后门，它使用 Gmail 作为命令和控制服务器。 [https://github.com/byt3bl33d3r/gcat](https://link.zhihu.com/?target=https://github.com/byt3bl33d3r/gcat "https://github.com/byt3bl33d3r/gcat")

*   **TrevorC2** 是一个合法的网站（可浏览），它通过隧道客户端/服务器通信来执行隐蔽的命令。 [https://github.com/trustedsec/trevorc2](https://link.zhihu.com/?target=https://github.com/trustedsec/trevorc2 "https://github.com/trustedsec/trevorc2")

*   **Merlin** 是一个用 golang 编写的跨平台的 HTTP/2 命令和控制服务器和代理。 [https://github.com/Ne0nd0g/merlin](https://link.zhihu.com/?target=https://github.com/Ne0nd0g/merlin "https://github.com/Ne0nd0g/merlin")

*   **Quasar** 是一个用 C# 编码的快速、轻量级的远程管理工具。Quasar 提供高稳定性和易于使用的用户界面，是您的完美远程管理解决方案。 [https://github.com/quasar/QuasarRAT](https://link.zhihu.com/?target=https://github.com/quasar/QuasarRAT "https://github.com/quasar/QuasarRAT")

*   **Covenant** 是一个 .NET 命令和控制框架，旨在突出 .NET 的攻击面，使攻击性 .NET 交易的使用更容易，并作为红队人员的协作命令和控制平台。 [https://github.com/cobbr/Covenant](https://link.zhihu.com/?target=https://github.com/cobbr/Covenant "https://github.com/cobbr/Covenant")

*   **FactionC2** 是一个 C2 框架，它使用基于 websockets 的 API，允许与代理和传输进行交互。 [https://github.com/FactionC2/](https://link.zhihu.com/?target=https://github.com/FactionC2/ "https://github.com/FactionC2/")

*   **DNScat2** 是一个旨在通过 DNS 协议创建加密命令和控制 (C\&C) 通道的工具。 [https://github.com/iagox86/dnscat2](https://link.zhihu.com/?target=https://github.com/iagox86/dnscat2 "https://github.com/iagox86/dnscat2")

*   **Sliver** 是一个通用的跨平台植入框架，支持 C2 over Mutual-TLS、HTTP(S) 和 DNS。 [https://github.com/BishopFox/sliver](https://link.zhihu.com/?target=https://github.com/BishopFox/sliver "https://github.com/BishopFox/sliver")

*   **EvilOSX** 适用于 macOS / OS X 的邪恶 RAT（远程管理工具）。 [https://github.com/Marten4n6/EvilOSX](https://link.zhihu.com/?target=https://github.com/Marten4n6/EvilOSX "https://github.com/Marten4n6/EvilOSX")

*   **EggShell** 是一个用 Python 编写的利用后监控工具。它为您提供了一个命令行会话，在您和目标机器之间具有额外的功能。 [https://github.com/neoneggplant/EggShell](https://link.zhihu.com/?target=https://github.com/neoneggplant/EggShell "https://github.com/neoneggplant/EggShell")

### **细分**

*   **快速攻击基础设施 (RAI)** 红队基础设施……快速……快速……简化 红队操作中最乏味的阶段之一通常是基础设施设置。这通常需要团队服务器或控制器、域、重定向器和网络钓鱼服务器。 [https://github.com/obscuritylabs/RAI](https://link.zhihu.com/?target=https://github.com/obscuritylabs/RAI "https://github.com/obscuritylabs/RAI")

*   **Red Baron** 是一组用于 Terraform 的模块和自定义/第三方提供商，它试图为红队自动创建弹性、一次性、安全和敏捷的基础设施。 [https://github.com/byt3bl33d3r/Red-Baron](https://link.zhihu.com/?target=https://github.com/byt3bl33d3r/Red-Baron "https://github.com/byt3bl33d3r/Red-Baron")

*   **EvilURL** 为 IDN Homograph Attack 生成 unicode 邪恶域并检测它们。 [https://github.com/UndeadSec/EvilURL](https://link.zhihu.com/?target=https://github.com/UndeadSec/EvilURL "https://github.com/UndeadSec/EvilURL")

*   **Domain Hunter** 检查过期域、bluecoat 分类和 [http://Archive.org](https://link.zhihu.com/?target=http://Archive.org "http://Archive.org") 历史，以确定适合网络钓鱼和 C2 域名的候选者。 [https://github.com/threatexpress/domainhunter](https://link.zhihu.com/?target=https://github.com/threatexpress/domainhunter "https://github.com/threatexpress/domainhunter")

*   **PowerDNS** 是一个简单的概念证明，用于演示仅使用 DNS 执行 PowerShell 脚本。 [https://github.com/mdsecactivebreach/PowerDNS](https://link.zhihu.com/?target=https://github.com/mdsecactivebreach/PowerDNS "https://github.com/mdsecactivebreach/PowerDNS")

*   **Chameleon** 是一种逃避代理分类的工具。 [https://github.com/mdsecactivebreach/Chameleon](https://link.zhihu.com/?target=https://github.com/mdsecactivebreach/Chameleon "https://github.com/mdsecactivebreach/Chameleon")

*   **CatMyFish** 搜索可在红队参与期间使用的分类域。非常适合为您的 Cobalt Strike 信标 C\&C 设置白名单域。 [https://github.com/Mr-Un1k0d3r/CatMyFish](https://link.zhihu.com/?target=https://github.com/Mr-Un1k0d3r/CatMyFish "https://github.com/Mr-Un1k0d3r/CatMyFish")

*   **Malleable C2** 是一种特定领域的语言，用于重新定义 Beacon 通信中的指标。 [https://github.com/rsmudge/Malleable-C2-Profiles](https://link.zhihu.com/?target=https://github.com/rsmudge/Malleable-C2-Profiles "https://github.com/rsmudge/Malleable-C2-Profiles")

*   **Malleable-C2-Randomizer** 此脚本通过使用元语言随机化 Cobalt Strike Malleable C2 配置文件，希望减少标记基于签名的检测控件的机会。 [https://github.com/bluscreenofjeff/Malleable-C2-Randomizer](https://link.zhihu.com/?target=https://github.com/bluscreenofjeff/Malleable-C2-Randomizer "https://github.com/bluscreenofjeff/Malleable-C2-Randomizer")

*   **FindFrontableDomains** 搜索潜在的可前端域。 [https://github.com/rvrsh3ll/FindFrontableDomains](https://link.zhihu.com/?target=https://github.com/rvrsh3ll/FindFrontableDomains "https://github.com/rvrsh3ll/FindFrontableDomains")

*   **Postfix-Server-Setup** 设置网络钓鱼服务器是一个非常漫长而乏味的过程。设置可能需要数小时，并且可能会在几分钟内受到影响。 [https://github.com/n0pe-sled/Postfix-Server-Setup](https://link.zhihu.com/?target=https://github.com/n0pe-sled/Postfix-Server-Setup "https://github.com/n0pe-sled/Postfix-Server-Setup")

*   **DomainFronting** 按 CDN 列出 Domain Frontable Domains 的列表。 [https://github.com/vysec/DomainFrontingLists](https://link.zhihu.com/?target=https://github.com/vysec/DomainFrontingLists "https://github.com/vysec/DomainFrontingLists")

*   **Apache2-Mod-Rewrite-Setup** 在您的基础设施中快速实施 Mod-Rewrite。 [https://github.com/n0pe-sled/Apache2-Mod-Rewrite-Setup](https://link.zhihu.com/?target=https://github.com/n0pe-sled/Apache2-Mod-Rewrite-Setup "https://github.com/n0pe-sled/Apache2-Mod-Rewrite-Setup")

*   **mod\_rewrite 规则** 来规避供应商沙箱。 [https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10](https://link.zhihu.com/?target=https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10 "https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10")

*   **external\_c2 framework** 一个 python 框架，用于与 Cobalt Strike 的 External C2 一起使用。 [https://github.com/Und3rf10w/external\_c2\_framework](https://link.zhihu.com/?target=https://github.com/Und3rf10w/external_c2_framework "https://github.com/Und3rf10w/external_c2_framework")

*   **Malleable-C2-Profiles** 使用 Cobalt Strike [https://www.cobaltstrike.com/](https://link.zhihu.com/?target=https://www.cobaltstrike.com/ "https://www.cobaltstrike.com/")在不同项目中使用的配置文件集合。 [https://github.com/xx0hcd/Malleable-C2-Profiles](https://link.zhihu.com/?target=https://github.com/xx0hcd/Malleable-C2-Profiles "https://github.com/xx0hcd/Malleable-C2-Profiles")

*   **ExternalC2** 一个库，用于将通信通道与 Cobalt Strike External C2 服务器集成。 [https://github.com/ryhanson/ExternalC2](https://link.zhihu.com/?target=https://github.com/ryhanson/ExternalC2 "https://github.com/ryhanson/ExternalC2")

*   **cs2modrewrite** 用于将 Cobalt Strike 配置文件转换为 modrewrite 脚本的工具。 [https://github.com/threatexpress/cs2modrewrite](https://link.zhihu.com/?target=https://github.com/threatexpress/cs2modrewrite "https://github.com/threatexpress/cs2modrewrite")

*   **e2modrewrite** 用于将 Empire 配置文件转换为 Apache modrewrite 脚本的工具。 [https://github.com/infosecn1nja/e2modrewrite](https://link.zhihu.com/?target=https://github.com/infosecn1nja/e2modrewrite "https://github.com/infosecn1nja/e2modrewrite")

*   用于设置 CobaltStrike 重定向器（nginx 反向代理、letsencrypt）的 **redi自动化脚本。**[https://github.com/taherio/redi](https://link.zhihu.com/?target=https://github.com/taherio/redi "https://github.com/taherio/redi")

*   **cat-sites** 用于分类的站点库。 [https://github.com/audrummer15/cat-sites](https://link.zhihu.com/?target=https://github.com/audrummer15/cat-sites "https://github.com/audrummer15/cat-sites")

*   **ycsm** 是使用 nginx 反向代理和letsencrypt 的弹性重定向器的快速脚本安装，与一些流行的Post-Ex 工具（Cobalt Strike、Empire、Metasploit、PoshC2）兼容。 [https://github.com/infosecn1nja/ycsm](https://link.zhihu.com/?target=https://github.com/infosecn1nja/ycsm "https://github.com/infosecn1nja/ycsm")

*   **域前端 Google App Engine**。 [https://github.com/redteam-cyberark/Google-Domain-fronting](https://link.zhihu.com/?target=https://github.com/redteam-cyberark/Google-Domain-fronting "https://github.com/redteam-cyberark/Google-Domain-fronting")

*   **DomainFrontDiscover** 用于查找域前端 CloudFront 域的脚本和结果。 [https://github.com/peewpw/DomainFrontDiscover](https://link.zhihu.com/?target=https://github.com/peewpw/DomainFrontDiscover "https://github.com/peewpw/DomainFrontDiscover")

*   **自动化帝国基础设施**[https://github.com/bneg/RedTeam-Automation](https://link.zhihu.com/?target=https://github.com/bneg/RedTeam-Automation "https://github.com/bneg/RedTeam-Automation")

*   **使用 NGINX提供随机有效** 负载。 [https://gist.github.com/jivoi/a33ace2e25515a31aa2ffbae246d98c9](https://link.zhihu.com/?target=https://gist.github.com/jivoi/a33ace2e25515a31aa2ffbae246d98c9 "https://gist.github.com/jivoi/a33ace2e25515a31aa2ffbae246d98c9")

*   **meek** 是 Tor 的一种抗阻塞可插拔传输。它将数据流编码为一系列 HTTPS 请求和响应。 [https://github.com/arlolra/meek](https://link.zhihu.com/?target=https://github.com/arlolra/meek "https://github.com/arlolra/meek")

*   **CobaltStrike-ToolKit CobaltStrike 的** 一些有用脚本。 [https://github.com/killswitch-GUI/CobaltStrike-ToolKit](https://link.zhihu.com/?target=https://github.com/killswitch-GUI/CobaltStrike-ToolKit "https://github.com/killswitch-GUI/CobaltStrike-ToolKit")

*   **mkhtaccess\_red** 自动生成一个 HTaccess 来传递有效载荷——自动从已知的沙箱公司/来源中提取 ips/nets/etc，并将它们重定向到一个良性有效载荷。 [https://github.com/violentlydave/mkhtaccess\_red](https://link.zhihu.com/?target=https://github.com/violentlydave/mkhtaccess_red "https://github.com/violentlydave/mkhtaccess_red")

*   **RedFile** 一个烧瓶 wsgi 应用程序，它提供智能文件，非常适合提供条件 RedTeam 有效负载。 [https://github.com/outflanknl/RedFile](https://link.zhihu.com/?target=https://github.com/outflanknl/RedFile "https://github.com/outflanknl/RedFile")

*   **keyserver** 轻松提供 HTTP 和 DNS 密钥以提供适当的有效负载保护。 [https://github.com/leoloobeek/keyserver](https://link.zhihu.com/?target=https://github.com/leoloobeek/keyserver "https://github.com/leoloobeek/keyserver")

*   **DoHC2** 允许通过基于 HTTPS 的 DNS (DoH) 将来自 Ryan Hanson ( [https://github.com/ryhanson/ExternalC2](https://link.zhihu.com/?target=https://github.com/ryhanson/ExternalC2 "https://github.com/ryhanson/ExternalC2") ) 的 ExternalC2 库用于命令和控制 (C2)。这是为流行的对手模拟和红队操作软件 Cobalt Strike ( [https://www.cobaltstrike.com](https://link.zhihu.com/?target=https://www.cobaltstrike.com/ "https://www.cobaltstrike.com") ) 而构建的。 [https://github.com/SpiderLabs/DoHC2](https://link.zhihu.com/?target=https://github.com/SpiderLabs/DoHC2 "https://github.com/SpiderLabs/DoHC2")

*   **HTran** 是一个连接保镖，一种代理服务器。一个“监听器”程序被悄悄入侵到 Internet 上任何地方的毫无戒心的主机上。 [https://github.com/HiwinCN/HTran](https://link.zhihu.com/?target=https://github.com/HiwinCN/HTran "https://github.com/HiwinCN/HTran")

## **横向运动**

*   **CrackMapExec** 是用于渗透测试网络的瑞士军刀。 [https://github.com/byt3bl33d3r/CrackMapExec](https://link.zhihu.com/?target=https://github.com/byt3bl33d3r/CrackMapExec "https://github.com/byt3bl33d3r/CrackMapExec")

*   **PowerLessShell** 依靠 MSBuild.exe 远程执行 PowerShell 脚本和命令，而无需生成 powershell.exe。 [https://github.com/Mr-Un1k0d3r/PowerLessShell](https://link.zhihu.com/?target=https://github.com/Mr-Un1k0d3r/PowerLessShell "https://github.com/Mr-Un1k0d3r/PowerLessShell")

*   **GoFetch** 是一个自动执行由 BloodHound 应用程序生成的攻击计划的工具。 [https://github.com/GoFetchAD/GoFetch](https://link.zhihu.com/?target=https://github.com/GoFetchAD/GoFetch "https://github.com/GoFetchAD/GoFetch")

*   **ANGRYPUPPY CobaltStrike 中** 的猎犬攻击路径自动化。 [https://github.com/vysec/ANGRYPUPPY](https://link.zhihu.com/?target=https://github.com/vysec/ANGRYPUPPY "https://github.com/vysec/ANGRYPUPPY")

*   **DeathStar** 是一个 Python 脚本，它使用 Empire 的 RESTful API 使用各种技术在 Active Directory 环境中自动获得域管理员权限。 [https://github.com/byt3bl33d3r/DeathStar](https://link.zhihu.com/?target=https://github.com/byt3bl33d3r/DeathStar "https://github.com/byt3bl33d3r/DeathStar")

*   **SharpHound** C# 重写 BloodHound Ingestor。 [https://github.com/BloodHoundAD/SharpHound](https://link.zhihu.com/?target=https://github.com/BloodHoundAD/SharpHound "https://github.com/BloodHoundAD/SharpHound")

*   [**BloodHound.py**](http://BloodHound.py "BloodHound.py") 是一个基于 Python 的 BloodHound 摄取器，基于 Impacket。 [https://github.com/fox-it/BloodHound.py](https://link.zhihu.com/?target=https://github.com/fox-it/BloodHound.py "https://github.com/fox-it/BloodHound.py")

*   **Responder** 是 LLMNR、NBT-NS 和 MDNS 毒药，内置 HTTP/SMB/MSSQL/FTP/LDAP 流氓身份验证服务器，支持 NTLMv1/NTLMv2/LMv2、扩展安全 NTLMSSP 和基本 HTTP 身份验证。 [https://github.com/SpiderLabs/Responder](https://link.zhihu.com/?target=https://github.com/SpiderLabs/Responder "https://github.com/SpiderLabs/Responder")

*   **SessionGopher** 是一个 PowerShell 工具，它使用 WMI 为 WinSCP、PuTTY、SuperPuTTY、FileZilla 和 Microsoft 远程桌面等远程访问工具提取保存的会话信息。它可以远程或本地运行。 [https://github.com/fireeye/SessionGopher](https://link.zhihu.com/?target=https://github.com/fireeye/SessionGopher "https://github.com/fireeye/SessionGopher")

*   **PowerSploit** 是 Microsoft PowerShell 模块的集合，可用于在评估的所有阶段帮助渗透测试人员。 [https://github.com/PowerShellMafia/PowerSploit](https://link.zhihu.com/?target=https://github.com/PowerShellMafia/PowerSploit "https://github.com/PowerShellMafia/PowerSploit")

*   **Nishang** 是一个框架和脚本和有效负载的集合，它支持使用 PowerShell 进行攻击性安全、渗透测试和红队。Nishang 在渗透测试的所有阶段都很有用。 [https://github.com/samratashok/nishang](https://link.zhihu.com/?target=https://github.com/samratashok/nishang "https://github.com/samratashok/nishang")

*   **Inveigh** 是一个 Windows PowerShell LLMNR/mDNS/NBNS spoofer/man-in-the-middle 工具。 [https://github.com/Kevin-Robertson/Inveigh](https://link.zhihu.com/?target=https://github.com/Kevin-Robertson/Inveigh "https://github.com/Kevin-Robertson/Inveigh")

*   **PowerUpSQL** 一个用于攻击 SQL Server 的 PowerShell 工具包。 [https://github.com/NetSPI/PowerUpSQL](https://link.zhihu.com/?target=https://github.com/NetSPI/PowerUpSQL "https://github.com/NetSPI/PowerUpSQL")

*   **MailSniper** 是一种渗透测试工具，用于在 Microsoft Exchange 环境中通过电子邮件搜索特定术语（密码、内部情报、网络架构信息等）。 [https://github.com/dafthack/MailSniper](https://link.zhihu.com/?target=https://github.com/dafthack/MailSniper "https://github.com/dafthack/MailSniper")

*   **DomainPasswordSpray** 是一个用 PowerShell 编写的工具，用于对域用户执行密码喷射攻击。 [https://github.com/dafthack/DomainPasswordSpray](https://link.zhihu.com/?target=https://github.com/dafthack/DomainPasswordSpray "https://github.com/dafthack/DomainPasswordSpray")

*   **WMIOps** 是一个 powershell 脚本，它使用 WMI 在 Windows 环境中对本地或远程主机执行各种操作。它主要设计用于渗透测试或红队活动。 [https://github.com/ChrisTruncer/WMIOps](https://link.zhihu.com/?target=https://github.com/ChrisTruncer/WMIOps "https://github.com/ChrisTruncer/WMIOps")

*   **Mimikatz** 是一个开源实用程序，可以从 Windows lsass 查看凭据信息。 [https://github.com/gentilkiwi/mimikatz](https://link.zhihu.com/?target=https://github.com/gentilkiwi/mimikatz "https://github.com/gentilkiwi/mimikatz")

*   **LaZagne** 项目是一个开源应用程序，用于检索存储在本地计算机上的大量密码。 [https://github.com/AlessandroZ/LaZagne](https://link.zhihu.com/?target=https://github.com/AlessandroZ/LaZagne "https://github.com/AlessandroZ/LaZagne")

*   **mimipenguin** 一个从当前 linux 桌面用户转储登录密码的工具。改编自流行的 Windows 工具 mimikatz 背后的想法。 [https://github.com/huntergregal/mimipenguin](https://link.zhihu.com/?target=https://github.com/huntergregal/mimipenguin "https://github.com/huntergregal/mimipenguin")

*   **PsExec** 是一种轻量级 telnet 替代品，可让您在其他系统上执行进程，并与控制台应用程序完全交互，而无需手动安装客户端软件。 [https://docs.microsoft.com/en-us/sysinternals/downloads/psexec](https://link.zhihu.com/?target=https://docs.microsoft.com/en-us/sysinternals/downloads/psexec "https://docs.microsoft.com/en-us/sysinternals/downloads/psexec")

*   **KeeThief** 允许从内存中提取 KeePass 2.X 密钥材料，以及 KeePass 触发系统的后门和枚举。 [https://github.com/HarmJ0y/KeeThief](https://link.zhihu.com/?target=https://github.com/HarmJ0y/KeeThief "https://github.com/HarmJ0y/KeeThief")

*   **PSAttack** 将 infosec powershell 社区中的一些最佳项目组合到一个自包含的自定义 PowerShell 控制台中。 [https://github.com/jaredhaight/PSAttack](https://link.zhihu.com/?target=https://github.com/jaredhaight/PSAttack "https://github.com/jaredhaight/PSAttack")

*   **内部独白攻击** 在不接触 LSASS 的情况下检索 NTLM 哈希。 [https://github.com/eladshamir/Internal-Monologue](https://link.zhihu.com/?target=https://github.com/eladshamir/Internal-Monologue "https://github.com/eladshamir/Internal-Monologue")

*   **Impacket** 是用于处理网络协议的 Python 类的集合。Impacket 专注于为数据包和某些协议（例如 NMB、SMB1-3 和 MS-DCERPC）提供协议实现本身的低级编程访问。 [https://github.com/CoreSecurity/impacket](https://link.zhihu.com/?target=https://github.com/CoreSecurity/impacket "https://github.com/CoreSecurity/impacket")

*   如果您在内部网络上但在 AD 环境之外， **icebreaker会获取明文 Active Directory 凭据。**[https://github.com/DanMcInerney/icebreaker](https://link.zhihu.com/?target=https://github.com/DanMcInerney/icebreaker "https://github.com/DanMcInerney/icebreaker")

*   **以土地为生 二进制文件和脚本（现在还有库）** 这些列表的目标是记录可用于其他目的的每个二进制文件、脚本和库，而不是它们的设计目的。 [https://github.com/api0cradle/LOLBAS](https://link.zhihu.com/?target=https://github.com/api0cradle/LOLBAS "https://github.com/api0cradle/LOLBAS")

*   **WSUSpendu** 用于受感染的 WSUS 服务器，以将威胁扩展到客户端。 [https://github.com/AlsidOfficial/WSUSpendu](https://link.zhihu.com/?target=https://github.com/AlsidOfficial/WSUSpendu "https://github.com/AlsidOfficial/WSUSpendu")

*   **Evilgrade** 是一个模块化框架，允许用户通过注入虚假更新来利用糟糕的升级实现。 [https://github.com/infobyte/evilgrade](https://link.zhihu.com/?target=https://github.com/infobyte/evilgrade "https://github.com/infobyte/evilgrade")

*   **NetRipper** 是一个针对 Windows 系统的后期利用工具，它使用 API 挂钩来拦截来自低权限用户的网络流量和加密相关功能，能够在加密之前/解密之后捕获纯文本流量和加密流量。 [https://github.com/NytroRST/NetRipper](https://link.zhihu.com/?target=https://github.com/NytroRST/NetRipper "https://github.com/NytroRST/NetRipper")

*   使用 DCOM 和 HTA 的 **LethalHTA横向运动技术。**[https://github.com/codewhitesec/LethalHTA](https://link.zhihu.com/?target=https://github.com/codewhitesec/LethalHTA "https://github.com/codewhitesec/LethalHTA")

*   **Invoke-PowerThIEf** 一个 Internet Explorer Post Exploitation 库。 [https://github.com/nettitude/Invoke-PowerThIEf](https://link.zhihu.com/?target=https://github.com/nettitude/Invoke-PowerThIEf "https://github.com/nettitude/Invoke-PowerThIEf")

*   **RedSnarf** 是用于 Windows 环境的笔测试/红队工具。 [https://github.com/nccgroup/redsnarf](https://link.zhihu.com/?target=https://github.com/nccgroup/redsnarf "https://github.com/nccgroup/redsnarf")

*   **HoneypotBuster** Microsoft PowerShell 模块，专为红队设计，可用于在网络或主机上查找蜜罐和蜜令牌。 [https://github.com/JavelinNetworks/HoneypotBuster](https://link.zhihu.com/?target=https://github.com/JavelinNetworks/HoneypotBuster "https://github.com/JavelinNetworks/HoneypotBuster")

*   **PAExec** 允许您在远程 Windows 计算机上启动 Windows 程序，而无需先在远程计算机上安装软件。 [https://www.poweradmin.com/paexec/](https://link.zhihu.com/?target=https://www.poweradmin.com/paexec/ "https://www.poweradmin.com/paexec/")

## **建立立足点**

*   **Tunna** 是一组工具，它将通过 HTTP 包装和隧道任何 TCP 通信。它可用于绕过完全防火墙环境中的网络限制。 [https://github.com/SECFORCE/Tunna](https://link.zhihu.com/?target=https://github.com/SECFORCE/Tunna "https://github.com/SECFORCE/Tunna")

*   **reGeorg** 是 reDuh 的继任者，pwn 一个堡垒网络服务器并通过 DMZ 创建 SOCKS 代理。枢轴和 pwn。 [https://github.com/sensepost/reGeorg](https://link.zhihu.com/?target=https://github.com/sensepost/reGeorg "https://github.com/sensepost/reGeorg")

*   **Blade** 是一个基于控制台的 webshell 连接工具，目前正在开发中，旨在成为 Chooper 的替代选择。 [https://github.com/wonderqs/Blade](https://link.zhihu.com/?target=https://github.com/wonderqs/Blade "https://github.com/wonderqs/Blade")

*   **TinyShell** Web Shell 框架。 [https://github.com/threatexpress/tinyshell](https://link.zhihu.com/?target=https://github.com/threatexpress/tinyshell "https://github.com/threatexpress/tinyshell")

*   **PowerLurk** 是一个用于构建恶意 WMI 事件订阅的 PowerShell 工具集。 [https://github.com/Sw4mpf0x/PowerLurk](https://link.zhihu.com/?target=https://github.com/Sw4mpf0x/PowerLurk "https://github.com/Sw4mpf0x/PowerLurk")

*   **DAMP** 自主 ACL 修改项目：通过基于主机的安全描述符修改实现持久性。 [https://github.com/HarmJ0y/DAMP](https://link.zhihu.com/?target=https://github.com/HarmJ0y/DAMP "https://github.com/HarmJ0y/DAMP")

## **提升权限**

### **域升级**

*   **PowerView** 是一种 PowerShell 工具，用于在 Windows 域上获得网络态势感知。 [https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1](https://link.zhihu.com/?target=https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1 "https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1")

*   **Get-GPPPassword** 检索通过组策略首选项推送的帐户的明文密码和其他信息。 [https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1](https://link.zhihu.com/?target=https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1 "https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1")

*   **Invoke-ACLpwn** 是一个自动发现和 pwnage Active Directory 中配置不安全的 ACL 的工具。 [https://github.com/fox-it/Invoke-ACLPwn](https://link.zhihu.com/?target=https://github.com/fox-it/Invoke-ACLPwn "https://github.com/fox-it/Invoke-ACLPwn")

*   **BloodHound** 使用图论来揭示 Active Directory 环境中隐藏的和经常意外的关系。 [https://github.com/BloodHoundAD/BloodHound](https://link.zhihu.com/?target=https://github.com/BloodHoundAD/BloodHound "https://github.com/BloodHoundAD/BloodHound")

*   **PyKEK** （Python Kerberos Exploitation Kit），一个用于操作 KRB5 相关数据的 python 库。 [https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-068/pykek](https://link.zhihu.com/?target=https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-068/pykek "https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-068/pykek")

*   **Grouper** 一个 PowerShell 脚本，用于帮助在 AD 组策略中查找易受攻击的设置。 [https://github.com/l0ss/Grouper](https://link.zhihu.com/?target=https://github.com/l0ss/Grouper "https://github.com/l0ss/Grouper")

*   **ADRecon** 是一种工具，可在特殊格式的 Microsoft Excel 报告中从 AD 环境中提取各种工件（如下所示），该报告包括带有指标的摘要视图，以方便分析。 [https://github.com/sense-of-security/ADRecon](https://link.zhihu.com/?target=https://github.com/sense-of-security/ADRecon "https://github.com/sense-of-security/ADRecon")

*   **ADACLScanner** 一个用于 Active Directory 中 ACL 的脚本。 [https://github.com/canix1/ADACLScanner](https://link.zhihu.com/?target=https://github.com/canix1/ADACLScanner "https://github.com/canix1/ADACLScanner")

*   **ACLight** 一个有用的脚本，用于高级发现可能成为目标的域特权帐户 - 包括影子管理员。 [https://github.com/cyberark/ACLight](https://link.zhihu.com/?target=https://github.com/cyberark/ACLight "https://github.com/cyberark/ACLight")

*   **LAPSToolkit** 是一个审计和攻击 LAPS 环境的工具。 [https://github.com/leoloobeek/LAPSToolkit](https://link.zhihu.com/?target=https://github.com/leoloobeek/LAPSToolkit "https://github.com/leoloobeek/LAPSToolkit")

*   **PingCastle** 是一款基于 Windows 的免费实用程序，用于审核 AD 基础架构的风险级别并检查易受攻击的做法。 [https://www.pingcastle.com/download](https://link.zhihu.com/?target=https://www.pingcastle.com/download "https://www.pingcastle.com/download")

*   **RiskySPNs** 是一组 PowerShell 脚本，专注于检测和滥用与 SPN（服务主体名称）关联的帐户。 [https://github.com/cyberark/RiskySPN](https://link.zhihu.com/?target=https://github.com/cyberark/RiskySPN "https://github.com/cyberark/RiskySPN")

*   **Mystique** 是一个使用 Kerberos S4U 扩展的 PowerShell 工具，该模块可以帮助蓝队识别有风险的 Kerberos 委派配置，并帮助红队通过利用 KCD 和协议转换来模拟任意用户。 [https://github.com/machosec/Mystique](https://link.zhihu.com/?target=https://github.com/machosec/Mystique "https://github.com/machosec/Mystique")

*   **Rubeus** 是一个用于原始 Kerberos 交互和滥用的 C# 工具集。它大量改编自 Benjamin Delpy 的 Kekeo 项目。 [https://github.com/GhostPack/Rubeus](https://link.zhihu.com/?target=https://github.com/GhostPack/Rubeus "https://github.com/GhostPack/Rubeus")

*   **kekeo** 是一个小工具箱，我已经开始在 C 中操作 Microsoft Kerberos（为了好玩）。 [https://github.com/gentilkiwi/kekeo](https://link.zhihu.com/?target=https://github.com/gentilkiwi/kekeo "https://github.com/gentilkiwi/kekeo")

### **本地升级**

*   **UACMe** 是一个开源评估工具，其中包含许多在多个版本的操作系统上绕过 Windows 用户帐户控制的方法。 [https://github.com/hfiref0x/UACME](https://link.zhihu.com/?target=https://github.com/hfiref0x/UACME "https://github.com/hfiref0x/UACME")

*   **windows-kernel-exploits** 收集windows 内核漏洞利用。 [https://github.com/SecWiki/windows-kernel-exploits](https://link.zhihu.com/?target=https://github.com/SecWiki/windows-kernel-exploits "https://github.com/SecWiki/windows-kernel-exploits")

*   **PowerUp** 旨在成为依赖于错误配置的常见 Windows 权限提升向量的交换所。 [https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1](https://link.zhihu.com/?target=https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1 "https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1")

*   **Elevate Kit** 演示了如何通过 Cobalt Strike 的 Beacon 有效负载使用第三方权限提升攻击。 [https://github.com/rsmudge/ElevateKit](https://link.zhihu.com/?target=https://github.com/rsmudge/ElevateKit "https://github.com/rsmudge/ElevateKit")

*   **Sherlock** 一个 powerShell 脚本，用于快速查找本地权限提升漏洞的缺失软件补丁。 [https://github.com/rasta-mouse/Sherlock](https://link.zhihu.com/?target=https://github.com/rasta-mouse/Sherlock "https://github.com/rasta-mouse/Sherlock")

*   **Tokenvator** 是一种使用 Windows 令牌提升权限的工具。 [https://github.com /](https://link.zhihu.com/?target=https://github.com/0xbadjuju/Tokenvator "https://github.com /") [0xbadjuju](https://link.zhihu.com/?target=https://github.com/0xbadjuju/Tokenvator "0xbadjuju") [/Tokenvator](https://link.zhihu.com/?target=https://github.com/0xbadjuju/Tokenvator "/Tokenvator")

## **数据泄露**

*   **CloakifyFactory** 和 Cloakify 工具集——数据泄露和渗透一目了然；避开 DLP/MLS 设备；分析师社会工程学；击败数据白名单控制；避开 AV 检测。 [https://github.com/TryCatchHCF/Cloakify](https://link.zhihu.com/?target=https://github.com/TryCatchHCF/Cloakify "https://github.com/TryCatchHCF/Cloakify")

*   **DET** （按原样提供）是同时使用单个或多个通道执行数据泄露的概念证明。 [https://github.com/sensepost/DET](https://link.zhihu.com/?target=https://github.com/sensepost/DET "https://github.com/sensepost/DET")

*   **DNSExfiltrator** 允许通过 DNS 请求隐蔽通道传输（过滤）文件。这基本上是一个数据泄漏测试工具，允许通过隐蔽通道泄露数据。 [https://github.com/Arno0x/DNSExfiltrator](https://link.zhihu.com/?target=https://github.com/Arno0x/DNSExfiltrator "https://github.com/Arno0x/DNSExfiltrator")

*   **PyExfil** 一个用于数据泄露的 Python 包。 [https://github.com/ytisf/PyExfil](https://link.zhihu.com/?target=https://github.com/ytisf/PyExfil "https://github.com/ytisf/PyExfil")

*   **Egress-Assess** 是一个用于测试出口数据检测能力的工具。 [https://github.com/ChrisTruncer/Egress-Assess](https://link.zhihu.com/?target=https://github.com/ChrisTruncer/Egress-Assess "https://github.com/ChrisTruncer/Egress-Assess")

*   **基于Powershell RAT** python 的后门，它使用 Gmail 将数据作为电子邮件附件泄露。 [https://github.com/Viralmaniar/Powershell-RAT](https://link.zhihu.com/?target=https://github.com/Viralmaniar/Powershell-RAT "https://github.com/Viralmaniar/Powershell-RAT")

## **杂项**

### **对手仿真**

*   **MITRE CALDERA** – 一种自动对手仿真系统，可在 Windows Enterprise 网络中执行妥协后的对抗行为。 [https://github.com/mitre/caldera](https://link.zhihu.com/?target=https://github.com/mitre/caldera "https://github.com/mitre/caldera")

*   **APTSimulator** – 一个 Windows Batch 脚本，它使用一组工具和输出文件使系统看起来像是被入侵了。 [https://github.com/NextronSystems/APTSimulator](https://link.zhihu.com/?target=https://github.com/NextronSystems/APTSimulator "https://github.com/NextronSystems/APTSimulator")

*   **Atomic Red Team** – 映射到 Mitre ATT\&CK 框架的小型且高度便携的检测测试。 [https://github.com/redcanaryco/atomic-red-team](https://link.zhihu.com/?target=https://github.com/redcanaryco/atomic-red-team "https://github.com/redcanaryco/atomic-red-team")

*   **网络飞行模拟器** ——flightsim 是一个轻量级实用程序，用于生成恶意网络流量并帮助安全团队评估安全控制和网络可见性。 [https://github.com/alphasoc/flightsim](https://link.zhihu.com/?target=https://github.com/alphasoc/flightsim "https://github.com/alphasoc/flightsim")

*   **Metta** – 一种用于对抗模拟的安全准备工具。 [https://github.com/uber-common/metta](https://link.zhihu.com/?target=https://github.com/uber-common/metta "https://github.com/uber-common/metta")

*   **红队自动化 (RTA)** – RTA 提供了一个脚本框架，旨在允许蓝队测试其针对恶意交易的检测能力，以 MITRE ATT\&CK 为模型。 [https://github.com/endgameinc/RTA](https://link.zhihu.com/?target=https://github.com/endgameinc/RTA "https://github.com/endgameinc/RTA")

### **无线网络**

*   **Wifiphisher** 是一种安全工具，它执行 Wi-Fi 自动关联攻击以强制无线客户端在不知不觉中连接到攻击者控制的接入点。 [https://github.com/wifiphisher/wifiphisher](https://link.zhihu.com/?target=https://github.com/wifiphisher/wifiphisher "https://github.com/wifiphisher/wifiphisher")

*   用于 wifi 流氓 AP 攻击和 MitM 的 **法力工具包。**[https://github.com/sensepost/mana](https://link.zhihu.com/?target=https://github.com/sensepost/mana "https://github.com/sensepost/mana")

### **嵌入式和外围设备黑客**

*   **magspoof** 一种便携式设备，可以“无线”欺骗/模拟任何磁条、信用卡或酒店卡，即使在标准磁条（非 NFC/RFID）阅读器上也是如此。 [https://github.com/samyk/magspoof](https://link.zhihu.com/?target=https://github.com/samyk/magspoof "https://github.com/samyk/magspoof")

*   **WarBerryPi** 是为在红队场景中用作硬件植入物而构建的，在这种场景中，我们希望尽可能隐蔽地在短时间内获取尽可能多的信息。 [https://github.com/secgroundzero/warberry](https://link.zhihu.com/?target=https://github.com/secgroundzero/warberry "https://github.com/secgroundzero/warberry")

*   **P4wnP1** 是一个高度可定制的 USB 攻击平台，基于低成本 Raspberry Pi Zero 或 Raspberry Pi Zero W（HID 后门所需）。 [https://github.com/mame82/P4wnP1](https://link.zhihu.com/?target=https://github.com/mame82/P4wnP1 "https://github.com/mame82/P4wnP1")

*   **malusb** HID 欺骗 Teensy 的多操作系统有效负载。 [https://github.com/ebursztein/malusb](https://link.zhihu.com/?target=https://github.com/ebursztein/malusb "https://github.com/ebursztein/malusb")

*   **Fenrir** 是一种旨在“开箱即用”地进行渗透测试和进攻性交战的工具。它的主要功能和目的是绕过有线 802.1x 保护并让您访问目标网络。 [https://github.com/Orange-Cyberdefense/fenrir-ocd](https://link.zhihu.com/?target=https://github.com/Orange-Cyberdefense/fenrir-ocd "https://github.com/Orange-Cyberdefense/fenrir-ocd")

*   **Poisontap** 通过 USB 攻击锁定/密码保护的计算机，丢弃基于 WebSocket 的持久后门，暴露内部路由器，并使用 Raspberry Pi Zero 和 Node.js 虹吸 cookie。 [https://github.com/samyk/poisontap](https://link.zhihu.com/?target=https://github.com/samyk/poisontap "https://github.com/samyk/poisontap")

*   **WHID** WiFi HID 注射器 – 类固醇上的 USB Rubberducky / BadUSB。 [https://github.com/whid-injector/WHID](https://link.zhihu.com/?target=https://github.com/whid-injector/WHID "https://github.com/whid-injector/WHID")

*   **PhanTap** 是针对红队的“隐形”网络分流器。由于对目标建筑物的物理访问受限，该分路器可以在线安装在网络设备和公司网络之间。 [https://github.com/nccgroup/phantap](https://link.zhihu.com/?target=https://github.com/nccgroup/phantap "https://github.com/nccgroup/phantap")

### **团队沟通软件**

*   **RocketChat** 是免费、无限制和开源的。用终极团队聊天软件解决方案替换电子邮件和 Slack。 [https://rocket.chat](https://link.zhihu.com/?target=https://rocket.chat/ "https://rocket.chat")

*   **Etherpad** 是一个开源、基于 Web 的协作式实时编辑器，允许作者同时编辑文本文档 [https://etherpad.org/](https://link.zhihu.com/?target=https://etherpad.org/ "https://etherpad.org/")

### **日志聚合**

*   **RedELK** Red Team 的 SIEM – Red Team 易于部署的工具，用于跟踪和警告 Blue Team 活动以及在长期运营中更好的可用性。 [https://github.com/outflanknl/RedELK/](https://link.zhihu.com/?target=https://github.com/outflanknl/RedELK/ "https://github.com/outflanknl/RedELK/")

*   **CobaltSplunk** 用于 CobaltStrike 日志的 Splunk 仪表板。 [https://github.com/vysec/CobaltSplunk](https://link.zhihu.com/?target=https://github.com/vysec/CobaltSplunk "https://github.com/vysec/CobaltSplunk")

*   **红队遥测** 一组脚本和配置，用于启用红队基础设施的集中日志记录。 [https://github.com/ztgrace/red\_team\_telemetry](https://link.zhihu.com/?target=https://github.com/ztgrace/red_team_telemetry "https://github.com/ztgrace/red_team_telemetry")

*   **Elastic for Red Teaming** 用于使用 Elastic 配置 Red Team SIEM 的资源存储库。 [https://github.com/SecurityRiskAdvisors/RedTeamSIEM](https://link.zhihu.com/?target=https://github.com/SecurityRiskAdvisors/RedTeamSIEM "https://github.com/SecurityRiskAdvisors/RedTeamSIEM")

*   **Ghostwriter** 是一个用 Python 3.7 编写的 Django 项目，旨在供一组操作员使用。 [https://github.com/GhostManager/Ghostwriter](https://link.zhihu.com/?target=https://github.com/GhostManager/Ghostwriter "https://github.com/GhostManager/Ghostwriter")

### **C# 攻击性框架**

*   **SharpSploit** 是一个用 C# 编写的 .NET 后利用库，旨在突出 .NET 的攻击面，并使红队更容易使用攻击性 .NET。 [https://github.com/cobbr/SharpSploit](https://link.zhihu.com/?target=https://github.com/cobbr/SharpSploit "https://github.com/cobbr/SharpSploit")

*   **GhostPack** （目前）是以前 PowerShell 功能的各种 C# 实现的集合，包括今天发布的六个独立工具集——Seatbelt、SharpUp、SharpRoast、SharpDump、SafetyKatz 和 SharpWMI。 [https://github.com/GhostPack](https://link.zhihu.com/?target=https://github.com/GhostPack "https://github.com/GhostPack")

*   **SharpWeb** .NET 2.0 CLR 项目，用于从 Google Chrome、Mozilla Firefox 和 Microsoft Internet Explorer/Edge 检索保存的浏览器凭据。 [https://github.com/djhohnstein/SharpWeb](https://link.zhihu.com/?target=https://github.com/djhohnstein/SharpWeb "https://github.com/djhohnstein/SharpWeb")

*   **reconerator** C# 目标攻击侦察工具。 [https://github.com/stufus/reconerator](https://link.zhihu.com/?target=https://github.com/stufus/reconerator "https://github.com/stufus/reconerator")

*   **SharpView** C# 实现harmj0y 的PowerView。 [https://github.com/tevora-threat/SharpView](https://link.zhihu.com/?target=https://github.com/tevora-threat/SharpView "https://github.com/tevora-threat/SharpView")

*   **Watson** 是 Sherlock 的（兼容 .NET 2.0）C# 实现。 [https://github.com/rasta-mouse/Watson](https://link.zhihu.com/?target=https://github.com/rasta-mouse/Watson "https://github.com/rasta-mouse/Watson")

### **实验室**

*   **检测实验室** 该实验室的设计考虑了防御者。它的主要目的是允许用户快速构建一个 Windows 域，该域预装了安全工具和一些关于系统日志配置的最佳实践。 [https://github.com/clong/DetectionLab](https://link.zhihu.com/?target=https://github.com/clong/DetectionLab "https://github.com/clong/DetectionLab")

*   **现代 Windows 攻击和防御实验室** 这是 Sean Metcalf (@pyrotek3) 和我教授的现代 Windows 攻击和防御课程的实验室配置。 [https://github.com/jaredhaight/WindowsAttackAndDefenseLab](https://link.zhihu.com/?target=https://github.com/jaredhaight/WindowsAttackAndDefenseLab "https://github.com/jaredhaight/WindowsAttackAndDefenseLab")

*   **Invoke-UserSimulator** 模拟本地和远程 Windows 主机上的常见用户行为。 [https://github.com/ubeeri/Invoke-UserSimulator](https://link.zhihu.com/?target=https://github.com/ubeeri/Invoke-UserSimulator "https://github.com/ubeeri/Invoke-UserSimulator")

*   **Invoke-ADLabDeployer** 自动部署 Windows 和 Active Directory 测试实验室网络。对红队和蓝队有用。 [https://github.com/outflanknl/Invoke-ADLabDeployer](https://link.zhihu.com/?target=https://github.com/outflanknl/Invoke-ADLabDeployer "https://github.com/outflanknl/Invoke-ADLabDeployer")

*   **Sheepl** 创建逼真的用户行为以支持实验室环境中的贸易技术开发。 [https://github.com/SpiderLabs/sheepl](https://link.zhihu.com/?target=https://github.com/SpiderLabs/sheepl "https://github.com/SpiderLabs/sheepl")

### **脚本**

*   **Aggressor Scripts** 是一种用于红队操作和对手模拟的脚本语言，其灵感来自可编写脚本的 IRC 客户端和机器人。

*   [https://github.com/invokethreatguy/CSASC](https://link.zhihu.com/?target=https://github.com/invokethreatguy/CSASC "https://github.com/invokethreatguy/CSASC")

*   [https://github.com/secgroundzero/CS-Aggressor-Scripts](https://link.zhihu.com/?target=https://github.com/secgroundzero/CS-Aggressor-Scripts "https://github.com/secgroundzero/CS-Aggressor-Scripts")

*   [https://github.com/Und3rf10w/Aggressor-scripts](https://link.zhihu.com/?target=https://github.com/Und3rf10w/Aggressor-scripts "https://github.com/Und3rf10w/Aggressor-scripts")

*   [https://github.com/harleyQu1nn/AggressorScripts](https://link.zhihu.com/?target=https://github.com/harleyQu1nn/AggressorScripts "https://github.com/harleyQu1nn/AggressorScripts")

*   [https://github.com/rasta-mouse/Aggressor-Script](https://link.zhihu.com/?target=https://github.com/rasta-mouse/Aggressor-Script "https://github.com/rasta-mouse/Aggressor-Script")

*   [https://github.com/RhinoSecurityLabs/Aggressor-Scripts](https://link.zhihu.com/?target=https://github.com/RhinoSecurityLabs/Aggressor-Scripts "https://github.com/RhinoSecurityLabs/Aggressor-Scripts")

*   [https://github.com/bluscreenofjeff/AggressorScripts](https://link.zhihu.com/?target=https://github.com/bluscreenofjeff/AggressorScripts "https://github.com/bluscreenofjeff/AggressorScripts")

*   [https://github.com/001SPARTaN/aggressor\_scripts](https://link.zhihu.com/?target=https://github.com/001SPARTaN/aggressor_scripts "https://github.com/001SPARTaN/aggressor_scripts")

*   [https://github.com/360-A-Team/CobaltStrike-Toolset](https://link.zhihu.com/?target=https://github.com/360-A-Team/CobaltStrike-Toolset "https://github.com/360-A-Team/CobaltStrike-Toolset")

*   [https://github.com/FortyNorthSecurity/AggressorAssessor](https://link.zhihu.com/?target=https://github.com/FortyNorthSecurity/AggressorAssessor "https://github.com/FortyNorthSecurity/AggressorAssessor")

*   [https://github.com/ramen0x3f/AggressorScripts](https://link.zhihu.com/?target=https://github.com/ramen0x3f/AggressorScripts "https://github.com/ramen0x3f/AggressorScripts")

*   对红队和渗透测试有用的集合脚本

*   [https://gi](https://link.zhihu.com/?target=https://github.com/FuzzySecurity/PowerShell-Suite "https://gi") [t](https://link.zhihu.com/?target=https://github.com/FuzzySecurity/PowerShell-Suite "t") [hub.com/FuzzySecurity/PowerShell-Suite](https://link.zhihu.com/?target=https://github.com/FuzzySecurity/PowerShell-Suite "hub.com/FuzzySecurity/PowerShell-Suite")

*   [https://github.com/nettitude/Powershell](https://link.zhihu.com/?target=https://github.com/nettitude/Powershell "https://github.com/nettitude/Powershell")

*   [https://github.com/Mr-Un1k0d3r/RedTeamPowershellScripts](https://link.zhihu.com/?target=https://github.com/Mr-Un1k0d3r/RedTeamPowershellScripts "https://github.com/Mr-Un1k0d3r/RedTeamPowershellScripts")

*   [https://github.com/threatexpress/red-team-scripts](https://link.zhihu.com/?target=https://github.com/threatexpress/red-team-scripts "https://github.com/threatexpress/red-team-scripts")

*   [https://github.com/SadProcessor/SomeStuff](https://link.zhihu.com/?target=https://github.com/SadProcessor/SomeStuff "https://github.com/SadProcessor/SomeStuff")

*   [https://github.com/rvrsh3ll/Misc-Powershell-Scripts](https://link.zhihu.com/?target=https://github.com/rvrsh3ll/Misc-Powershell-Scripts "https://github.com/rvrsh3ll/Misc-Powershell-Scripts")

*   [https://github.com/enigma0x3/Misc-PowerShell-Stuff](https://link.zhihu.com/?target=https://github.com/enigma0x3/Misc-PowerShell-Stuff "https://github.com/enigma0x3/Misc-PowerShell-Stuff")

*   [https://github.com/ChrisTruncer/PenTestScripts](https://link.zhihu.com/?target=https://github.com/ChrisTruncer/PenTestScripts "https://github.com/ChrisTruncer/PenTestScripts")

*   [https://github.com/bluscreenofjeff/Scripts](https://link.zhihu.com/?target=https://github.com/bluscreenofjeff/Scripts "https://github.com/bluscreenofjeff/Scripts")

*   [https://github.com/xorrior/RandomPS-Scripts](https://link.zhihu.com/?target=https://github.com/xorrior/RandomPS-Scripts "https://github.com/xorrior/RandomPS-Scripts")

*   [https://github.com/xorrior/Random-CSharpTools](https://link.zhihu.com/?target=https://github.com/xorrior/Random-CSharpTools "https://github.com/xorrior/Random-CSharpTools")

*   [https://github.com/leechristensen/Random](https://link.zhihu.com/?target=https://github.com/leechristensen/Random "https://github.com/leechristensen/Random")

*   [https://github.com/mgeeky/Penetration-Testing-Tools/tree/master/social-engineering](https://link.zhihu.com/?target=https://github.com/mgeeky/Penetration-Testing-Tools/tree/master/social-engineering "https://github.com/mgeeky/Penetration-Testing-Tools/tree/master/social-engineering")

## **参考**

*   **MITRE 的 ATT\&CK™** 是针对网络对手行为的精选知识库和模型，反映了对手生命周期的各个阶段以及他们已知的目标平台。 [https](https://link.zhihu.com/?target=https://attack.mitre.org/wiki/Main_Page "https") [:](https://link.zhihu.com/?target=https://attack.mitre.org/wiki/Main_Page ":") [//attack.mitre.org/wiki/Main\_Page](https://link.zhihu.com/?target=https://attack.mitre.org/wiki/Main_Page "//attack.mitre.org/wiki/Main_Page")

*   各种项目的备忘单（Beacon/Cobalt Strike、PowerView、PowerUp、Empire 和 PowerSploit） **。**[https://github.com/HarmJ0y/CheatSheets](https://link.zhihu.com/?target=https://github.com/HarmJ0y/CheatSheets "https://github.com/HarmJ0y/CheatSheets")

*   **PRE-ATT\&CK** 对抗策略、技术和针对被利用左侧的常识。 [https://attack.mitre.org/pre-attack/index.php/Main\_Page](https://link.zhihu.com/?target=https://attack.mitre.org/pre-attack/index.php/Main_Page "https://attack.mitre.org/pre-attack/index.php/Main_Page")

*   **对手 OPSEC** 包括使用各种技术或第 3 方服务来混淆、隐藏或融入已接受的网络流量或系统行为。 [https://attack.mitre.org/pre-attack/index.php/Adversary\_OPSEC](https://link.zhihu.com/?target=https://attack.mitre.org/pre-attack/index.php/Adversary_OPSEC "https://attack.mitre.org/pre-attack/index.php/Adversary_OPSEC")

*   **对手仿真计划** 为了展示 ATT\&CK 在进攻性操作员和防御者中的实际用途，MITRE 创建了对手仿真计划。 [https://attack.mitre.org/wiki/Adversary\_Emulation\_Plans](https://link.zhihu.com/?target=https://attack.mitre.org/wiki/Adversary_Emulation_Plans "https://attack.mitre.org/wiki/Adversary_Emulation_Plans")

*   **Red-Team-Infrastructure-Wiki** 收集 Red Team 基础设施强化资源的 Wiki。 [https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki](https://link.zhihu.com/?target=https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki "https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki")

*   **Advanced Threat Tactics – Course and Notes** 这是一门关于红队操作和对手模拟的课程。 [https://blog.cobaltstrike.com/2015/09/30/advanced-threat-tactics-course-and-notes](https://link.zhihu.com/?target=https://blog.cobaltstrike.com/2015/09/30/advanced-threat-tactics-course-and-notes "https://blog.cobaltstrike.com/2015/09/30/advanced-threat-tactics-course-and-notes")

*   @vysecurity 在 Twitter 上发布的 **红队提示。**[https://vincentyiu.co.uk/red-team-tips](https://link.zhihu.com/?target=https://vincentyiu.co.uk/red-team-tips "https://vincentyiu.co.uk/red-team-tips")

*   **真棒** 红队/红队资源的真棒红队列表。 [https://github.com/yeyintminthuhtut/Awesome-Red-Teaming](https://link.zhihu.com/?target=https://github.com/yeyintminthuhtut/Awesome-Red-Teaming "https://github.com/yeyintminthuhtut/Awesome-Red-Teaming")

*   **APT 和网络犯罪活动集合** 这是 APT 和网络犯罪活动的集合。如果有任何丢失的 APT/恶意软件事件/活动，请向我发送问题。 [https://github.com/CyberMonitor/APT\_CyberCriminal\_Campagin\_Collections](https://link.zhihu.com/?target=https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections "https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections")

*   **ATT\&CK for Enterprise Software** 是自定义或商业代码、操作系统实用程序、开源软件或其他用于执行在 ATT\&CK 中建模的行为的工具的通用术语。 [https://attack.mitre.org/wiki/Software](https://link.zhihu.com/?target=https://attack.mitre.org/wiki/Software "https://attack.mitre.org/wiki/Software")

*   **规划红队练习** 本文档通过与红队中描述的非常具体的红队风格进行对比，有助于为红队规划提供信息。 [https://github.com/magoo/redteam-plan](https://link.zhihu.com/?target=https://github.com/magoo/redteam-plan "https://github.com/magoo/redteam-plan")

*   **Awesome Lockpicking 精选** 指南、工具和其他与锁、保险箱和钥匙的安全性和危害相关的资源的精选列表。 [https://github.com/meitar/awesome-lockpicking](https://link.zhihu.com/?target=https://github.com/meitar/awesome-lockpicking "https://github.com/meitar/awesome-lockpicking")

*   **Awesome Threat Intelligence** 令人敬畏的威胁情报资源的精选列表。 [https://github.com/hslatman/awesome-threat-intelligence](https://link.zhihu.com/?target=https://github.com/hslatman/awesome-threat-intelligence "https://github.com/hslatman/awesome-threat-intelligence")

*   **APT 笔记** 需要一些场景吗？APTnotes 是与供应商定义的 APT（高级持续威胁）组和/或工具集相关的恶意活动/活动/软件相关的公开论文和博客（按年份排序）的存储库。 [https://github.com/aptnotes/data](https://link.zhihu.com/?target=https://github.com/aptnotes/data "https://github.com/aptnotes/data")

*   **TIBER-EU FRAMEWORK** 欧洲基于威胁情报的道德红队框架 (TIBER-EU)，这是第一个在欧洲范围内针对金融市场网络攻击进行受控和定制测试的框架。 [http://www.ecb.europa.eu/pub/pdf/other/ecb.tiber\_eu\_framework.en.pdf](https://link.zhihu.com/?target=https://www.ecb.europa.eu/pub/pdf/other/ecb.tiber_eu_framework.en.pdf "http://www.ecb.europa.eu/pub/pdf/other/ecb.tiber_eu_framework.en.pdf")

*   **CBEST 实施指南** CBEST 是一个提供受控、定制、情报主导的网络安全测试的框架。这些测试复制了威胁行为者的行为，经英国政府和商业情报提供者评估为对具有系统重要性的金融机构构成真正的威胁。 [https://www.crest-approved.org/wp-content/uploads/2014/07/CBEST-Implementation-Guide.pdf](https://link.zhihu.com/?target=https://www.crest-approved.org/wp-content/uploads/2014/07/CBEST-Implementation-Guide.pdf "https://www.crest-approved.org/wp-content/uploads/2014/07/CBEST-Implementation-Guide.pdf")

*   **红队：新加坡金融业对抗性攻击模拟练习指南 新加坡** 银行协会 (ABS) 在新加坡金融管理局 (MAS) 的支持下，今天制定了一套网络安全评估指南，以加强网络弹性新加坡金融业。该指南被称为对抗性攻击模拟练习 (AASE) 指南或“红队”指南，为金融机构 (FI) 提供有关规划和进行红队练习以增强其安全测试的最佳实践和指导。 [https://abs.org.sg/docs/library](https://link.zhihu.com/?target=https://abs.org.sg/docs/library/abs-red-team-adversarial-attack-simulation-exercises-guidelines-v1-06766a69f299c69658b7dff00006ed795.pdf "https://abs.org.sg/docs/library")
