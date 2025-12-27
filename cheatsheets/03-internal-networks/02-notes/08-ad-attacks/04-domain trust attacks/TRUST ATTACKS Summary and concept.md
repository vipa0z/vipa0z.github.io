## s

This module introduces AD enumeration and attack techniques targeting intra-forest and cross forest trusts. We will cover enumerating and mapping trust relationships, exploitation of intra-forest trusts and various attacks that can be performed between forests, dispelling the notion that the forest is _the_ security boundary.

In this module, we will cover:

- Enumerating and mapping domain/forest trusts
- Intra forest attacks, such as:
    - Unconstrained Delegation
    - Configuration Naming Context (NC)
    - Abusing Active Directory Certificate Services (AD CS)
    - GPO on Site Attack
    - GoldenGMSA Attack
    - DNS Trust Attack
    - Abusing Foreign Groups & ACL Principals
    - The ExtraSids Attack
- Cross Forest trust attacks:
    - Common attacks/easy wins
    - Trust Account Attack
    - Unconstrained Delegation cross forest
    - SID History Injection Attack
    - SID Filter Bypass (CVE-2020-0665)
    - SQL Server Links across forest trusts
    - Abusing Foreign Security Principals & ACLs across forest trusts
    - Abusing PAM Trusts

We will also briefly cover mitigations against trust attacks and go into a short primer on detections, though detailed defensive considerations fall outside the scope of this mainly offensive security oriented module.

---

This module is broken down into sections with accompanying hands-on exercises to practice each of the tools, tactics, and techniques we cover. The module includes several guided and non-guided labs to reinforce the techniques covered throughout.

As you work through the module, you will see example commands and command output for the various topics introduced. It is worth reproducing as many examples as possible to reinforce further the concepts presented in each section. You can do this in the Pwnbox provided in the interactive sections or your virtual machine.

You can start and stop the module at any time and pick up where you left off. There is no time limit or "grading," but you must complete all of the exercises and the skills assessments to receive the maximum number of cubes and have this module marked as complete in any paths you have chosen.

The module is classified as "Hard" and assumes in-depth knowledge of the Windows and Linux command line, the structure and function of Active Directory, and common Active Directory enumeration tasks and attacks from both Linux and Windows attack hosts.

A firm grasp of the following modules can be considered prerequisites for successful completion of this module:

- Introduction to Active Directory
- Active Directory Enumeration & Attacks
- Kerberos Attacks

## Sections

- Introduction To Active Directory Trust Attacks PREVIEW
- Enumerating Domain & Forest Trusts
- Mapping Active Directory Trusts
- Unconstrained Delegation
- Configuration Naming Context (NC)
- Abusing ADCS
- GPO On Site Attack
- GoldenGMSA Attack
- DNS Trust Attack
- Abusing Foreign Groups & ACL Principals
- ExtraSids Attack
- Attacking Cross Forest Trusts
- Trust Account Attack
- Unconstrained Delegation Cross Forest
- SID History Injection Attack
- SID Filter Bypass (CVE-2020-0665)
- Abusing SQL Server Links
- Abusing Foreign Security Principals & ACLs
- Abusing PAM Trusts
- Trust Attack Mitigations and Detections
- Active Directory Trust Attacks - Skills Assessment
# Introduction to Active Directory Trust Attacks

---

## Setting the Stage

Active Directory (AD) is prevalent across organizations of all sizes. Even with the push in recent years to move to a hybrid or full cloud-based environment, AD still reigns supreme in many companies. Hence, as penetration testers we must have a deep understanding of the ins and outs of AD, its complexities, intricacies, and the many ways it can be misconfigured or native features can be abused. One aspect of Active Directory that came to the forefront almost a decade ago with the work of researchers such as [harmj0y](https://twitter.com/harmj0y?lang=en) with iconic blog posts such as [The Trustpocalypse](https://blog.harmj0y.net/redteaming/the-trustpocalypse/) in 2015 and [A Guide to Attacking Domain Trusts](https://harmj0y.medium.com/a-guide-to-attacking-domain-trusts-ef5f8992bb9d) in 2017. At that time, for many penetration testers, attacking domain trusts was a relatively new/foreign concept but for those actively testing in those times it opened up many new avenues of attack to be successful in our assessments and to help our customers further secure their environments. Over the years, more and more excellent research has been published by various members of the InfoSec community, furthering the early work and opening up many new possibilities for abusing AD trust relationships (both within the same forest and across forests).

This module is designed to equip you with the knowledge and skills necessary to understand and defend against trust-based attacks within Active Directory environments. In today's cybersecurity landscape, where organizations rely heavily on interconnected systems for seamless operations, understanding the intricacies of trust relationships is paramount. Active Directory, as a central component of many networks, forms the backbone of user authentication, authorization, and resource management. However, its complexity also presents vulnerabilities that malicious actors can exploit to gain unauthorized access and wreak havoc on organizational assets.

This module focuses specifically on two types of trust relationships: intra-forest and cross-forest trusts. Intra-forest trusts allow for communication and resource sharing between multiple domains within a single forest, while cross-forest trusts extend this capability across domains in different forests. While these trust relationships enhance collaboration and resource access, they also introduce potential security risks if not properly configured and monitored. As penetration testers, understanding the nuances of these trust relationships enables us to identify and exploit weaknesses that adversaries may leverage to compromise network integrity.

---

## Why Should We Care About Trusts?

Oftentimes a penetration tester will find themselves assessing a large organization where they are able to gain a foothold in their current Active Directory domain but unable to escalate privileges. Enter trusts. Perhaps we have exhausted all avenues of attack but find that we can Kerberoast across a trust and compromise a child domain. Once compromised, we can use that access to easily compromise the parent domain that we are positioned in. We may also identify trust relationships with other forests and compromising a partner forest may grant us access that we need to compromise our current forest through any number of attacks.

Throughout this module, we will delve into the intricacies of both intra-forest and cross-forest trust relationships, exploring common and lesser-known attack vectors from both Windows and Linux machines. In the sections that follow, we will explore real-world scenarios, case studies, and hands-on exercises to gain a deeper understanding of Active Directory trust attacks. By the end of this training, you will be equipped with the knowledge and skills necessary to assess, mitigate, and defend against trust-related threats. This knowledge in turn will help sharpen your skills as a penetration tester, or for any blue teamers, it may help you to bolster the resilience of your organization's Active Directory infrastructure after gaining a deep understanding of _why_ certain attacks are possible.

---

## Trust Types

While this module assumes an intermediate understanding of how Active Directory works, it's worth defining the various types of trusts that we may encounter in the wild. Not all of these will be covered in this module.

- `Parent-Child`: This trust relationship forms between a parent domain and a child domain within the same forest. The parent domain inherently trusts the child domain, and vice versa. It's established automatically whenever a new child domain is created within a forest.
    
- `Tree-Root`: This trust relationship links the root domain of one tree to the root domain of another tree within the same forest. Whenever a new tree is created in a forest, this trust is automatically established.
    
- `External Trust`: This trust link forms between a domain in one forest and a domain in a separate forest. It facilitates users from one domain to access resources located in the other domain. Typically, it's implemented when accessing resources in a forest lacking established trust relationships.
    
- `Forest Trust`: This trust relationship is established between two forests, specifically between the root domains of each forest. It enables users from one forest to access resources hosted in the other forest.
    
- `Shortcut (or Cross-Link) Trust`: This trust connection emerges between two child domains belonging to different trees (or parent domains) within the same forest. It aims to minimize authentication hops between distant domains and can be either one-way or two-way transitive.
    
- `Realm Trust`: This trust relationship connects a Windows domain with a non-Windows domain, such as a Kerberos realm. It enables users within the Windows domain to access resources situated in the non-Windows domain.
    

The most commonly seen trust types are `Parent-Child,` `Tree-Root`, `External`, and `Forest` trust. `Cross-Link` trusts are seen occasionally along with `Realm` trusts but more infrequently. In this module, we will focus on `Parent-Child` and `Forest Trust` relationships.

---

## Hands-On Lab Scenarios

Throughout this module we will cover real-world attack examples with accompanying command output, the majority of which can be reproduced on the lab machines that can be spawned in each section. You will be provided with the access needed to master intra-forest and cross-forest trust attacks from Linux and Windows testing machines. Challenge yourself to reproduce all examples shown throughout the sections and complete the end of the section questions. The module culminates in an intensive skills assessment that will test your knowledge of enumerating and attacking both intra and cross forest trust.

This module assumes a thorough understanding of Active Directory and its various technologies, common attacks, and misconfigurations. If you need a refresher on trusts in general or common Active Directory attacks, some of which we will be reproducing across trusts, consult the [Active Directory Enumeration & Attacks module](https://academy.hackthebox.com/module/details/143). Now let's dive into enumerating domain & forest trusts to set the stage for the multitude of attacks we will cover in the coming sections.