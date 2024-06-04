#!/bin/env python3
import datetime

import stix2

apt41_threat_actor = stix2.ThreatActor(
    type="threat-actor",
    name="APT41",
    description="APT41 is a threat group that researchers have assessed as Chinese state-sponsored espionage group "
    "that also conducts financially-motivated operations. Active since at least 2012, APT41 has been "
    "observed targeting healthcare, telecom, technology, and video game industries in 14 countries.",
    threat_actor_types=["crime-syndicate"],
    aliases=["Wicked Panda", "Brass Typhoon", "BARIUM"],
    roles=["agent", "malware-author"],
    goals=[
        "steal-intellectual-property",
        "financial-gain",
        "ransomware-attacks",
        "cryptocurrency-mining",
    ],
    sophistication="expert",
    resource_level="organization",
    primary_motivation="personal-gain",
)

ccp_identity = stix2.Identity(
    type="identity",
    name="CCP",
    description="The Chinese Communist Party",
    identity_class="organization",
)

ccp_relationship = stix2.Relationship(
    type="relationship",
    relationship_type="attributed-to",
    source_ref=apt41_threat_actor.id,
    target_ref=ccp_identity.id,
)

china_location = stix2.Location(
    type="location",
    name="China",
    country="CN",
)

ccp_china_relationship = stix2.Relationship(
    type="relationship",
    relationship_type="located-at",
    source_ref=ccp_identity.id,
    target_ref=china_location.id,
)

apt41_threat_actor_china_relationship = stix2.Relationship(
    type="relationship",
    relationship_type="located-at",
    source_ref=apt41_threat_actor.id,
    target_ref=china_location.id,
)

apt41_intrusion_set = stix2.IntrusionSet(
    type="intrusion-set",
    name="APT41",
    description="APT41 is a threat group that has conducted Chinese state-sponsored cyber espionage activity and "
                "financially motivated intrusions.",
    aliases=["Wicked Panda", "Brass Typhoon", "BARIUM"],
    first_seen=datetime.datetime(2012, 1, 1),
    last_seen=datetime.datetime(2024, 4, 3),
    goals=[],
    resource_level="organization",
    primary_motivation="personal-gain",
)

apt41_relationship = stix2.Relationship(
    type="relationship",
    relationship_type="attributed-to",
    source_ref=apt41_intrusion_set.id,
    target_ref=apt41_threat_actor.id,
)

western_world_identity = stix2.Identity(
    type="identity",
    name="Western World",
    description="The western world",
    identity_class="class",
)

western_world_target_relationship = stix2.Relationship(
    type="relationship",
    relationship_type="targets",
    source_ref=apt41_intrusion_set,
    target_ref=western_world_identity,
)

techniques = [
    stix2.AttackPattern(
        type="attack-pattern",
        external_references=[stix2.ExternalReference(
            source_name="organization",
            description=f"MITRE reference for {name}",
            url=url,
        )],
        name=name,
        description=description,
    )
    for
    (name, url, description)
    in
    [
        (
            "Access Token Manipulation",
            "https://attack.mitre.org/techniques/T1134/",
            """Adversaries may modify access tokens to operate under a different user or system security context to 
perform actions and bypass access controls. Windows uses access tokens to determine the ownership of a 
running process. A user can manipulate access tokens to make a running process appear as though it is the 
child of a different process or belongs to someone other than the user that started the process. When 
this occurs, the process also takes on the security context associated with the new token.

An adversary can use built-in Windows API functions to copy access tokens from existing processes; this is known as 
token stealing. These token can then be applied to an existing process (i.e. Token Impersonation/Theft) or used to 
spawn a new process (i.e. Create Process with Token). An adversary must already be in a privileged user context (i.e. 
administrator) to steal a token. However, adversaries commonly use token stealing to elevate their security context 
from the administrator level to the SYSTEM level. An adversary can then use a token to authenticate to a remote 
system as the account for that token if the account has appropriate permissions on the remote system.

Any standard user can use the runas command, and the Windows API functions, to create impersonation tokens; it does 
not require access to an administrator account. There are also other mechanisms, such as Active Directory fields, 
that can be used to modify access tokens."""
        ),
        (
            "Hijack Execution Flow",
            "https://attack.mitre.org/techniques/T1574/",
            """Adversaries may execute their own malicious payloads by hijacking the way operating systems run 
programs. Hijacking execution flow can be for the purposes of persistence, since this hijacked execution 
may reoccur over time. Adversaries may also use these mechanisms to elevate privileges or evade defenses, 
such as application control or other restrictions on execution.

There are many ways an adversary may hijack the flow of execution, including by manipulating how the operating system 
locates programs to be executed. How the operating system locates libraries to be used by a program can also be 
intercepted. Locations where the operating system looks for programs/resources, such as file directories and in the 
case of Windows the Registry, could also be poisoned to include malicious payloads."""
        ),
        (
            "Data Obfuscation: Protocol Impersonation",
            "https://attack.mitre.org/techniques/T1001/003/",
            """Adversaries may impersonate legitimate protocols or web service traffic to disguise command and 
control activity and thwart analysis efforts. By impersonating legitimate protocols or web services, 
adversaries can make their command and control traffic blend in with legitimate network traffic.

Adversaries may impersonate a fake SSL/TLS handshake to make it look like subsequent traffic is SSL/TLS encrypted, 
potentially interfering with some security tooling, or to make the traffic look like it is related with a trusted 
entity."""
        ),
        (
            "Phishing",
            "https://attack.mitre.org/techniques/T1566/",
            """Adversaries may send phishing messages to gain access to victim systems. All forms of phishing are 
electronically delivered social engineering. Phishing can be targeted, known as spearphishing. In 
spearphishing, a specific individual, company, or industry will be targeted by the adversary. More 
generally, adversaries can conduct non-targeted phishing, such as in mass malware spam campaigns.

Adversaries may send victims emails containing malicious attachments or links, typically to execute malicious code on 
victim systems. Phishing may also be conducted via third-party services, like social media platforms. Phishing may 
also involve social engineering techniques, such as posing as a trusted source, as well as evasive techniques such as 
removing or manipulating emails or metadata/headers from compromised accounts being abused to send messages (e.g., 
Email Hiding Rules). Another way to accomplish this is by forging or spoofing the identity of the sender 
which can be used to fool both the human recipient as well as automated security tools.

Victims may also receive phishing messages that instruct them to call a phone number where they are directed to visit 
a malicious URL, download malware, or install adversary-accessible remote management tools onto their computer 
(i.e., User Execution)."""
        )
    ]
]

techniques_relationships = [
    relationship
    for technique in techniques
    for relationship in [
        stix2.Relationship(
            type="relationship",
            relationship_type="uses",
            source_ref=apt41_intrusion_set,
            target_ref=technique,
        ),
        stix2.Relationship(
            type="relationship",
            relationship_type="uses",
            source_ref=apt41_threat_actor,
            target_ref=technique,
        ),
    ]
]

malware = [
    stix2.Malware(
        type="malware",
        name=name,
        description=description,
        malware_types=malware_types,
        capabilities=capabilities,
        is_family=False,
    )
    for
    (name, description, malware_types, capabilities)
    in
    [
        (
            "ASPXSpy",
            "ASPXSpy is a Web shell. It has been modified by Threat Group-3390 actors to create the ASPXTool version.",
            [
                "backdoor",
                "webshell",
            ],
            [
                "accesses-remote-machines",
                "controls-local-machine",
            ],
        ),
        (
            "BLACKCOFFEE",
            "BLACKCOFFEE is malware that has been used by several Chinese groups since at least 2013.",
            [
                "backdoor",
            ],
            [
                "cleans-traces-of-infection",
                "communicates-with-c2",
                "determines-c2-server",
                "controls-local-machine",
            ],
        ),
        (
            "gh0st RAT",
            "gh0st RAT is a remote access tool (RAT). The source code is public and it has been used by multiple "
            "groups.",
            [
                "backdoor",
            ],
            [
                "captures-input-peripherals",
                "captures-system-state-data",
                "cleans-traces-of-infection",
                "communicates-with-c2",
                "controls-local-machine",
                "persists-after-system-reboot",
            ],
        ),
    ]
]

malware_relationships = [
    stix2.Relationship(
        type="relationship",
        relationship_type="uses",
        source_ref=apt41_threat_actor,
        target_ref=malware_,
    )
    for malware_ in malware
]

apt41_bundle = stix2.Bundle(
    objects=[
        apt41_threat_actor,
        ccp_identity,
        ccp_relationship,
        china_location,
        ccp_china_relationship,
        apt41_threat_actor_china_relationship,
        apt41_intrusion_set,
        apt41_relationship,
        western_world_identity,
        western_world_target_relationship,
        *techniques,
        *techniques_relationships,
        *malware,
        *malware_relationships,
    ]
)

print(apt41_bundle.serialize(pretty=True))
