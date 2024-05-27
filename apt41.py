#!/bin/env python3
import stix2

apt41_threat_actor = stix2.ThreatActor(
    type="threat-actor",
    name="APT41",
    description="APT41 is a threat group that researchers have assessed as Chinese state-sponsored espionage group that also conducts financially-motivated operations. Active since at least 2012, APT41 has been observed targeting healthcare, telecom, technology, and video game industries in 14 countries.",
    threat_actor_types=["crime-syndicate"],
    aliases=["Wicked Panda","Brass Typhoon","BARIUM"],
    roles=["agent","malware-author"],
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

apt41_indentity = stix2.Identity(
    type="identity",
    name="APT41",
    description="APT41 is the name of an organized threat actor crime-syndicate",
    identity_class="orgnization",
)

apt41_relationship = stix2.Relationship(
    type="relationship",
    relationship_type="attributed-to",
    source_ref=apt41_threat_actor.id,
    target_ref=apt41_indentity.id,
)

apt41_bundle = stix2.Bundle(objects=[
    apt41_threat_actor,
    apt41_indentity,
    apt41_relationship
])

print(apt41_bundle.serialize(pretty=True))
