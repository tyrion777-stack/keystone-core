# Keystone — The End User Vision

This document exists for one reason: to stop us from building the wrong thing.
Every technical decision should trace back to a story in here. If it doesn't,
we question whether it needs to be built at all.

---

## The Core Problem

Platforms own your digital life. Your followers, your content, your reputation,
your customer relationships — all of it lives in a database you don't control.
The platform can delete it, sell it, restrict it, or disappear with it overnight.

You built the audience. They keep the audience.

Keystone is the infrastructure that puts it back in your hands.

---

## The Personas

### Joe — the creator

Joe makes short cooking videos. He built 40,000 followers on one platform over
three years. One morning his account is suspended — community guidelines violation,
automated flag, no human reviewed it. Appeal form goes nowhere. Three years of
content, relationships, income — gone.

Joe is not paranoid. This happens every week to real people.

**What Joe needs:** an identity and an audience that no single company can delete.

---

### Sarah — the fan

Sarah found Joe's channel two years ago. She doesn't think about infrastructure.
She just wants to keep seeing his content wherever she is, on whatever app she's
using, without re-following him every time a new platform emerges.

**What Sarah needs:** her follow graph to travel with her automatically.

---

### Maria — the small business owner

Maria runs a bakery. She takes custom cake orders. Her entire customer base lives
inside her Instagram DMs and her Facebook page. Last year Instagram changed their
algorithm and her reach collapsed overnight. She pays for ads now just to reach
people who already said they want to hear from her.

Her loyal customers — people who've ordered from her ten times — have no way to
find her if Instagram disappears. She has no list, no direct line, nothing she owns.

She also sells at a local farmers market. Cash only because card readers take 2.5%.
She'd love to let regulars pay digitally but every option has a middleman taking a cut.

**What Maria needs:** a direct, owned relationship with her customers that no
platform intermediates. And eventually, a way to take payments without a middleman.

---

### Kyle — the developer

Kyle wants to build a proximity file sharing app. Zero data charges when two
people are on the same WiFi. He doesn't want to run servers, manage user accounts,
store personal data, or deal with GDPR compliance. He just wants to build the
interesting part — the app.

Today he'd need: an auth system, a user database, file storage (S3 or similar),
a CDN, a payment system if he ever monetises, and lawyers for the privacy policy.

**What Kyle needs:** infrastructure that already exists so he only builds the app.

---

## The Ideal Experience

### Joe's experience (the creator)

Joe downloads an app built on Keystone. It asks him to create a passkey —
one Face ID scan. That's it. No email. No password. No username to choose.

Under the hood, his device generated a cryptographic keypair in the secure chip.
His public key is his identity on the network. It's permanent. No company issued
it. No company can revoke it.

Joe publishes a video. It's hashed — the hash is the video's permanent address,
like a fingerprint. It's stored across multiple nodes on the network. No single
server holds it. No single company can take it down.

Joe's followers are stored as signed records — "I, Joe, follow this person" —
signed with his key, living on the distributed network. Not in anyone's database.

If CreatorHub bans Joe tomorrow, he opens VibeSpace, scans a QR code to import
his identity, and his 40,000 followers are there — because they were never
CreatorHub's to begin with.

---

### Sarah's experience (the follower)

Sarah doesn't know any of this is happening. She uses the app. She follows Joe.
When Joe moves platforms, Sarah's app surfaces his new content automatically —
because it's following his identity, not his account on a specific platform.

The app might say "Joe is now also posting on VibeSpace" — not because VibeSpace
told the app, but because Joe's node announced it and Sarah's node is subscribed
to Joe's identity.

---

### Maria's experience (the small business owner)

Maria's bakery has a Keystone identity. Her menu, photos, and business hours are
content addressed on the network — permanent links that don't break, that she
controls.

A loyal customer, Paulo, has bought from her twelve times. That relationship is
a signed credential — "Maria's bakery verifies Paulo is a regular customer" —
stored in Paulo's identity wallet. Paulo can show that credential anywhere.
Maria never loses that customer relationship to a platform.

When Maria is at the farmers market, Paulo is nearby. His app and her app find
each other over local WiFi via the same discovery protocol that powers everything
else on Keystone. He taps to order. No app store. No middleman. No 2.5% fee.

Eventually (Phase 7): Paulo pays in a way that settles directly, no payment
processor intermediating. Maria gets the full amount.

---

### Kyle's experience (the developer)

Kyle builds his file sharing app in three months instead of eighteen. He imports
the Keystone JS SDK. Identity is handled — no auth system to build. Discovery
is handled — mDNS finds nearby users automatically. File integrity is handled —
Blake3 hashing is built in. Trust is handled — users' follow graphs tell the
app who they already trust.

Kyle never touches a database schema for user accounts. He has no GDPR liability
for storing personal data because he stores none. His AWS bill is close to zero
because files move device to device.

Kyle's app works in countries with restricted internet because it works on local
WiFi without touching the open internet. That's a market most app developers
never even try to reach.

---

## What Makes This Different from "Sign in with Google"

Google's identity layer is excellent. Zero friction, universal support, instant
recovery. We should be honest that Keystone is harder to use today.

But Google's identity has a structural problem it can never fix: Google owns it.

- Google can suspend your account with no appeal and no warning. This happens.
- Google can read everything associated with your identity. They do.
- Google can be pressured by governments to revoke identities. They comply.
- If Google shuts down a product, your identity in that product is gone.
- You cannot take your Google social graph to a competitor.

Keystone's identity has different structural properties it can never lose:

- No company can suspend it. The key lives on your device.
- No company can read your private data. Encryption is end to end.
- No government can force a single point of revocation. There isn't one.
- The content and relationships survive any platform dying.
- Your social graph travels with you by design.

This is not better for every use case. For logging into a pizza ordering app,
Sign in with Google is fine. Keystone wins when the stakes are higher — when
your livelihood depends on the platform not betraying you.

---

## What Keystone Is Not

- Not a blockchain. No tokens. No mining. No speculation.
- Not trying to replace the internet. It runs on top of it.
- Not anonymous by default. Your public key is public. Privacy tools can be
  layered on top but that is not the base layer.
- Not ready for Joe today. The UX work (WebAuthn, JS SDK, mobile apps) comes
  after the protocol is solid. We are building the road before the cars.

---

## The Small Business Owner Opportunity

This is underexplored and worth building toward deliberately.

Small businesses are disproportionately hurt by platform dependency:

- A restaurant loses 30% of revenue when Yelp manipulates their reviews.
- A boutique loses their entire customer list when Facebook changes the rules.
- A market vendor pays 2.5% on every transaction to a processor who adds no value.
- A freelancer's portfolio disappears when a platform shuts down.

Keystone gives small businesses:

1. **A permanent address.** A public key and content-addressed presence that
   no platform owns. QR code on the door links to their Keystone identity.

2. **Owned customer relationships.** Regulars opt into a signed relationship.
   The business keeps that list forever, platform independent.

3. **Verifiable credentials.** "Regular customer," "loyalty tier," "paid membership"
   — issued by the business, held by the customer, verifiable by anyone without
   calling home to a server.

4. **Local discovery.** Customers nearby find the business via the same
   proximity protocol that works for everything else. No Google Maps listing fee.

5. **Eventually: direct payments.** No processor intermediary. (Phase 7.)

The small business market is massive, underserved by crypto (too complex),
and already feels the pain of platform dependency viscerally. This is a
strong second beachhead after creators.

---

## Build Order (what the story demands)

Reading these stories, here is what needs to exist, in order of impact:

1. **Content layer** (Phase 4) — Joe can't publish without this. Files need to
   live on the network, not on a server. This unlocks the core promise.

2. **JS SDK** (Phase 6) — Kyle can't build his app without this. Rust binaries
   are not how normal developers build web apps.

3. **WebAuthn / hardware binding** (Phase 5) — Face ID instead of passwords.
   This is the moment the UX becomes acceptable for normal people.

4. **Cross-device sync** (Phase 5) — Joe uses his phone and his laptop.
   Identity needs to move between them securely.

5. **Relay nodes** (Phase 5) — Sarah is offline when Joe publishes. The content
   needs to wait for her. Without relays, the network only works when both
   parties are online simultaneously.

6. **Payments** (Phase 7) — Maria's full story doesn't work without this.
   But it's last because the identity and content layers have to be solid first.

---

## The Test

Before shipping any feature, ask:

> Which person in this document does this help, and how does their day get better?

If the answer is only "it makes the protocol more correct" — that matters, but
it is not sufficient on its own. The protocol exists to serve these people.
Build accordingly.
