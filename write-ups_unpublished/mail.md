# The basics of email security features.
_Notes from 2022-12 & 2023-10, Eliot Roxbergh_

SPF, DKIM, and DMARC are DNS values, which a sender of an email (email server for a domain) can set, telling the receiver when to reject an invalid message (e.g. spoofed) from that domain.

<https://dmarcian.com/wp-content/uploads/2022/05/DMARCPolicyOverview_Table.png>

## Domain vs webserver

If you're using a mail service they have hopefully already configured SPF, DKIM, and DMARC. However, if you're using such a service in conjuction with a custom domain you need to enable each of these by setting DNS (TXT) records.
DKIM for instance is signed by the email server which holds a private key, you as a customer however can get the public key and set in the DNS record to use DKIM.
SPF and DKIM are also configured via DNS TXT records.


## SPF

DNS TXT record which states which mx server emails should come FROM. In this way it's IP based (i.e. it checks envelope from / return path), wheras DKIM is public key based (signed).

Return-Path (=envelope from) is where the email if from and where any bounces will be sent. This domain is used to verify the email with SPF (envlope IP address is present in DNS record).

With SPF we verify that an email is sent from a certain IP address (envelope from), but this sender can still forge the FROM field. Instead, this is checked with DMARC policies (check FROM == Return-Path) - see DMARC alignment [1]. \
The reason is - I think - that SPF is on a lower layer / before message DATA such as "From field", and only verifies the origin IP.
Therefore, SPF does not by itself protect against forgeries, instead it only promises that the source IP is that of the sender domain; we know which domain sent the email.
So SPF is quite weak by itself again spam?!

(A good start but use with other protection mechanisms, especially for shared mail server?)

_"Receivers use ordinary DNS queries, which are typically cached to enhance performance. Receivers then interpret the SPF information as specified and act upon the result."_ - wikipedia

Your policy (~all -all ?all e.g.) is a recommendation how the receiver should handle messages with incorrect SPF (i.e. from another domain?).
However, as per RFC 7489 (§6.7 “Policy Enforcement Considerations”), it is up to the receiver MX to decide what action to take (reject, quarantine, accept).
If SPF fails, but the mail server decides to accept the message regardless they should at least ("RECOMMENDED") add Authentication-Results header field so the end user may see that SPF failed [RFC 7489 §6.7].

NOTE: no integrity protection, or anything, is added by SPF.

[1] - <https://www.dmarcly.com/blog/what-is-dmarc-identifier-alignment-domain-alignment>

## DKIM

DKIM adds integrity protection to the email, by providing a public key in a DNS TXT entry.

With DKIM, the MX server, signs the email sent, which can then be verified.

It is recommended to use both SPF and DKIM, however, why is DKIM not enough? If we assume the public key is received from DNS
and the private key is only in possession of the MX server? And no replay possible. Still of course it is nice to still have SPF, at least for clarity.


More reading for good measure: https://powerdmarc.com/what-is-dkim-signature/

## DMARC

**tl;dr** 1) check SPF & DKIM. 2) check alignment with SPF & DKIM (FROM field). 3) What to do if steps 1 or 2 failed (including reporting).

DMARC is (another) policy for the receiver. This time, it's for telling the receiver when to enforce SPF and/or DKIM and what to do otherwise. A report can also be sent back to the sender.

_"A DMARC policy allows a sender's domain to indicate that their email messages are protected by SPF and/or DKIM, and tells a receiver what to do if neither of those authentication methods passes – such as to reject the message or quarantine it. The policy can also specify how an email receiver can report back to the sender's domain about messages that pass and/or fail."_ - Wikipedia

Therefore, to use DMARC you also need to use DKIM or SPF.

Another option of DMARC is to check the FROM field, see DMARC alignment [1].
Basically, _DKIM alignment_ or _SPF alignment_ means that the FROM field matches the fields verified by DKIM (i.e. in DKIM DNS entry) or SPF (i.e. Return-Path in email) respectively. \
Comment: One would think this should be enforced even without DMARC (?) - by SPF or DKIM directly - but well it can optionally be done by the reciever anyway (but might break something that's why we have DMARC?) or it SPF/DKIM is done on another layer/time/purpose and thus inconvenient?

[1] - <https://www.dmarcly.com/blog/what-is-dmarc-identifier-alignment-domain-alignment>
