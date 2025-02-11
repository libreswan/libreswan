# Google Summer of Code

## Previous Student projects

See [Student projects](https://libreswan.org/wiki/Student_projects for
completed student projects (sponsored by GSoC and others).

## Proposal submissions

Submissions must comply to all GSoC rules. We strongly urge any
interested students to read up on the previous student projects and
the below project ideas.  It is not required to be one of these ideas
- we welcome new ideas too!  Submissions that tend to be accepted and
successful are those that show from the start that the student is
putting in the time to understand the concepts.  You don't have to be
an expert already, and you can contact us at `gsoc at libreswan dot
org` for questions. Mentors like to see students that have put in some
work to understand and try things.  It is the only reliable metric we
have for new people to indicate how serious they are to take on a
project for the summer.  If implementing an RFC, read the RFC and ask
us any questions you have.  Have a look at the code base structure in
general, look at our testing/ directory.  If you don't have VPN/IPsec
experience, we are happy to give you a client configuration to gain
experience using libreswan to a real VPN server.

## Google Summer of Code Ideas

While IKE and IPsec have been around for 20 years, like SSL/TLS, the
protocols are still evolving and getting new features to deal with an
ever changing world.  The Libreswan Project's core developers have
come up with a list of projects that they believe would be interesting
for students to work on.  The mentors have a personal interest in
these projects as well.  If any of these projects look interesting to
you, feel free to contact the developers either on the (developer
mailing list)(https://lists.libreswan.org/mailman/listinfo/swan-dev)
the `#libreswan` channel on `LiberaChat` IRC.  You can also email
`gsoc at libreswan org` with any questions you have or if you would
like to introduce yourself.

A quick overview and history of The Libreswan Project was presented by
Paul Wouters as part of the Opportunistic IPsec presentation at the
[2016 Linux Security
Summit](http://events.linuxfoundation.org/events/linux-security-summit)
and there is a [video
recording](https://www.youtube.com/watch?v=Me_rl6N1m7c&list=PLbzoR-pLrL6pq6qCHZUuhbXsTsyz1N1c0&index=17)
of the presentation.

## Improvements

### Implement CHAP authentication within EAP

Libreswan currently has support for
[EAP](https://www.rfc-editor.org/rfc/rfc3748.html) authentication
using [EAP-TLS](https://www.rfc-editor.org/rfc/rfc5216).  This project
would extend Libreswan to also support EAP authentication to use CHAP.

#### Expected outcomes

A testcase demonstrating Libreswan authenticating a peer using a
[FreeRADIUS](https://www.freeradius.org/) server for CHAP
authentication.

#### Skills Required/prefered

C programming.\
Writing documentation and test cases, Internet Protocols

#### Possible Mentors

TBD

#### Expected size

175 Hours

#### Dificulty

Intermediate.

### Dynamically configure IKE algorithms based on cryptographic policy

Several things determine which cryptographic algorithms Libreswan can
use when establishing an IKE SA:

- the way libreswan was built
- the systems current crypographic policy
- the default crypto-suite
- the IKE SA's configuration

The goal of this project is to modify Libreswan so that dynamically
configures its default and acceptable cryptographic algorithms based
on what is permitted by the systems cryptographic policy.

#### Expected outcomes

Test case demonstrating Libreswan accepting / rejecting IKE algorithms
based on the system's crypto policy.

#### Skills Required/prefered

C programming\
Writing documentation and test cases, Internet Protocols

#### Possible Mentors

TBD

#### Expected size

175 Hours

#### Dificulty

Intermediate.

## RFCs (Requests for Comment), including drafts

### [(draft)](https://datatracker.ietf.org/doc/draft-ietf-ipsecme-g-ikev2/) Group Key Management using IKEv2

#### Expected outcomes
#### Skills Required/prefered

C programming\
Writing documentation and test cases, Internet Protocols

#### Possible Mentors

TBD

#### Expected size
(90, 175 or 350 hour)
#### Dificulty
An easy, intermediate or hard/difficult rating of each project.

### [(draft)](https://datatracker.ietf.org/doc/draft-ietf-ipsecme-ikev2-qr-alt/) Mixing Preshared Keys in the IKE_INTERMEDIATE and in the CREATE_CHILD_SA Exchanges of IKEv2 for Post-quantum Security

more detailed description of the project (2-5 sentences)
#### Expected outcomes
#### Skills Required/prefered

C programming\
Writing documentation and test cases, Internet Protocols

#### Possible Mentors

TBD

#### Expected size
(90, 175 or 350 hour)
#### Dificulty
An easy, intermediate or hard/difficult rating of each project.

### [RFC 9611](https://www.rfc-editor.org/rfc/rfc9593.html): Support for Per-Resource Child Security Associations (SAs)

more detailed description of the project (2-5 sentences)
#### Expected outcomes
#### Skills Required/prefered

C programming\
Writing documentation and test cases, Internet Protocols

#### Possible Mentors

TBD

#### Expected size
(90, 175 or 350 hour)
#### Dificulty
An easy, intermediate or hard/difficult rating of each project.

### [RFC 9593](https://www.rfc-editor.org/rfc/rfc9593.html): Announcing Supported Authentication Methods ...

more detailed description of the project (2-5 sentences)
#### Expected outcomes
#### Skills Required/prefered

C programming.
Writing documentation and test cases, Internet Protocols

#### Possible Mentors

TBD

#### Expected size
(90, 175 or 350 hour)
#### Dificulty
An easy, intermediate or hard/difficult rating of each project.

### [RFC 9464](https://www.rfc-editor.org/rfc/rfc9464.html): Configuration for Encrypted DNS; huh?

more detailed description of the project (2-5 sentences)
#### Expected outcomes
#### Skills Required/prefered

C programming.
Writing documentation and test cases, Internet Protocols

#### Possible Mentors

TBD

#### Expected size
(90, 175 or 350 hour)
#### Dificulty
An easy, intermediate or hard/difficult rating of each project.

### [RFC 9370](https://www.rfc-editor.org/rfc/rfc9370.html): Intermediate Exchange in the IKEv2 Protocol

Ueno has a
pull-request for some of the work; but not IKE_FOLLOWUP_KE

more detailed description of the project (2-5 sentences)
#### Expected outcomes
#### Skills Required/prefered

C programming\
Writing documentation and test cases, Internet Protocols

#### Possible Mentors

TBD

#### Expected size
(90, 175 or 350 hour)
#### Dificulty
An easy, intermediate or hard/difficult rating of each project.

### [RFC 8598](https://www.rfc-editor.org/rfc/rfc8598.html): Split DNS Configuration

more detailed description of the project (2-5 sentences)
#### Expected outcomes
#### Skills Required/prefered

C programming\
Writing documentation and test cases, Internet Protocols

#### Possible Mentors

TBD

#### Expected size
(90, 175 or 350 hour)
#### Dificulty
An easy, intermediate or hard/difficult rating of each project.

### [RFC 7670](https://www.rfc-editor.org/rfc/rfc7670.html): Generic Raw public key support

more detailed description of the project (2-5 sentences)
#### Expected outcomes
#### Skills Required/prefered

C programming\
Writing documentation and test cases, Internet Protocols

#### Possible Mentors

TBD

#### Expected size
(90, 175 or 350 hour)
#### Dificulty
An easy, intermediate or hard/difficult rating of each project.
