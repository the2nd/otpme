# NAME

otpme-client - say which service may have a login checked, and how

# SYNOPSIS

**otpme-client** *command* \[*options*\] \[*client*\]

# DESCRIPTION

A client is a service that asks OTPme whether somebody may come in: a
switch or an access point doing RADIUS, a VPN gateway, an LDAP client, a
web application that signs its users in with OpenID Connect, or an
application on the SSO portal. It is the other side of a login — the
token says who, the client says where.

Every client has one access group, and that group is what decides
whether the token is let in; the client itself holds no such list. A
client without an access group lets nobody in. See
**otpme-accessgroup**(1).

What a client holds is how it is reached and what it is allowed to ask
for: the shared secret and the addresses of a RADIUS client, the
registration data of an OIDC application, the tile of an application on
the portal, and — where logins are limited — the tokens and roles that
may use it.

A client lives in the **clients** unit of a site, and the nodes of that
site are what answers with it. Every site is created with two of them,
see **THE CLIENTS A SITE BRINGS**.

For the bigger picture — what a token is, what an access group does, how
a login runs — see **otpme**(7).

# COMMANDS

## Client Management

**add \[**--enable-oidc**\] \[**--scopes** *s1,s2*\] \[**--add-scopes** *s1,s2*\] \[**--no-default-scopes**\] *client* \[*address*\]**  
Create a client.  
It is created in the **clients** unit of your site; a path puts it into
another unit, and **move** takes it there afterwards. A secret of 32
characters is generated with it, whether or not anything uses one.  
With an *address* the address is added right away and the secret is
printed — that pair is what a RADIUS client needs. An address that
another client already has is refused.  

**--enable-oidc**  
Switch OIDC on for the new client and put it into the scopes the site
names in **oidc_default_scopes** (see **otpme**(7)).

**--scopes *s1,s2***  
Use these scopes instead of that list.

**--add-scopes *s1,s2***  
Use these as well as the ones that are left.

**--no-default-scopes**  
Use none of the site's list.

A scope that does not exist is refused before any of them is applied,
and all of this needs **--enable-oidc**; without it the scope options
are ignored and OTPme says so. Which scopes there are, and who may hand
them out, is in **otpme-scope**(1).  
Needs the ACL **add:client** on the unit it is created in, not on the
client — there is none yet.

**del \[**--no-trash**\] *client***  
Delete a client. It goes to the trash, from where **otpme-trash**(1) can
bring it back; **--no-trash** deletes it right away.  
Needs the ACL **delete:object** on the client, or **delete:client** on
the unit it sits in.  
A client a site brings with it cannot be deleted.

**show \[**-a**\] \[**-z** *N*\] \[**--fields** *F1,F2*\] \[**--limit** *N*\] \[**--policy-limit** *N*\] \[**--scope-limit** *N*\] \[**--sort-by** *field*\] \[**--reverse**\] \[**--raw**\] \[**--csv**\] \[**--csv-sep** *sep*\] \[*client*\]**  
Without a client: a table of all of them, with their unit, their access
group, their roles and tokens, their scopes, whether 802.1X and OIDC are
on, whether logins are limited, their addresses, the auth cache and its
timeout, and their policies.

**-a**  
Also the clients you may only look at, not just the ones you may change.

**-z *N***  
How many clients to print.

**--fields *F1,F2***  
Print these columns and no others, in the order they are named. The
names are the ones in the header of the table. A name with a **+** in
front is added to the columns that are shown anyway, and one with a
**-** is left out of them.

**--limit *N*, **--policy-limit** *N*, **--scope-limit** *N***  
How many items to print per client, and the same for the policies and
the scopes alone.

**--sort-by *field*, **--reverse****  
Which column to sort by, and the other way round.

**--raw, **--csv**, **--csv-sep** *sep***  
For reading with something other than your eyes: **--raw** leaves the
header and the borders out, **--csv** prints one row per line with **;**
between the columns, and **--csv-sep** uses another separator.

A column you may not see says **-**. Which ACL opens which column is the
**view:** ACL of that value, and the ACL that sets the same value does
as well — whoever may set a thing may read it.  
Nothing of the SSO portal and nothing of OIDC beyond the two flags is in
the table. With a client named, this prints the object itself instead of
a table row, and that is where all of it is: one value per line, from
the addresses to the redirect URIs. The secret is in there only for
whoever may see it.

**list \[**-a**\] \[**--attribute** *attribute*\] \[*regex*\]**  
List the client names, and with a regex only those that match it. You
get the clients you may change; **-a** adds those you may only look
at.  
**--attribute** matches the regex against that attribute instead of the
name: **list --attribute oidc_auth True** lists the OIDC clients. A
value that is not text has to be spelled out — **\*** matches none of
it.

**enable *client***  
Enable a disabled client.  
Needs the ACL **enable:object**.

**disable *client***  
Switch a client off without deleting it. Nobody is let in through it,
and it is gone from the application list of the portal.  
Needs the ACL **disable:object**.

**rename *client* *new_name***  
Rename a client.  
The name is what a RADIUS request names as its **NAS-Identifier**, and
what an LDAP client puts in front of the realm as a **dc=**, so a rename
is a change on the other side as well.  
Needs the ACL **rename:object**.

**move \[**--keep-acls**\] *client* *unit***  
Move the client into another unit. Its ACLs move with it: the default
ACLs of the old unit are taken away and those of the new one are
applied. **--keep-acls** leaves the ACLs of the client as they are.  
A client does not inherit ACLs by default, see
**enable_acl_inheritance** below.

**touch *client***  
Re-index the object to fix potential index problems.  
Needs the ACL **touch**.

## The Access Group

**access_group *client* \[*accessgroup*\]**  
Say which access group decides the logins of this client.  
That group holds the tokens and roles that may come in, and it says what
a login creates: whether there is a session, how long it lives, how many
failed logins lock a user out of this service. Two clients may share one
group, and the LDAP client picks one per request, see **HOW A CLIENT IS
USED**.  
The group has to exist in the site of the client. Without a group the
client is left without one, and then it lets nobody in and is on no
portal.  
Needs the ACL **edit:accessgroup**.

## Who May Log In

A token is named by its path, *user***/***token*. A role is named by its
name, which is looked for in the site of the client, or as
*site***/***role* to take one from another site of the realm.

**limit_logins *client***  
From now on let only the tokens of this client in.  
A login through this client is then refused unless the token is one the
client holds, or one of a role it holds — the access group alone is no
longer enough. An administrator token is let in either way. See
**LIMITED LOGINS**.  
Needs the ACL **limit_logins**.

**unlimit_logins *client***  
Go back to letting in whoever the access group lets in. The tokens and
roles of the client stay as they are and stop deciding anything.  
This is how a client is created.  
Needs the ACL **unlimit_logins**.

**add_token \[**--skip-portal-token**\] *client* *token_path* \[*token_options*\]**  
Put a token into the client.  
With limited logins this is what lets it in; without them it decides
nothing.  
If the token is the SSO token of a site's portal (its name is that
site's **default_sso_token_name**), the tokens the portal manages for
the user are added as well, after a confirmation.
**--skip-portal-token** adds only the given token.  
*token_options* are SSH **authorized_keys** options. Nothing reads them
on a client; they are kept with the assignment, see **otpme-host**(1).  
The assignment is never signed, and there is no **--sign** here. A token
signature is verified in one place, the **authorized_keys** a host
writes, and what is asked for there is whose token it is — never which
client it was assigned to. Where a signed assignment does mean something
is on a role, a group, a host or a node.  
Needs the ACL **add:token**.

**remove_token \[**--skip-portal-token**\] *client* *token_path***  
Take the token out of the client. A UUID is taken as well, which is how
a reference to a token that is gone is cleared out.  
If the token is the SSO token of a portal, the tokens the portal manages
are removed with it; **--skip-portal-token** removes only the given
token.  
Needs the ACL **remove:token**.

**list_tokens \[**--return-type** *TYPE*\] \[**--token-types** *t1,t2*\] \[*client*\]**  
List the tokens of the client, disabled ones included.  
**--return-type** selects what is printed per token; the default is the
path. **--token-types** lists only tokens of the given types, for
example **hotp,totp**.  
Needs the ACL **view:tokens**.

**add_role *client* *role***  
Put a role into the client, which is the way to do it for more than one
user.  
Needs the ACL **add:role**.

**remove_role *client* *role***  
Take the role out of the client.  
Needs the ACL **remove:role**.

**list_roles *client***  
List the roles of the client.  
Needs the ACL **view:roles**.

## RADIUS

What a RADIUS client needs is a secret and a way to be recognised, see
**HOW A CLIENT IS USED**.

**secret *client* \[*secret*\]**  
Set the shared secret of the client.  
Without one OTPme offers to generate it and prints what it generated;
otherwise it asks for it twice. The secret of a new client is 32
characters.  
It is kept encrypted with the key of the site, like a password.  
Needs the ACL **edit:secret**.

**show_secret *client***  
Print the secret in clear, which is how it gets into the configuration
of the switch or the VPN gateway.  
Needs the ACL **view:secret**.

**add_address *client* *address***  
Add an address the client sends its requests from.  
A RADIUS request that carries no **NAS-Identifier** is matched by this,
and FreeRADIUS is told to reload after the change. A client may have
several addresses.  
Needs the ACL **add:address**.

**del_address *client* *address***  
Take an address away again.  
Needs the ACL **delete:address**.

**enable_dot1x *client***  
Say that this client does 802.1X, i.e. that it is a switch or an access
point asking for a port.  
Two things change: the answer carries the VLAN of the token, which is
what puts the port into its network (see **otpme-vlan**(1)), and only
the tokens that can answer without a question of their own are tried — a
password token and a PIV token, not a token that needs a challenge or a
card on the user's side.  
Needs the ACL **enable:dot1x_auth**.

**disable_dot1x *client***  
Stop doing that.  
Needs the ACL **disable:dot1x_auth**.

**enable_auth_cache *client***  
Let this client authenticate from the cache for a while, see **THE AUTH
CACHE**.  
Needs the ACL **enable:auth_cache**.

**disable_auth_cache *client***  
Check every request again.  
Needs the ACL **disable:auth_cache**.

**auth_cache_timeout *client* *timeout***  
How long a cached answer counts, in seconds. Default **60**.  
The same value also says how long the RADIUS side keeps the client
object itself in memory, 120 seconds where it is unset.  
Needs the ACL **edit:auth_cache_timeout**.

## OIDC

What an application needs to sign users in with OpenID Connect, see
**OIDC** below. The provider itself is switched on per site, see
**enable_oidc** in **otpme-site**(1), and what the application may learn
about a user is decided by its scopes, see **otpme-scope**(1).

**enable_oidc *client***  
Say that this client is an OIDC application.  
It then has a client ID (its name), a client secret (**show_secret**),
the grant types **authorization_code** and **refresh_token**, the
response type **code** and the auth method **client_secret_basic** — and
no redirect URI, which is the one thing it cannot work without.  
Needs the ACL **enable:oidc_auth**.

**disable_oidc *client***  
Stop answering OIDC for it. Everything that was registered stays.  
Needs the ACL **disable:oidc_auth**.

**add_oidc_redirect_uri *client* *uri***  
Register a URI the user may be sent back to after signing in.  
A request that names another one is refused, so this is what keeps an
authorization code from being delivered anywhere else.  
It has to be **https**, or **http** with **localhost**, **127.0.0.1** or
**::1**; it has to name a host; and it must carry no fragment.  
Needs the ACL **add:oidc_redirect_uri**.

**del_oidc_redirect_uri *client* *uri***  
Take a redirect URI off the list.  
Needs the ACL **delete:oidc_redirect_uri**.

**show_oidc_redirect_uris *client***  
List them.  
Needs the ACL **view:oidc_redirect_uris**.

**add_oidc_logout_redirect_uri *client* *uri***  
Register a URI the user may be sent back to after signing *out*, which
the application asks for at */end_session* as its
**post_logout_redirect_uri**.  
Same rules as for a redirect URI.  
Needs the ACL **add:oidc_logout_redirect_uri**.

**del_oidc_logout_redirect_uri *client* *uri***  
Take one off the list.  
Needs the ACL **delete:oidc_logout_redirect_uri**.

**show_oidc_logout_redirect_uris *client***  
List them.  
Needs the ACL **view:oidc_logout_redirect_uris**.

**oidc_auth_method *client* *method***  
How the application authenticates itself at the token endpoint.

**client_secret_basic**  
The secret in an HTTP Basic header. This is the default.

**client_secret_post**  
The secret in the form body.

**none**  
No secret at all, for an application that cannot keep one — a
single-page application, a mobile app. What protects it then is PKCE,
which OTPme requires anyway.

Needs the ACL **edit:oidc_auth_method**.

**oidc_id_token_alg *client* *alg***  
What the ID Token of this application is signed with: **RS256** (the
default), **RS384**, **RS512**, **ES256**, **ES384**, **ES512** or
**EdDSA**.  
The site has to have a signing key for it. That is not checked here, so
the key can be added afterwards — but until it is, no token is issued.  
Needs the ACL **edit:oidc_id_token_alg**.

**oidc_subject_type *client* *subject_type***  
What the application is told as the *sub* of a user.

**public**  
The same identifier for every application. This is the default.

**pairwise**  
An identifier of its own per application, derived with the pairwise
secret of the site, so two applications cannot tell that they are
talking about the same person.

For **pairwise** the site needs that secret, see **otpme-site**(1).  
Needs the ACL **edit:oidc_subject_type**.

**oidc_sector_identifier_uri \[**--validate**\] \[**--clear**\] *client* \[*uri*\]**  
The URI that groups several applications into one sector, so they get
the same pairwise identifiers.  
It has to be **https** and name a host. **--validate** fetches it right
away and checks that every registered redirect URI is in it; without
that the check waits until a token is signed. **--clear** removes it.  
Needs the ACL **edit:oidc_sector_identifier_uri**.

**oidc_backchannel_logout_uri \[**--clear**\] *client* \[*uri*\]**  
Where this application is told that the user has signed out.  
When a session ends, OTPme sends every application a signed message,
from server to server, so each of them can end its own session as well —
the browser is not involved and need not even be open any more. An
application without this URI is not told, and its session lives until it
runs out by itself.  
It has to be **https**, name a host and carry no fragment. **--clear**
removes it.  
Needs the ACL **edit:oidc_backchannel_logout_uri**.

**enable_oidc_force_backchannel_logout *client***  
Send that message to this application even when the sign-out came from
the application itself.

Normally OTPme skips exactly that one. An application that sends the
user to */end_session* already knows the user is leaving and is clearing
up its own session at that moment; a message arriving in the middle of
it is answered with an error more often than not, and says nothing new.

Switch this on for an application that ends its session only when the
message arrives, and not when it starts the sign-out itself.

Needs the ACL **enable:oidc_force_backchannel_logout**.

**disable_oidc_force_backchannel_logout *client***  
Skip the application that asked for the sign-out again. This is how a
client is created.  
Needs the ACL **disable:oidc_force_backchannel_logout**.

**enable_oidc_backchannel_tls_verify *client***  
Check the TLS certificate of the application when that message is sent.
This is how a client is created.  
Needs the ACL **enable:oidc_backchannel_tls_verify**.

**disable_oidc_backchannel_tls_verify *client***  
Do not check it.  
For a lab application with a self-signed certificate. In production pin
the CA instead, with **oidc_backchannel_ca_cert** below.  
Needs the ACL **disable:oidc_backchannel_tls_verify**.

**oidc_backchannel_ca_cert \[**--clear**\] *client* *ca_cert_file***  
Verify that certificate against this CA bundle instead of the trust
store of the system.  
The file is read here and has to be PEM. **--clear** removes it, and the
trust store counts again.  
Needs the ACL **edit:oidc_backchannel_ca_cert**.

**add_oidc_grant_type *client* *grant_type***  
Allow one more way of getting a token: **authorization_code**,
**refresh_token**, **client_credentials** or
**urn:ietf:params:oauth:grant-type:device_code**.  
A new client has the first two. Without **authorization_code** it cannot
sign anybody in; without **refresh_token** it gets no refresh token,
whatever it asks for. The other two are accepted here and not
implemented at the endpoint.  
Needs the ACL **add:oidc_grant_type**.

**del_oidc_grant_type *client* *grant_type***  
Take one away.  
Needs the ACL **delete:oidc_grant_type**.

**show_oidc_grant_types *client***  
List them.  
Needs the ACL **view:oidc_grant_types**.

**add_oidc_response_type *client* *response_type***  
Allow a response type. **code** is the only one there is, and a new
client has it.  
The hybrid and the implicit flow are not implemented, so nothing else
can be added, see **otpme-site**(1).  
Needs the ACL **add:oidc_response_type**.

**del_oidc_response_type *client* *response_type***  
Take it away, which stops the application from signing anybody in.  
Needs the ACL **delete:oidc_response_type**.

**show_oidc_response_types *client***  
List them.  
Needs the ACL **view:oidc_response_types**.

**find_scopes \[**--return-type** *TYPE*\] \[*client*\]**  
The other direction: which scopes hold this client, i.e. what it may ask
for. Disabled ones are listed too, and the roles of the client are not
followed.  
Needs the ACL **find:scopes**.

## The SSO Portal

A client with a login URL is an application on the portal of its site,
see **THE SSO PORTAL**.

**login_url *client* *login_url***  
Where the portal sends the user when they click the application.  
Without it the application is not on the portal at all, whatever else is
set.  
Needs the ACL **edit:login_url**.

**helper_url *client* *helper_url***  
Where the portal posts the name and a one time password of the user, for
an application that cannot do OIDC and has to be filled into a form.  
Needs the ACL **edit:helper_url**.

**enable_sso *client***  
Hand that application its login through the helper.  
Only with a login URL and a helper URL set; OTPme says which one is
missing. An OIDC application needs none of this — it is on the portal as
soon as it has a login URL.  
Needs the ACL **enable:sso**.

**disable_sso *client***  
Stop doing that.  
Needs the ACL **disable:sso**.

**enable_sso_popup *client***  
Let the helper open the application by itself, with nothing to click.

Without it the helper shows a page with the name of the application and
a button, and opens the application in a new tab when that button is
pressed. With it the helper opens that tab as soon as its own page is
loaded.

A browser counts that as a popup, because no click asked for it, and
blocks it: the first attempt fails and the user has to allow popups for
that application once. From then on it works with nothing to click.

This is what the helper that comes with OTPme does
(**otpme/web/sso.php**). The flag is handed to the helper as it is, so
another one may read it differently.

Only with a login URL and a helper URL, like **enable_sso** above.

Needs the ACL **enable:sso_popup**.

**disable_sso_popup *client***  
Have the helper wait for a click. This is how a client is created, and
it needs no permission from the user.  
Needs the ACL **disable:sso_popup**.

**sso_name *client* *sso_name***  
The name the portal writes under the tile. It is the name of the client
to begin with, which is seldom what a user should read.  
Needs the ACL **edit:sso_name**.

**sso_logo *client* *image_path***  
The picture on the tile. The file is read here and kept with the
client.  
Needs the ACL **add:sso_logo**.

**dump_sso_logo *client***  
Write that picture out again, base64 encoded.  
Needs the ACL **dump:sso_logo**.

**del_sso_logo *client***  
Remove it. The tile then carries the name alone.  
Needs the ACL **delete:sso_logo**.

## Object Changelog

Every change to the object writes an entry: who made it, when, and what
was done. A change can carry a comment of its own, through the global
option **--changelog**.

An *entry_id* is the number the listing shows in front of an entry,
counted from 0.

Only the comment of an entry can be changed or removed. What was done
and by whom stays as it is.

**changelog *client***  
Show the changelog of the client. Needs the ACL **view:changelog**.

**edit_changelog *client* *entry_id* *comment***  
Set the comment of that entry, or replace the one it has. Needs the ACL
**edit:changelog**.

**del_changelog *client* *entry_id***  
Remove the comment of that entry. The entry itself stays, and an entry
without a comment is refused. Needs the ACL **edit:changelog**.

**clear_changelog *client***  
Remove every entry of the changelog.  
This needs more than the ACL **clear:changelog**: the config parameter
**allow_changelog_clearing** has to allow it (see **otpme**(7)). It is
true by default, but where no value is found at all, clearing is
refused. OTPme asks the token you are signed in with first, then the
object.

## Policy Management

A *policy* is the name of a policy, not a path. It is looked for in the
site of the client. Which policies there are, and what each of them
does, is in **otpme-policy**(1).

**add_policy *client* *policy***  
Attach a policy to the client.  
A policy has a list of object types it is for; one that does not name
**client** is refused. So is a second policy of a type that allows only
one per object.  
Needs the ACL **assign:policy**.

**remove_policy *client* *policy***  
Remove a policy from the client.  
Needs the ACL **remove:policy**, and that one verbatim: a plain
**remove** does not cover it.

**list_policies \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *client***  
List the policies attached to the client. Use **--return-type** to
select the attribute returned (**name**, **read_oid**, **full_oid**,
**uuid**). Use **--policy-types** to list only policies of the given
types; these are policy types, not policy names.  
Needs the ACL **view:policies**.

## ACL Management

An ACL says what somebody may do with this client. The somebody is a
role or a token, never a user.

What the three forms **acl**, **+acl** and **++acl** mean, and which
ACLs exist, is under **ACLs** in **otpme**(7).

**add_acl *client* *owner_type* *owner* *acl*\[:*value*\]\[,*acl*\[:*value*\]\]**  
Give a role or a token one or more ACLs on this client.  
*owner_type* is **role** or **token**, and *owner* the path of that role
or token. An ACL may carry a value, for example **view:secret**, and
several are separated by commas.  
Needs the ACL **add:acl**.

**del_acl *client* *acl*\[,*acl*\]**  
Take those ACLs away again.  
Here an *acl* is the whole entry, owner and all, the way **list_acls**
prints it: **role:berlin/sw-admins:view**.  
Needs the ACL **delete:acl**.

**list_acls *client***  
Show the ACLs that lie on this client, i.e. who may do what with it.
Needs the ACL **view:acl**.

**enable_acl_inheritance *client***  
Let the client inherit the default ACLs of the unit above it.

A client does not, and that is on purpose: whoever may change a unit
full of other objects should not get the secret of a service by that
alone.

Only default ACLs are inherited. An ordinary ACL on the unit never is.

Moving the client into another unit then takes away the default ACLs of
the old unit and applies those of the new one. While inheritance is off,
a move leaves the ACLs of the client as they are.

Needs the ACL **enable:acl_inheritance**.

**disable_acl_inheritance *client***  
Stop inheriting them. Only the ACLs on the client itself count from then
on. Needs the ACL **disable:acl_inheritance**.

## Configuration

A config parameter is looked for on the client, then on the units above
it, then on the site. The first value found is the one that applies, and
the realm holds none. A site can turn that around for a parameter it
names in **force_site_config_parameters,** and then its own value wins
(see **otpme**(7)).

Which parameters a client takes is in **CONFIG PARAMETERS** below.

**config \[**-d**\] \[**-a**\] *client* *parameter* \[*value*\]**  
Set a parameter on the client.

**-d**  
Remove the parameter from the client, or with a value only that one
value from a list. It is not set back to a default: what applies
afterwards is whatever the unit or the site says.

**-a**  
Append the value to a parameter that holds a list, instead of replacing
what is there.

Without a *value* the parameter is set to its default, which is not the
same as leaving it unset: the value then stands on the client and
nothing above it is read any more.  
The ACL is per parameter, **set:config:***parameter*.

**show_config *client* \[*parameter*\]**  
The config parameters set on the client itself, or only the one named.  
Nothing is shown for a parameter that the client gets from a unit or
from the site, and nothing for one whose ACL **view:config:***parameter*
you do not hold. The settings of the client — its secret, its addresses,
its OIDC registration — are not config parameters: **show** and
**export** are where those are.

**get_config *client* *parameter***  
What the parameter comes to for this client, once the client, its units
and its site have been looked at. So this answers what applies, where
**show_config** answers what was set here.  
Needs the ACL **view:config:***parameter*, the same one that opens it in
**show_config**.

**description *client* \[*description*\]**  
Set the description. Without one OTPme asks and offers the current text
for editing.  
Needs the ACL **edit:description**.

**info \[**--language** *LANG*\] *client* \[*info*\]**  
Set free-form info text. If *info* is omitted, the current text is
opened in the editor named by the **EDITOR** environment variable.  
Without **--language** the text is the administrator's own note about
the object, which no user is ever shown. With a language it is text for
the users in that language.  
Needs the ACL **edit:info**.

**dump_info \[**--language** *LANG*\] *client***  
Print the info text, of that language or the administrator's own.  
Needs the ACL **view:info**.

## Export and Cleanup

**export \[**--password** *password*\] *client***  
Write the whole object of the client to stdout, as JSON.  
Without **--password** it is written as it is, in clear — and that
includes the secret. With one, a key is derived from that password and
the object is encrypted with it; the salt goes into the output, so the
password is all you need to read it back.  
Needs the ACL **export**.

**remove_orphans *client***  
Remove references to objects that are gone.  
A token or a role that is deleted leaves its UUID behind in every client
that held it. This clears those out, together with orphan ACLs, policies
and signatures.  
It asks once for everything it found; the global option **-f** skips the
question.  
Needs the ACL **remove:orphans**.

# HOW A CLIENT IS USED

Four services answer logins with a client, and each of them finds it its
own way.

**RADIUS**  
A request names itself with a **NAS-Identifier**, and that is matched
against the name of the client. A request without one is matched against
the addresses, so a switch that cannot be told an identifier is
recognised by where it comes from. The shared secret is the one of the
client, and FreeRADIUS is told to reload whenever an address or a secret
changes.  
With **enable_dot1x** the answer also carries the VLAN of the token.

**LDAP**  
The client is named in the bind DN, as a **dc=** in front of the realm:
**uid=alice,ou=users,dc=wiki,dc=example,dc=org** says "the client
**wiki**". What that picks is the access group of that client, so one
**ldapd** serves several applications, each with its own group and its
own session rules. Which object the DN means does not depend on it. See
**otpme**(7).

**OIDC**  
The application sends the user to the portal of the site and names
itself with its **client_id**, which is the name of the client.
Everything else it may do is on the client: the redirect URIs, the grant
and response types, how it authenticates at the token endpoint, what the
ID Token is signed with, what it is told as the *sub*.

**The portal**  
A client with a login URL is an application on the portal, see **THE SSO
PORTAL**.

In all four the access group decides who gets in, and with
**limit_logins** the client does as well.

# LIMITED LOGINS

A client lets in whoever its access group lets in. With **limit_logins**
it lets in only the tokens it holds itself, or the tokens of a role it
holds — the access group still has to allow them, so this narrows and
never widens.

A login that fails on it is answered with **LOGINS_LIMITED** and is not
counted as a failed login, so it locks nobody out. An administrator
token is let in either way.

This is off for a new client, and on for a new host or node — there it
is the other way round, see **otpme-host**(1).

# THE AUTH CACHE

A RADIUS client asks the same question over and over: 802.1X
re-authenticates, a VPN checks its tunnel, a portal page reloads. With
**enable_auth_cache** an answer counts again for **auth_cache_timeout**
seconds, 60 by default.

What is cached is the user, the client and the password, as a SHA-512
hash, together with the session the login created. A second request is
answered from it only where all three are the same and the entry is
younger than the timeout. Everything else goes to the authentication
daemon as usual.

So with a one time password the cache is what makes the same OTP work
again for that many seconds, which is what a supplicant that retries
needs. Keep the timeout short for that reason: it is the window in which
a password that was seen once is enough.

The cache lives in the RADIUS worker that answered, not in the cluster,
and it is gone when that process is.

# THE SSO PORTAL

The portal shows a user the applications they may use, as tiles with the
name of **sso_name** and the picture of **sso_logo**. An application is
on it when it is enabled, has a login URL, has an access group, and that
access group is one the token of the user reaches.

What clicking it does depends on the kind of application.

**An OIDC application**  
The browser is sent to the login URL and the application does the rest:
it sends the user back to the provider, where the session cookie of the
portal says who they are. Nothing more than **enable_oidc** and the
login URL is needed for the tile.

**An application with a helper**  
The portal asks for a one time password for the access group of the
application and posts it, with the name of the user, to the
**helper_url**. The helper opens the login URL in a tab of its own,
fills the name and that password into the form there and closes
itself.  
Whether the user has to press a button for that is **enable_sso_popup**
above. This is the way in for an application that can take a form but
not OIDC.

An application whose access group is disabled stays on the portal with
its button greyed out, so a user sees that it exists and is off rather
than wondering where it went. A user who was given **otpme-user
enable_disabled_login** sees it as usual (see **otpme-user**(1)).

# OIDC

What an application needs, in the order it is usually set up:

> -   **enable_oidc** and an access group, which is what decides who may
>     sign in;
>
> -   at least one redirect URI, with **add_oidc_redirect_uri**;
>
> -   the client ID, which is the name of the client, and the secret,
>     which **show_secret** prints — or **oidc_auth_method none** for an
>     application that cannot keep one;
>
> -   the scopes it may ask for, which are objects of their own: see
>     **otpme-scope**(1);
>
> -   for a single sign-out, **oidc_backchannel_logout_uri**.

The rest has defaults that work: grant types **authorization_code** and
**refresh_token**, response type **code**, auth method
**client_secret_basic**, ID Token signed with **RS256**, a public *sub*,
and PKCE required.

What the provider offers is in its discovery document, which an
application reads at  
**https://***sso_fqdn***/oidc/.well-known/openid-configuration**  
— the issuer is **https://***sso_fqdn***/oidc**, and the well-known path
hangs under it. The parameters that change how it answers this client —
consent, PKCE, the lifetime of an access token, whether the ID Token
carries the user claims — are config parameters, see **CONFIG
PARAMETERS**.

# THE CLIENTS A SITE BRINGS

Every site is created with two clients. They cannot be deleted.

**SSO**  
The portal of the site itself, with the access group **SSO**.

**LDAP**  
The one an LDAP client gets when it names none of its own, with the
access group **LDAP**.

# OPTIONS

Every option belongs to one command and is described with that command
above.

Global options work with every command, see **otpme**(1).

# CONFIG PARAMETERS

A client takes these. What each of them does is in **otpme**(7); the
OIDC ones are under **OIDC Provider** there.

**changelog (bool, default: true)**  
Whether the commands on this client are written to its changelog.

**allow_changelog_clearing (bool, default: true)**  
Whether that changelog may be cleared.

**oidc_require_consent (bool, default: false)**  
Whether the user is asked at */authorize* whether this application may
have the data.

**oidc_pkce_required (bool, default: true)**  
Whether PKCE is required of it.

**oidc_allow_plain_pkce (bool, default: false)**  
Whether the PKCE method **plain** is accepted from it.

**oidc_access_token_ttl (time, default: 1h)**  
How long an access token for it lives.

**oidc_id_token_user_claims (bool, default: false)**  
Whether the claims of the granted scopes are put into the ID Token as
well, for an application that never calls */userinfo*.

**oidc_id_token_hint_max_age (time, default: 3M)**  
How old an **id_token_hint** may be at */end_session*.

**oidc_logout_scope (str, default: sso)**  
Whether a logout of this application ends the whole SSO session or only
its own.

**oidc_acr_scheme (str, default: numeric)**  
What is written into the *acr* claim.

**oidc_avatar_dimensions (str, default: 300x300)**  
The size of the photo the *picture* claim points at.

# EXAMPLES

## A switch doing 802.1X

**otpme-client add switch1 10.0.0.5**  
Create it with its address; the secret is printed.

**otpme-client access_group switch1 lan**  
Logins of this switch go through the **lan** access group.

**otpme-client enable_dot1x switch1**  
It asks for a port, so the answer carries the VLAN of the token.

**otpme-client enable_auth_cache switch1**  

**otpme-client auth_cache_timeout switch1 30**  
Re-authentication within half a minute is answered from the cache.

## A web application with OIDC

**otpme-client add --enable-oidc wiki**  
Create it with the default scopes of the site.

**otpme-client access_group wiki wiki**  
Who may sign in to it, which is said in the access group of that name.

**otpme-client add_oidc_redirect_uri wiki https://wiki.example.org/oidc/callback**  
Where the user is sent back to.

**otpme-client show_secret wiki**  
The client secret for the configuration of the application.

**otpme-client oidc_backchannel_logout_uri wiki https://wiki.example.org/oidc/logout**  
Where it is told that the user signed out.

**otpme-client login_url wiki https://wiki.example.org/**  
And it is on the portal.

## An application that only takes a form

**otpme-client login_url shop https://shop.example.org/login**  

**otpme-client helper_url shop https://shop.example.org/otpme-helper**  

**otpme-client enable_sso shop**  
The portal hands the helper a one time password for the access group of
the client.

**otpme-client sso_name shop "Online Shop"**  

**otpme-client sso_logo shop /srv/logos/shop.png**  
What the user sees on the tile.

## Narrowing a client down

**otpme-client add_role vpn vpn-users**  

**otpme-client limit_logins vpn**  
From now on only the tokens of that role get through this client, even
though the access group would let more in.

**otpme-client add_acl vpn role it-support view:secret**  
The service desk may read the shared secret of the VPN, and nothing else
about it.

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-acls**(7), **otpme-accessgroup**(1),
**otpme-scope**(1), **otpme-site**(1), **otpme-token**(1),
**otpme-role**(1), **otpme-user**(1), **otpme-vlan**(1),
**otpme-host**(1), **otpme-policy**(1), **otpme-unit**(1),
**otpme-trash**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2026 the2nd. License: GPLv3
