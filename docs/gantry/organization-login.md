# Organization login

Sign in to use your organization's sandbox policy and discover its remote
managers. Organization login is optional; personal and standalone remotes do
not require it.

## Sign in

Get an organization configuration file and its referenced policy files from
your administrator. Only use files from a trusted source.

```sh
gantry org login -config organization.json
gantry org status example-company
```

Gantry opens your browser. Run the browser on the same computer as the CLI.
If several profiles are available, add `-profile developer`. Use `-no-browser`
to display the login URL instead of opening it automatically.

In the dashboard, press **n → Organization** and select your configuration.
Press **esc** to cancel. **Remotes (B) → L** signs in or refreshes discovery
without creating a sandbox.

## Use an organization remote

If your organization provides remote discovery, list its available managers:

```sh
gantry org remotes example-company
```

Choose a manager in the dashboard's **Organization** flow, then complete the
create form. An unregistered manager still needs its **separate manager token**;
organization login alone does not grant manager access.

See [Remote access](remote-access.md) for connecting to a standalone manager.

## Apply policy to an existing sandbox

Login does not change existing sandboxes. To apply the selected policy, stop
the sandbox first:

```sh
gantry stop dev
gantry org apply example-company dev
gantry policy show dev
gantry resume dev
```

Organization policy cannot be combined with `-oauth-custody`.
See [Organization policy](organization-policy.md) for direct bundle management.

## Sign out or refresh

```sh
gantry org logout example-company
```

Logout removes the local login receipt. It does not log out your browser,
stop sandboxes, or remove policies already applied to them. Gantry saves no
OIDC tokens; sign in again when the login or discovery information expires.

- **No matching profile:** ask your administrator to check your membership.
- **No available remotes:** refresh with another login, or ask whether your
  organization provides a remote catalog.
- **Browser cannot finish:** check that it runs on the CLI host and can reach
  the loopback callback address.

For administrator configuration, catalog setup and security details, see
[Architecture](architecture.md#organization-identity-and-discovery).
