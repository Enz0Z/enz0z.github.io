---
layout: post
title: "Syncing Discord roles to ACE permissions on FiveM Enhanced (a temporary workaround)"
date: 2026-09-24
tags: [fivem, esx, lua, txadmin, discord]
---

While migrating my server from FiveM Legacy to FiveM Enhanced, one of the first things that
broke was something I'd stopped thinking about years ago: my Discord permission sync.

## The setup

My staff and VIP ranks live in Discord. When a player joins, the queue asks the Discord API
for their roles in the guild, maps each role to an ACE group, and grants those groups at
runtime with `add_principal` (and revokes stale ones with `remove_principal`). On Legacy this
was just a couple of `ExecuteCommand` calls from a resource that had `command.add_principal`
granted in `server.cfg`.

## What broke

On Enhanced, those calls silently do nothing. No "access denied", no error. The principal
simply never shows up, and `IsPlayerAceAllowed` keeps returning false.

It turns out I wasn't alone: this is tracked in
[citizenfx/rfc#473](https://github.com/citizenfx/rfc/discussions/473). ACEs and principals
added at runtime **by a resource** have no effect on Enhanced, even when the resource is
authorized. The exact same commands typed into the server console *do* work, and ACEs
from `server.cfg` at boot work too. Only resource-issued runtime writes are dropped. It's
been acknowledged and triaged, but at the time of writing it's still open.

Since there's no native for mutating the ACL (the console commands are the only way), this
kills every resource that grants permissions at runtime.

## Finding another way in

So the question became: what path still counts as "the console"? On Legacy you could also
use UDP RCON, but Enhanced dropped it along with the old out-of-band protocol. What's left
is FXServer's **stdin**, which is exactly what you type into.

And who writes to FXServer's stdin? **txAdmin.** Its Live Console sends every line you type
there straight to the server process. So if a resource can talk to txAdmin as if it were
an admin using the Live Console, its commands arrive with console origin and the ACL
accepts them.

## The workaround

I created a dedicated txAdmin admin called `console_command` with only the `console.view`
and `console.write` permissions, and put its password in a server convar. `ESX.ConsoleCommand`
then:

1. Logs into txAdmin at `/auth/password` and keeps the session cookie.
2. Opens a socket.io session using the HTTP long-polling transport, joining the
   `liveconsole` room.
3. Sends `40` to connect the default namespace and polls once. A healthy session answers
   with `40{...}`; an expired one sends a `logout` event. In that case it drops the cookie,
   logs in again and retries once.
4. Emits a `consoleCommand` event (`42["consoleCommand", "..."]`) for each command.
5. Closes the session with `1`.

If `txadmin_password` isn't set, it falls back to plain `ExecuteCommand`, which is all you
need on Legacy, so the same code runs on both.

```lua
-- Runs console commands with console origin. Enhanced ignores add_ace / add_principal issued by a resource
-- (citizenfx/rfc#473, open in 2026-09) and dropped the UDP RCON together with the old OOB protocol, so the only runtime
-- path that still mutates the ACL is FXServer's stdin. txAdmin writes its live console there: this logs in as the admin
-- "console_command" (needs console.view + console.write) and pushes each line through the socket.io polling transport
-- of the liveconsole room. Without txadmin_password it falls back to ExecuteCommand, which is enough on Legacy.
-- Coupled to txAdmin internals (event name, rooms query, password login): a failure is logged, never silent.
ESX.ConsoleCommand = function(commands, retried)
    local password = GetConvar('txadmin_password', '')

    if password == '' then
        for _, command in ipairs(commands) do
            ExecuteCommand(command)
        end
        return true
    end
    local url = GetConvar('txadmin_url', 'http://127.0.0.1:40120')

    if not txAdminCookie then
        local login = ESX.HttpRequest(url .. '/auth/password', {['Content-Type'] = 'application/json'}, 'POST', json.encode({username = 'console_command', password = password}))

        for name, value in pairs(login.head or {}) do
            if string.lower(name) == 'set-cookie' then
                txAdminCookie = string.match(value, '^([^%s;=]+=[^;]+)')
            end
        end
        if not txAdminCookie then
            print(('[es_extended] ConsoleCommand: txAdmin login failed (HTTP %s): %s'):format(tostring(login.code), tostring(login.content)))
            return false
        end
    end
    local function call(method, path, body)
        return ESX.HttpRequest(url .. path, {['Cookie'] = txAdminCookie, ['Content-Type'] = 'text/plain;charset=UTF-8'}, method, body)
    end
    local handshake = call('GET', '/socket.io/?EIO=4&transport=polling&rooms=liveconsole')
    local sid = handshake.code == 200 and string.match(handshake.content, '"sid":"([^"]+)"')
    local endpoint = sid and '/socket.io/?EIO=4&transport=polling&sid=' .. sid
    -- "40" connects the default namespace; the first poll answers "40{...}" and, when the session is dead, a "logout" event
    local connect = endpoint and call('POST', endpoint, '40') and call('GET', endpoint)

    if not connect or connect.code ~= 200 or not string.find(connect.content, '^40') or string.find(connect.content, '"logout"', 1, true) then
        txAdminCookie = nil

        if not retried then
            return ESX.ConsoleCommand(commands, true)
        end
        print(('[es_extended] ConsoleCommand: txAdmin socket failed (handshake HTTP %s, connect %s)'):format(tostring(handshake.code), connect and tostring(connect.content) or 'none'))
        return false
    end
    for _, command in ipairs(commands) do
        call('POST', endpoint, '42' .. json.encode({'consoleCommand', command}))
    end
    call('POST', endpoint, '1')
    return true
end
```

## Using it from the Discord sync

The queue check fetches the member's roles, maps each role ID to a group through
`discord_role_<id>` convars, revokes whatever it granted last time, grants the current set,
and pushes it all through `ESX.ConsoleCommand` in one batch:

```lua
Queue.SetCheck(function(source, deferrals)
    local _, _, license, _, discord = ESX.GetIdentifiers(source)
    local discord_token = GetConvar('discord_token', '')
    local discord_guild = GetConvar('discord_guild', '0')

    if discord_token ~= '' and discord_guild ~= '0' then
        deferrals.update('\xF0\x9F\x94\x8E Sincronizando tus rangos de Discord...')
        local response = discord and ESX.HttpRequest('https://discord.com/api/v10/guilds/' .. discord_guild .. '/members/' .. string.sub(discord, 9), {['Authorization'] = 'Bot ' .. discord_token})
        local member_roles

        if not discord or response.code == 404 then
            member_roles = {}
        elseif response.code == 200 then
            member_roles = json.decode(response.content).roles
        end
        if member_roles then
            local groups = {}

            for _, role_id in ipairs(member_roles) do
                local group = GetConvar('discord_role_' .. role_id, '')

                if group ~= '' then
                    groups[group] = true
                end
            end
            local commands = {}

            for group in pairs(granted_groups[license] or {}) do
                commands[#commands + 1] = 'remove_principal identifier.' .. license .. ' group.' .. group
            end
            for group in pairs(groups) do
                commands[#commands + 1] = 'add_principal identifier.' .. license .. ' group.' .. group
            end
            granted_groups[license] = groups

            if commands[1] then
                ESX.ConsoleCommand(commands)
                Wait(100) -- stdin is read on the next server tick; the queue.priority check below needs the principals in place
            end
        end
    end
    return true, IsPlayerAceAllowed(source, 'queue.priority')
end)
```

A couple of details worth pointing out. A player who isn't in the guild (404) or has no
Discord linked gets an empty role list, so any groups they had are revoked; a Discord outage
(any other status) leaves their groups untouched instead of wiping them. And the
`Wait(100)` matters: commands written to stdin are processed on the next server tick, and
the `queue.priority` check right after needs the new principals to already be there.

The config ends up looking like this:

```cfg
set txadmin_password "a-long-random-password"
set discord_token "your-bot-token"
set discord_guild "123456789012345678"
set discord_role_111111111111111111 "admin"
set discord_role_222222222222222222 "vip"
```

Use `set`, not `setr` or `sets`, so the password and token are never replicated to clients
or published in the server list.

## Caveats

Let's be honest: this is a hack. It depends on txAdmin internals that aren't a public API
(the password login, the socket.io event name, the `rooms` query), so a txAdmin update could
break it. That's why every failure is printed to the console instead of failing silently.
Keep the `console_command` admin restricted to console permissions, and remember every
command it sends will show up in txAdmin's Live Console and logs under that account.

As soon as rfc#473 is fixed, all of this can go away: remove `txadmin_password` and the code
goes back to plain `ExecuteCommand` on its own.
